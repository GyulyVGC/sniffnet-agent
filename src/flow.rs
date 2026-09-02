use crate::direction::{FlowDirection, get_direction};
use sniffnet_packet_parser::Protocol;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Source/destination IPs of a flow, paired by family so mixed-family
/// [`FlowKey`]s are unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowAddrs {
    V4 { src: Ipv4Addr, dst: Ipv4Addr },
    V6 { src: Ipv6Addr, dst: Ipv6Addr },
}

impl FlowAddrs {
    fn src(self) -> IpAddr {
        match self {
            FlowAddrs::V4 { src, .. } => IpAddr::V4(src),
            FlowAddrs::V6 { src, .. } => IpAddr::V6(src),
        }
    }

    fn dst(self) -> IpAddr {
        match self {
            FlowAddrs::V4 { dst, .. } => IpAddr::V4(dst),
            FlowAddrs::V6 { dst, .. } => IpAddr::V6(dst),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub addrs: FlowAddrs,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: u8,
}

impl FlowKey {
    /// True for flows that look like the agent's own IPFIX export (UDP to the
    /// collector's address+port). Filtered out on the main thread so they
    /// don't appear in the exported stream.
    pub fn is_self_export(&self, collector: SocketAddr) -> bool {
        Protocol::from_number(self.protocol) == Some(Protocol::Udp)
            && self.addrs.dst() == collector.ip()
            && self.dst_port == Some(collector.port())
    }
}

/// Value of a flow. `src_mac` / `dst_mac` are `None` when the link type
/// carries no MACs or when no MAC has been observed yet for this flow; the
/// encoder writes all-zero on the wire in that case. `direction` is `None`
/// while the flow is accumulating and is filled in after drain.
/// `first_seen_ms` / `last_seen_ms` are kernel packet timestamps (ms since
/// UNIX epoch) from libpcap — emitted as IPFIX IE 152 / 153.
#[derive(Debug, Clone, Copy)]
pub struct FlowVal {
    pub bytes: u64,
    pub packets: u64,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub direction: Option<FlowDirection>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

impl FlowVal {
    /// Compute and attach direction for this flow given its `key` and the
    /// current interface address snapshot.
    pub fn with_direction(mut self, key: &FlowKey, my_addresses: &[IpAddr]) -> Self {
        let src = key.addrs.src();
        let dst = key.addrs.dst();
        self.direction = get_direction(&src, &dst, key.src_port, key.dst_port, my_addresses);
        self
    }
}

pub struct FlowTable {
    inner: HashMap<FlowKey, FlowVal>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn record(
        &mut self,
        key: FlowKey,
        bytes: u64,
        src_mac: Option<[u8; 6]>,
        dst_mac: Option<[u8; 6]>,
        ts_ms: u64,
    ) {
        self.inner
            .entry(key)
            .and_modify(|val| {
                val.bytes = val.bytes.saturating_add(bytes);
                val.packets = val.packets.saturating_add(1);
                if val.src_mac.is_none() {
                    val.src_mac = src_mac;
                }
                if val.dst_mac.is_none() {
                    val.dst_mac = dst_mac;
                }
                if ts_ms < val.first_seen_ms {
                    val.first_seen_ms = ts_ms;
                }
                if ts_ms > val.last_seen_ms {
                    val.last_seen_ms = ts_ms;
                }
            })
            .or_insert(FlowVal {
                bytes,
                packets: 1,
                src_mac,
                dst_mac,
                direction: None,
                first_seen_ms: ts_ms,
                last_seen_ms: ts_ms,
            });
    }

    /// Hand the accumulated flow map off to the main thread. All post-processing
    /// (self-export filtering, direction annotation, export) happens downstream
    /// so the capture loop stays tight. The table is empty after this call;
    /// flows still active will be re-inserted by the capture thread when their
    /// next packet arrives.
    pub fn drain(&mut self) -> HashMap<FlowKey, FlowVal> {
        std::mem::take(&mut self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(a: u8, b: u8) -> FlowKey {
        FlowKey {
            addrs: FlowAddrs::V4 {
                src: Ipv4Addr::new(10, 0, 0, a),
                dst: Ipv4Addr::new(10, 0, 0, b),
            },
            src_port: Some(1000 + u16::from(a)),
            dst_port: Some(443),
            protocol: 6,
        }
    }

    #[test]
    fn record_accumulates_bytes_and_packets() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, Some([1; 6]), Some([2; 6]), 1_000);
        table.record(k, 50, None, None, 2_500);

        let flows = table.drain();
        assert_eq!(flows.len(), 1);
        let state = flows[&k];
        assert_eq!(state.bytes, 150);
        assert_eq!(state.packets, 2);
        assert_eq!(state.src_mac, Some([1; 6]));
        assert_eq!(state.dst_mac, Some([2; 6]));
        assert_eq!(state.first_seen_ms, 1_000);
        assert_eq!(state.last_seen_ms, 2_500);
    }

    #[test]
    fn drain_empties_the_table() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, None, None, 0);

        let first = table.drain();
        assert_eq!(first.len(), 1);
        assert_eq!(table.inner.len(), 0, "drain must clear the table");

        let second = table.drain();
        assert!(second.is_empty());
    }

    #[test]
    fn record_after_drain_creates_fresh_entry() {
        let mut table = FlowTable::new();
        table.record(key(1, 2), 100, None, None, 0);
        table.record(key(3, 4), 200, None, None, 0);
        let _ = table.drain();
        table.record(key(3, 4), 50, None, None, 0);

        let flows = table.drain();
        assert_eq!(flows.len(), 1);
        let v = flows[&key(3, 4)];
        assert_eq!(v.bytes, 50);
    }

    #[test]
    fn record_does_not_clobber_existing_mac() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, Some([0xaa; 6]), Some([0xbb; 6]), 0);
        table.record(k, 100, Some([0xcc; 6]), Some([0xdd; 6]), 0);
        let flows = table.drain();
        assert_eq!(flows[&k].src_mac, Some([0xaa; 6]));
        assert_eq!(flows[&k].dst_mac, Some([0xbb; 6]));
    }

    #[test]
    fn record_first_and_last_track_min_max() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 1, None, None, 5_000);
        table.record(k, 1, None, None, 3_000); // out-of-order earlier packet
        table.record(k, 1, None, None, 7_000);
        let flows = table.drain();
        assert_eq!(flows[&k].first_seen_ms, 3_000);
        assert_eq!(flows[&k].last_seen_ms, 7_000);
    }

    #[test]
    fn is_self_export_only_matches_udp_to_collector() {
        let collector_v4 = Ipv4Addr::new(127, 0, 0, 1);
        let collector_port = 4739;
        let collector = SocketAddr::new(IpAddr::V4(collector_v4), collector_port);

        // UDP to collector — matches
        let self_export = FlowKey {
            addrs: FlowAddrs::V4 {
                src: Ipv4Addr::new(192, 168, 1, 10),
                dst: collector_v4,
            },
            src_port: Some(54321),
            dst_port: Some(collector_port),
            protocol: 17,
        };
        // TCP to same dst:port — different protocol, no match
        let tcp_to_collector_port = FlowKey {
            protocol: 6,
            ..self_export
        };
        // UDP to different dst — no match
        let unrelated_udp = FlowKey {
            addrs: FlowAddrs::V4 {
                src: Ipv4Addr::new(192, 168, 1, 10),
                dst: Ipv4Addr::new(8, 8, 8, 8),
            },
            ..self_export
        };
        // UDP to different port — no match
        let udp_to_other_port = FlowKey {
            dst_port: Some(9999),
            ..self_export
        };

        assert!(self_export.is_self_export(collector));
        assert!(!tcp_to_collector_port.is_self_export(collector));
        assert!(!unrelated_udp.is_self_export(collector));
        assert!(!udp_to_other_port.is_self_export(collector));
    }

    #[test]
    fn with_direction_classifies_against_interface_addresses() {
        let local_v4 = Ipv4Addr::new(192, 168, 1, 10);
        let remote_v4 = Ipv4Addr::new(8, 8, 8, 8);
        let local = IpAddr::V4(local_v4);

        let outgoing = FlowKey {
            addrs: FlowAddrs::V4 {
                src: local_v4,
                dst: remote_v4,
            },
            src_port: Some(40000),
            dst_port: Some(443),
            protocol: 6,
        };
        let incoming = FlowKey {
            addrs: FlowAddrs::V4 {
                src: remote_v4,
                dst: local_v4,
            },
            src_port: Some(443),
            dst_port: Some(40000),
            protocol: 6,
        };
        let val = FlowVal {
            bytes: 0,
            packets: 0,
            src_mac: None,
            dst_mac: None,
            direction: None,
            first_seen_ms: 0,
            last_seen_ms: 0,
        };
        let by_key: HashMap<_, _> = [(outgoing, val), (incoming, val)]
            .into_iter()
            .map(|(k, v)| (k, v.with_direction(&k, &[local]).direction))
            .collect();
        assert_eq!(by_key[&outgoing], Some(FlowDirection::Outgoing));
        assert_eq!(by_key[&incoming], Some(FlowDirection::Incoming));
    }

    #[test]
    fn with_direction_is_none_without_interface_addresses() {
        let val = FlowVal {
            bytes: 0,
            packets: 0,
            src_mac: None,
            dst_mac: None,
            direction: None,
            first_seen_ms: 0,
            last_seen_ms: 0,
        };
        let annotated = val.with_direction(&key(1, 2), &[]);
        assert_eq!(annotated.direction, None);
    }
}
