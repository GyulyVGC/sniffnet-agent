use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::direction::{FlowDirection, get_direction};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// True for flows that look like the agent's own IPFIX export (UDP to the
    /// collector's address+port). Filtered out on the main thread so they
    /// don't appear in the exported stream.
    pub fn is_self_export(&self, collector: SocketAddr) -> bool {
        self.protocol == 17 && self.dst_ip == collector.ip() && self.dst_port == collector.port()
    }
}

/// Value of a flow. `src_mac` / `dst_mac` are `None` when the link type
/// carries no MACs or when no MAC has been observed yet for this flow; the
/// encoder writes all-zero on the wire in that case. `direction` is `None`
/// while the flow is accumulating and is filled in after drain.
#[derive(Debug, Clone, Copy)]
pub struct FlowVal {
    pub bytes: u64,
    pub packets: u64,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub direction: Option<FlowDirection>,
}

impl FlowVal {
    /// Compute and attach direction for this flow given its `key` and the
    /// current interface address snapshot. Builder-shaped so it slots into an
    /// iterator: `.map(|(k, v)| (k, v.with_direction(&k, &addrs)))`. Runs on
    /// the main thread so the pcap address lookup doesn't compete with capture.
    pub fn with_direction(mut self, key: &FlowKey, my_addresses: &[IpAddr]) -> Self {
        // Sniffnet's get_traffic_direction takes Option<u16> ports — None when
        // the packet has no transport-layer port (ICMP). Mirror that here.
        let port_aware = matches!(key.protocol, 6 | 17);
        self.direction = get_direction(
            &key.src_ip,
            &key.dst_ip,
            port_aware.then_some(key.src_port),
            port_aware.then_some(key.dst_port),
            my_addresses,
        );
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
            })
            .or_insert(FlowVal {
                bytes,
                packets: 1,
                src_mac,
                dst_mac,
                direction: None,
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

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(a: u8, b: u8) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, a)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, b)),
            src_port: 1000 + u16::from(a),
            dst_port: 443,
            protocol: 6,
        }
    }

    #[test]
    fn record_accumulates_bytes_and_packets() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, Some([1; 6]), Some([2; 6]));
        table.record(k, 50, None, None);

        let flows = table.drain();
        assert_eq!(flows.len(), 1);
        let state = flows[&k];
        assert_eq!(state.bytes, 150);
        assert_eq!(state.packets, 2);
        assert_eq!(state.src_mac, Some([1; 6]));
        assert_eq!(state.dst_mac, Some([2; 6]));
    }

    #[test]
    fn drain_empties_the_table() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, None, None);

        let first = table.drain();
        assert_eq!(first.len(), 1);
        assert_eq!(table.len(), 0, "drain must clear the table");

        let second = table.drain();
        assert!(second.is_empty());
    }

    #[test]
    fn record_after_drain_creates_fresh_entry() {
        let mut table = FlowTable::new();
        table.record(key(1, 2), 100, None, None);
        table.record(key(3, 4), 200, None, None);
        let _ = table.drain();
        table.record(key(3, 4), 50, None, None);

        let flows = table.drain();
        assert_eq!(flows.len(), 1);
        let v = flows[&key(3, 4)];
        assert_eq!(v.bytes, 50);
    }

    #[test]
    fn record_does_not_clobber_existing_mac() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, Some([0xaa; 6]), Some([0xbb; 6]));
        table.record(k, 100, Some([0xcc; 6]), Some([0xdd; 6]));
        let flows = table.drain();
        assert_eq!(flows[&k].src_mac, Some([0xaa; 6]));
        assert_eq!(flows[&k].dst_mac, Some([0xbb; 6]));
    }

    #[test]
    fn is_self_export_only_matches_udp_to_collector() {
        let collector_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let collector_port = 4739;
        let collector = SocketAddr::new(collector_ip, collector_port);

        // UDP to collector — matches
        let self_export = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: collector_ip,
            src_port: 54321,
            dst_port: collector_port,
            protocol: 17,
        };
        // TCP to same dst:port — different protocol, no match
        let tcp_to_collector_port = FlowKey {
            protocol: 6,
            ..self_export
        };
        // UDP to different dst — no match
        let unrelated_udp = FlowKey {
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ..self_export
        };

        assert!(self_export.is_self_export(collector));
        assert!(!tcp_to_collector_port.is_self_export(collector));
        assert!(!unrelated_udp.is_self_export(collector));
    }

    #[test]
    fn with_direction_classifies_against_interface_addresses() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let outgoing = FlowKey {
            src_ip: local,
            dst_ip: remote,
            src_port: 40000,
            dst_port: 443,
            protocol: 6,
        };
        let incoming = FlowKey {
            src_ip: remote,
            dst_ip: local,
            src_port: 443,
            dst_port: 40000,
            protocol: 6,
        };
        let val = FlowVal {
            bytes: 0,
            packets: 0,
            src_mac: None,
            dst_mac: None,
            direction: None,
        };
        let by_key: std::collections::HashMap<_, _> = [(outgoing, val), (incoming, val)]
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
        };
        let annotated = val.with_direction(&key(1, 2), &[]);
        assert_eq!(annotated.direction, None);
    }
}
