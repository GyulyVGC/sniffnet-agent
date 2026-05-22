use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Value of a flow. `src_mac` / `dst_mac` are `None` when the link type
/// carries no MACs or when no MAC has been observed yet for this flow; the
/// encoder writes all-zero on the wire in that case.
#[derive(Debug, Clone, Copy)]
pub struct FlowVal {
    pub bytes: u64,
    pub packets: u64,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
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
            });
    }

    /// Drain all entries from the table. Flows matching `(dst_ip, dst_port, UDP)`
    /// of `exclude` are dropped — used to suppress the agent's own outbound IPFIX
    /// exports from the output. The table is empty after this call; flows still
    /// active will be re-inserted by the capture thread when their next packet
    /// arrives.
    pub fn drain(&mut self, exclude: SocketAddr) -> Vec<(FlowKey, FlowVal)> {
        self.inner
            .drain()
            .filter(|(key, _)| {
                !(key.protocol == 17
                    && key.dst_ip == exclude.ip()
                    && key.dst_port == exclude.port())
            })
            .collect()
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

    // Test flows are TCP (protocol 6); the exclude only fires on UDP, so any
    // SocketAddr works as a no-op exclude.
    #[test]
    fn record_accumulates_bytes_and_packets() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, Some([1; 6]), Some([2; 6]));
        table.record(k, 50, None, None);

        let flows = table.drain(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(flows.len(), 1);
        let (got_key, state) = flows[0];
        assert_eq!(got_key, k);
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

        let first = table.drain(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(first.len(), 1);
        assert_eq!(table.len(), 0, "drain must clear the table");

        let second = table.drain(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert!(second.is_empty());
    }

    #[test]
    fn record_after_drain_creates_fresh_entry() {
        let mut table = FlowTable::new();
        table.record(key(1, 2), 100, None, None);
        table.record(key(3, 4), 200, None, None);
        let _ = table.drain(SocketAddr::from(([0, 0, 0, 0], 0)));
        table.record(key(3, 4), 50, None, None);

        let flows = table.drain(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].0, key(3, 4));
        assert_eq!(flows[0].1.bytes, 50);
    }

    #[test]
    fn record_does_not_clobber_existing_mac() {
        let mut table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, Some([0xaa; 6]), Some([0xbb; 6]));
        table.record(k, 100, Some([0xcc; 6]), Some([0xdd; 6]));
        let flows = table.drain(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(flows[0].1.src_mac, Some([0xaa; 6]));
        assert_eq!(flows[0].1.dst_mac, Some([0xbb; 6]));
    }

    #[test]
    fn drain_excludes_only_udp_matching_collector() {
        let mut table = FlowTable::new();
        let collector_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let collector_port = 4739;
        let exclude = SocketAddr::new(collector_ip, collector_port);

        // self-export (UDP to collector) — must be dropped
        let self_export = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_ip: collector_ip,
            src_port: 54321,
            dst_port: collector_port,
            protocol: 17,
        };
        // TCP to same dst:port — must be kept (different protocol)
        let tcp_to_collector_port = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
            dst_ip: collector_ip,
            src_port: 1000,
            dst_port: collector_port,
            protocol: 6,
        };
        // UDP to different dst — must be kept
        let unrelated_udp = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 5000,
            dst_port: 53,
            protocol: 17,
        };

        table.record(self_export, 100, None, None);
        table.record(tcp_to_collector_port, 200, None, None);
        table.record(unrelated_udp, 300, None, None);

        let flows = table.drain(exclude);
        assert_eq!(flows.len(), 2);
        let keys: std::collections::HashSet<_> = flows.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&tcp_to_collector_port));
        assert!(keys.contains(&unrelated_udp));
        assert!(!keys.contains(&self_export));
    }
}
