use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct FlowState {
    pub delta_bytes: u64,
    pub delta_packets: u64,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
}

/// Snapshot of a flow emitted to the encoder. MACs default to all-zero when unknown.
#[derive(Debug, Clone, Copy)]
pub struct FlowSnapshot {
    pub bytes: u64,
    pub packets: u64,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

pub struct FlowTable {
    inner: Mutex<HashMap<FlowKey, FlowState>>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn record(
        &self,
        key: FlowKey,
        bytes: u64,
        src_mac: Option<[u8; 6]>,
        dst_mac: Option<[u8; 6]>,
    ) {
        let mut map = self.inner.lock().expect("flow table mutex poisoned");
        map.entry(key)
            .and_modify(|state| {
                state.delta_bytes = state.delta_bytes.saturating_add(bytes);
                state.delta_packets = state.delta_packets.saturating_add(1);
                if state.src_mac.is_none() {
                    state.src_mac = src_mac;
                }
                if state.dst_mac.is_none() {
                    state.dst_mac = dst_mac;
                }
            })
            .or_insert(FlowState {
                delta_bytes: bytes,
                delta_packets: 1,
                src_mac,
                dst_mac,
            });
    }

    /// Drain all entries from the table, returning a snapshot of each. Flows
    /// matching `(dst_ip, dst_port, UDP)` of `exclude` are dropped — used to
    /// suppress the agent's own outbound IPFIX exports from the output. The
    /// table is empty after this call; flows still active will be re-inserted
    /// by the capture thread when their next packet arrives.
    pub fn drain_deltas(&self, exclude: SocketAddr) -> Vec<(FlowKey, FlowSnapshot)> {
        let mut map = self.inner.lock().expect("flow table mutex poisoned");
        map.drain()
            .filter(|(key, _)| {
                !(key.protocol == 17
                    && key.dst_ip == exclude.ip()
                    && key.dst_port == exclude.port())
            })
            .map(|(key, state)| {
                (
                    key,
                    FlowSnapshot {
                        bytes: state.delta_bytes,
                        packets: state.delta_packets,
                        src_mac: state.src_mac.unwrap_or([0; 6]),
                        dst_mac: state.dst_mac.unwrap_or([0; 6]),
                    },
                )
            })
            .collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
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
    fn record_accumulates_deltas_and_packet_count() {
        let table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, Some([1; 6]), Some([2; 6]));
        table.record(k, 50, None, None);

        let snap = table.drain_deltas(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(snap.len(), 1);
        let (got_key, state) = snap[0];
        assert_eq!(got_key, k);
        assert_eq!(state.bytes, 150);
        assert_eq!(state.packets, 2);
        assert_eq!(state.src_mac, [1; 6]);
        assert_eq!(state.dst_mac, [2; 6]);
    }

    #[test]
    fn drain_empties_the_table() {
        let table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, None, None);

        let first = table.drain_deltas(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(first.len(), 1);
        assert_eq!(table.len(), 0, "drain must clear the table");

        let second = table.drain_deltas(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert!(second.is_empty());
    }

    #[test]
    fn record_after_drain_creates_fresh_entry() {
        let table = FlowTable::new();
        table.record(key(1, 2), 100, None, None);
        table.record(key(3, 4), 200, None, None);
        let _ = table.drain_deltas(SocketAddr::from(([0, 0, 0, 0], 0)));
        table.record(key(3, 4), 50, None, None);

        let snap = table.drain_deltas(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, key(3, 4));
        assert_eq!(snap[0].1.bytes, 50);
    }

    #[test]
    fn record_does_not_clobber_existing_mac() {
        let table = FlowTable::new();
        let k = key(1, 2);
        table.record(k, 100, Some([0xaa; 6]), Some([0xbb; 6]));
        table.record(k, 100, Some([0xcc; 6]), Some([0xdd; 6]));
        let snap = table.drain_deltas(SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(snap[0].1.src_mac, [0xaa; 6]);
        assert_eq!(snap[0].1.dst_mac, [0xbb; 6]);
    }

    #[test]
    fn drain_excludes_only_udp_matching_collector() {
        let table = FlowTable::new();
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

        let snap = table.drain_deltas(exclude);
        assert_eq!(snap.len(), 2);
        let keys: std::collections::HashSet<_> = snap.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&tcp_to_collector_port));
        assert!(keys.contains(&unrelated_udp));
        assert!(!keys.contains(&self_export));
    }
}
