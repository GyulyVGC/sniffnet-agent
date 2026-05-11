use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
    pub last_seen: Instant,
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
        now: Instant,
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
                state.last_seen = now;
            })
            .or_insert(FlowState {
                delta_bytes: bytes,
                delta_packets: 1,
                src_mac,
                dst_mac,
                last_seen: now,
            });
    }

    /// Walk the table, snapshot all flows with non-zero deltas, zero their deltas
    /// in place, and return the snapshots. Entries themselves are retained.
    pub fn drain_deltas(&self) -> Vec<(FlowKey, FlowSnapshot)> {
        let mut map = self.inner.lock().expect("flow table mutex poisoned");
        let mut out = Vec::with_capacity(map.len());
        for (key, state) in map.iter_mut() {
            if state.delta_bytes == 0 && state.delta_packets == 0 {
                continue;
            }
            out.push((
                *key,
                FlowSnapshot {
                    bytes: state.delta_bytes,
                    packets: state.delta_packets,
                    src_mac: state.src_mac.unwrap_or([0; 6]),
                    dst_mac: state.dst_mac.unwrap_or([0; 6]),
                },
            ));
            state.delta_bytes = 0;
            state.delta_packets = 0;
        }
        out
    }

    /// Remove entries whose `last_seen` is older than `now - max_idle`.
    /// Returns the number of evicted entries.
    pub fn evict_idle(&self, now: Instant, max_idle: Duration) -> usize {
        let mut map = self.inner.lock().expect("flow table mutex poisoned");
        let before = map.len();
        map.retain(|_, state| now.duration_since(state.last_seen) < max_idle);
        before - map.len()
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

    #[test]
    fn record_accumulates_deltas_and_packet_count() {
        let table = FlowTable::new();
        let now = Instant::now();
        let k = key(1, 2);
        table.record(k, 100, Some([1; 6]), Some([2; 6]), now);
        table.record(k, 50, None, None, now);

        let snap = table.drain_deltas();
        assert_eq!(snap.len(), 1);
        let (got_key, state) = snap[0];
        assert_eq!(got_key, k);
        assert_eq!(state.bytes, 150);
        assert_eq!(state.packets, 2);
        assert_eq!(state.src_mac, [1; 6]);
        assert_eq!(state.dst_mac, [2; 6]);
    }

    #[test]
    fn drain_zeroes_deltas_and_retains_entries() {
        let table = FlowTable::new();
        let now = Instant::now();
        let k = key(1, 2);
        table.record(k, 100, None, None, now);

        let first = table.drain_deltas();
        assert_eq!(first.len(), 1);

        let second = table.drain_deltas();
        assert!(second.is_empty(), "second drain should yield no records");
        assert_eq!(table.len(), 1, "entry must be retained across drain");
    }

    #[test]
    fn drain_skips_zero_delta_entries() {
        let table = FlowTable::new();
        let now = Instant::now();
        table.record(key(1, 2), 100, None, None, now);
        table.record(key(3, 4), 200, None, None, now);
        let _ = table.drain_deltas();
        table.record(key(3, 4), 50, None, None, now);

        let snap = table.drain_deltas();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, key(3, 4));
        assert_eq!(snap[0].1.bytes, 50);
    }

    #[test]
    fn evict_idle_removes_stale_entries_only() {
        let table = FlowTable::new();
        let old = Instant::now();
        std::thread::sleep(Duration::from_millis(20));
        let fresh = Instant::now();

        table.record(key(1, 2), 100, None, None, old);
        table.record(key(3, 4), 100, None, None, fresh);

        let now = Instant::now();
        let evicted = table.evict_idle(now, Duration::from_millis(15));
        assert_eq!(evicted, 1);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn record_does_not_clobber_existing_mac() {
        let table = FlowTable::new();
        let now = Instant::now();
        let k = key(1, 2);
        table.record(k, 100, Some([0xaa; 6]), Some([0xbb; 6]), now);
        table.record(k, 100, Some([0xcc; 6]), Some([0xdd; 6]), now);
        let snap = table.drain_deltas();
        assert_eq!(snap[0].1.src_mac, [0xaa; 6]);
        assert_eq!(snap[0].1.dst_mac, [0xbb; 6]);
    }
}
