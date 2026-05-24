//! RFC 7011 IPFIX message encoder.
//!
//! Builds one or more IPFIX-over-UDP datagrams from a batch of flow flows,
//! splitting across datagrams to stay under `mtu`. Each datagram has the form
//!
//! ```text
//! [Message Header (16B)]
//! [Template Set (84B)]?       <-- only in the first datagram when refresh due
//! [Data Set v4 (4B + N*41)]?  <-- present only if there are v4 records
//! [Data Set v6 (4B + N*65)]?  <-- present only if there are v6 records
//! ```
//!
//! Sequence number semantics follow RFC 7011 §3.1 (cumulative count of Data
//! Records sent on the stream, modulo 2^32).

use std::net::IpAddr;

use crate::flow::{FlowKey, FlowVal};
use crate::ipfix::template::write_template_set;
use crate::ipfix::{
    RECORD_SIZE_V4, RECORD_SIZE_V6, SET_HEADER_LEN, TEMPLATE_ID_V4, TEMPLATE_ID_V6, VERSION,
};

/// Encode `flows` into one or more UDP-ready datagrams.
///
/// Returns the datagrams (in send order) and the new sequence number that the
/// caller should persist as the starting point for the next call.
pub fn build_datagrams(
    flows: &[(FlowKey, FlowVal)],
    seq_start: u32,
    mut include_template_set: bool,
    now_unix: u32,
) -> (Vec<Vec<u8>>, u32) {
    let mtu: usize = 1400;

    let mut v4: Vec<&(FlowKey, FlowVal)> = Vec::new();
    let mut v6: Vec<&(FlowKey, FlowVal)> = Vec::new();
    for flow in flows {
        match flow.0.src_ip {
            IpAddr::V4(_) => v4.push(flow),
            IpAddr::V6(_) => v6.push(flow),
        }
    }

    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    let mut seq = seq_start;
    let mut v4_idx = 0usize;
    let mut v6_idx = 0usize;

    while v4_idx < v4.len() || v6_idx < v6.len() {
        let mut buf = Vec::with_capacity(mtu);

        // Message header placeholder; backfilled with length/seq below.
        buf.extend_from_slice(&VERSION.to_be_bytes());
        buf.extend_from_slice(&[0u8, 0u8]); // length placeholder
        buf.extend_from_slice(&now_unix.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());

        if include_template_set {
            write_template_set(&mut buf);
            include_template_set = false;
        }

        let mut records_in_msg = 0u32;

        if v4_idx < v4.len() {
            let remaining_budget = mtu.saturating_sub(buf.len()).saturating_sub(SET_HEADER_LEN);
            let fit = remaining_budget / RECORD_SIZE_V4;
            let take = fit.min(v4.len() - v4_idx);
            if take > 0 {
                write_data_set(&mut buf, TEMPLATE_ID_V4, take * RECORD_SIZE_V4, |out| {
                    for flow in &v4[v4_idx..v4_idx + take] {
                        write_v4_record(out, &flow.0, &flow.1);
                    }
                });
                v4_idx += take;
                records_in_msg += take as u32;
            }
        }

        if v6_idx < v6.len() {
            let remaining_budget = mtu.saturating_sub(buf.len()).saturating_sub(SET_HEADER_LEN);
            let fit = remaining_budget / RECORD_SIZE_V6;
            let take = fit.min(v6.len() - v6_idx);
            if take > 0 {
                write_data_set(&mut buf, TEMPLATE_ID_V6, take * RECORD_SIZE_V6, |out| {
                    for flow in &v6[v6_idx..v6_idx + take] {
                        write_v6_record(out, &flow.0, &flow.1);
                    }
                });
                v6_idx += take;
                records_in_msg += take as u32;
            }
        }

        debug_assert!(records_in_msg > 0, "encoder made no forward progress");

        // Back-patch message length (offsets 2..4).
        let total_len = u16::try_from(buf.len()).expect("datagram exceeds u16 length");
        let len_be = total_len.to_be_bytes();
        buf[2] = len_be[0];
        buf[3] = len_be[1];

        seq = seq.wrapping_add(records_in_msg);
        datagrams.push(buf);
    }

    (datagrams, seq)
}

fn write_data_set(
    out: &mut Vec<u8>,
    set_id: u16,
    payload_len: usize,
    write_payload: impl FnOnce(&mut Vec<u8>),
) {
    let set_len = SET_HEADER_LEN + payload_len;
    out.extend_from_slice(&set_id.to_be_bytes());
    out.extend_from_slice(&(set_len as u16).to_be_bytes());
    write_payload(out);
}

fn write_v4_record(out: &mut Vec<u8>, key: &FlowKey, val: &FlowVal) {
    let IpAddr::V4(src) = key.src_ip else {
        unreachable!("v4 bucket only contains v4 source addresses");
    };
    let IpAddr::V4(dst) = key.dst_ip else {
        // If src is v4 but dst is v6 we have a misconfigured flow; emit zero
        // address rather than panic. Capture pipeline rejects mixed-family flows.
        out.extend_from_slice(&src.octets());
        out.extend_from_slice(&[0u8; 4]);
        write_common_tail(out, key, val);
        return;
    };
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    write_common_tail(out, key, val);
}

fn write_v6_record(out: &mut Vec<u8>, key: &FlowKey, val: &FlowVal) {
    let IpAddr::V6(src) = key.src_ip else {
        unreachable!("v6 bucket only contains v6 source addresses");
    };
    let IpAddr::V6(dst) = key.dst_ip else {
        out.extend_from_slice(&src.octets());
        out.extend_from_slice(&[0u8; 16]);
        write_common_tail(out, key, val);
        return;
    };
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    write_common_tail(out, key, val);
}

fn write_common_tail(out: &mut Vec<u8>, key: &FlowKey, val: &FlowVal) {
    out.extend_from_slice(&key.src_port.unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&key.dst_port.unwrap_or(0).to_be_bytes());
    out.push(key.protocol);
    out.extend_from_slice(&val.src_mac.unwrap_or([0; 6]));
    out.extend_from_slice(&val.dst_mac.unwrap_or([0; 6]));
    out.push(match val.direction {
        Some(crate::direction::FlowDirection::Incoming) => 0x00,
        Some(crate::direction::FlowDirection::Outgoing) => 0x01,
        None => 0xFF,
    });
    out.extend_from_slice(&val.bytes.to_be_bytes());
    out.extend_from_slice(&val.packets.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4_flow(a: u8, b: u8, bytes: u64, packets: u64) -> (FlowKey, FlowVal) {
        (
            FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, a)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, b)),
                src_port: Some(1000 + u16::from(a)),
                dst_port: Some(443),
                protocol: 6,
            },
            FlowVal {
                bytes,
                packets,
                src_mac: Some([0xaa; 6]),
                dst_mac: Some([0xbb; 6]),
                direction: None,
            },
        )
    }

    fn v6_flow(bytes: u64, packets: u64) -> (FlowKey, FlowVal) {
        (
            FlowKey {
                src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                src_port: Some(5555),
                dst_port: Some(80),
                protocol: 17,
            },
            FlowVal {
                bytes,
                packets,
                src_mac: None,
                dst_mac: None,
                direction: None,
            },
        )
    }

    #[test]
    fn empty_flows_produces_no_datagrams() {
        let (out, seq) = build_datagrams(&[], 0, false, 12345);
        assert!(out.is_empty());
        assert_eq!(seq, 0);
    }

    #[test]
    fn header_layout_is_exact() {
        let s = [v4_flow(1, 2, 100, 5)];
        let (out, _) = build_datagrams(&s, 0x1122_3344, false, 0xDEADBEEF);
        assert_eq!(out.len(), 1);
        let dg = &out[0];
        assert_eq!(dg[0..2], 0x000Au16.to_be_bytes(), "version");
        // length back-patched: header(16) + data set header(4) + 1 v4 record(42) = 62
        assert_eq!(u16::from_be_bytes([dg[2], dg[3]]), 62);
        assert_eq!(dg[4..8], 0xDEADBEEFu32.to_be_bytes(), "export_time");
        assert_eq!(dg[8..12], 0x1122_3344u32.to_be_bytes(), "sequence");
        assert_eq!(dg[12..16], 0u32.to_be_bytes(), "odid");
    }

    #[test]
    fn template_set_only_in_first_datagram() {
        let flows: Vec<_> = (0..50)
            .map(|i| v4_flow(i as u8, (i + 1) as u8, 100, 1))
            .collect();
        let (out, _) = build_datagrams(&flows, 0, true, 0);
        assert!(out.len() >= 2);
        // first datagram should contain template set id (2) right after header
        let first_set_id = u16::from_be_bytes([out[0][16], out[0][17]]);
        assert_eq!(first_set_id, 2);
        // subsequent datagrams should start with a data set (id 256)
        let second_set_id = u16::from_be_bytes([out[1][16], out[1][17]]);
        assert_eq!(second_set_id, 256);
    }

    #[test]
    fn v4_record_byte_layout() {
        let key = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            src_port: Some(0xAABB),
            dst_port: Some(0x01BB),
            protocol: 6,
        };
        let val = FlowVal {
            bytes: 0x0102_0304_0506_0708,
            packets: 0x00FF,
            src_mac: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            dst_mac: Some([0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC]),
            direction: Some(crate::direction::FlowDirection::Outgoing),
        };
        let (out, _) = build_datagrams(&[(key, val)], 0, false, 0);
        let dg = &out[0];
        // Skip 16B header + 4B data set header = 20B prefix.
        let rec = &dg[20..20 + RECORD_SIZE_V4];
        assert_eq!(rec[0..4], [10, 0, 0, 1]);
        assert_eq!(rec[4..8], [192, 168, 1, 5]);
        assert_eq!(rec[8..10], [0xAA, 0xBB]);
        assert_eq!(rec[10..12], [0x01, 0xBB]);
        assert_eq!(rec[12], 6);
        assert_eq!(rec[13..19], [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(rec[19..25], [0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC]);
        assert_eq!(rec[25], 0x01, "flowDirection egress");
        assert_eq!(
            rec[26..34],
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(rec[34..42], 0x00FFu64.to_be_bytes());
    }

    #[test]
    fn direction_byte_encodes_all_three_states() {
        let key = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: 6,
        };
        let make = |dir| FlowVal {
            bytes: 1,
            packets: 1,
            src_mac: None,
            dst_mac: None,
            direction: dir,
        };
        let cases = [
            (Some(crate::direction::FlowDirection::Incoming), 0x00),
            (Some(crate::direction::FlowDirection::Outgoing), 0x01),
            (None, 0xFF),
        ];
        for (dir, expected) in cases {
            let (out, _) = build_datagrams(&[(key, make(dir))], 0, false, 0);
            // Byte offset for flowDirection: header(16) + set hdr(4) + 4+4+2+2+1+6+6 = 45.
            assert_eq!(out[0][45], expected, "dir {:?}", dir);
        }
    }

    #[test]
    fn sequence_number_advances_by_record_count() {
        let flows = vec![v4_flow(1, 2, 100, 1), v4_flow(3, 4, 200, 1)];
        let (_, seq) = build_datagrams(&flows, 100, false, 0);
        assert_eq!(seq, 102);
    }

    #[test]
    fn sequence_number_carries_across_messages() {
        // At mtu=1400 a no-template datagram fits floor((1400 - 16 - 4) / 42) = 32 v4
        // records. 67 records therefore splits into 32 + 32 + 3 across three datagrams.
        let flows: Vec<_> = (0..67)
            .map(|i| v4_flow((i % 250) as u8, ((i + 1) % 250) as u8, 100, 1))
            .collect();
        let (out, seq) = build_datagrams(&flows, 0, false, 0);
        assert_eq!(out.len(), 3);
        assert_eq!(
            u32::from_be_bytes([out[0][8], out[0][9], out[0][10], out[0][11]]),
            0
        );
        assert_eq!(
            u32::from_be_bytes([out[1][8], out[1][9], out[1][10], out[1][11]]),
            32
        );
        assert_eq!(
            u32::from_be_bytes([out[2][8], out[2][9], out[2][10], out[2][11]]),
            64
        );
        assert_eq!(seq, 67);
    }

    #[test]
    fn sequence_number_wraps_modulo_2_32() {
        let flows = vec![v4_flow(1, 2, 100, 1), v4_flow(3, 4, 100, 1)];
        let (_, seq) = build_datagrams(&flows, u32::MAX - 1, false, 0);
        assert_eq!(seq, 0);
    }

    #[test]
    fn mtu_split_v4_count_matches_input() {
        let flows: Vec<_> = (0..200)
            .map(|i| v4_flow((i % 250) as u8, ((i + 1) % 250) as u8, 100, 1))
            .collect();
        let (out, seq) = build_datagrams(&flows, 0, false, 0);
        assert_eq!(seq, 200);
        // Sum the records reported in each datagram's message length.
        let mut total_records = 0u32;
        for dg in &out {
            assert!(dg.len() <= 1400);
            let msg_len = u16::from_be_bytes([dg[2], dg[3]]) as usize;
            // After 16B msg hdr + 4B set hdr, what remains is records.
            let data_bytes = msg_len - 20;
            assert_eq!(data_bytes % RECORD_SIZE_V4, 0);
            total_records += (data_bytes / RECORD_SIZE_V4) as u32;
        }
        assert_eq!(total_records, 200);
    }

    #[test]
    fn v4_and_v6_share_a_datagram_when_room_allows() {
        let flows = vec![v4_flow(1, 2, 100, 1), v6_flow(200, 2)];
        let (out, _) = build_datagrams(&flows, 0, false, 0);
        assert_eq!(out.len(), 1);
        let dg = &out[0];
        // After 16B header: v4 data set (4 + 41 = 45B) then v6 data set (4 + 65 = 69B)
        let first_set_id = u16::from_be_bytes([dg[16], dg[17]]);
        let first_set_len = u16::from_be_bytes([dg[18], dg[19]]) as usize;
        assert_eq!(first_set_id, TEMPLATE_ID_V4);
        assert_eq!(first_set_len, SET_HEADER_LEN + RECORD_SIZE_V4);
        let off = 16 + first_set_len;
        let second_set_id = u16::from_be_bytes([dg[off], dg[off + 1]]);
        let second_set_len = u16::from_be_bytes([dg[off + 2], dg[off + 3]]) as usize;
        assert_eq!(second_set_id, TEMPLATE_ID_V6);
        assert_eq!(second_set_len, SET_HEADER_LEN + RECORD_SIZE_V6);
    }

    #[test]
    fn include_template_set_flag_drives_first_datagram_layout() {
        let flows = [v4_flow(1, 2, 100, 1)];
        let (with, _) = build_datagrams(&flows, 0, true, 0);
        let (without, _) = build_datagrams(&flows, 0, false, 0);
        // With template, the first set is the template set (id=2)
        let with_id = u16::from_be_bytes([with[0][16], with[0][17]]);
        let without_id = u16::from_be_bytes([without[0][16], without[0][17]]);
        assert_eq!(with_id, 2);
        assert_eq!(without_id, TEMPLATE_ID_V4);
        // With template ⇒ longer message
        assert!(with[0].len() > without[0].len());
    }
}
