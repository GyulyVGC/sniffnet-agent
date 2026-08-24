//! RFC 7011 IPFIX message encoder.
//!
//! Builds one or more IPFIX-over-UDP datagrams from a batch of flow flows,
//! splitting across datagrams to stay under `MTU`. Each datagram has the form
//!
//! ```text
//! [Message Header (16B)]
//! [Template Set (108B)]?      <-- only in the first datagram when refresh due
//! [Data Set v4 (4B + N*58)]?  <-- present only if there are v4 records
//! [Data Set v6 (4B + N*82)]?  <-- present only if there are v6 records
//! ```
//!
//! Sequence number semantics follow RFC 7011 §3.1 (cumulative count of Data
//! Records sent on the stream, modulo 2^32).

use crate::flow::{FlowAddrs, FlowKey, FlowVal};
use crate::ipfix::template::{TEMPLATE_SET_LEN, write_template_set};
use crate::ipfix::{
    MSG_HEADER_LEN, RECORD_SIZE_V4, RECORD_SIZE_V6, SET_HEADER_LEN, TEMPLATE_ID_V4, TEMPLATE_ID_V6,
    VERSION,
};

const MTU: u16 = 1200;

// MTU must hold the header, a template set, a set header, and at least one
// v6 record — otherwise the encode loop could spin without making progress.
const _: () = assert!(MTU >= MSG_HEADER_LEN + TEMPLATE_SET_LEN + SET_HEADER_LEN + RECORD_SIZE_V6);

/// Encode `flows` into one or more UDP-ready datagrams.
///
/// Returns the datagrams (in send order) and the new sequence number that the
/// caller should persist as the starting point for the next call.
pub fn build_datagrams(
    flows: &[(FlowKey, FlowVal)],
    seq_start: u32,
    mut include_template_set: bool,
    now_unix: u32,
    odid: u32,
) -> (Vec<Vec<u8>>, u32) {
    let mut v4: Vec<&(FlowKey, FlowVal)> = Vec::new();
    let mut v6: Vec<&(FlowKey, FlowVal)> = Vec::new();
    for flow in flows {
        match flow.0.addrs {
            FlowAddrs::V4 { .. } => v4.push(flow),
            FlowAddrs::V6 { .. } => v6.push(flow),
        }
    }

    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    let mut seq = seq_start;
    let mut v4_idx = 0usize;
    let mut v6_idx = 0usize;

    while v4_idx < v4.len() || v6_idx < v6.len() {
        let mut buf = Vec::with_capacity(usize::from(MTU));
        let mut msg_len: u16 = MSG_HEADER_LEN;

        // Message header placeholder; backfilled with length/seq below.
        buf.extend_from_slice(&VERSION.to_be_bytes());
        buf.extend_from_slice(&[0u8, 0u8]); // length placeholder
        buf.extend_from_slice(&now_unix.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&odid.to_be_bytes());

        if include_template_set {
            write_template_set(&mut buf);
            msg_len += TEMPLATE_SET_LEN;
            include_template_set = false;
        }

        let mut records_in_msg: u16 = 0;
        records_in_msg += pack_set(
            &mut buf,
            &v4,
            &mut v4_idx,
            TEMPLATE_ID_V4,
            RECORD_SIZE_V4,
            &mut msg_len,
        );
        records_in_msg += pack_set(
            &mut buf,
            &v6,
            &mut v6_idx,
            TEMPLATE_ID_V6,
            RECORD_SIZE_V6,
            &mut msg_len,
        );

        // Back-patch message length (offsets 2..4).
        let len_be = msg_len.to_be_bytes();
        buf[2] = len_be[0];
        buf[3] = len_be[1];

        seq = seq.wrapping_add(u32::from(records_in_msg));
        datagrams.push(buf);
    }

    (datagrams, seq)
}

/// Pack as many records as fit into one set; returns how many were written.
fn pack_set(
    buf: &mut Vec<u8>,
    flows: &[&(FlowKey, FlowVal)],
    idx: &mut usize,
    template_id: u16,
    record_size: u16,
    msg_len: &mut u16,
) -> u16 {
    let take = take_records(flows.len() - *idx, *msg_len, record_size);
    if take == 0 {
        return 0;
    }
    let payload_len = take * record_size;
    write_set_header(buf, template_id, payload_len);
    for flow in &flows[*idx..*idx + usize::from(take)] {
        write_record(buf, &flow.0, &flow.1);
    }
    *idx += usize::from(take);
    *msg_len += SET_HEADER_LEN + payload_len;
    take
}

/// How many `record_size`-byte records fit alongside one set header in the
/// remaining MTU budget, capped at the number still owed.
fn take_records(remaining: usize, msg_len: u16, record_size: u16) -> u16 {
    let budget = MTU.saturating_sub(msg_len).saturating_sub(SET_HEADER_LEN);
    let fit = budget / record_size;
    let remaining_capped = u16::try_from(remaining).unwrap_or(u16::MAX);
    fit.min(remaining_capped)
}

fn write_set_header(out: &mut Vec<u8>, set_id: u16, payload_len: u16) {
    out.extend_from_slice(&set_id.to_be_bytes());
    out.extend_from_slice(&(SET_HEADER_LEN + payload_len).to_be_bytes());
}

fn write_record(out: &mut Vec<u8>, key: &FlowKey, val: &FlowVal) {
    match key.addrs {
        FlowAddrs::V4 { src, dst } => {
            out.extend_from_slice(&src.octets());
            out.extend_from_slice(&dst.octets());
        }
        FlowAddrs::V6 { src, dst } => {
            out.extend_from_slice(&src.octets());
            out.extend_from_slice(&dst.octets());
        }
    }
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
    out.extend_from_slice(&val.first_seen_ms.to_be_bytes());
    out.extend_from_slice(&val.last_seen_ms.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4_flow(a: u8, b: u8, bytes: u64, packets: u64) -> (FlowKey, FlowVal) {
        (
            FlowKey {
                addrs: FlowAddrs::V4 {
                    src: Ipv4Addr::new(10, 0, 0, a),
                    dst: Ipv4Addr::new(10, 0, 0, b),
                },
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
                first_seen_ms: 0,
                last_seen_ms: 0,
            },
        )
    }

    fn v6_flow(bytes: u64, packets: u64) -> (FlowKey, FlowVal) {
        (
            FlowKey {
                addrs: FlowAddrs::V6 {
                    src: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                    dst: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
                },
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
                first_seen_ms: 0,
                last_seen_ms: 0,
            },
        )
    }

    #[test]
    fn empty_flows_produces_no_datagrams() {
        let (out, seq) = build_datagrams(&[], 0, false, 12345, 0);
        assert!(out.is_empty());
        assert_eq!(seq, 0);
    }

    #[test]
    fn header_layout_is_exact() {
        let s = [v4_flow(1, 2, 100, 5)];
        let (out, _) = build_datagrams(&s, 0x1122_3344, false, 0xDEADBEEF, 0);
        assert_eq!(out.len(), 1);
        let dg = &out[0];
        assert_eq!(dg[0..2], 0x000Au16.to_be_bytes(), "version");
        // length back-patched: header(16) + data set header(4) + 1 v4 record(58) = 78
        assert_eq!(u16::from_be_bytes([dg[2], dg[3]]), 78);
        assert_eq!(dg[4..8], 0xDEADBEEFu32.to_be_bytes(), "export_time");
        assert_eq!(dg[8..12], 0x1122_3344u32.to_be_bytes(), "sequence");
        assert_eq!(dg[12..16], 0u32.to_be_bytes(), "odid");
    }

    #[test]
    fn odid_is_written_in_every_datagram_header() {
        // enough flows to spill over more than one datagram
        let flows: Vec<_> = (0..50)
            .map(|i| v4_flow(i as u8, (i + 1) as u8, 100, 1))
            .collect();
        let (out, _) = build_datagrams(&flows, 0, true, 0, 0x0102_0304);
        assert!(out.len() >= 2);
        for dg in &out {
            assert_eq!(dg[12..16], 0x0102_0304u32.to_be_bytes(), "odid");
        }
    }

    #[test]
    fn template_set_only_in_first_datagram() {
        let flows: Vec<_> = (0..50)
            .map(|i| v4_flow(i as u8, (i + 1) as u8, 100, 1))
            .collect();
        let (out, _) = build_datagrams(&flows, 0, true, 0, 0);
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
            addrs: FlowAddrs::V4 {
                src: Ipv4Addr::new(10, 0, 0, 1),
                dst: Ipv4Addr::new(192, 168, 1, 5),
            },
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
            first_seen_ms: 0x1111_2222_3333_4444,
            last_seen_ms: 0x5555_6666_7777_8888,
        };
        let (out, _) = build_datagrams(&[(key, val)], 0, false, 0, 0);
        let dg = &out[0];
        // Skip 16B header + 4B data set header = 20B prefix.
        let rec = &dg[20..20 + usize::from(RECORD_SIZE_V4)];
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
        assert_eq!(rec[42..50], 0x1111_2222_3333_4444u64.to_be_bytes());
        assert_eq!(rec[50..58], 0x5555_6666_7777_8888u64.to_be_bytes());
    }

    #[test]
    fn v6_record_byte_layout() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let key = FlowKey {
            addrs: FlowAddrs::V6 { src, dst },
            src_port: Some(0xAABB),
            dst_port: Some(0x01BB),
            protocol: 17,
        };
        let val = FlowVal {
            bytes: 0x0102_0304_0506_0708,
            packets: 0x00FF,
            src_mac: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            dst_mac: Some([0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC]),
            direction: Some(crate::direction::FlowDirection::Incoming),
            first_seen_ms: 0x1111_2222_3333_4444,
            last_seen_ms: 0x5555_6666_7777_8888,
        };
        let (out, _) = build_datagrams(&[(key, val)], 0, false, 0, 0);
        let dg = &out[0];
        // Skip 16B header + 4B data set header = 20B prefix.
        let rec = &dg[20..20 + usize::from(RECORD_SIZE_V6)];
        assert_eq!(rec[0..16], src.octets());
        assert_eq!(rec[16..32], dst.octets());
        assert_eq!(rec[32..34], [0xAA, 0xBB]);
        assert_eq!(rec[34..36], [0x01, 0xBB]);
        assert_eq!(rec[36], 17);
        assert_eq!(rec[37..43], [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(rec[43..49], [0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC]);
        assert_eq!(rec[49], 0x00, "flowDirection ingress");
        assert_eq!(rec[50..58], 0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(rec[58..66], 0x00FFu64.to_be_bytes());
        assert_eq!(rec[66..74], 0x1111_2222_3333_4444u64.to_be_bytes());
        assert_eq!(rec[74..82], 0x5555_6666_7777_8888u64.to_be_bytes());
    }

    #[test]
    fn direction_byte_encodes_all_three_states() {
        let key = FlowKey {
            addrs: FlowAddrs::V4 {
                src: Ipv4Addr::new(10, 0, 0, 1),
                dst: Ipv4Addr::new(10, 0, 0, 2),
            },
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
            first_seen_ms: 0,
            last_seen_ms: 0,
        };
        let cases = [
            (Some(crate::direction::FlowDirection::Incoming), 0x00),
            (Some(crate::direction::FlowDirection::Outgoing), 0x01),
            (None, 0xFF),
        ];
        for (dir, expected) in cases {
            let (out, _) = build_datagrams(&[(key, make(dir))], 0, false, 0, 0);
            // Byte offset for flowDirection: header(16) + set hdr(4) + 4+4+2+2+1+6+6 = 45.
            assert_eq!(out[0][45], expected, "dir {:?}", dir);
        }
    }

    #[test]
    fn sequence_number_advances_by_record_count() {
        let flows = vec![v4_flow(1, 2, 100, 1), v4_flow(3, 4, 200, 1)];
        let (_, seq) = build_datagrams(&flows, 100, false, 0, 0);
        assert_eq!(seq, 102);
    }

    #[test]
    fn sequence_number_carries_across_messages() {
        // At mtu=1200 a no-template datagram fits floor((1200 - 16 - 4) / 58) = 20 v4
        // records. 67 records therefore splits into 20 + 20 + 20 + 7 across four datagrams.
        let flows: Vec<_> = (0..67)
            .map(|i| v4_flow((i % 250) as u8, ((i + 1) % 250) as u8, 100, 1))
            .collect();
        let (out, seq) = build_datagrams(&flows, 0, false, 0, 0);
        assert_eq!(out.len(), 4);
        assert_eq!(
            u32::from_be_bytes([out[0][8], out[0][9], out[0][10], out[0][11]]),
            0
        );
        assert_eq!(
            u32::from_be_bytes([out[1][8], out[1][9], out[1][10], out[1][11]]),
            20
        );
        assert_eq!(
            u32::from_be_bytes([out[2][8], out[2][9], out[2][10], out[2][11]]),
            40
        );
        assert_eq!(
            u32::from_be_bytes([out[3][8], out[3][9], out[3][10], out[3][11]]),
            60
        );
        assert_eq!(seq, 67);
    }

    #[test]
    fn sequence_number_wraps_modulo_2_32() {
        let flows = vec![v4_flow(1, 2, 100, 1), v4_flow(3, 4, 100, 1)];
        let (_, seq) = build_datagrams(&flows, u32::MAX - 1, false, 0, 0);
        assert_eq!(seq, 0);
    }

    #[test]
    fn mtu_split_v4_count_matches_input() {
        let flows: Vec<_> = (0..200)
            .map(|i| v4_flow((i % 250) as u8, ((i + 1) % 250) as u8, 100, 1))
            .collect();
        let (out, seq) = build_datagrams(&flows, 0, false, 0, 0);
        assert_eq!(seq, 200);
        // Sum the records reported in each datagram's message length.
        let mut total_records = 0u32;
        for dg in &out {
            assert!(dg.len() <= 1200);
            let msg_len = u16::from_be_bytes([dg[2], dg[3]]);
            assert_eq!(
                usize::from(msg_len),
                dg.len(),
                "length field matches datagram size"
            );
            // After 16B msg hdr + 4B set hdr, what remains is records.
            let data_bytes = msg_len - 20;
            assert_eq!(data_bytes % RECORD_SIZE_V4, 0);
            total_records += u32::from(data_bytes / RECORD_SIZE_V4);
        }
        assert_eq!(total_records, 200);
    }

    #[test]
    fn mtu_split_v6_count_matches_input() {
        let flows: Vec<_> = (0..200).map(|_| v6_flow(200, 1)).collect();
        let (out, seq) = build_datagrams(&flows, 0, false, 0, 0);
        assert_eq!(seq, 200);
        // Sum the records reported in each datagram's message length.
        let mut total_records = 0u32;
        for dg in &out {
            assert!(dg.len() <= 1200);
            let msg_len = u16::from_be_bytes([dg[2], dg[3]]);
            assert_eq!(
                usize::from(msg_len),
                dg.len(),
                "length field matches datagram size"
            );
            // After 16B msg hdr + 4B set hdr, what remains is records.
            let data_bytes = msg_len - 20;
            assert_eq!(data_bytes % RECORD_SIZE_V6, 0);
            total_records += u32::from(data_bytes / RECORD_SIZE_V6);
        }
        assert_eq!(total_records, 200);
    }

    #[test]
    fn v4_and_v6_share_a_datagram_when_room_allows() {
        let flows = vec![v4_flow(1, 2, 100, 1), v6_flow(200, 2)];
        let (out, _) = build_datagrams(&flows, 0, false, 0, 0);
        assert_eq!(out.len(), 1);
        let dg = &out[0];
        // After 16B header: v4 data set (4 + 58 = 62B) then v6 data set (4 + 82 = 86B)
        let first_set_id = u16::from_be_bytes([dg[16], dg[17]]);
        let first_set_len = u16::from_be_bytes([dg[18], dg[19]]);
        assert_eq!(first_set_id, TEMPLATE_ID_V4);
        assert_eq!(first_set_len, SET_HEADER_LEN + RECORD_SIZE_V4);
        let off = 16 + usize::from(first_set_len);
        let second_set_id = u16::from_be_bytes([dg[off], dg[off + 1]]);
        let second_set_len = u16::from_be_bytes([dg[off + 2], dg[off + 3]]);
        assert_eq!(second_set_id, TEMPLATE_ID_V6);
        assert_eq!(second_set_len, SET_HEADER_LEN + RECORD_SIZE_V6);
    }

    #[test]
    fn include_template_set_flag_drives_first_datagram_layout() {
        let flows = [v4_flow(1, 2, 100, 1)];
        let (with, _) = build_datagrams(&flows, 0, true, 0, 0);
        let (without, _) = build_datagrams(&flows, 0, false, 0, 0);
        // With template, the first set is the template set (id=2)
        let with_id = u16::from_be_bytes([with[0][16], with[0][17]]);
        let without_id = u16::from_be_bytes([without[0][16], without[0][17]]);
        assert_eq!(with_id, 2);
        assert_eq!(without_id, TEMPLATE_ID_V4);
        // With template ⇒ longer message
        assert!(with[0].len() > without[0].len());
    }
}
