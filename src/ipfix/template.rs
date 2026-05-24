//! IPFIX template definitions (RFC 7011 §3.4.1).
//!
//! We define two templates with canonical IANA-registered IE lengths:
//! - Template 256 carries IPv4 5-tuple + MACs + delta counters.
//! - Template 257 carries IPv6 5-tuple + MACs + delta counters.
//!
//! Both templates are emitted together inside a single Template Set whenever a
//! refresh is due (see `exporter.rs`).

// IANA IPFIX Information Element IDs we use. Kept here so the only place that
// "knows" the wire layout is the template definition.
const IE_OCTET_DELTA_COUNT: u16 = 1;
const IE_PACKET_DELTA_COUNT: u16 = 2;
const IE_PROTOCOL_IDENTIFIER: u16 = 4;
const IE_SOURCE_TRANSPORT_PORT: u16 = 7;
const IE_SOURCE_IPV4_ADDRESS: u16 = 8;
const IE_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IE_DESTINATION_IPV4_ADDRESS: u16 = 12;
const IE_SOURCE_IPV6_ADDRESS: u16 = 27;
const IE_DESTINATION_IPV6_ADDRESS: u16 = 28;
const IE_SOURCE_MAC_ADDRESS: u16 = 56;
const IE_FLOW_DIRECTION: u16 = 61;
const IE_POST_DESTINATION_MAC_ADDRESS: u16 = 80;

/// Field specifier (IE, length) tuples in record byte order.
const V4_FIELDS: &[(u16, u16)] = &[
    (IE_SOURCE_IPV4_ADDRESS, 4),
    (IE_DESTINATION_IPV4_ADDRESS, 4),
    (IE_SOURCE_TRANSPORT_PORT, 2),
    (IE_DESTINATION_TRANSPORT_PORT, 2),
    (IE_PROTOCOL_IDENTIFIER, 1),
    (IE_SOURCE_MAC_ADDRESS, 6),
    (IE_POST_DESTINATION_MAC_ADDRESS, 6),
    (IE_FLOW_DIRECTION, 1),
    (IE_OCTET_DELTA_COUNT, 8),
    (IE_PACKET_DELTA_COUNT, 8),
];

const V6_FIELDS: &[(u16, u16)] = &[
    (IE_SOURCE_IPV6_ADDRESS, 16),
    (IE_DESTINATION_IPV6_ADDRESS, 16),
    (IE_SOURCE_TRANSPORT_PORT, 2),
    (IE_DESTINATION_TRANSPORT_PORT, 2),
    (IE_PROTOCOL_IDENTIFIER, 1),
    (IE_SOURCE_MAC_ADDRESS, 6),
    (IE_POST_DESTINATION_MAC_ADDRESS, 6),
    (IE_FLOW_DIRECTION, 1),
    (IE_OCTET_DELTA_COUNT, 8),
    (IE_PACKET_DELTA_COUNT, 8),
];

/// Template set length (set header + both template records) per RFC 7011 §3.4.1.
/// Set header (4) + template record header (4) + 10 fields × 4 bytes,
/// twice over for the two templates: 4 + 2 × (4 + 40) = 92.
pub const TEMPLATE_SET_LEN: usize = 92;

/// Write the combined Template Set (containing both templates) to `out`.
/// The set header carries `set_id=2` and the set length includes itself.
pub fn write_template_set(out: &mut Vec<u8>) {
    let start = out.len();
    // Set header: set_id=2, length placeholder.
    out.extend_from_slice(&super::TEMPLATE_SET_ID.to_be_bytes());
    out.extend_from_slice(&[0u8, 0u8]);

    write_template_record(out, super::TEMPLATE_ID_V4, V4_FIELDS);
    write_template_record(out, super::TEMPLATE_ID_V6, V6_FIELDS);

    let set_len = out.len() - start;
    debug_assert_eq!(set_len, TEMPLATE_SET_LEN);
    let len_be = (set_len as u16).to_be_bytes();
    out[start + 2] = len_be[0];
    out[start + 3] = len_be[1];
}

fn write_template_record(out: &mut Vec<u8>, template_id: u16, fields: &[(u16, u16)]) {
    out.extend_from_slice(&template_id.to_be_bytes());
    out.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (ie, len) in fields {
        // Standard IEs only — enterprise bit (0x8000) stays clear.
        out.extend_from_slice(&ie.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference bytes computed from the spec — if this fails, either the field
    /// ordering, the IE numbers, or the length encoding has drifted.
    #[rustfmt::skip]
    const EXPECTED: &[u8] = &[
        // Set header: set_id=2, length=92
        0x00, 0x02, 0x00, 0x5c,
        // Template 256 header: template_id=256, field_count=10
        0x01, 0x00, 0x00, 0x0a,
        // Template 256 fields: (IE, length) pairs
        0x00, 0x08, 0x00, 0x04, // IE 8 (srcIPv4), 4B
        0x00, 0x0c, 0x00, 0x04, // IE 12 (dstIPv4), 4B
        0x00, 0x07, 0x00, 0x02, // IE 7 (srcPort), 2B
        0x00, 0x0b, 0x00, 0x02, // IE 11 (dstPort), 2B
        0x00, 0x04, 0x00, 0x01, // IE 4 (protocol), 1B
        0x00, 0x38, 0x00, 0x06, // IE 56 (srcMac), 6B
        0x00, 0x50, 0x00, 0x06, // IE 80 (postDstMac), 6B
        0x00, 0x3d, 0x00, 0x01, // IE 61 (flowDirection), 1B
        0x00, 0x01, 0x00, 0x08, // IE 1 (octetDeltaCount), 8B
        0x00, 0x02, 0x00, 0x08, // IE 2 (packetDeltaCount), 8B
        // Template 257 header: template_id=257, field_count=10
        0x01, 0x01, 0x00, 0x0a,
        // Template 257 fields
        0x00, 0x1b, 0x00, 0x10, // IE 27 (srcIPv6), 16B
        0x00, 0x1c, 0x00, 0x10, // IE 28 (dstIPv6), 16B
        0x00, 0x07, 0x00, 0x02,
        0x00, 0x0b, 0x00, 0x02,
        0x00, 0x04, 0x00, 0x01,
        0x00, 0x38, 0x00, 0x06,
        0x00, 0x50, 0x00, 0x06,
        0x00, 0x3d, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x08,
        0x00, 0x02, 0x00, 0x08,
    ];

    #[test]
    fn template_set_matches_spec_bytes() {
        let mut buf = Vec::new();
        write_template_set(&mut buf);
        assert_eq!(buf.len(), TEMPLATE_SET_LEN);
        assert_eq!(buf, EXPECTED);
    }
}
