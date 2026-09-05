//! IPFIX template definitions (RFC 7011 §3.4.1).
//!
//! We define two templates with canonical IANA-registered IE lengths:
//! - Template 256 carries IPv4 5-tuple + MACs + VLAN + `EtherType` + delta counters.
//! - Template 257 carries IPv6 5-tuple + MACs + VLAN + `EtherType` + delta counters.
//!
//! ARP flows ride these same templates: they have no ports and no IANA protocol
//! number, so those fields go out as 0 and `ethernetType` is what identifies them.
//!
//! Both templates are emitted together inside a single Template Set whenever a
//! refresh is due (see `exporter.rs`).

// IANA IPFIX Information Element IDs we use. Kept here so the only place that
// "knows" the wire layout is the template definition.
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
const IE_DESTINATION_MAC_ADDRESS: u16 = 80;
const IE_FLOW_START_MILLISECONDS: u16 = 152;
const IE_FLOW_END_MILLISECONDS: u16 = 153;
const IE_DOT1Q_VLAN_ID: u16 = 243;
const IE_ETHERNET_TYPE: u16 = 256;
const IE_LAYER2_OCTET_DELTA_COUNT: u16 = 352;

const FIELD_COUNT: u16 = 14;
const TEMPLATE_RECORD_LEN: u16 = 4 + FIELD_COUNT * 4;
pub const TEMPLATE_SET_LEN: u16 = 4 + 2 * TEMPLATE_RECORD_LEN;

/// Field specifier (IE, length) tuples in record byte order.
const V4_FIELDS: [(u16, u16); FIELD_COUNT as usize] = [
    (IE_SOURCE_IPV4_ADDRESS, 4),
    (IE_DESTINATION_IPV4_ADDRESS, 4),
    (IE_SOURCE_TRANSPORT_PORT, 2),
    (IE_DESTINATION_TRANSPORT_PORT, 2),
    (IE_PROTOCOL_IDENTIFIER, 1),
    (IE_SOURCE_MAC_ADDRESS, 6),
    (IE_DESTINATION_MAC_ADDRESS, 6),
    (IE_DOT1Q_VLAN_ID, 2),
    (IE_ETHERNET_TYPE, 2),
    (IE_FLOW_DIRECTION, 1),
    (IE_LAYER2_OCTET_DELTA_COUNT, 8),
    (IE_PACKET_DELTA_COUNT, 8),
    (IE_FLOW_START_MILLISECONDS, 8),
    (IE_FLOW_END_MILLISECONDS, 8),
];

const V6_FIELDS: [(u16, u16); FIELD_COUNT as usize] = [
    (IE_SOURCE_IPV6_ADDRESS, 16),
    (IE_DESTINATION_IPV6_ADDRESS, 16),
    (IE_SOURCE_TRANSPORT_PORT, 2),
    (IE_DESTINATION_TRANSPORT_PORT, 2),
    (IE_PROTOCOL_IDENTIFIER, 1),
    (IE_SOURCE_MAC_ADDRESS, 6),
    (IE_DESTINATION_MAC_ADDRESS, 6),
    (IE_DOT1Q_VLAN_ID, 2),
    (IE_ETHERNET_TYPE, 2),
    (IE_FLOW_DIRECTION, 1),
    (IE_LAYER2_OCTET_DELTA_COUNT, 8),
    (IE_PACKET_DELTA_COUNT, 8),
    (IE_FLOW_START_MILLISECONDS, 8),
    (IE_FLOW_END_MILLISECONDS, 8),
];

/// Write the combined Template Set (containing both templates) to `out`.
/// The set header carries `set_id=2` and the set length includes itself.
pub fn write_template_set(out: &mut Vec<u8>) {
    out.extend_from_slice(&super::TEMPLATE_SET_ID.to_be_bytes());
    out.extend_from_slice(&TEMPLATE_SET_LEN.to_be_bytes());
    write_template_record(out, super::TEMPLATE_ID_V4, &V4_FIELDS);
    write_template_record(out, super::TEMPLATE_ID_V6, &V6_FIELDS);
}

fn write_template_record(
    out: &mut Vec<u8>,
    template_id: u16,
    fields: &[(u16, u16); FIELD_COUNT as usize],
) {
    out.extend_from_slice(&template_id.to_be_bytes());
    out.extend_from_slice(&FIELD_COUNT.to_be_bytes());
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
        // Set header: set_id=2, length=124
        0x00, 0x02, 0x00, 0x7c,
        // Template 256 header: template_id=256, field_count=14
        0x01, 0x00, 0x00, 0x0e,
        // Template 256 fields: (IE, length) pairs
        0x00, 0x08, 0x00, 0x04, // IE 8 (srcIPv4), 4B
        0x00, 0x0c, 0x00, 0x04, // IE 12 (dstIPv4), 4B
        0x00, 0x07, 0x00, 0x02, // IE 7 (srcPort), 2B
        0x00, 0x0b, 0x00, 0x02, // IE 11 (dstPort), 2B
        0x00, 0x04, 0x00, 0x01, // IE 4 (protocol), 1B
        0x00, 0x38, 0x00, 0x06, // IE 56 (srcMac), 6B
        0x00, 0x50, 0x00, 0x06, // IE 80 (DstMac), 6B
        0x00, 0xf3, 0x00, 0x02, // IE 243 (dot1qVlanId), 2B
        0x01, 0x00, 0x00, 0x02, // IE 256 (ethernetType), 2B
        0x00, 0x3d, 0x00, 0x01, // IE 61 (flowDirection), 1B
        0x01, 0x60, 0x00, 0x08, // IE 352 (layer2OctetDeltaCount), 8B
        0x00, 0x02, 0x00, 0x08, // IE 2 (packetDeltaCount), 8B
        0x00, 0x98, 0x00, 0x08, // IE 152 (flowStartMilliseconds), 8B
        0x00, 0x99, 0x00, 0x08, // IE 153 (flowEndMilliseconds), 8B
        // Template 257 header: template_id=257, field_count=14
        0x01, 0x01, 0x00, 0x0e,
        // Template 257 fields
        0x00, 0x1b, 0x00, 0x10, // IE 27 (srcIPv6), 16B
        0x00, 0x1c, 0x00, 0x10, // IE 28 (dstIPv6), 16B
        0x00, 0x07, 0x00, 0x02, // IE 7 (srcPort), 2B
        0x00, 0x0b, 0x00, 0x02, // IE 11 (dstPort), 2B
        0x00, 0x04, 0x00, 0x01, // IE 4 (protocol), 1B
        0x00, 0x38, 0x00, 0x06, // IE 56 (srcMac), 6B
        0x00, 0x50, 0x00, 0x06, // IE 80 (DstMac), 6B
        0x00, 0xf3, 0x00, 0x02, // IE 243 (dot1qVlanId), 2B
        0x01, 0x00, 0x00, 0x02, // IE 256 (ethernetType), 2B
        0x00, 0x3d, 0x00, 0x01, // IE 61 (flowDirection), 1B
        0x01, 0x60, 0x00, 0x08, // IE 352 (layer2OctetDeltaCount), 8B
        0x00, 0x02, 0x00, 0x08, // IE 2 (packetDeltaCount), 8B
        0x00, 0x98, 0x00, 0x08, // IE 152 (flowStartMilliseconds), 8B
        0x00, 0x99, 0x00, 0x08, // IE 153 (flowEndMilliseconds), 8B
    ];

    #[test]
    fn template_set_matches_spec_bytes() {
        let mut buf = Vec::new();
        write_template_set(&mut buf);
        assert_eq!(buf.len(), 124);
        assert_eq!(buf, EXPECTED);
    }
}
