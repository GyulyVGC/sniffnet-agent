use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use etherparse::{EtherType, LaxPacketHeaders, LinkHeader, NetHeaders, TransportHeader};
use pcap::{Active, Capture, Linktype};
use tracing::{debug, error, info, warn};

use crate::cli::Args;
use crate::flow::{FlowKey, FlowTable};

struct Decoded {
    key: FlowKey,
    bytes: u64,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
}

pub fn run(args: Args, table: Arc<FlowTable>, shutdown: Arc<AtomicBool>) {
    let mut cap = match open_capture(&args) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to open capture on '{}': {e}", args.interface);
            shutdown.store(true, Ordering::SeqCst);
            return;
        }
    };

    let link_type = cap.get_datalink();
    if !link_type_is_supported(link_type) {
        warn!(
            "interface '{}' has link type {:?} which is not specifically handled; \
             falling back to Ethernet decode",
            args.interface, link_type
        );
    }
    if !link_type_has_macs(link_type) {
        debug!("link type {:?} carries no MAC addresses", link_type);
    }
    info!(interface = %args.interface, ?link_type, "capture started");

    while !shutdown.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(d) = decode_packet(packet.data, link_type) {
                    table.record(d.key, d.bytes, d.src_mac, d.dst_mac);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(pcap::Error::NoMorePackets) => {
                debug!("capture exhausted");
                break;
            }
            Err(e) => {
                warn!("capture error: {e}");
            }
        }
    }
    info!("capture stopped");
}

fn link_type_is_supported(lt: Linktype) -> bool {
    matches!(
        lt,
        Linktype::ETHERNET
            | Linktype::NULL
            | Linktype::LOOP
            | Linktype::IPV4
            | Linktype::IPV6
            | Linktype::LINUX_SLL
            | Linktype::LINUX_SLL2
            | Linktype(12) // DLT_RAW
    )
}

fn link_type_has_macs(lt: Linktype) -> bool {
    lt == Linktype::ETHERNET
}

fn open_capture(args: &Args) -> Result<Capture<Active>, pcap::Error> {
    // pcap setup mirrors Sniffnet's live capture (capture_context.rs): buffered
    // mode + a 2 MB ring buffer trades sub-millisecond latency for throughput,
    // which is what we want for a 900 ms aggregation window.
    let mut cap = Capture::from_device(args.interface.as_str())?
        .promisc(false)
        .buffer_size(2_000_000)
        .snaplen(200)
        .immediate_mode(false)
        .timeout(150)
        .open()?;
    if let Some(expr) = args
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty())
    {
        cap.filter(expr, true)?;
    }
    Ok(cap)
}

/// Dispatch decoding based on pcap link type. Mirrors Sniffnet's
/// `parse_packets::get_sniffable_headers`.
fn parse_by_link_type(data: &[u8], link_type: Linktype) -> Option<LaxPacketHeaders<'_>> {
    match link_type {
        Linktype::ETHERNET => LaxPacketHeaders::from_ethernet(data).ok(),
        Linktype::NULL | Linktype::LOOP => from_null(data),
        Linktype::LINUX_SLL => from_linux_sll(data, true),
        Linktype::LINUX_SLL2 => from_linux_sll(data, false),
        // DLT_RAW (12) — raw IP packets with no link layer.
        Linktype::IPV4 | Linktype::IPV6 | Linktype(12) => LaxPacketHeaders::from_ip(data).ok(),
        // Forgiving default for unknown link types: try Ethernet, same as Sniffnet.
        _ => LaxPacketHeaders::from_ethernet(data).ok(),
    }
}

/// BSD/macOS loopback (DLT_NULL/DLT_LOOP): 4-byte address-family prefix then IP.
/// AF values vary by platform and endianness; cf. Sniffnet's `from_null` and
/// https://wiki.wireshark.org/NullLoopback.md
fn from_null(packet: &[u8]) -> Option<LaxPacketHeaders<'_>> {
    if packet.len() <= 4 {
        return None;
    }
    fn matches(value: u32) -> bool {
        // 2 = IPv4 (all platforms); 24, 28, 30 = IPv6 (platform-dependent).
        matches!(value, 2 | 24 | 28 | 30)
    }
    let h = [packet[0], packet[1], packet[2], packet[3]];
    if matches(u32::from_le_bytes(h)) || matches(u32::from_be_bytes(h)) {
        LaxPacketHeaders::from_ip(&packet[4..]).ok()
    } else {
        None
    }
}

/// Linux cooked capture (SLL v1 = 16 bytes, SLL2 = 20 bytes). Reads the
/// EtherType from the cooked header and hands the payload to etherparse.
fn from_linux_sll(packet: &[u8], is_v1: bool) -> Option<LaxPacketHeaders<'_>> {
    let header_len = if is_v1 { 16 } else { 20 };
    if packet.len() <= header_len {
        return None;
    }
    let protocol_type = u16::from_be_bytes(if is_v1 {
        [packet[14], packet[15]]
    } else {
        [packet[0], packet[1]]
    });
    Some(LaxPacketHeaders::from_ether_type(
        EtherType(protocol_type),
        &packet[header_len..],
    ))
}

fn decode_packet(data: &[u8], link_type: Linktype) -> Option<Decoded> {
    // LaxPacketHeaders tolerates payloads truncated by snaplen, unlike SlicedPacket
    // which rejects any IP datagram whose `total_len` exceeds the captured slice.
    let parsed = parse_by_link_type(data, link_type)?;

    let (src_mac, dst_mac) = match parsed.link {
        Some(LinkHeader::Ethernet2(eth)) => (Some(eth.source), Some(eth.destination)),
        _ => (None, None),
    };

    let (src_ip, dst_ip, bytes) = match parsed.net? {
        NetHeaders::Ipv4(h, _) => (
            IpAddr::V4(Ipv4Addr::from(h.source)),
            IpAddr::V4(Ipv4Addr::from(h.destination)),
            u64::from(h.total_len),
        ),
        NetHeaders::Ipv6(h, _) => (
            IpAddr::V6(Ipv6Addr::from(h.source)),
            IpAddr::V6(Ipv6Addr::from(h.destination)),
            u64::from(h.payload_length) + 40,
        ),
        // ARP and other non-IP L3 protocols have no representation in our IPFIX
        // templates (which key on IPv4/IPv6 addresses) — drop them here.
        _ => return None,
    };

    let (src_port, dst_port, protocol) = match parsed.transport? {
        TransportHeader::Tcp(t) => (t.source_port, t.destination_port, 6u8),
        TransportHeader::Udp(u) => (u.source_port, u.destination_port, 17u8),
        TransportHeader::Icmpv4(_) => (0, 0, 1u8),
        TransportHeader::Icmpv6(_) => (0, 0, 58u8),
    };

    Some(Decoded {
        key: FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        },
        bytes,
        src_mac,
        dst_mac,
    })
}
