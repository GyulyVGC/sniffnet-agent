use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use etherparse::{EtherType, LaxPacketHeaders, LinkHeader, NetHeaders, TransportHeader};
use pcap::{Active, Capture, Linktype};

use crate::cli::Config;
use crate::flow::{FlowKey, FlowTable, FlowVal};

struct Decoded {
    key: FlowKey,
    bytes: u64,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
}

pub fn open(cfg: &Config) -> Result<(Capture<Active>, Linktype), pcap::Error> {
    let cap = open_capture(cfg)?;
    let link_type = cap.get_datalink();
    if !link_type_is_supported(link_type) {
        log::warn!(
            "interface '{}' has link type {:?} which is not specifically handled; \
             falling back to Ethernet decode",
            cfg.interface,
            link_type
        );
    }
    log::info!(
        "capture started: interface={}, link_type={link_type:?}",
        cfg.interface
    );
    Ok((cap, link_type))
}

pub fn run(mut cap: Capture<Active>, link_type: Linktype, tx: &Sender<HashMap<FlowKey, FlowVal>>) {
    let mut table = FlowTable::new();
    let interval = Duration::from_millis(900);
    let mut last_drain = Instant::now();

    loop {
        if last_drain.elapsed() >= interval {
            if tx.send(table.drain()).is_err() {
                return;
            }
            last_drain = Instant::now();
        }

        match cap.next_packet() {
            Ok(packet) => {
                if let Some(d) = decode_packet(packet.data, link_type) {
                    let ts = packet.header.ts;
                    let ts_ms =
                        (ts.tv_sec as u64).saturating_mul(1_000) + (ts.tv_usec as u64) / 1_000;
                    table.record(d.key, d.bytes, d.src_mac, d.dst_mac, ts_ms);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => log::debug!("next_packet error: {e}"),
        }
    }
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

fn open_capture(cfg: &Config) -> Result<Capture<Active>, pcap::Error> {
    // pcap setup mirrors Sniffnet's live capture (capture_context.rs): buffered
    // mode + a 2 MB ring buffer trades sub-millisecond latency for throughput,
    // which is what we want for a 900 ms aggregation window.
    let mut cap = Capture::from_device(cfg.interface.as_str())?
        .promisc(false)
        .buffer_size(2_000_000)
        .snaplen(200)
        .immediate_mode(false)
        .timeout(150)
        .open()?;
    if let Some(expr) = cfg
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty())
    {
        cap.filter(expr, true)?;
    }
    Ok(cap)
}

fn get_sniffable_headers(packet: &[u8], link_type: Linktype) -> Option<LaxPacketHeaders<'_>> {
    match link_type {
        Linktype::NULL | Linktype::LOOP => from_null(packet),
        Linktype::LINUX_SLL => from_linux_sll(packet, true),
        Linktype::LINUX_SLL2 => from_linux_sll(packet, false),
        Linktype::IPV4 | Linktype::IPV6 | Linktype(12) => LaxPacketHeaders::from_ip(packet).ok(),
        _ => LaxPacketHeaders::from_ethernet(packet).ok(),
    }
}

fn from_null(packet: &[u8]) -> Option<LaxPacketHeaders<'_>> {
    if packet.len() <= 4 {
        return None;
    }

    let is_valid_af_inet = {
        // based on https://wiki.wireshark.org/NullLoopback.md (2023-12-31)
        fn matches(val: u32) -> bool {
            match val {
                // 2 = IPv4 on all platforms
                // 24, 28, or 30 = IPv6 depending on platform
                2 | 24 | 28 | 30 => true,
                _ => false,
            }
        }
        let h = &packet[..4];
        let b = [h[0], h[1], h[2], h[3]];
        // check both big endian and little endian representations
        // as some OS'es use native endianness and others use big endian
        matches(u32::from_le_bytes(b)) || matches(u32::from_be_bytes(b))
    };

    if is_valid_af_inet {
        LaxPacketHeaders::from_ip(&packet[4..]).ok()
    } else {
        None
    }
}

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
    let payload = &packet[header_len..];

    Some(LaxPacketHeaders::from_ether_type(
        EtherType(protocol_type),
        payload,
    ))
}

fn decode_packet(data: &[u8], link_type: Linktype) -> Option<Decoded> {
    let headers = get_sniffable_headers(data, link_type)?;

    let (src_mac, dst_mac) = match headers.link {
        Some(LinkHeader::Ethernet2(eth)) => (Some(eth.source), Some(eth.destination)),
        _ => (None, None),
    };

    let (src_ip, dst_ip, bytes) = match headers.net? {
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
        NetHeaders::Arp(_) => return None,
    };

    let (src_port, dst_port, protocol) = match headers.transport? {
        TransportHeader::Tcp(t) => (Some(t.source_port), Some(t.destination_port), 6u8),
        TransportHeader::Udp(u) => (Some(u.source_port), Some(u.destination_port), 17u8),
        TransportHeader::Icmpv4(_) => (None, None, 1u8),
        TransportHeader::Icmpv6(_) => (None, None, 58u8),
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
