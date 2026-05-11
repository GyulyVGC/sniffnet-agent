use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use etherparse::{LaxPacketHeaders, LinkHeader, NetHeaders, TransportHeader};
use pcap::{Active, Capture, Linktype};
use tracing::{debug, error, info, warn};

use crate::cli::Args;
use crate::flow::{FlowKey, FlowTable};

const BPF_FILTER: &str = "tcp or udp or icmp or icmp6";

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
    let is_ethernet = link_type == Linktype::ETHERNET;
    if !is_ethernet {
        warn!(
            "interface '{}' has non-Ethernet link type ({:?}); MAC fields will be zero",
            args.interface, link_type
        );
    }
    info!(interface = %args.interface, "capture started");

    while !shutdown.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(d) = decode_packet(packet.data, is_ethernet) {
                    table.record(d.key, d.bytes, d.src_mac, d.dst_mac, Instant::now());
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

fn open_capture(args: &Args) -> Result<Capture<Active>, pcap::Error> {
    let cap = Capture::from_device(args.interface.as_str())?
        .snaplen(args.snaplen)
        .promisc(args.promiscuous)
        .immediate_mode(true)
        .timeout(200)
        .open()?;
    let mut cap = cap;
    cap.filter(BPF_FILTER, true)?;
    Ok(cap)
}

fn decode_packet(data: &[u8], is_ethernet: bool) -> Option<Decoded> {
    // LaxPacketHeaders tolerates payloads truncated by snaplen, unlike SlicedPacket
    // which rejects any IP datagram whose `total_len` exceeds the captured slice.
    let parsed = if is_ethernet {
        LaxPacketHeaders::from_ethernet(data).ok()?
    } else {
        LaxPacketHeaders::from_ip(data).ok()?
    };

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
        // ARP and other L3 protocols are dropped by the BPF filter already.
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
