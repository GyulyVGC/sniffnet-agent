use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use crate::cli::Config;
use crate::flow::{FlowAddrs, FlowKey, FlowTable, FlowVal};
use pcap::{Active, Capture};
use sniffnet_packet_parser::{LinkType, ParsedPacket};

struct Decoded {
    key: FlowKey,
    bytes: u64,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    vlan_id: Option<u16>,
}

pub fn open(cfg: &Config) -> Result<(Capture<Active>, LinkType), pcap::Error> {
    let cap = open_capture(cfg)?;
    let link_type = LinkType::from_pcap(cap.get_datalink());
    let lt_label = link_type.description();
    if !link_type.is_supported() {
        log::warn!(
            "unsupported link type '{lt_label}' on '{}'; decoding as Ethernet",
            cfg.interface.name,
        );
    }
    log::info!(
        "capture started: interface='{}', link_type='{lt_label}'",
        cfg.interface.name
    );
    Ok((cap, link_type))
}

pub fn run(mut cap: Capture<Active>, link_type: LinkType, tx: &Sender<HashMap<FlowKey, FlowVal>>) {
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
                    #[allow(clippy::useless_conversion)]
                    let ts_ms = u64::from(ts.tv_sec.cast_unsigned()).saturating_mul(1_000)
                        + u64::from(ts.tv_usec.cast_unsigned()) / 1_000;
                    table.record(d.key, d.bytes, d.src_mac, d.dst_mac, d.vlan_id, ts_ms);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => log::debug!("next_packet error: {e}"),
        }
    }
}

fn open_capture(cfg: &Config) -> Result<Capture<Active>, pcap::Error> {
    let mut cap = Capture::from_device(cfg.interface.clone())?
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

fn decode_packet(data: &[u8], link_type: LinkType) -> Option<Decoded> {
    let parsed = ParsedPacket::from_bytes(data, link_type)?;

    let src_mac = parsed.link_info.src_mac;
    let dst_mac = parsed.link_info.dst_mac;
    let vlan_id = parsed.link_info.vlan_id;

    let src_ip = parsed.net_info.src_ip;
    let dst_ip = parsed.net_info.dst_ip;
    let addrs = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => FlowAddrs::V4 { src, dst },
        (IpAddr::V6(src), IpAddr::V6(dst)) => FlowAddrs::V6 { src, dst },
        _ => return None,
    };

    let src_port = parsed.transport_info.src_port;
    let dst_port = parsed.transport_info.dst_port;
    let protocol = parsed.transport_info.protocol.number()?;

    let bytes = parsed.bytes_count() as u64;

    Some(Decoded {
        key: FlowKey {
            addrs,
            src_port,
            dst_port,
            protocol,
        },
        bytes,
        src_mac,
        dst_mac,
        vlan_id,
    })
}
