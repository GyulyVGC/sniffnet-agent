// TODO: exporter identity!!! interfaceDescription maybe

// TODO: ICMP message types
// TODO: VLAN tags
// TODO: dropped packets
// TODO: ARP support
// TODO: adjust Linux SLL parsing once etherparse supports Linux SLL2
// TODO: observation domain ID

mod capture;
mod cli;
mod direction;
mod exporter;
mod flow;
mod ipfix;
mod logger;

use clap::Parser;
use std::collections::HashMap;
use std::sync::mpsc;

use crate::cli::Args;
use crate::direction::interface_addresses;
use crate::exporter::Exporter;
use crate::flow::{FlowKey, FlowVal};

fn main() {
    let cfg = Args::parse().resolve();
    logger::init_logger(cfg.verbose);

    let collector_addr = cfg.collector;

    log::info!(
        "starting sniffnet-agent: interface='{}', collector='{collector_addr}'",
        cfg.interface.name
    );

    let mut exporter = match Exporter::connect(collector_addr) {
        Ok(e) => e,
        Err(e) => {
            log::error!("failed to connect exporter to '{collector_addr}': {e}");
            std::process::exit(1);
        }
    };

    let (cap, link_type) = match capture::open(&cfg) {
        Ok(x) => x,
        Err(e) => {
            log::error!("failed to open capture on '{}': {e}", cfg.interface.name);
            std::process::exit(1);
        }
    };

    let (tx, rx) = mpsc::channel::<HashMap<FlowKey, FlowVal>>();
    if let Err(e) = std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || capture::run(cap, link_type, &tx))
    {
        log::error!("failed to spawn capture thread: {e}");
        std::process::exit(1);
    }

    for flow_map in rx {
        let addrs = interface_addresses(&cfg.interface.name, link_type);
        let flows: Vec<_> = flow_map
            .into_iter()
            .filter(|(key, _)| !key.is_self_export(collector_addr))
            .map(|(k, v)| (k, v.with_direction(&k, &addrs)))
            .collect();
        run_flush(&mut exporter, &flows);
    }
}

fn run_flush(exporter: &mut Exporter, flows: &[(FlowKey, FlowVal)]) {
    if flows.is_empty() {
        return;
    }
    let count = flows.len();
    if let Err(e) = exporter.flush(flows) {
        log::warn!("flush failed: {e}");
    } else {
        log::debug!("flushed {count} records");
    }
}
