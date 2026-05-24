// TODO: improve logging
// TODO: verbose logging including PCAP errors?
// TODO: thoroughly check manifest, README, docs

// TODO: dropped packets
// TODO: ICMP message types
// TODO: ARP support
// TODO: flow timestamps (?)
// TODO: exporter identity!!! interfaceDescription maybe
// TODO: VLAN tags

mod capture;
mod cli;
mod direction;
mod exporter;
mod flow;
mod ipfix;

use clap::Parser;
use std::collections::HashMap;
use std::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::cli::Args;
use crate::direction::interface_addresses;
use crate::exporter::Exporter;
use crate::flow::{FlowKey, FlowVal};

fn main() {
    let cfg = Args::parse().resolve();
    init_logging(cfg.verbose);

    let collector_addr = match cfg.collector_addr() {
        Ok(addr) => addr,
        Err(e) => {
            error!("{e}");
            std::process::exit(2);
        }
    };

    info!(
        interface = %cfg.interface,
        collector = %collector_addr,
        "starting sniffnet-agent"
    );

    if let Err(e) = ctrlc::set_handler(|| std::process::exit(130)) {
        error!("failed to install signal handler: {e}");
        std::process::exit(1);
    }

    let mut exporter = match Exporter::connect(collector_addr) {
        Ok(e) => e,
        Err(e) => {
            error!("failed to bind UDP socket: {e}");
            std::process::exit(1);
        }
    };

    let (cap, link_type) = match capture::open(&cfg) {
        Ok(x) => x,
        Err(e) => {
            error!("failed to open capture on '{}': {e}", cfg.interface);
            std::process::exit(1);
        }
    };

    let (tx, rx) = mpsc::channel::<HashMap<FlowKey, FlowVal>>();
    if let Err(e) = std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || capture::run(cap, link_type, &tx))
    {
        error!("failed to spawn capture thread: {e}");
        std::process::exit(1);
    }

    for flow_map in rx {
        let addrs = interface_addresses(&cfg.interface);
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
        tracing::warn!("flush failed: {e}");
    } else {
        tracing::debug!(records = count, "flushed");
    }
}

fn init_logging(verbose: bool) {
    let default = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("sniffnet_agent={default}")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
