// TODO: improve logging
// TODO: pass collector IP and port separately?
// TODO: thoroughly check manifest, README, docs
// TODO: carefully check /ipfix files
// TODO: verbose logging including PCAP errors?
// TODO: info about dropped packets? (IE 164 ignoredPacketTotalCount)
// TODO: add CLI arg to list interfaces and exit

mod capture;
mod cli;
mod exporter;
mod flow;
mod ipfix;

use clap::Parser;
use std::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::cli::Args;
use crate::exporter::Exporter;
use crate::flow::{FlowKey, FlowVal};

fn main() {
    let args = Args::parse();
    init_logging(args.verbose);

    let collector_addr = match args.collector_addr() {
        Ok(addr) => addr,
        Err(e) => {
            error!("{e}");
            std::process::exit(2);
        }
    };

    info!(
        interface = %args.interface,
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

    let (cap, link_type) = match capture::open(&args) {
        Ok(x) => x,
        Err(e) => {
            error!("failed to open capture on '{}': {e}", args.interface);
            std::process::exit(1);
        }
    };

    let (tx, rx) = mpsc::channel::<Vec<(FlowKey, FlowVal)>>();
    if let Err(e) = std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || capture::run(cap, link_type, &tx, collector_addr))
    {
        error!("failed to spawn capture thread: {e}");
        std::process::exit(1);
    }

    // Main thread exports each set of flows delivered by the capture thread.
    for flows in rx {
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
