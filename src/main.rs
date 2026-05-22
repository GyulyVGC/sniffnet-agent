// TODO: improve logging
// TODO: pass collector IP and port separately?
// TODO: thoroughly check manifest, README, docs

mod capture;
mod cli;
mod exporter;
mod flow;
mod ipfix;

use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::cli::Args;
use crate::exporter::Exporter;
use crate::flow::FlowTable;

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

    let table = Arc::new(FlowTable::new());

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

    if let Err(e) = std::thread::Builder::new().name("capture".into()).spawn({
        let table = table.clone();
        move || capture::run(cap, link_type, &table)
    }) {
        error!("failed to spawn capture thread: {e}");
        std::process::exit(1);
    }

    // Flush loop runs on the main thread; exits only via ctrl+c handler.
    let flush_interval = Duration::from_millis(900);
    loop {
        std::thread::sleep(flush_interval);
        run_flush(&mut exporter, &table, collector_addr);
    }
}

fn run_flush(exporter: &mut Exporter, table: &FlowTable, collector: std::net::SocketAddr) {
    let snapshots = table.drain_deltas(collector);
    if snapshots.is_empty() {
        return;
    }
    let count = snapshots.len();
    if let Err(e) = exporter.flush(&snapshots) {
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
