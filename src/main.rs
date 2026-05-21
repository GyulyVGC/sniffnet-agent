// TODO: handle logging?

mod capture;
mod cli;
mod exporter;
mod flow;
mod ipfix;

use clap::Parser;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::cli::Args;
use crate::exporter::Exporter;
use crate::flow::FlowTable;

fn main() -> ExitCode {
    let args = Args::parse();
    init_logging(args.verbose);

    let collector_addr = match args.collector_addr() {
        Ok(addr) => addr,
        Err(e) => {
            error!("{e}");
            return ExitCode::from(2);
        }
    };

    info!(
        interface = %args.interface,
        collector = %collector_addr,
        "starting sniffnet-agent"
    );

    let table = Arc::new(FlowTable::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    let shutdown_signal = shutdown.clone();
    if let Err(e) = ctrlc::set_handler(move || shutdown_signal.store(true, Ordering::SeqCst)) {
        error!("failed to install signal handler: {e}");
        return ExitCode::from(1);
    }

    let exporter = match Exporter::connect(collector_addr) {
        Ok(e) => e,
        Err(e) => {
            error!("failed to bind UDP socket: {e}");
            return ExitCode::from(1);
        }
    };

    let capture_handle = {
        let table = table.clone();
        let shutdown = shutdown.clone();
        let cap_args = args.clone();
        std::thread::Builder::new()
            .name("capture".into())
            .spawn(move || capture::run(cap_args, table, shutdown))
    };

    let capture_handle = match capture_handle {
        Ok(h) => h,
        Err(e) => {
            error!("failed to spawn capture thread: {e}");
            return ExitCode::from(1);
        }
    };

    // Flush loop runs on the main thread.
    let flush_interval = Duration::from_millis(900);
    let mut exporter = exporter;
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(flush_interval);
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        run_flush(&mut exporter, &table, collector_addr);
    }

    // Final flush before exit so the last window of deltas isn't lost.
    run_flush(&mut exporter, &table, collector_addr);

    let _ = capture_handle.join();

    info!("shutdown complete");
    ExitCode::SUCCESS
}

fn run_flush(exporter: &mut Exporter, table: &FlowTable, collector: std::net::SocketAddr) {
    let snapshots = table.drain_deltas(collector);
    if snapshots.is_empty() {
        return;
    }
    let count = snapshots.len();
    if let Err(e) = exporter.flush(snapshots) {
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
