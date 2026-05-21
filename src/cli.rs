use clap::Parser;
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Parser, Debug, Clone)]
#[command(version, about = "IPFIX exporter for Sniffnet", long_about = None)]
pub struct Args {
    /// Network interface to capture on (e.g. "en0", "eth0").
    #[arg(short, long)]
    pub interface: String,
    /// Collector address as HOST:PORT.
    #[arg(short, long)]
    pub collector: String,
    /// BPF filter expression applied to the capture.
    #[arg(short, long)]
    pub filter: Option<String>,
    /// Enable debug logging.
    #[arg(short, long)]
    pub verbose: bool,
}

impl Args {
    pub fn collector_addr(&self) -> Result<SocketAddr, String> {
        self.collector
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve collector address '{}': {e}", self.collector))?
            .next()
            .ok_or_else(|| format!("no address resolved for '{}'", self.collector))
    }
}
