use clap::Parser;
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Parser, Debug, Clone)]
#[command(version, about = "IPFIX exporter for Sniffnet", long_about = None)]
pub struct Args {
    /// Network interface to capture on (e.g. "en0", "eth0").
    #[arg(short, long)]
    pub interface: String,

    /// Collector address as HOST:PORT.
    #[arg(short, long, default_value = "127.0.0.1:4739")]
    pub collector: String,

    /// IPFIX Observation Domain ID.
    #[arg(short = 'd', long, default_value_t = 1)]
    pub observation_domain_id: u32,

    /// Flush interval in milliseconds.
    #[arg(long, default_value_t = 900)]
    pub flush_interval_ms: u64,

    /// Template re-send interval in seconds (RFC 7011 §10.3.6).
    #[arg(long, default_value_t = 30)]
    pub template_refresh_secs: u64,

    /// Evict flow-table entries idle for this many seconds.
    #[arg(long, default_value_t = 300)]
    pub idle_evict_secs: u64,

    /// pcap snapshot length (bytes per packet). Matches Sniffnet's default; we
    /// only need headers, and a smaller snaplen lets more packets sit in the
    /// kernel ring buffer.
    #[arg(long, default_value_t = 200)]
    pub snaplen: i32,

    /// Target maximum UDP datagram size in bytes (avoid IP fragmentation).
    #[arg(long, default_value_t = 1400)]
    pub mtu: usize,

    /// Put the capture interface in promiscuous mode.
    #[arg(long)]
    pub promiscuous: bool,

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
