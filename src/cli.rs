use clap::Parser;
use pcap::Device;
use std::io::{BufRead, IsTerminal};
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Lightweight network flows exporter compatible with Sniffnet"
)]
pub struct Args {
    /// Network interface to capture on (e.g. "eth0")
    #[arg(short, long, value_parser = parse_interface)]
    interface: Option<Device>,
    /// Collector address as HOST:PORT
    #[arg(short, long, value_name = "HOST:PORT", value_parser = parse_collector)]
    collector: Option<SocketAddr>,
    /// BPF filter expression applied to the capture
    #[arg(short, long)]
    filter: Option<String>,
    /// IPFIX Observation Domain ID
    #[arg(short, long, value_name = "ODID", default_value_t = 0)]
    odid: u32,
    /// Enable debug logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: Device,
    pub collector: SocketAddr,
    pub filter: Option<String>,
    pub odid: u32,
    pub verbose: bool,
}

impl Args {
    pub fn resolve(self) -> Config {
        Config {
            interface: self.interface.unwrap_or_else(prompt_interface),
            collector: self.collector.unwrap_or_else(prompt_collector),
            filter: self.filter,
            odid: self.odid,
            verbose: self.verbose,
        }
    }
}

fn parse_interface(name: &str) -> Result<Device, String> {
    Device::list()
        .map_err(|e| format!("failed to list interfaces: {e}"))?
        .into_iter()
        .find(|d| d.name == name)
        .ok_or_else(|| format!("interface '{name}' not found"))
}

fn parse_collector(s: &str) -> Result<SocketAddr, String> {
    s.to_socket_addrs()
        .map_err(|e| format!("cannot resolve collector address '{s}': {e}"))?
        .next()
        .ok_or_else(|| format!("no address resolved for '{s}'"))
}

#[allow(clippy::print_stderr)]
fn require_tty(arg: &str) {
    if !std::io::stdin().is_terminal() {
        eprintln!("missing --{arg}");
        std::process::exit(2);
    }
}

#[allow(clippy::print_stderr)]
fn read_line() -> String {
    let mut buf = String::new();
    if let Err(e) = std::io::stdin().lock().read_line(&mut buf) {
        eprintln!("failed to read input: {e}");
        std::process::exit(1);
    }
    buf.trim().to_string()
}

#[allow(clippy::print_stderr)]
fn prompt_interface() -> Device {
    require_tty("interface");
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to list interfaces: {e}");
            std::process::exit(1);
        }
    };
    if devices.is_empty() {
        eprintln!("no network interfaces available");
        std::process::exit(1);
    }
    eprintln!("Available network interfaces:");
    for (i, d) in devices.iter().enumerate() {
        let desc = d.desc.as_deref().unwrap_or("");
        eprintln!("  {}) {}\t{desc}", i + 1, d.name);
    }
    loop {
        eprint!("Choose one (1-{}): ", devices.len());
        match read_line().parse::<usize>() {
            Ok(n) if (1..=devices.len()).contains(&n) => return devices[n - 1].clone(),
            _ => eprintln!(
                "invalid choice; enter a number between 1 and {}",
                devices.len()
            ),
        }
    }
}

#[allow(clippy::print_stderr)]
fn prompt_collector() -> SocketAddr {
    require_tty("collector");
    loop {
        eprint!("Collector address (HOST:PORT): ");
        match parse_collector(&read_line()) {
            Ok(addr) => return addr,
            Err(e) => eprintln!("{e}"),
        }
    }
}
