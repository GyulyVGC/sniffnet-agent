use clap::Parser;
use std::io::{BufRead, IsTerminal, Write};
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Lightweight network flows exporter compatible with Sniffnet"
)]
pub struct Args {
    /// Network interface to capture on (e.g. "en0", "eth0").
    #[arg(short, long)]
    pub interface: Option<String>,
    /// Collector address as HOST:PORT.
    #[arg(short, long, value_name = "HOST:PORT")]
    pub collector: Option<String>,
    /// BPF filter expression applied to the capture.
    #[arg(short, long)]
    pub filter: Option<String>,
    /// Enable debug logging.
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub collector: String,
    pub filter: Option<String>,
    pub verbose: bool,
}

impl Args {
    pub fn resolve(self) -> Config {
        Config {
            interface: self.interface.unwrap_or_else(prompt_interface),
            collector: self.collector.unwrap_or_else(prompt_collector),
            filter: self.filter,
            verbose: self.verbose,
        }
    }
}

impl Config {
    pub fn collector_addr(&self) -> Result<SocketAddr, String> {
        self.collector
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve collector address '{}': {e}", self.collector))?
            .next()
            .ok_or_else(|| format!("no address resolved for '{}'", self.collector))
    }
}

fn require_tty(arg: &str) {
    if !std::io::stdin().is_terminal() {
        eprintln!("missing --{arg}");
        std::process::exit(2);
    }
}

fn read_line() -> String {
    let mut buf = String::new();
    if std::io::stdin().lock().read_line(&mut buf).is_err() {
        eprintln!("failed to read input");
        std::process::exit(1);
    }
    buf.trim().to_string()
}

fn prompt_interface() -> String {
    require_tty("interface");
    let devices = match pcap::Device::list() {
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
    println!("Available network interfaces:");
    for (i, d) in devices.iter().enumerate() {
        let desc = d.desc.as_deref().unwrap_or("");
        println!("  {}) {}\t{desc}", i + 1, d.name);
    }
    loop {
        print!("Choose one (1-{}): ", devices.len());
        std::io::stdout().flush().ok();
        match read_line().parse::<usize>() {
            Ok(n) if (1..=devices.len()).contains(&n) => return devices[n - 1].name.clone(),
            _ => eprintln!(
                "invalid choice; enter a number between 1 and {}",
                devices.len()
            ),
        }
    }
}

fn prompt_collector() -> String {
    require_tty("collector");
    loop {
        print!("Collector address (HOST:PORT): ");
        std::io::stdout().flush().ok();
        let input = read_line();
        match input.to_socket_addrs() {
            Ok(mut addrs) => {
                if addrs.next().is_some() {
                    return input;
                }
                eprintln!("no address resolved for '{input}'");
            }
            Err(e) => eprintln!("invalid address '{input}': {e}"),
        }
    }
}
