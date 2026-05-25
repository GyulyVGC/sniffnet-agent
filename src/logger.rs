use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::IsTerminal;
use std::sync::OnceLock;

struct Logger {
    colored: bool,
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let ts = jiff::Zoned::now().strftime("%Y-%m-%d %H:%M:%S");
        let level = record.level();
        if self.colored {
            eprintln!(
                "[{ts}] {}{level}\x1b[0m {}",
                color_code(level),
                record.args()
            );
        } else {
            eprintln!("[{ts}] {level} {}", record.args());
        }
    }

    fn flush(&self) {}
}

fn color_code(level: Level) -> &'static str {
    match level {
        Level::Error => "\x1b[31m",
        Level::Warn => "\x1b[33m",
        Level::Info => "\x1b[32m",
        Level::Debug => "\x1b[36m",
        Level::Trace => "\x1b[35m",
    }
}

fn detect_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    std::io::stderr().is_terminal()
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

pub fn init_logger(verbose: bool) {
    let level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let logger = LOGGER.get_or_init(|| Logger {
        colored: detect_color(),
    });
    log::set_logger(logger).unwrap();
    log::set_max_level(level);
}
