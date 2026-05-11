use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tracing::debug;

use crate::flow::FlowTable;

pub fn run(table: Arc<FlowTable>, max_idle: Duration, shutdown: Arc<AtomicBool>) {
    let check_interval = check_interval(max_idle);
    let tick = Duration::from_millis(200);
    let mut last_check = Instant::now();

    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(tick);
        if last_check.elapsed() >= check_interval {
            let evicted = table.evict_idle(Instant::now(), max_idle);
            if evicted > 0 {
                debug!(evicted, "gc evicted idle flows");
            }
            last_check = Instant::now();
        }
    }
}

fn check_interval(max_idle: Duration) -> Duration {
    let candidate = max_idle / 10;
    candidate.clamp(Duration::from_secs(5), Duration::from_secs(60))
}
