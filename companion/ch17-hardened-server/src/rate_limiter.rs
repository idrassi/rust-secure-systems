use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    clients: Mutex<HashMap<IpAddr, ClientRecord>>,
    max_requests: usize,
    window: Duration,
    max_tracked_clients: usize,
}

struct ClientRecord {
    count: usize,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration, max_tracked_clients: usize) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            max_requests,
            window,
            max_tracked_clients,
        }
    }

    pub fn check(&self, addr: IpAddr) -> bool {
        let mut clients = self.lock_clients();
        let now = Instant::now();

        if !clients.contains_key(&addr) {
            let double_window = self.window * 2;
            clients.retain(|_, record| now.duration_since(record.window_start) <= double_window);
            if clients.len() >= self.max_tracked_clients {
                log::warn!(
                    "Rate limiter state full ({} tracked clients); rejecting {}",
                    self.max_tracked_clients,
                    addr
                );
                return false;
            }
        }

        let record = clients.entry(addr).or_insert_with(|| ClientRecord {
            count: 0,
            window_start: now,
        });

        if now.duration_since(record.window_start) > self.window {
            record.count = 0;
            record.window_start = now;
        }

        record.count += 1;

        if record.count > self.max_requests {
            log::warn!("Rate limit exceeded for {}", addr);
            false
        } else {
            true
        }
    }

    pub fn cleanup(&self) {
        let mut clients = self.lock_clients();
        let now = Instant::now();
        let double_window = self.window * 2;
        clients.retain(|_, record| now.duration_since(record.window_start) <= double_window);
    }

    fn lock_clients(&self) -> MutexGuard<'_, HashMap<IpAddr, ClientRecord>> {
        match self.clients.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!("Rate limiter state poisoned; clearing state and recovering");
                let mut guard = poisoned.into_inner();
                guard.clear();
                guard
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{self, AssertUnwindSafe};
    use std::str::FromStr;

    #[test]
    fn poisoned_mutex_is_recovered_without_panicking() {
        let limiter = RateLimiter::new(10, Duration::from_secs(60), 16);

        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = limiter.clients.lock().expect("lock");
            panic!("poison the mutex");
        }));

        assert!(limiter.check(IpAddr::from_str("127.0.0.1").expect("ip")));
    }

    #[test]
    fn rejects_new_clients_once_state_is_full() {
        let limiter = RateLimiter::new(10, Duration::from_secs(60), 2);

        assert!(limiter.check(IpAddr::from_str("127.0.0.1").expect("ip1")));
        assert!(limiter.check(IpAddr::from_str("127.0.0.2").expect("ip2")));
        assert!(!limiter.check(IpAddr::from_str("127.0.0.3").expect("ip3")));
    }
}
