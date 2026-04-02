use std::sync::atomic::{AtomicU64, Ordering};

pub struct ServerMetrics {
    pub connections_accepted: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub messages_processed: AtomicU64,
    pub errors: AtomicU64,
    pub auth_failures: AtomicU64,
    pub rate_limits_triggered: AtomicU64,
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self {
            connections_accepted: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            messages_processed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            rate_limits_triggered: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_rejected: self.connections_rejected.load(Ordering::Relaxed),
            messages_processed: self.messages_processed.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            rate_limits_triggered: self.rate_limits_triggered.load(Ordering::Relaxed),
        }
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MetricsSnapshot {
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub messages_processed: u64,
    pub errors: u64,
    pub auth_failures: u64,
    pub rate_limits_triggered: u64,
}
