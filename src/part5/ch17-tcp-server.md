# Chapter 17 - Building a Hardened TCP Server

> *"Theory without practice is empty. Practice without theory is blind."*

This chapter brings together everything from the previous chapters into a complete, production-quality hardened TCP server. We'll build a secure echo server with TLS, rate limiting, connection management, and security-relevant logging. Every design decision will reference the security principles covered earlier in the book.

The companion crate in this repository lives at `companion/ch17-hardened-server`. The snippets below use that package layout directly so Chapter 19 can deploy the same binary without translation.

## 17.1 Design and Threat Model

### Threat Model

| Threat | Mitigation | Chapter |
|--------|-----------|---------|
| Unencrypted communication | TLS via rustls | Ch 8, 12 |
| Resource exhaustion (DoS) | Connection limits, timeouts | Ch 12 |
| Slowloris attacks | Read timeouts | Ch 12 |
| Brute-force attacks | Connection-attempt throttling + per-request rate limiting for both valid and malformed frames | Ch 12 |
| Memory exhaustion | Bounded buffers, size limits | Ch 7 |
| Buffer overflows | Rust's memory safety | Ch 3 |
| Data races | Rust's concurrency model | Ch 6 |
| Information disclosure | Sanitized logging, no secret leaks | Ch 5, 19 |
| Dependency vulnerabilities | cargo-audit, cargo-deny | Ch 15, 16 |
| Panic-induced crashes | `panic = "abort"`, explicit error handling, and poison recovery for shared state | Ch 5, 6 |

### Architecture

```text
Client → TLS Termination → Connection Handler → Request Parser → Business Logic → Response
              ↓                    ↓                    ↓
          rustls            Rate Limiter         Input Validation
                            Conn Counter          (newtypes)
```

## 17.2 Project Setup

Because the real example lives in a workspace, the package manifest and the release profile live in different files. Cargo only honors `[profile.*]` settings from the workspace root, so the deployed companion binary inherits its hardening flags from the top-level `Cargo.toml`.

```toml
# companion/ch17-hardened-server/Cargo.toml
[package]
name = "ch17-hardened-server"
version = "0.1.0"
edition.workspace = true

[dependencies]
tokio.workspace = true
tokio-rustls.workspace = true
rustls.workspace = true
log.workspace = true
env_logger.workspace = true
thiserror.workspace = true

[dev-dependencies]
proptest.workspace = true
```

```toml
# Cargo.toml (workspace root excerpt)
[workspace]
members = [
    "companion/ch10-ffi",
    "companion/ch12-networking",
    "companion/ch17-hardened-server",
    "companion/ch19-hardening",
]
resolver = "3"

[workspace.package]
edition = "2024"

[profile.release]
overflow-checks = true
lto = true
codegen-units = 1
panic = "abort"
strip = "symbols"
opt-level = "z"
```

## 17.3 Secure Types

```rust,no_run
# extern crate rust_secure_systems_book as thiserror;
// src/types.rs
use thiserror::Error;

/// Maximum number of concurrent connections
pub const MAX_CONNECTIONS: usize = 1000;

/// Maximum message size (64 KiB)
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Read timeout in seconds
pub const READ_TIMEOUT_SECS: u64 = 30;

/// Write timeout in seconds
pub const WRITE_TIMEOUT_SECS: u64 = 10;

/// TLS handshake timeout in seconds
pub const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Maximum session duration in seconds
pub const MAX_SESSION_SECS: u64 = 300;

/// Grace period for in-flight connections during shutdown
pub const SHUTDOWN_GRACE_SECS: u64 = 30;

/// Rate limit: max connection attempts per minute per IP
pub const CONNECTION_ATTEMPT_RATE_LIMIT: usize = 60;

/// Rate limit: max requests per minute per IP
pub const RATE_LIMIT: usize = 60;

/// Bound tracked client state between cleanup cycles
pub const MAX_TRACKED_CLIENTS: usize = 8192;

/// A validated message with a non-empty payload and guaranteed bounds
#[derive(Debug)]
pub struct Message(Vec<u8>);

impl Message {
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge {
                size: data.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        // Validate message format: 4-byte length prefix + payload
        if data.len() < 4 {
            return Err(ProtocolError::IncompleteHeader);
        }
        let declared_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if declared_len == 0 {
            return Err(ProtocolError::EmptyMessage);
        }
        if declared_len > MAX_MESSAGE_SIZE - 4 {
            return Err(ProtocolError::DeclaredLengthTooLarge(declared_len));
        }
        if data.len() < 4 + declared_len {
            return Err(ProtocolError::IncompleteMessage {
                expected: 4 + declared_len,
                actual: data.len(),
            });
        }
        Ok(Message(data[..4 + declared_len].to_vec()))
    }
    
    pub fn payload(&self) -> &[u8] {
        &self.0[4..]
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Create an echo response message
pub fn echo_response(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if payload.is_empty() {
        return Err(ProtocolError::EmptyMessage);
    }
    if payload.len() > MAX_MESSAGE_SIZE - 4 {
        return Err(ProtocolError::MessageTooLarge {
            size: payload.len() + 4,
            max: MAX_MESSAGE_SIZE,
        });
    }
    let len = payload.len() as u32;
    let mut response = len.to_be_bytes().to_vec();
    response.extend_from_slice(payload);
    Ok(response)
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("empty message")]
    EmptyMessage,

    #[error("incomplete header")]
    IncompleteHeader,

    #[error("declared length too large: {0}")]
    DeclaredLengthTooLarge(usize),

    #[error("incomplete message: expected {expected}, got {actual}")]
    IncompleteMessage { expected: usize, actual: usize },
}
```

Size caps are necessary but not sufficient for robustness under memory pressure. Rust's default allocation path still calls `handle_alloc_error`; with `panic = "abort"`, that usually terminates the process. For request paths that allocate from attacker-influenced lengths, prefer fallible reservation APIs so overload becomes an ordinary error:

```rust,no_run
fn copy_frame_fallible(frame: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(frame.len())
        .map_err(|_| std::io::Error::other("out of memory while buffering frame"))?;
    out.extend_from_slice(frame);
    Ok(out)
}
```

This server already keeps a fixed read buffer to reduce per-read allocation, but the same review rule still applies to copies you make after validation.

The 64 KiB cap is an example policy for a small framed service. In a real protocol, derive this from the wire specification and observed traffic profile, then lower it for constrained deployments rather than copying the book's ceiling blindly.

## 17.4 Rate Limiter

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::log as log;
// src/rate_limiter.rs
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
        RateLimiter {
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
            clients.retain(|_, record| {
                now.duration_since(record.window_start) <= double_window
            });
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
    
    /// Remove expired entries to prevent memory growth
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
```

Bounding the map prevents untrusted clients from turning rate-limit state into an unbounded memory sink. It is still a baseline policy: in IPv6-heavy environments, exact-address limits are often paired with `/64` aggregation, authenticated quotas, or an upstream proxy that can shed abusive sources earlier.

## 17.5 TLS Configuration

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::rustls as rustls;
// src/tls.rs
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::sync::Arc;

pub fn create_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let certs = CertificateDer::pem_file_iter(cert_path)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    Ok(Arc::new(config))
}
```

This keeps the PEM parsing path inside `rustls` itself, which avoids carrying an extra helper crate just to load certificates and keys.

**Operational note**: This server configuration loads certificates and private keys, but revocation policy is separate. If your deployment requires CRL or OCSP enforcement, configure it explicitly in your verifier or enforce it at a proxy or service mesh; otherwise prefer short-lived certificates and deliberate rotation.

## 17.6 Connection Handler

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::companion::ch17_hardened_server as ch17_hardened_server;
# use rust_secure_systems_book::deps::log as log;
# use rust_secure_systems_book::deps::tokio as tokio;
// src/handler.rs
use ch17_hardened_server::rate_limiter::RateLimiter;
use ch17_hardened_server::types::*;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Duration};

pub struct ConnectionHandler {
    admission_limiter: Arc<RateLimiter>,
    request_limiter: Arc<RateLimiter>,
    connection_count: Arc<AtomicUsize>,
}

pub struct ConnectionPermit {
    connection_count: Arc<AtomicUsize>,
}

const RATE_LIMIT_RESPONSE: &[u8] = b"rate limit exceeded";

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.connection_count.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ConnectionHandler {
    pub fn new(admission_limiter: Arc<RateLimiter>, request_limiter: Arc<RateLimiter>) -> Self {
        ConnectionHandler {
            admission_limiter,
            request_limiter,
            connection_count: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    pub fn connection_count(&self) -> usize {
        self.connection_count.load(Ordering::SeqCst)
    }
    pub fn try_admit(&self, addr: SocketAddr) -> Option<ConnectionPermit> {
        // Reserve capacity before the expensive TLS handshake begins without
        // ever letting the counter exceed MAX_CONNECTIONS.
        let current = match self.connection_count.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |current| (current < MAX_CONNECTIONS).then_some(current + 1),
        ) {
            Ok(previous) => previous,
            Err(_) => {
                log::warn!("Rejecting connection from {}: limit reached", addr);
                return None;
            }
        };

        if !self.admission_limiter.check(addr.ip()) {
            self.connection_count.fetch_sub(1, Ordering::SeqCst);
            log::warn!("Rate limited before TLS handshake: {}", addr);
            return None;
        }

        log::info!("Admitted connection from {} (total: {})", addr, current + 1);

        Some(ConnectionPermit {
            connection_count: Arc::clone(&self.connection_count),
        })
    }

    pub async fn handle<S>(
        &self,
        mut stream: S,
        addr: SocketAddr,
        _permit: ConnectionPermit,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        log::info!("Handling established connection from {}", addr);

        // Handle with overall session timeout
        let result = timeout(
            Duration::from_secs(MAX_SESSION_SECS),
            self.handle_inner(&mut stream, addr),
        ).await;
        
        match result {
            Ok(Ok(())) => log::info!("Connection from {} closed normally", addr),
            Ok(Err(e)) => {
                if e.downcast_ref::<io::Error>()
                    .is_some_and(|io_error| io_error.kind() == io::ErrorKind::PermissionDenied)
                {
                    log::warn!("Connection from {} closed after rate limiting", addr);
                } else {
                    log::error!("Error handling {}: {}", addr, e);
                }
            }
            Err(_) => log::warn!("Session timeout for {}", addr),
        }

        Ok(())
    }
    
    async fn handle_inner<S>(
        &self,
        stream: &mut S,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buffer = vec![0u8; MAX_MESSAGE_SIZE];
        let mut buffered: usize = 0;
        
        loop {
            // Read with timeout, accumulating partial reads into buffer
            let n = timeout(
                Duration::from_secs(READ_TIMEOUT_SECS),
                stream.read(&mut buffer[buffered..]),
            ).await??;
            
            if n == 0 {
                if buffered == 0 {
                    break; // Connection closed
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-frame",
                ).into());
            }
            
            buffered += n;
            
            while buffered > 0 {
                // Count both valid and malformed frames once enough bytes are
                // buffered to classify them. Incomplete fragments are not
                // charged yet.
                let message = match Message::from_bytes(&buffer[..buffered]) {
                    Ok(msg) => {
                        if !self.request_limiter.check(addr.ip()) {
                            log::warn!("Per-request rate limit exceeded for {}", addr);
                            let error_response = echo_response(RATE_LIMIT_RESPONSE)?;
                            timeout(
                                Duration::from_secs(WRITE_TIMEOUT_SECS),
                                stream.write_all(&error_response),
                            ).await??;
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "rate limit exceeded",
                            ).into());
                        }
                        msg
                    },
                    Err(ProtocolError::IncompleteHeader) | Err(ProtocolError::IncompleteMessage { .. }) => {
                    // Need more data - keep reading
                    break;
                    }
                    Err(e) => {
                    if !self.request_limiter.check(addr.ip()) {
                        log::warn!("Per-request rate limit exceeded for {}", addr);
                        let error_response = echo_response(RATE_LIMIT_RESPONSE)?;
                        timeout(
                            Duration::from_secs(WRITE_TIMEOUT_SECS),
                            stream.write_all(&error_response),
                        ).await??;
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "rate limit exceeded",
                        ).into());
                    }
                    log::warn!("Invalid message from {}: {}", addr, e);
                    // Keep parser details in logs, not on the wire.
                    let error_response = echo_response(b"invalid request")?;
                    timeout(
                        Duration::from_secs(WRITE_TIMEOUT_SECS),
                        stream.write_all(&error_response),
                    ).await??;
                    buffered = 0;
                    break;
                    }
                };
                // Echo response
                let response = echo_response(message.payload())?;
                
                timeout(
                    Duration::from_secs(WRITE_TIMEOUT_SECS),
                    stream.write_all(&response),
                ).await??;
                
                // Shift unconsumed bytes to the front of the buffer
                let consumed = message.as_bytes().len();
                buffered -= consumed;
                if buffered > 0 {
                    buffer.copy_within(consumed..consumed + buffered, 0);
                }
            }
        }
        
        Ok(())
    }
}
```

Passing `ConnectionPermit` by value is the RAII part of the design: explicit increment/decrement pairs are easy to miss on early returns, timeout branches, or future refactors, while `Drop` keeps the counter balanced on every normal exit path.

## 17.7 Main Server

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::companion::ch17_hardened_server as ch17_hardened_server;
# use rust_secure_systems_book::deps::env_logger as env_logger;
# use rust_secure_systems_book::deps::log as log;
# use rust_secure_systems_book::deps::tokio as tokio;
# use rust_secure_systems_book::deps::tokio_rustls as tokio_rustls;
// src/main.rs
use ch17_hardened_server::{handler::ConnectionHandler, rate_limiter::RateLimiter, tls, types};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
    
    let admission_limiter = Arc::new(RateLimiter::new(
        types::CONNECTION_ATTEMPT_RATE_LIMIT,
        std::time::Duration::from_secs(60),
        types::MAX_TRACKED_CLIENTS,
    ));
    let request_limiter = Arc::new(RateLimiter::new(
        types::RATE_LIMIT,
        std::time::Duration::from_secs(60),
        types::MAX_TRACKED_CLIENTS,
    ));
    
    let handler = Arc::new(ConnectionHandler::new(
        Arc::clone(&admission_limiter),
        Arc::clone(&request_limiter),
    ));

    // Hardened server: require TLS configuration at startup and fail fast if it
    // is missing. Development-only plain TCP belongs in a separate example.
    let cert_path = std::env::var("TLS_CERT_PATH")
        .map_err(|_| "TLS_CERT_PATH must be set for the hardened server")?;
    let key_path = std::env::var("TLS_KEY_PATH")
        .map_err(|_| "TLS_KEY_PATH must be set for the hardened server")?;
    let config = tls::create_server_config(&cert_path, &key_path)?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(config);
    
    let listener = TcpListener::bind("0.0.0.0:8443").await?;
    log::info!("Server listening on 0.0.0.0:8443 with TLS enabled");
    
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    // Periodic cleanup task
    let cleanup_admission_limiter = Arc::clone(&admission_limiter);
    let cleanup_request_limiter = Arc::clone(&request_limiter);
    let mut cleanup_shutdown = shutdown_rx.clone();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    cleanup_admission_limiter.cleanup();
                    cleanup_request_limiter.cleanup();
                }
                changed = cleanup_shutdown.changed() => {
                    if changed.is_err() || *cleanup_shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    
    loop {
        tokio::select! {
            biased;

            result = &mut shutdown => {
                result?;
                log::info!("Shutdown signal received; stopping new accepts");
                break;
            }

            accepted = listener.accept() => {
                let (stream, addr) = accepted?;
                if let Err(e) = stream.set_nodelay(true) {
                    log::warn!("Failed to configure TCP_NODELAY for {}: {}", addr, e);
                    continue;
                }

                let Some(permit) = handler.try_admit(addr) else {
                    continue;
                };

                let handler = Arc::clone(&handler);
                let tls_acceptor = tls_acceptor.clone();
                
                tasks.spawn(async move {
                    let tls_stream = match timeout(
                        Duration::from_secs(types::TLS_HANDSHAKE_TIMEOUT_SECS),
                        tls_acceptor.accept(stream),
                    ).await {
                        Ok(Ok(tls_stream)) => {
                            log::info!("TLS handshake completed for {}", addr);
                            tls_stream
                        }
                        Ok(Err(e)) => {
                            log::error!("TLS handshake failed for {}: {}", addr, e);
                            return;
                        }
                        Err(_) => {
                            log::warn!("TLS handshake timeout for {}", addr);
                            return;
                        }
                    };
                    
                    if let Err(e) = handler.handle(tls_stream, addr, permit).await {
                        log::error!("Fatal error for {}: {}", addr, e);
                    }
                    // `permit` was moved into `handle`; it is dropped when
                    // `handle` returns, decrementing the connection count on
                    // every exit path instead of relying on a hand-written
                    // `fetch_sub` at each return site.
                });
            }
        }
    }

    drop(listener);
    let _ = shutdown_tx.send(true);

    match timeout(
        Duration::from_secs(types::SHUTDOWN_GRACE_SECS),
        wait_for_tasks(&mut tasks),
    ).await {
        Ok(()) => log::info!("Shutdown completed cleanly"),
        Err(_) => {
            log::warn!(
                "Graceful shutdown timed out after {}s; aborting remaining tasks",
                types::SHUTDOWN_GRACE_SECS
            );
            tasks.abort_all();
            wait_for_tasks(&mut tasks).await;
        }
    }

    Ok(())
}

async fn wait_for_tasks(tasks: &mut JoinSet<()>) {
    while let Some(result) = tasks.join_next().await {
        if let Err(e) = result {
            if e.is_cancelled() {
                log::info!("Task cancelled during shutdown");
            } else {
                log::error!("Task failed during shutdown: {}", e);
            }
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}
```

⚠️ **Security note**: `0.0.0.0` is intentional here because this example represents the externally reachable production service. For local development bind `127.0.0.1`; in production prefer the specific interface, socket-activation unit, or load-balancer path you actually intend to expose.

If the production service must accept both IPv4 and IPv6, do not assume this listener is enough. An explicit IPv4 bind keeps the example simple and portable, but real deployments often need either a second IPv6 listener or a deliberate `[::]:8443` socket after verifying the target platform's `IPV6_V6ONLY` behavior.

Admission control happens before `tls_acceptor.accept()`, so connection floods consume a bounded number of slots and cannot trigger unlimited concurrent handshakes. A separate per-request limiter runs once enough bytes are buffered to classify a frame, so malformed requests also consume the same request budget and one long-lived TLS session cannot bypass brute-force throttling.

> **Note**: The handler already accepts any `AsyncRead + AsyncWrite + Unpin` stream, so the same code works with `TcpStream`, `tokio_rustls::server::TlsStream<TcpStream>`, and test doubles.

Production shutdown is part of hardening too. The `main` loop above implements the bounded-drain pattern directly: listen for `SIGTERM` (or Ctrl+C during development), stop accepting new sockets, notify the housekeeping task, wait up to `SHUTDOWN_GRACE_SECS` for in-flight connections, then abort anything still running. That avoids half-written responses, leaked permits, and the operational habit of using `SIGKILL` for routine restarts.

## 17.8 Tests

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::proptest as proptest;
// src/types.rs
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_message_validation_valid() {
        let payload = b"hello";
        let mut data = (payload.len() as u32).to_be_bytes().to_vec();
        data.extend_from_slice(payload);
        
        let msg = Message::from_bytes(&data).unwrap();
        assert_eq!(msg.payload(), payload);
    }

    #[test]
    fn test_message_validation_too_large() {
        let large_size = MAX_MESSAGE_SIZE + 1;
        let data = vec![0u8; large_size];
        assert!(Message::from_bytes(&data).is_err());
    }

    #[test]
    fn test_message_validation_incomplete() {
        // Only 2 bytes of header
        assert!(Message::from_bytes(&[0, 0]).is_err());
    }

    #[test]
    fn test_zero_length_frame_rejected() {
        assert!(matches!(
            Message::from_bytes(&[0, 0, 0, 0]),
            Err(ProtocolError::EmptyMessage)
        ));
    }

    #[test]
    fn test_message_validation_declared_length_mismatch() {
        let mut data = 1000u32.to_be_bytes().to_vec();
        data.extend_from_slice(b"short");
        assert!(Message::from_bytes(&data).is_err());
    }

    #[test]
    fn test_echo_response_format() {
        let response = echo_response(b"test").unwrap();
        let len = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
        assert_eq!(len, 4);
        assert_eq!(&response[4..], b"test");
    }

    proptest! {
        #[test]
        fn message_roundtrip(payload in prop::collection::vec(any::<u8>(), 1..1000)) {
            let response = echo_response(&payload).unwrap();
            let msg = Message::from_bytes(&response).unwrap();

            assert_eq!(msg.payload(), &payload[..]);
        }
    }
}
```

If you later split shared code into `src/lib.rs`, the same test cases can be moved into `tests/` as integration tests with minimal changes.

## 17.9 Security Review Checklist

Review this server against our security checklist:

- [x] **Memory safety**: No `unsafe` code (safe Rust throughout)
- [x] **Integer overflow**: `overflow-checks = true` in release, checked length parsing
- [x] **Input validation**: `Message::from_bytes` validates length, bounds, format
- [x] **Connection limiting**: MAX_CONNECTIONS enforced before the TLS handshake starts
- [x] **Rate limiting**: Connection-attempt throttling before the handshake and per-IP request limiting for both valid and malformed frames once they are parseable
- [x] **Timeouts**: Read, write, and session timeouts
- [x] **Logging**: Security-relevant logs with no sensitive data
- [x] **Error handling**: No `unwrap()` in production paths; mutex poisoning is recovered explicitly
- [x] **TLS**: rustls is required; the server refuses to start without `TLS_CERT_PATH` and `TLS_KEY_PATH`
- [x] **DoS protection**: Bounded message sizes, handshake/session timeouts, and both admission/request rate limits

## 17.10 Summary

This server demonstrates the practical application of secure Rust development:

1. **Types enforce validity**: `Message` validates at construction time
2. **Defense in depth**: Connection limits, rate limits, timeouts, message size limits
3. **Safe concurrency**: `Arc`, `AtomicUsize`, `Mutex` with clear ownership
4. **No unsafe code**: The entire server is safe Rust
5. **Comprehensive testing**: Unit tests and property tests around the protocol layer

In the next chapter, we build a secure binary parser: another common security-critical component.

> **Note**: This server uses the `log` crate for simplicity. See §19.4.1 for a drop-in path to replace `log`/`env_logger` with `tracing` once you need structured JSON logs, request spans, or SIEM-friendly fields.

## 17.11 Exercises

1. **Mutual TLS**: Extend `create_server_config()` to require and verify client certificates for privileged peers. Add tests for: valid client certificate accepted, unknown CA rejected, expired client certificate rejected, and plaintext clients rejected before application data is processed.

2. **TLS Handshake Drain**: Extend the shutdown path so it tracks in-flight TLS handshakes separately from established sessions. On shutdown, stop accepting new sockets, wait up to `SHUTDOWN_GRACE_SECS` for both handshakes and active sessions to drain, then abort anything still stuck. Add tests that verify the connection counter returns to zero and that a stalled handshake cannot hang shutdown forever.

3. **Load Test**: Write a load-testing client that opens 500 concurrent connections and sends 100 messages per connection. Verify that: (a) the server never exceeds `MAX_CONNECTIONS`, (b) the rate limiter triggers for abusive clients, (c) no panics or errors appear in the server logs. Measure throughput and latency percentiles (p50, p99).
