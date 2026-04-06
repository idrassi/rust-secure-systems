# Chapter 12 — Secure Network Programming

> *"The network is not trustworthy. Design accordingly."*

Network services are the most exposed attack surface in any system. Every connection could be an attacker probing for vulnerabilities—buffer overflows in parsers, resource exhaustion through connection floods, injection attacks through malformed input, and timing attacks through crafted requests.

Rust's memory safety eliminates many traditional network vulnerabilities, but secure network programming requires more than memory safety. This chapter covers the patterns and practices for building robust, attack-resistant network services.

## 12.1 Connection Handling

### 12.1.1 Basic TCP Server with tokio

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::log as log;
# use rust_secure_systems_book::deps::tokio as tokio;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

const MAX_CONNECTIONS: usize = 1000;
const MAX_PAYLOAD_SIZE: usize = 64 * 1024; // 64 KiB payload
const MAX_FRAME_SIZE: usize = 4 + MAX_PAYLOAD_SIZE; // length prefix + payload

struct ServerState {
    connection_count: std::sync::atomic::AtomicUsize,
}

fn try_acquire_connection(state: &ServerState) -> bool {
    state.connection_count
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |current| (current < MAX_CONNECTIONS).then_some(current + 1),
        )
        .is_ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(ServerState {
        connection_count: std::sync::atomic::AtomicUsize::new(0),
    });
    
    let listener = TcpListener::bind("0.0.0.0:8443").await?;
    // Note: 0.0.0.0 binds to all interfaces. In production, consider binding
    // to a specific interface or 127.0.0.1 for development.
    println!("Server listening on port 8443");
    
    loop {
        let (stream, addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        
        // Connection limiting
        if !try_acquire_connection(&state) {
            log::warn!("Rejecting connection from {}: limit reached", addr);
            drop(stream);
            continue;
        }
        
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr, &state).await {
                log::error!("Error handling {}: {}", addr, e);
            }
            state.connection_count
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    _state: &ServerState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set timeouts
    stream.set_nodelay(true)?;
    
    let mut buffer = vec![0u8; MAX_FRAME_SIZE];
    let mut buffered = 0usize;
    
    loop {
        // Read with timeout
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read(&mut buffer[buffered..])
        ).await??;
        
        if n == 0 {
            if buffered == 0 {
                break; // Connection closed cleanly
            }
            return Err("connection closed mid-frame".into());
        }

        buffered += n;

        // TCP is a byte stream: one read may contain part of a frame
        // or several complete frames back-to-back.
        while let Some((response, consumed)) = process_message(&buffer[..buffered])? {
            let framed_response = build_frame(&response);
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stream.write_all(&framed_response)
            ).await??;

            buffered -= consumed;
            if buffered > 0 {
                buffer.copy_within(consumed..consumed + buffered, 0);
            }
        }
    }
    
    Ok(())
}

fn process_message(
    data: &[u8],
) -> Result<Option<(Vec<u8>, usize)>, Box<dyn std::error::Error + Send + Sync>> {
    // Validate message structure
    if data.len() < 4 {
        return Ok(None);
    }
    
    let declared_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if declared_len > MAX_PAYLOAD_SIZE {
        return Err("declared message length too large".into());
    }

    let frame_len = 4usize
        .checked_add(declared_len)
        .ok_or("length overflow")?;
    if frame_len > MAX_FRAME_SIZE {
        return Err("frame too large".into());
    }

    // Verify we have the complete frame (4-byte header + payload)
    if data.len() < frame_len {
        return Ok(None);
    }
    
    // Return only the payload (excluding the 4-byte length prefix)
    Ok(Some((data[4..frame_len].to_vec(), frame_len)))
}

fn build_frame(payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_PAYLOAD_SIZE);
    let len = payload.len() as u32;
    let mut frame = len.to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame
}
```

This buffering is not optional. TCP preserves byte order, not message boundaries, so a secure server must handle both partial frames and multiple frames delivered in one read.

On Unix, broken-pipe `SIGPIPE` delivery is a classic networking footgun. For Rust socket code, `std::net` and Tokio already suppress `SIGPIPE` on TCP sockets (`MSG_NOSIGNAL` / `SO_NOSIGPIPE` style handling), so a dead peer normally becomes an `io::Error`, not process termination. Revisit `SIGPIPE` only when you drop to raw `libc` writes, interact with pipes or child stdio, or deliberately change the process signal disposition.

🔒 **Security measures in this server**:
1. **Connection limiting**: Prevents resource exhaustion (CWE-400)
2. **Read timeouts**: Prevents slowloris attacks (CWE-400)
3. **Write timeouts**: Prevents blocked clients from consuming resources
4. **Message size limits**: Prevents memory exhaustion (CWE-789)
5. **TCP_NODELAY**: Reduces latency, prevents delayed ACK interaction
6. **Explicit framing buffer**: Correctly handles fragmented and coalesced TCP reads

> **Note**: The examples above use `.unwrap()` in a few places (e.g., on `lock()` results and `join` handles) for readability. In production code, replace these with proper error handling—especially around mutex acquisition where poisoning may indicate data corruption from a panicked thread.

### 12.1.2 Rate Limiting

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct RateLimiter {
    clients: Mutex<HashMap<std::net::IpAddr, ClientRecord>>,
    max_requests: usize,
    window: Duration,
}

struct ClientRecord {
    count: usize,
    window_start: Instant,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        RateLimiter {
            clients: Mutex::new(HashMap::new()),
            max_requests,
            window,
        }
    }
    
    fn check(&self, addr: std::net::IpAddr) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let now = Instant::now();
        
        let record = clients.entry(addr).or_insert_with(|| ClientRecord {
            count: 0,
            window_start: now,
        });
        
        if now.duration_since(record.window_start) > self.window {
            record.count = 0;
            record.window_start = now;
        }
        
        record.count += 1;
        record.count <= self.max_requests
    }
    
    /// Clean up old entries periodically
    fn cleanup(&self) {
        let mut clients = self.clients.lock().unwrap();
        let now = Instant::now();
        clients.retain(|_, record| {
            now.duration_since(record.window_start) <= self.window * 2
        });
    }
}
```

🔒 **Security impact**: Rate limiting prevents brute-force attacks (CWE-307), denial of service (CWE-770), and credential stuffing. Apply per-IP and per-user limits.

If you keep per-client state in memory, schedule cleanup rather than leaving the helper unused:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::tokio as tokio;
use std::sync::Arc;
use std::time::Duration;

# struct RateLimiter;
# impl RateLimiter { fn cleanup(&self) {} }
fn spawn_rate_limiter_cleanup(limiter: Arc<RateLimiter>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            limiter.cleanup();
        }
    });
}
```

## 12.2 TLS Configuration

### 12.2.1 Server TLS with rustls

```toml
[dependencies]
tokio-rustls = "0.26"
rustls = "0.23"
rustls-pemfile = "2"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::rustls as rustls;
# use rust_secure_systems_book::deps::rustls_pemfile as rustls_pemfile;
use rustls::ServerConfig;
use std::sync::Arc;

fn create_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;
    
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;
    
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))?
        .ok_or("no private key found")?;
    
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    // Harden TLS configuration
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // rustls enforces:
    // - TLS 1.2 minimum (TLS 1.3 preferred)
    // - No RC4, DES, or other weak ciphers
    // - No compression (CRIME attack prevention)
    // - No renegotiation (renegotiation attack prevention)
    
    Ok(Arc::new(config))
}
```

The config object is only half the story. You still need to wrap accepted TCP streams with `tokio-rustls`:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::rustls as rustls;
# use rust_secure_systems_book::deps::tokio as tokio;
# use rust_secure_systems_book::deps::tokio_rustls as tokio_rustls;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

# fn create_tls_config(
#     cert_path: &str,
#     key_path: &str,
# ) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
#     unimplemented!()
# }
# async fn handle_tls_client<S>(_stream: S) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
# where
#     S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
# {
#     Ok(())
# }
# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let config = create_tls_config("server.crt", "server.key")?;
let acceptor = TlsAcceptor::from(config);
let listener = TcpListener::bind("0.0.0.0:8443").await?;

loop {
    let (tcp_stream, addr) = listener.accept().await?;
    let acceptor = acceptor.clone();

    tokio::spawn(async move {
        match acceptor.accept(tcp_stream).await {
            Ok(tls_stream) => {
                if let Err(err) = handle_tls_client(tls_stream).await {
                    eprintln!("{}: {}", addr, err);
                }
            }
            Err(err) => eprintln!("TLS handshake failed for {}: {}", addr, err),
        }
    });
}
# }
```

🔒 **TLS hardening checklist**:
- ✅ Use TLS 1.2 minimum (prefer TLS 1.3)
- ✅ Use AEAD ciphers only (AES-GCM, ChaCha20-Poly1305)
- ✅ Use ECDHE key exchange (forward secrecy)
- ✅ Disable TLS compression (CRIME attack)
- ✅ Set ALPN protocols explicitly
- ✅ Use strong certificates (ECDSA P-256 or Ed25519)
- ✅ Implement certificate pinning for internal services

### 12.2.2 Mutual TLS for Service-to-Service Traffic

`with_no_client_auth()` is appropriate for public-facing services where clients authenticate at the application layer. For internal RPC, admin APIs, and other service-to-service traffic, prefer mutual TLS: configure a client-certificate verifier from your internal CA roots, require every client to present a certificate, and map the validated subject or SAN to an expected service identity.

Treat mTLS as authentication input, not just encryption. Reject missing or expired client certificates, rotate your client CA set deliberately, and still authorize each peer for the specific operations it is allowed to perform.

In zero-trust terms, the network path is not the trust boundary. mTLS gives you a cryptographic identity for each peer, but you still need per-service authorization, narrow trust domains, and audit trails for which identity invoked which action.

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::rustls as rustls;
# use rust_secure_systems_book::deps::rustls_pemfile as rustls_pemfile;
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use std::io::BufReader;
use std::sync::Arc;

fn create_mtls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert_path)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key_path)?))?
        .ok_or("no private key found")?;

    let mut client_roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(client_ca_path)?)) {
        client_roots.add(cert?)?;
    }

    let client_verifier = WebPkiClientVerifier::builder(client_roots.into()).build()?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}
```

## 12.3 Defense Against Network Attacks

### 12.3.1 Preventing Buffer Overflows in Parsers

Rust's safe code is immune to buffer overflows, but parser logic errors can still cause denial of service:

```rust
# const MAX_MESSAGE_SIZE: usize = 64 * 1024;
# #[derive(Debug)]
# enum ParseError {
#     TooShort,
#     TooLong(usize),
#     Incomplete,
# }
#
fn parse_length_prefixed_message(data: &[u8]) -> Result<&[u8], ParseError> {
    if data.len() < 4 {
        return Err(ParseError::TooShort);
    }
    
    let declared_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    
    // Validate declared length against actual data
    if declared_len > MAX_MESSAGE_SIZE {
        return Err(ParseError::TooLong(declared_len));
    }
    
    if data.len() - 4 < declared_len {
        return Err(ParseError::Incomplete);
    }
    
    Ok(&data[4..4 + declared_len])
}
```

### 12.3.2 Preventing Integer Overflow in Length Fields

```rust
# const MAX_MESSAGE_SIZE: usize = 64 * 1024;
#
fn safe_length_add(a: usize, b: usize) -> Option<usize> {
    a.checked_add(b).filter(|&sum| sum <= MAX_MESSAGE_SIZE)
}
```

🔒 **Security impact**: Network protocols with length fields are a primary attack vector. Always:
1. Validate declared lengths against limits.
2. Use checked arithmetic for length calculations.
3. Never trust a length field from the network without bounds checking.

DNS is another security boundary, not just a lookup mechanism. For outbound clients, pin the resolver path you trust, defend against DNS rebinding when hostnames eventually authorize private-network access, and prefer authenticated resolver transports (DNS-over-TLS / DNS-over-HTTPS, or DNSSEC-aware infrastructure) when your deployment depends on hostile networks.

If you need an in-process encrypted resolver, `hickory-resolver` exposes ready-made configurations for DNS-over-TLS and DNS-over-HTTPS:

```rust,ignore
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;

let resolver = Resolver::builder_with_config(
    ResolverConfig::cloudflare_tls(), // or `cloudflare_https()` for DoH
    TokioConnectionProvider::default(),
).build();

let ips = resolver.lookup_ip("api.example.com.").await?;
```

Prefer a reviewed resolver configuration over ad hoc plaintext DNS for services that make authorization or routing decisions from hostnames.

### 12.3.3 Preventing Amplification Attacks

```rust,no_run
// BAD: unbounded response to small request
# fn generate_large_response(query: &[u8]) -> Vec<u8> {
#     vec![0u8; query.len().saturating_mul(64).max(1)]
# }
async fn handle_query_unbounded(query: &[u8]) -> Vec<u8> {
    // An attacker sends a tiny query that generates a huge response
    generate_large_response(query)  // Amplification!
}

// GOOD: limit response size
# const MAX_RESPONSE_SIZE: usize = 4096;
# #[derive(Debug)]
# enum QueryError {
#     ResponseTooLarge,
# }
# fn generate_response(query: &[u8]) -> Result<Vec<u8>, QueryError> {
#     Ok(query.to_vec())
# }
async fn handle_query_bounded(query: &[u8]) -> Result<Vec<u8>, QueryError> {
    let response = generate_response(query)?;
    if response.len() > MAX_RESPONSE_SIZE {
        return Err(QueryError::ResponseTooLarge);
    }
    Ok(response)
}
```

### 12.3.4 Timeouts and Deadlines

Always use timeouts for network operations:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::tokio as tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

async fn handle_with_deadlines(
    stream: &mut tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let read_deadline = Duration::from_secs(30);
    let write_deadline = Duration::from_secs(10);
    let total_deadline = Duration::from_secs(300);  // 5 min max session
    
    let result = timeout(total_deadline, async {
        // Read with per-operation timeout
        let mut buf = [0u8; 4096];
        let n = timeout(read_deadline, stream.read(&mut buf)).await??;
        
        // Process...
        
        // Write with per-operation timeout
        timeout(write_deadline, stream.write_all(b"response")).await??;
        
        Ok::<(), std::io::Error>(())
    }).await?;
    
    result?;
    Ok(())
}
```

🔒 **Security impact**: Timeouts prevent:
- **Slowloris attacks**: Attacker holds connections open with partial requests
- **Slow read attacks**: Attacker reads very slowly to consume server memory
- **Resource exhaustion**: Long-running connections consuming memory and file descriptors

## 12.4 Logging and Monitoring

### Security-Relevant Logging

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::log as log;
use log::{warn, error};

# use std::net::SocketAddr;
# enum SecurityEvent {
#     AuthenticationFailure { addr: SocketAddr, username: String },
#     RateLimitExceeded { addr: SocketAddr },
#     InvalidInput { addr: SocketAddr, reason: String },
#     TlsError { addr: SocketAddr, error: String },
# }

fn log_security_event(event: &SecurityEvent) {
    match event {
        SecurityEvent::AuthenticationFailure { addr, username } => {
            warn!(
                "Authentication failure: addr={}, username={}",
                addr, username
            );
        }
        SecurityEvent::RateLimitExceeded { addr } => {
            warn!("Rate limit exceeded: addr={}", addr);
        }
        SecurityEvent::InvalidInput { addr, reason } => {
            warn!("Invalid input: addr={}, reason={}", addr, reason);
        }
        SecurityEvent::TlsError { addr, error } => {
            error!("TLS error: addr={}, error={}", addr, error);
        }
    }
}
```

⚠️ **Logging security**: 
- Never log passwords, tokens, or session keys.
- Log enough detail for incident response but not enough to aid attackers.
- Use structured logging for machine parsing (SIEM integration).

## 12.5 Summary

- Use connection limiting, rate limiting, and timeouts to prevent DoS attacks.
- Always set read/write/session timeouts on network connections.
- Use `rustls` for TLS—memory-safe by design.
- Validate all length fields from network data with checked arithmetic.
- Limit both request and response sizes to prevent amplification attacks.
- Log security events without exposing sensitive data.
- Apply the principle of least privilege: bind to specific interfaces, use firewall rules.

In the next chapter, we move to Part IV—testing and verification strategies for proving your code is secure.

## 12.6 Exercises

1. **Hardened Echo Server**: Build a tokio-based TCP echo server with: connection limiting (max 100 concurrent), per-IP rate limiting (max 10 requests per second), read timeout (30s), write timeout (10s), and message size limit (64 KiB). Test each defense individually by writing a client that attempts each attack vector.

2. **TLS Configuration Audit**: Set up a TLS server using `rustls`. Connect to it using `openssl s_client` and verify: TLS 1.2 and TLS 1.3 behave as configured, weak cipher suites are rejected, and the certificate chain is valid. Then attempt a TLS 1.1 client and confirm the handshake fails because current `rustls` does not support TLS 1.1.

3. **Protocol Fuzzer**: Write a simple length-prefixed protocol parser (4-byte big-endian length + payload). Create a fuzz target using `cargo-fuzz` that feeds arbitrary bytes to the parser. Run the fuzzer for at least 10 minutes and report any crashes or hangs found.
