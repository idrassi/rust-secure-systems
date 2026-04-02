# Chapter 19 — Deployment Hardening and Release

> *"Secure code deployed insecurely is insecure."*

Writing secure Rust code is necessary but not sufficient. How you compile, package, deploy, and operate your software determines its real-world security posture. This chapter covers the full deployment pipeline—from compiler hardening flags to runtime protections, from container security to monitoring.

This chapter is intentionally generic, but the concrete commands use the Chapter 17 companion service from this repository where that makes verification less ambiguous. When you see `ch17-hardened-server`, substitute your own package or binary name in a different codebase.

## 19.1 Compilation Hardening

### 19.1.1 Release Profile Configuration

```toml
# Cargo.toml
[profile.release]
# Security-relevant settings
overflow-checks = true       # Panic on integer overflow (prevents CWE-190)
lto = true                   # Link-time optimization (removes dead code, reduces attack surface)
codegen-units = 1            # Single codegen unit (better optimization, no parallel shortcuts)
panic = "abort"              # Abort on panic (smaller binary, no unwinding table attack surface)
strip = "symbols"            # Strip debug symbols from release binary
opt-level = "z"              # Optimize for size (smaller attack surface)

# Optional: customize debug info for crash analysis
debug = 1                    # Line tables only (enough for stack traces, no full debug info)
```

### 19.1.2 Linker Hardening Flags

```toml
# .cargo/config.toml (Linux)
[build]
rustflags = [
    # Keep frame pointers for profiling and post-mortem analysis
    "-C", "force-frame-pointers=yes",
    
    # Link-time hardening
    "-C", "link-arg=-Wl,-z,noexecstack",    # Non-executable stack (NX bit)
    "-C", "link-arg=-Wl,-z,relro",          # Partial RELRO (read-only relocations)
    "-C", "link-arg=-Wl,-z,now",            # Full RELRO (resolve all symbols at load)
    
    # Position-independent executable (required for ASLR)
    "-C", "relocation-model=pic",
]

# Stable Rust/Linux already enables PIE, NX, and RELRO for ordinary binaries.
# These extra linker flags are mostly useful when you want the intent to be
# explicit or when you also link C/assembly objects.
#
# Note: For C dependencies compiled via the `cc` crate, set environment variables:
#   CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong"
# These are C compiler flags, not Rust linker flags.
# They apply during compilation of C code, not at link time. On stable Rust,
# stack-smashing protection for Rust code itself is not enabled via these flags.

[target.x86_64-unknown-linux-gnu]
rustflags = [
    "-C", "target-feature=+cet",  # Advanced, target-specific hardware support
]
```

### 19.1.3 Windows-Specific Hardening

```toml
# .cargo/config.toml (Windows)
[build]
rustflags = [
    # Control Flow Guard (CFG)
    "-C", "control-flow-guard=yes",
    
    # Dynamic Base (ASLR)
    "-C", "link-arg=/DYNAMICBASE",
    
    # High Entropy ASLR
    "-C", "link-arg=/HIGHENTROPYVA",
    
    # Data Execution Prevention (DEP/NX)
    "-C", "link-arg=/NXCOMPAT",
]
```

### 19.1.4 Security Comparison: Hardening Technologies

| Protection | What It Prevents | Linux | Windows |
|-----------|-----------------|-------|---------|
| **NX/DEP** | Code execution on stack/heap | Enabled by default; reinforce when linking non-Rust objects | `/NXCOMPAT` |
| **ASLR** | Fixed-address attacks | PIE enabled by default | `/DYNAMICBASE` |
| **Stack canaries** | Stack buffer overflow | `-fstack-protector` for C/C++ code; Rust SSP is nightly-only today | `/GS` for MSVC-compiled C/C++ |
| **RELRO** | GOT overwrite | Full RELRO enabled by default on mainstream targets | N/A (ELF-specific mitigation) |
| **CFG** | Indirect-call hijacking | Target-specific hardware hardening, not a general stable default | `-C control-flow-guard=yes` |
| **Fortify** | glibc buffer overflow | `-D_FORTIFY_SOURCE=2` for C dependencies | N/A |

## 19.2 Container Security

### 19.2.1 Multi-Stage Docker Build

The Dockerfile below uses the Chapter 17 companion service as a real workspace example. If your project is a single crate rather than a workspace, simplify the `COPY` lines accordingly. In a workspace, Cargo validates every member during the dependency-caching stage, so the example copies every member manifest and creates minimal placeholder targets before the first `cargo build`.

```dockerfile
# Dockerfile

# Stage 1: Build
FROM rust:1.85-slim AS builder

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY book-snippets/lib.rs book-snippets/lib.rs
COPY companion/ch10-ffi/Cargo.toml companion/ch10-ffi/Cargo.toml
COPY companion/ch12-networking/Cargo.toml companion/ch12-networking/Cargo.toml
COPY companion/ch17-hardened-server/Cargo.toml companion/ch17-hardened-server/Cargo.toml
COPY companion/ch19-hardening/Cargo.toml companion/ch19-hardening/Cargo.toml
RUN mkdir -p companion/ch10-ffi/src \
             companion/ch12-networking/src \
             companion/ch17-hardened-server/src \
             companion/ch19-hardening/src \
 && printf "" > companion/ch10-ffi/src/lib.rs \
 && printf "" > companion/ch12-networking/src/lib.rs \
 && printf "" > companion/ch17-hardened-server/src/lib.rs \
 && printf "fn main() {}\n" > companion/ch17-hardened-server/src/main.rs \
 && printf "" > companion/ch19-hardening/src/lib.rs
RUN cargo build --locked --release -p ch17-hardened-server

# Build actual application
COPY companion/ch17-hardened-server ./companion/ch17-hardened-server
RUN cargo build --locked --release -p ch17-hardened-server

# Stage 2: Minimal runtime
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy only the binary
COPY --from=builder /app/target/release/ch17-hardened-server /usr/local/bin/secure-server

# Run as non-root user (distroless/cc nonroot already does this)
USER nonroot:nonroot

EXPOSE 8443

ENTRYPOINT ["secure-server"]
```

🔒 **Security features of this Dockerfile**:
1. **Multi-stage build**: Build tools, source code, and build-time dependencies are not in the final image.
2. **Distroless base**: No shell, no package manager, minimal attack surface.
3. **Non-root user**: Runs as `nonroot` by default.
4. **No unnecessary files**: Only the compiled binary is copied.

### 19.2.2 Container Hardening with Podman/Docker

```yaml
# docker-compose.yml (or podman kube)
services:
  secure-server:
    image: secure-server:latest
    security_opt:
      - no-new-privileges:true     # Prevent privilege escalation
    cap_drop:
      - ALL                         # Drop all capabilities
    read_only: true                 # Read-only filesystem
    tmpfs:
      - /tmp:noexec,nosuid,size=100m  # Writable temp with restrictions
    volumes:
      - ./certs:/run/certs:ro
    ports:
      - "8443:8443"
    environment:
      - RUST_LOG=info
      - TLS_CERT_PATH=/run/certs/server.crt
      - TLS_KEY_PATH=/run/certs/server.key
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 512M             # Prevent resource exhaustion
        reservations:
          cpus: "0.5"
          memory: 128M
```

Only add `seccomp:seccomp-profile.json` after you have produced a profile that is strictly tighter than the runtime default for the exact image you deploy.

No capability is added here because the sample server binds to port 8443, which is not a privileged port on Linux. Only add `NET_BIND_SERVICE` if you must bind below 1024.

Enable `RUST_BACKTRACE=1` only during controlled debugging sessions, not as a standing production setting.

### 19.2.3 Seccomp Profile

The safest default is to keep Docker or Podman's built-in seccomp profile. Do **not** replace it with a short denylist: that often weakens isolation by allowing more syscalls than the runtime would have permitted by default.

When you do need a custom profile, derive it from the runtime default profile for the exact engine version you deploy, trace the syscalls your service actually needs, and then tighten from there. The example below is an **illustrative excerpt**, not a complete profile:

```jsonc
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
        {
            "comment": "Excerpt only. Start from the runtime default profile, then trim to the exact syscall set your service uses.",
            "names": [
                "accept4", "bind", "brk", "clock_gettime",
                "close", "epoll_create1", "epoll_ctl", "epoll_pwait",
                "exit", "exit_group", "futex", "getrandom",
                "listen", "madvise", "mmap", "mprotect",
                "munmap", "nanosleep", "read", "recvfrom",
                "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt",
                "socket", "write"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
```

Treat this as process guidance, not a copy-paste policy. A production seccomp allowlist must be derived from the exact binary, libc, and container runtime you deploy. If you are not ready to maintain a custom allowlist, keeping the runtime default profile is safer than shipping an incomplete one.

🔒 **Security impact**: Seccomp restricts the system calls available to the process. Even if an attacker achieves arbitrary code execution, they are limited to the syscalls you leave available—dramatically reducing what they can do.

## 19.3 Binary Hardening Verification

After building, verify the hardening was applied:

### Linux (checksec)

```bash
APP_BIN=ch17-hardened-server

# Install checksec
sudo apt install checksec

# Verify binary hardening
checksec --file=target/release/$APP_BIN

# Expected output on a stable pure-Rust build:
# RELRO        STACK CANARY  NX         PIE       RPATH     RUNPATH   Symbols
# Full RELRO   No canary found NX enabled PIE enabled No RPATH No RUNPATH No Symbols
#
# If you compile C/C++ objects with stack protectors, or build Rust with
# nightly-only SSP support, the canary column may instead show "Canary found".
```

### Manual Verification

```bash
# Check for NX (non-executable stack)
readelf -l target/release/$APP_BIN | grep GNU_STACK
# Should show: RWE → RW (no execute)

# Check for PIE (position-independent)
readelf -h target/release/$APP_BIN | grep Type
# Should show: DYN (Position-Independent Executable)

# Check for GNU_RELRO segment (presence only)
readelf -l target/release/$APP_BIN | grep RELRO
# Should show: GNU_RELRO

# Check for full RELRO (eager binding)
readelf -d target/release/$APP_BIN | grep BIND_NOW
# Should show: BIND_NOW

# Check symbol stripping
file target/release/$APP_BIN
# Should show: "stripped"
```

## 19.4 Runtime Monitoring and Observability

### 19.4.1 Structured Logging with the `tracing` Crate

For production security monitoring, the `tracing` crate provides structured, async-aware logging with spans that track request context. It is far more powerful than the basic `log` crate for security observability:

```toml
# Cargo.toml
[dependencies]
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::tracing as tracing;
# use rust_secure_systems_book::deps::tracing_subscriber as tracing_subscriber;
// src/logging.rs
use std::sync::Once;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

static LOGGING_INIT: Once = Once::new();

/// Initialize structured JSON logging for production
pub fn init_logging() {
    LOGGING_INIT.call_once(|| {
        let subscriber = fmt()
            .json()                           // Structured JSON output for log aggregation
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info"))
            )
            .with_target(true)                // Include module path
            .with_thread_ids(true)            // Identify threads
            .with_file(true)                  // Source file
            .with_line_number(true)           // Line number
            .finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// Log a security-relevant event with structured fields
pub fn log_security_event(
    event_type: &str,
    severity: SecurityEventSeverity,
    source_ip: Option<std::net::IpAddr>,
    user_id: Option<u64>,
    details: &str,
) {
    match severity {
        SecurityEventSeverity::Info => {
            info!(
                event_type,
                source_ip = ?source_ip,
                user_id = ?user_id,
                details,
                "Security event"
            );
        }
        SecurityEventSeverity::Warning => {
            warn!(
                event_type,
                source_ip = ?source_ip,
                user_id = ?user_id,
                details,
                "Security event"
            );
        }
        SecurityEventSeverity::Critical => {
            error!(
                event_type,
                source_ip = ?source_ip,
                user_id = ?user_id,
                details,
                "Security event"
            );
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SecurityEventSeverity {
    Info,
    Warning,
    Critical,
}
```

Initialize the subscriber once during startup. Do not call logging initialization from request paths, and do not assume repeated `.init()` calls are harmless in tests or embedded runtimes.

### 19.4.2 Request Tracing with Spans

Spans attach context to all log events within a request, enabling you to trace a request from acceptance through processing to response:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::companion::ch19_hardening as ch19_hardening;
# use rust_secure_systems_book::deps::tokio as tokio;
# use rust_secure_systems_book::deps::tracing as tracing;
# use ch19_hardening::logging::{log_security_event, SecurityEventSeverity};
use tracing::{instrument, info_span, Instrument};
use std::net::SocketAddr;

# fn generate_connection_id() -> u64 { 1 }
# async fn read_message(_stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
#     Ok(b"ping".to_vec())
# }
# async fn process_message(message: &[u8]) -> std::io::Result<Vec<u8>> {
#     Ok(message.to_vec())
# }
# async fn write_response(
#     _stream: &mut tokio::net::TcpStream,
#     _response: &[u8],
# ) -> std::io::Result<()> {
#     Ok(())
# }

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a span for this connection with identifying fields
    let span = info_span!(
        "connection",
        peer_addr = %addr,
        connection_id = %generate_connection_id(),
    );
    
    async move {
        tracing::info!("Connection accepted");
        
        // All log events inside this block include peer_addr and connection_id
        loop {
            let message = read_message(&mut stream).await?;
            tracing::info!(message_size = message.len(), "Message received");
            
            match process_message(&message).await {
                Ok(response) => {
                    write_response(&mut stream, &response).await?;
                    tracing::info!(response_size = response.len(), "Response sent");
                }
                Err(e) => {
                    // Security events are automatically associated with this connection
                    log_security_event(
                        "invalid_input",
                        SecurityEventSeverity::Warning,
                        Some(addr.ip()),
                        None,
                        &format!("Message rejected: {}", e),
                    );
                    tracing::warn!(error = %e, "Message processing failed");
                    break;
                }
            }
        }
        
        tracing::info!("Connection closed");
        Ok(())
    }.instrument(span).await
}
```

🔒 **Security benefits of structured tracing**:
1. **Correlation**: Every event is tagged with connection ID, peer address, and user ID, enabling post-incident analysis.
2. **Machine-readable**: JSON output integrates with SIEM systems (Splunk, ELK, Datadog) for automated alerting.
3. **Contextual spans**: A security event in a handler automatically includes the full request context—no manual threading of parameters.
4. **Audit trail**: Structured logs serve as an audit trail for compliance (SOC 2, PCI-DSS).

⚠️ **Critical rule**: Never log secrets. Add fields to the deny list:

```rust
// Alternative: simply never include secrets in span fields or event arguments.
// If you must log a field that sometimes contains secrets, mask it:
fn mask_token(token: &str) -> String {
    let len = token.chars().count();
    if len > 8 {
        let prefix: String = token.chars().take(4).collect();
        let suffix: String = token.chars().skip(len - 4).collect();
        format!("{prefix}****{suffix}")
    } else {
        "****".to_string()
    }
}
```

Keep the masking logic character-aware so valid UTF-8 tokens cannot panic the logging path.

### 19.4.3 Security Event Taxonomy

Define a consistent set of security event types across your application for reliable alerting:

```rust
/// Security event types for consistent logging and alerting
pub mod security_events {
    // Authentication events
    pub const AUTH_SUCCESS: &str = "auth.success";
    pub const AUTH_FAILURE: &str = "auth.failure";
    pub const AUTH_LOCKOUT: &str = "auth.lockout";
    pub const AUTH_TOKEN_REFRESH: &str = "auth.token_refresh";
    
    // Authorization events
    pub const ACCESS_GRANTED: &str = "access.granted";
    pub const ACCESS_DENIED: &str = "access.denied";
    pub const PRIVILEGE_ESCALATION_ATTEMPT: &str = "access.privilege_escalation";
    
    // Input validation events
    pub const INPUT_REJECTED: &str = "input.rejected";
    pub const INPUT_SIZE_EXCEEDED: &str = "input.size_exceeded";
    pub const MALFORMED_REQUEST: &str = "input.malformed";
    
    // Rate limiting
    pub const RATE_LIMIT_EXCEEDED: &str = "rate_limit.exceeded";
    pub const CONNECTION_LIMIT_EXCEEDED: &str = "rate_limit.connections";
    
    // TLS/cryptography
    pub const TLS_HANDSHAKE_FAILED: &str = "tls.handshake_failed";
    pub const TLS_CERTIFICATE_INVALID: &str = "tls.cert_invalid";
    pub const CRYPTO_OPERATION_FAILED: &str = "crypto.operation_failed";
    
    // Resource exhaustion
    pub const MEMORY_PRESSURE: &str = "resource.memory_pressure";
    pub const TASK_TIMEOUT: &str = "resource.task_timeout";
}
```

### 19.4.4 Health Checks and Metrics

```rust
// src/metrics.rs
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
        ServerMetrics {
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

pub struct MetricsSnapshot {
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub messages_processed: u64,
    pub errors: u64,
    pub auth_failures: u64,
    pub rate_limits_triggered: u64,
}
```

## 19.5 Secret Management in Production

### 19.5.1 Environment Variables

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::companion::ch19_hardening as ch19_hardening;
# use ch19_hardening::secrets::SecretError;
# use rust_secure_systems_book::deps::hex as hex;
# use rust_secure_systems_book::deps::zeroize as zeroize;
use std::env;
use zeroize::Zeroize;

fn load_secret(key: &str) -> Result<Vec<u8>, SecretError> {
    let mut value = env::var(key).map_err(|_| SecretError::NotFound(key.to_string()))?;
    let decoded = hex::decode(&value).map_err(|_| SecretError::InvalidFormat);
    value.zeroize();
    decoded
}
```

The companion implementation uses this exact pattern in `companion/ch19-hardening/src/secrets.rs`, so the secret buffer is zeroized on both success and decode failure.

⚠️ **Limitation**: Environment variables are visible in `/proc/<pid>/environ` on Linux and can leak through process listing. In Edition 2024, mutating the process environment with `std::env::set_var` or `std::env::remove_var` is `unsafe`, so "read then delete" is not a robust secret-management pattern for multithreaded services. Prefer dedicated secret management.

### 19.5.2 Files with Restricted Permissions

```rust,no_run
# extern crate rust_secure_systems_book;
use std::fs::File;
use std::io::Read;
# use rust_secure_systems_book::companion::ch19_hardening as ch19_hardening;
# use ch19_hardening::secrets::SecretError;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn load_secret_from_file(path: &str) -> Result<Vec<u8>, SecretError> {
    let mut file = File::open(path)?;

    #[cfg(unix)]
    {
        // Validate the already-open handle to avoid a path-swap race.
        let metadata = file.metadata()?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(SecretError::InsecurePermissions {
                path: path.to_string(),
                mode: format!("{:o}", mode & 0o777),
            });
        }
    }

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}
```

This pattern avoids a TOCTOU race on Unix by validating permissions on the same opened file handle that is later read. On Windows, `std` does not expose DACL inspection, so prefer Credential Manager, DPAPI, or a dedicated secret store, or validate ACLs with platform APIs before relying on raw secret files.

🔒 **Security practice**: On Unix, secret files should usually be mode `0400` or `0600` and owned by the service user.

### 19.5.3 Vault Integration (HashiCorp Vault, AWS Secrets Manager)

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::companion::ch19_hardening as ch19_hardening;
# use ch19_hardening::secrets::SecretError;
use std::future::Future;

async fn load_from_vault<F, Fut>(
    secret_id: &str,
    fetch_secret: F,
) -> Result<Vec<u8>, SecretError>
where
    F: FnOnce(&str) -> Fut,
    Fut: Future<Output = Result<Option<String>, SecretError>>,
{
    let secret_string = fetch_secret(secret_id)
        .await?
        .ok_or_else(|| SecretError::NotFound(secret_id.to_string()))?;

    Ok(secret_string.into_bytes())
}
```

## 19.6 OS-Level Hardening

### 19.6.1 systemd Service Hardening

For Linux deployments using systemd, apply security directives to restrict the service at the OS level:

```ini
# /etc/systemd/system/secure-server.service
[Unit]
Description=Secure Rust Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/secure-server
Restart=on-failure
RestartSec=5

# Run as a dedicated non-root user
User=secure-server
Group=secure-server

# Sandbox directives
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes

# Restrict filesystem access
ReadWritePaths=/var/lib/secure-server /var/log/secure-server
ReadOnlyPaths=/etc/secure-server/config.toml

# Restrict address families used by the service
# This does not restrict specific port numbers.
# Requires systemd 235+
RestrictAddressFamilies=AF_INET AF_INET6

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@mount @privileged @reboot @swap
SystemCallArchitectures=native

# Resource limits
LimitNOFILE=4096
MemoryMax=512M
TasksMax=50
CPUWeight=50

# Environment
Environment=RUST_LOG=info
Environment=TLS_CERT_PATH=/etc/secure-server/server.crt
Environment=TLS_KEY_PATH=/etc/secure-server/server.key

[Install]
WantedBy=multi-user.target
```

If you need to restrict the service to specific listen ports, combine
`RestrictAddressFamilies=` with socket activation, container/network policy, or
host firewall rules. Address-family filtering alone is not a port-level control.

🔒 **Security features**:
1. **NoNewPrivileges**: Prevents the process from gaining additional privileges via setuid/setgid.
2. **ProtectSystem=strict**: Makes the entire filesystem read-only except explicitly listed paths.
3. **PrivateTmp**: Gives the service its own private `/tmp` directory.
4. **RestrictAddressFamilies**: Limits the service to IPv4/IPv6 sockets, reducing the reachable kernel API surface.
5. **SystemCallFilter**: Restricts system calls — even arbitrary code execution is limited.
6. **MemoryMax/TasksMax**: Prevents resource exhaustion from affecting the rest of the system.

Verify the hardening is effective:

```bash
# Check the security properties of a running service
systemd-analyze security secure-server

# Expected output:
# NAME                                  DESCRIPTION
 # ...
# Overall exposure level for secure-server: 0.2 LOW
```

### 19.6.2 AppArmor / SELinux Profiles

For additional Mandatory Access Control (MAC), create an AppArmor profile:

```bash
# Generate a baseline profile
aa-genprof /usr/local/bin/secure-server

# The profile restricts:
# - Which files can be read/written
# - Which network ports can be bound/connected
# - Which capabilities can be used
# - Which syscalls are permitted
```

An example AppArmor profile:

```ini
#include <tunables/global>
/usr/local/bin/secure-server {
  #include <abstractions/base>
  
  # Network: allow IPv4/IPv6 TCP sockets.
  # Use host firewall rules, socket activation, or container policy to pin this
  # to port 8443.
  network inet tcp,
  network inet6 tcp,
  
  # Read config and certs
  /etc/secure-server/* r,
  
  # Write logs
  /var/log/secure-server/* rw,
  
  # Data directory
  /var/lib/secure-server/** rw,
  
  # Deny everything else
  deny /** w,
  deny /** l,
}
```

🔒 **Security practice**: Use at least one layer of MAC (systemd sandboxing, AppArmor, or SELinux) for any production Rust service. Defense in depth — even if the application has a memory corruption vulnerability in `unsafe` code, the OS-level restrictions limit what an attacker can do.

## 19.7 Release Checklist

Before deploying a Rust application to production:

### Build Verification
- [ ] Build with `cargo build --release` using hardened flags
- [ ] Verify binary hardening (checksec: RELRO, NX, PIE, and canary status for any C/C++ objects)
- [ ] Run full test suite (`cargo test --all-features`)
- [ ] Run clippy with security lints (`cargo clippy -- -W clippy::unwrap_used`)
- [ ] Run `cargo audit` — no known vulnerabilities
- [ ] Run `cargo deny check` — all policies pass
- [ ] Run fuzzing targets (at least 1 hour each)

### Binary Verification
- [ ] Binary is stripped (no debug symbols in production)
- [ ] Binary size is reasonable (no unexpectedly large binary)
- [ ] `overflow-checks = true` enabled in release profile
- [ ] Static linking for musl (fully static binary) or verified shared library versions

### Deployment Verification
- [ ] Container uses distroless or minimal base image
- [ ] Runs as non-root user
- [ ] Read-only filesystem with writable tmpfs
- [ ] Seccomp profile applied
- [ ] All capabilities dropped except required ones
- [ ] Resource limits set (CPU, memory)

### Runtime Verification
- [ ] Structured logging enabled
- [ ] Security metrics exported (prometheus, cloudwatch, etc.)
- [ ] Health check endpoint available
- [ ] Alerting configured for auth failures, rate limits, errors
- [ ] TLS certificates valid and monitored for expiry

### Documentation
- [ ] Security policy documented (`SECURITY.md`)
- [ ] Threat model documented
- [ ] Incident response plan in place
- [ ] Dependency list (SBOM) generated and archived

## 19.8 Summary

- Enable all available stable binary hardening: NX, ASLR, RELRO, CFG where supported, and stack canaries for any C/C++ objects you compile.
- Use multi-stage Docker builds with distroless base images.
- Run as non-root with minimal capabilities and seccomp filtering.
- Verify hardening with `checksec` or manual checks.
- Load secrets from vaults or permission-restricted files, never hardcode.
- **Use structured tracing** (`tracing` crate with JSON output) for security event logging, with consistent event types and spans that carry request context.
- Integrate logs with a SIEM for automated alerting on security events.
- Apply OS-level hardening: systemd sandboxing, AppArmor/SELinux, resource limits.
- Follow the release checklist for every production deployment.

This concludes the book. You now have the knowledge and practical skills to write secure systems software in Rust—from the language fundamentals through production deployment. The security landscape evolves constantly; continue learning, continue auditing, and continue building systems that are secure by design.

## 19.9 Exercises

1. **Hardened Build Pipeline**: Set up a complete hardened build pipeline for one of the projects from Chapters 17 or 18: configure `.cargo/config.toml` with all hardening flags, verify the binary with `checksec` (Linux) or `Dumpbin /headers` (Windows), build a distroless Docker image, and run it with all capabilities dropped. Document each step and its security benefit.

2. **systemd Service Unit**: Write a systemd service unit for the Chapter 17 TCP server with all the sandboxing directives from §19.6.1. Deploy it on a Linux VM, run `systemd-analyze security` to check the exposure score, and attempt an escape (e.g., try to write to `/etc`, try to load a kernel module). Verify each attempt is blocked.

3. **Incident Response Drill**: Simulate a security incident: deliberately introduce a vulnerability into one of the chapter projects (e.g., a `panic!` in a network handler, or a logging statement that leaks a secret). Deploy the service, trigger the vulnerability, and use the structured logs and metrics to: (a) detect the incident, (b) identify the affected component, (c) trace the timeline. Write an incident report.

---

## Appendix A: Recommended Reading

- **The Rust Programming Language** (Klabnik & Nichols): Official Rust book
- **Rust for Rustaceans** (Jon Gjengset): Advanced Rust patterns
- **Rust in Action** (Tim McNamara): Systems programming with Rust
- **The CERT C Secure Coding Standard**: Security patterns that apply universally
- **OWASP Application Security Verification Standard (ASVS)**: Security requirements
- **MITRE CWE Database**: Comprehensive weakness enumeration

## Appendix B: Essential Crates for Security

| Crate | Purpose | Trust Level |
|-------|---------|-------------|
| `ring` | Cryptography | High (BoringSSL-derived, audited) |
| `rustls` | TLS | High (memory-safe, audited) |
| `serde` | Serialization | High (rust-lang org) |
| `zeroize` | Memory wiping | High (widely audited) |
| `secrecy` | Secret encapsulation | High |
| `thiserror` | Error types | High |
| `proptest` | Property testing | High |
| `tokio` | Async runtime | High |
| `tracing` | Structured logging | High |

## Appendix C: Security Audit Resources

- **RustSec Advisory Database**: https://rustsec.org/
- **Clippy Lint List**: https://rust-lang.github.io/rust-clippy/master/
- **Miri Documentation**: https://github.com/rust-lang/miri
- **cargo-geiger**: https://github.com/rust-secure-code/cargo-geiger
- **cargo-vet**: https://mozilla.github.io/cargo-vet/
