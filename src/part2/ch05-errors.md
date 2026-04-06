# Chapter 5 — Error Handling Without Exceptions

> *"Errors are not exceptional. They are a normal part of system operation."*

Rust's approach to error handling is fundamentally different from C's return codes, C++'s exceptions, and Go's multiple return values. It leverages the type system to make error handling **explicit**, **type-safe**, and **impossible to forget**. For security developers, this matters because unhandled or improperly handled errors are a leading cause of vulnerabilities—from ignoring return values to catching the wrong exception type.

## 5.1 The Error Handling Landscape

| Language | Mechanism | Can You Forget to Handle? |
|----------|-----------|--------------------------|
| C | Return codes, `errno` | ✅ Yes — very common |
| C++ | Exceptions | ✅ Yes — catch may miss types |
| Go | Multiple return values | ⚠️ Possible (but `err` is visible) |
| Java | Checked exceptions | ⚠️ Partially enforced |
| Rust | `Result<T, E>` + `?` | ❌ No — compiler enforces handling |

## 5.2 `Result<T, E>` in Depth

```rust
enum Result<T, E> {
    Ok(T),   // Success, contains a value of type T
    Err(E),  // Failure, contains an error of type E
}
```

### 5.2.1 Creating Results

```rust
use std::io;

fn read_bytes(file: &mut impl io::Read, count: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; count];
    match file.read_exact(&mut buffer) {
        Ok(()) => Ok(buffer),
        Err(e) => Err(e),  // Propagate the I/O error
    }
}
```

`io::Result<T>` is a type alias for `Result<T, io::Error>`.

### 5.2.2 The `?` Operator

The `?` operator is the idiomatic way to propagate errors. It means: "If this result is `Ok`, unwrap the value. If it's `Err`, return it from the current function immediately."

```rust
use std::fs::File;
use std::io::{self, Read};

fn read_config(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;        // ? propagates io::Error
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;     // ? propagates io::Error
    Ok(contents)
}

#[derive(Debug)]
struct Config;

#[derive(Debug)]
enum ConfigError {
    Io(io::Error),
    InvalidFormat,
}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn parse_config(raw: &str) -> Result<Config, ConfigError> {
    if raw.trim().is_empty() {
        Err(ConfigError::InvalidFormat)
    } else {
        Ok(Config)
    }
}

fn load_and_parse_config(path: &str) -> Result<Config, ConfigError> {
    let raw = read_config(path)?;             // ? converts io::Error via From trait
    parse_config(&raw)
}
```

🔒 **Security impact**: The `?` operator ensures no error is silently dropped. Every fallible operation must either be handled locally or explicitly propagated.

### 5.2.3 Error Conversion with `From`

The `?` operator automatically converts errors using the `From` trait:

```rust
use std::io;
use std::num::ParseIntError;

#[derive(Debug)]
enum AppError {
    Io(io::Error),
    Parse(ParseIntError),
    InvalidData(String),
}

impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<ParseIntError> for AppError {
    fn from(e: ParseIntError) -> Self {
        AppError::Parse(e)
    }
}

fn parse_port_number(s: &str) -> Result<u16, AppError> {
    let port: u32 = s.parse()?;           // ParseIntError → AppError via From
    if port > 65535 {
        return Err(AppError::InvalidData(format!("Port {} out of range", port)));
    }
    Ok(port as u16)
}
```

## 5.3 Custom Error Types

For security-critical applications, define structured error types:

```rust
use std::fmt;

/// Security-relevant error conditions
#[derive(Debug)]
pub enum SecurityError {
    /// Authentication failed
    AuthenticationFailed { username: String, reason: String },
    /// Authorization denied
    AccessDenied { user_id: u64, resource: String, required_role: String },
    /// Input validation failure
    ValidationFailed { field: String, value: String, constraint: String },
    /// Rate limit exceeded
    RateLimited { client_ip: std::net::IpAddr, retry_after: std::time::Duration },
    /// Cryptographic operation failed
    CryptoError(String),
    /// Session expired or invalid
    InvalidSession(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::AuthenticationFailed { username, reason } => {
                write!(f, "Authentication failed for '{}': {}", username, reason)
            }
            SecurityError::AccessDenied { user_id, resource, required_role } => {
                write!(f, "User {} denied access to '{}' (requires {})", 
                       user_id, resource, required_role)
            }
            SecurityError::ValidationFailed { field, value, constraint } => {
                write!(f, "Validation failed for '{}': {} (constraint: {})", 
                       field, value, constraint)
            }
            SecurityError::RateLimited { client_ip, retry_after } => {
                write!(f, "Rate limited {}: retry after {:?}", client_ip, retry_after)
            }
            SecurityError::CryptoError(msg) => {
                write!(f, "Cryptographic error: {}", msg)
            }
            SecurityError::InvalidSession(msg) => {
                write!(f, "Invalid session: {}", msg)
            }
        }
    }
}

impl std::error::Error for SecurityError {}
```

🔒 **Security practice**: Never include sensitive data (passwords, tokens, raw keys) in error messages. Error strings may be logged, displayed, or leaked to attackers. Note in the example above, `username` is logged but passwords are never included.

## 5.4 The `thiserror` and `anyhow` Crates

### `thiserror` — Derive Error for Libraries

```rust,no_run
# extern crate rust_secure_systems_book as thiserror;
// Add to Cargo.toml: thiserror = "2"
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("handshake failed: {reason}")]
    HandshakeFailed { reason: String },

    #[error("certificate validation failed: {0}")]
    CertificateInvalid(String),

    #[error("MAC verification failed")]
    MacVerificationFailed,  // No details leaked—intentional for crypto errors

    #[error("IO error")]
    Io(#[from] std::io::Error),
}
```

🔒 **Crypto error best practice**: Cryptographic errors should be **generic**. Do not distinguish between "invalid padding" and "invalid MAC" in error messages visible to the caller. This prevents oracle attacks (e.g., padding oracle, MAC oracle).

### `anyhow` — Flexible Errors for Applications

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::anyhow as anyhow;
// Add to Cargo.toml: anyhow = "1"
use anyhow::{Context, Result};

fn load_key(path: &str) -> Result<Vec<u8>> {
    let key = std::fs::read(path)
        .context("failed to read configured key file")?;
    Ok(key)
}
```

If the path itself is sensitive, do not include it in user-facing error context. Log the path on a trusted internal channel if you need it for debugging, and return a generic external error instead of exposing filesystem layout.

## 5.5 Panic vs. Result

Rust has two error categories:

| Category | Mechanism | Recoverable? | When to Use |
|----------|-----------|-------------|-------------|
| Recoverable | `Result<T, E>` | Yes | All expected failure modes |
| Unrecoverable | `panic!` | No (by default) | Bugs, contract violations |

### When to Panic

In security-critical code, panic only for **bugs**, not for expected failure modes:

```rust
fn decode_port(input: &str) -> Result<u16, std::num::ParseIntError> {
    // This is an expected failure → use Result
    // BAD: input.parse::<u16>().unwrap()
    // STILL BAD: input.parse::<u16>().expect("invalid port") — still panics!
    // BEST: return Result
    input.parse()
}

fn hex_nibble(c: char) -> u8 {
    match c {
        '0'..='9' => c as u8 - b'0',
        'a'..='f' => c as u8 - b'a' + 10,
        'A'..='F' => c as u8 - b'A' + 10,
        _ => panic!("internal invariant violated: caller passed non-hex input"),
    }
}
```

⚠️ **Security concern**: In server applications, a panic unwinds the stack and may leave data in an inconsistent state. Do not use panics for attacker-controlled input such as packet lengths or request indexes; return a `Result` instead. Use `panic = "abort"` in `Cargo.toml` for a cleaner failure mode, or use `std::panic::catch_unwind` at FFI boundaries in builds that keep `panic = "unwind"`.

### Catching Panics at FFI Boundaries

```rust
use std::panic;

fn process_data(slice: &[u8]) -> Result<i32, ()> {
    Ok(slice.len() as i32)
}

extern "C" fn exported_function(data: *const u8, len: usize) -> i32 {
    if data.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(|| {
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        process_data(slice)
    });
    
    match result {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => -1,      // Application error
        Err(_) => -2,          // Panic occurred
    }
}
```

⚠️ **Profile interaction**: `catch_unwind` only catches unwinding panics. If your release profile sets `panic = "abort"`, the process aborts before this wrapper can recover. For FFI-facing libraries, either keep exported entry points panic-free or ship them in an unwind-enabled profile.

🔒 **Security pattern**: Wrap Rust functions called from C with `catch_unwind` when the ABI must survive panics and the build uses `panic = "unwind"`. A Rust panic that crosses an FFI boundary is undefined behavior.

## 5.6 Error Handling Patterns for Secure Code

### 5.6.1 Fail Fast, Fail Explicitly

```rust
# #[derive(Debug)]
# enum SecurityError {
#     AuthenticationFailed { username: String, reason: String },
#     AccessDenied { user_id: u64, resource: String, required_role: String },
#     ValidationFailed { field: String, value: String, constraint: String },
# }
#
#[derive(Debug)]
struct Credentials;

#[derive(Debug)]
struct Request;

#[derive(Debug)]
struct Response;

impl Request {
    fn credentials(&self) -> Credentials {
        Credentials
    }

    fn username(&self) -> &str {
        "alice"
    }

    fn resource(&self) -> &str {
        "/secure"
    }

    fn body(&self) -> &[u8] {
        b"payload"
    }
}

impl Response {
    fn success(_value: String) -> Self {
        Response
    }
}

#[derive(Debug)]
struct User {
    id: u64,
}

impl User {
    fn id(&self) -> u64 {
        self.id
    }
}

fn process_request(req: &Request) -> Result<Response, SecurityError> {
    // Validate early, reject early
    let user = authenticate(req.credentials())
        .map_err(|_| SecurityError::AuthenticationFailed {
            username: req.username().to_string(),
            reason: "Invalid credentials".to_string(),
        })?;
    
    authorize(&user, req.resource())
        .map_err(|_| SecurityError::AccessDenied {
            user_id: user.id(),
            resource: req.resource().to_string(),
            required_role: "read".to_string(),
        })?;
    
    let validated = validate_input(req.body())?;
    let result = execute(&user, &validated)?;
    Ok(Response::success(result))
}

fn authenticate(_credentials: Credentials) -> Result<User, ()> {
    Ok(User { id: 7 })
}

fn authorize(_user: &User, _resource: &str) -> Result<(), ()> {
    Ok(())
}

fn validate_input(body: &[u8]) -> Result<Vec<u8>, SecurityError> {
    if body.is_empty() {
        Err(SecurityError::ValidationFailed {
            field: "body".to_string(),
            value: String::new(),
            constraint: "must not be empty".to_string(),
        })
    } else {
        Ok(body.to_vec())
    }
}

fn execute(_user: &User, _validated: &[u8]) -> Result<String, SecurityError> {
    Ok("ok".to_string())
}
```

### 5.6.2 Never Use `unwrap()` in Production Security Code

```rust
#[derive(Debug)]
enum SecurityError {
    ValidationFailed { field: String, value: String, constraint: String },
}

fn parse_env_port(env_var: String) -> Result<u16, SecurityError> {
    // BAD: env_var.parse::<u16>().unwrap()

    // GOOD: explicit error handling
    env_var.parse()
        .map_err(|_| SecurityError::ValidationFailed {
            field: "PORT".to_string(),
            value: env_var.clone(),
            constraint: "must be a valid u16".to_string(),
        })
}
```

### 5.6.3 Sanitize Error Messages for External Consumers

```rust
# #[derive(Debug)]
# enum SecurityError {
#     AuthenticationFailed { username: String, reason: String },
#     AccessDenied { user_id: u64, resource: String, required_role: String },
#     ValidationFailed { field: String, value: String, constraint: String },
# }
#
mod log {
    pub fn warn(_message: &str) {}
    pub fn error(_message: &str) {}
}

#[derive(Debug)]
struct Request;

#[derive(Debug)]
struct Response;

impl Request {
    fn remote_addr(&self) -> &str {
        "127.0.0.1"
    }
}

impl Response {
    fn unauthorized(_message: &str) -> Self {
        Response
    }

    fn forbidden(_message: &str) -> Self {
        Response
    }

    fn bad_request(_message: &str) -> Self {
        Response
    }

    fn internal_error(_message: &str) -> Self {
        Response
    }
}

fn process_request(_req: &Request) -> Result<Response, SecurityError> {
    Err(SecurityError::AuthenticationFailed {
        username: "alice".to_string(),
        reason: "Invalid credentials".to_string(),
    })
}

fn handle_request(req: Request) -> Response {
    match process_request(&req) {
        Ok(response) => response,
        Err(SecurityError::AuthenticationFailed { .. }) => {
            // Generic message to client, detailed message to log
            log::warn(&format!("Authentication failed from {}", req.remote_addr()));
            Response::unauthorized("Invalid credentials")
        }
        Err(SecurityError::AccessDenied { .. }) => {
            Response::forbidden("Access denied")
        }
        Err(SecurityError::ValidationFailed { .. }) => {
            Response::bad_request("Invalid input")
        }
        Err(e) => {
            // Never expose internal errors to clients
            log::error(&format!("Internal error: {:?}", e));
            Response::internal_error("Internal server error")
        }
    }
}
```

🔒 **Security impact**: Never leak internal error details (stack traces, file paths, SQL queries) to external clients. Use detailed logging server-side and generic responses externally. This prevents information disclosure (CWE-209).

## 5.7 Summary

- `Result<T, E>` makes error handling explicit and compiler-enforced.
- The `?` operator provides ergonomic error propagation with automatic type conversion.
- Define structured error types for security-relevant failure modes.
- Panic only for bugs, never for expected failures.
- Use `catch_unwind` at FFI boundaries to prevent undefined behavior.
- Never use `unwrap()` in security-critical code paths.
- Sanitize error messages before exposing them externally.

In the next chapter, we explore Rust's concurrency model—how the ownership system extends to prevent data races and how to write concurrent code that is safe by construction.

## 5.8 Exercises

1. **Custom Error Type**: Define a `ParseError` enum with at least four variants using `thiserror`. Implement `From<std::io::Error>` and `From<std::num::ParseIntError>` for it. Write a function that uses the `?` operator with both underlying error types and verify the automatic conversion works.

2. **Error Sanitization**: Write a function `handle_request()` that returns `Result<Response, AppError>` where `AppError` contains sensitive internal details. Then write a `to_client_response()` method that converts the error into a generic user-facing message (no file paths, no SQL, no stack traces). Write tests verifying that sensitive fields never appear in the client-facing output.

3. **Remove All Unwrap**: Take an existing Rust project or code sample and run `cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used`. Refactor every flagged call to use proper `match`, `map_err`, or the `?` operator. Ensure all tests still pass.

4. **Panic Boundary**: Write an FFI-exported function that calls an internal function which might panic. Wrap it with `std::panic::catch_unwind` and return appropriate error codes for success, application error, and panic. Test the panic path by intentionally dividing by zero in the inner function.
