# Chapter 7 — Input Validation and Data Sanitization

> *"All input is evil until proven otherwise."*

Input validation is the cornerstone of secure software. Every major vulnerability class—injection, buffer overflow, path traversal, XSS—traces back to improperly validated input. As a security developer, you know that the attack surface of any system is defined by the inputs it processes.

Rust's type system gives you a significant advantage: many validation checks can be enforced at compile time rather than runtime. When that's not possible, Rust's expressive pattern matching and zero-cost abstractions make runtime validation both thorough and ergonomic.

## 7.1 The Validation Pyramid

Secure input handling follows three layers:

```text
┌─────────────────────────┐
│   Type-Level Validation  │  ← Compile-time (strongest)
├─────────────────────────┤
│   Parse, Don't Validate  │  ← Runtime but structural
├─────────────────────────┤
│   Sanitization           │  ← Runtime, contextual
└─────────────────────────┘
```

### Layer 1: Type-Level Validation

Use Rust's type system to make invalid states unrepresentable:

```rust
// BAD: a raw string can contain anything
fn connect_unvalidated(host: &str, port: u16) { /* ... */ }

// GOOD: use newtypes that enforce validity at construction time
#[derive(Debug)]
pub enum ValidationError {
    InvalidLength,
    NullByte,
    PathSeparator,
    InvalidLabel,
    InvalidCharacter,
    InvalidHyphenPosition,
    ReservedPortZero,
    PrivilegedPort,
}

#[derive(Debug)]
pub struct Hostname(String);

impl Hostname {
    pub fn new(raw: &str) -> Result<Self, ValidationError> {
        // Validate: no null bytes, no path separators, length limits
        if raw.is_empty() || raw.len() > 253 {
            return Err(ValidationError::InvalidLength);
        }
        if raw.contains('\0') {
            return Err(ValidationError::NullByte);
        }
        if raw.contains('/') || raw.contains('\\') {
            return Err(ValidationError::PathSeparator);
        }
        // RFC 952 / RFC 1123 hostname validation
        for label in raw.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(ValidationError::InvalidLabel);
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(ValidationError::InvalidCharacter);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(ValidationError::InvalidHyphenPosition);
            }
        }
        Ok(Hostname(raw.to_lowercase()))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct Port(u16);

impl Port {
    pub fn new(value: u16) -> Result<Self, ValidationError> {
        if value == 0 {
            return Err(ValidationError::ReservedPortZero);
        }
        Ok(Port(value))
    }
    
    pub fn value(&self) -> u16 {
        self.0
    }
}

#[derive(Debug)]
pub struct BindPort(Port);

impl BindPort {
    pub fn new(value: u16) -> Result<Self, ValidationError> {
        let port = Port::new(value)?;
        if port.value() < 1024 {
            return Err(ValidationError::PrivilegedPort);
        }
        Ok(BindPort(port))
    }
}

fn connect(host: Hostname, port: Port) {
    // Guaranteed: host is a valid hostname, port is a valid destination port
}

fn bind(port: BindPort) {
    // Guaranteed: port satisfies this service's binding policy
}
```

🔒 **Security pattern**: "Parse, don't validate." Borrowing Alexis King's phrasing, create types that can only be constructed with valid data. Once you have a `Hostname`, you never need to validate it again. The type itself is proof of validity.

⚠️ **Unicode note**: If you accept non-ASCII identifiers (usernames, domains, paths), normalization becomes part of validation. Normalize to a canonical form (usually NFC), reject bidirectional control characters unless you explicitly support them, and review confusable/homoglyph risks. NFC preserves distinctions that users may care about in display-oriented text. NFKC is more aggressive: it folds compatibility characters such as full-width forms, which is often desirable for login identifiers and usernames but too destructive for free-form content. For domain names, use an IDNA library and validate the ASCII A-label form rather than rolling your own Unicode hostname parser.

### Layer 2: Parse, Don't Validate

The principle comes from functional programming: instead of checking if data is valid and then using it, **parse** the data into a strongly-typed representation that is valid by construction:

```rust
use std::net::IpAddr;

#[derive(Debug)]
pub enum ParseError {
    InvalidFormat,
    InvalidPort,
    InvalidIp,
}

/// A validated network address
pub struct NetworkAddress {
    ip: IpAddr,
    port: u16,
}

impl std::str::FromStr for NetworkAddress {
    type Err = ParseError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip_text, port_text) = if let Some(stripped) = s.strip_prefix('[') {
            let (host, rest) = stripped
                .split_once(']')
                .ok_or(ParseError::InvalidFormat)?;
            if host.contains('[') || !rest.starts_with(':') || rest[1..].contains(']') {
                return Err(ParseError::InvalidFormat);
            }
            (host, &rest[1..])
        } else {
            let (host, port) = s.rsplit_once(':')
                .ok_or(ParseError::InvalidFormat)?;
            if host.contains(':') {
                return Err(ParseError::InvalidFormat);
            }
            (host, port)
        };

        let port: u16 = port_text.parse()
            .map_err(|_| ParseError::InvalidPort)?;
        let ip: IpAddr = ip_text.parse()
            .map_err(|_| ParseError::InvalidIp)?;
        Ok(NetworkAddress { ip, port })
    }
}
```

Use bracketed `[IPv6]:port` syntax for IPv6 literals. Rejecting bare IPv6 addresses here is intentional: the final colon is ambiguous between "part of the address" and "port separator."

### Layer 3: Sanitization

For data that must be embedded in a different context (HTML, SQL, shell commands, file paths):

```rust
#[derive(Debug)]
pub enum ValidationError {
    NullByte,
    DangerousCharacter,
}

/// Quote one argument for a POSIX shell command line.
/// This is illustrative only; quoting rules differ across shells.
pub fn sanitize_posix_shell_arg(input: &str) -> Result<String, ValidationError> {
    if input.contains('\0') {
        return Err(ValidationError::NullByte);
    }
    // Reject metacharacters this tiny helper does not try to quote.
    // Internal single quotes are handled below by escaping them.
    let dangerous = ['|', ';', '&', '$', '`', '(', ')', '<', '>', '\n', '\r'];
    if input.chars().any(|c| dangerous.contains(&c)) {
        return Err(ValidationError::DangerousCharacter);
    }
    // Single-quote and escape internal single quotes
    let escaped = input.replace("'", "'\\''");
    Ok(format!("'{}'", escaped))
}
```

⚠️ **Scope warning**: This helper only models POSIX-style single-quote escaping for cases like `sh -c ...`. It is **not** a general shell-safety API and it is **not** correct for PowerShell or `cmd.exe`.

⚠️ **Best practice**: Avoid shell escaping entirely. Use `std::process::Command` with explicit argument vectors:

```rust
use std::io;
use std::path::Path;
use std::process::Command;

fn list_directory(path: &Path) -> io::Result<String> {
    // GOOD: arguments are passed as separate strings, no shell involved
    let output = Command::new("ls")
        .arg("-la")
        .arg(path)  // No shell injection possible
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
```

Sanitization is context-specific:

- **SQL**: Use parameterized queries or your ORM's bind API (`sqlx`, Diesel, etc.). Do not build SQL by concatenating attacker-controlled strings.
- **HTML / XSS**: Output-encode for the exact sink (HTML text, attribute, URL, JavaScript string). Input validation helps reduce garbage data, but it is not an XSS defense on its own.
- **HTTP headers**: Never splice attacker-controlled strings directly into header lines. Reject `\r`/`\n`, let a real HTTP library serialize the header map, and treat response splitting as an injection sink just like SQL or shell construction.

For example, with `sqlx`:

```rust,ignore
// BAD: attacker input changes the SQL structure
let sql = format!("SELECT * FROM users WHERE email = '{}'", email);

// GOOD: attacker input stays data, not SQL syntax
let row = sqlx::query("SELECT id, email FROM users WHERE email = ?")
    .bind(email)
    .fetch_optional(&pool)
    .await?;
```

For PostgreSQL, use `$1`, `$2`, ... placeholders instead of `?`.

## 7.2 Common Validation Patterns

### 7.2.1 Length Limits

```rust
#[derive(Debug)]
pub enum ValidationError {
    TooShort { min: usize, actual: usize },
    TooLong { max: usize, actual: usize },
}

pub fn validate_length(input: &[u8], min: usize, max: usize) -> Result<(), ValidationError> {
    let len = input.len();
    if len < min {
        Err(ValidationError::TooShort { min, actual: len })
    } else if len > max {
        Err(ValidationError::TooLong { max, actual: len })
    } else {
        Ok(())
    }
}
```

🔒 **Security impact**: Length validation prevents buffer overflows (CWE-120), denial of service via unbounded allocation (CWE-789), and resource exhaustion.

### 7.2.2 Whitelist Over Blacklist

```rust
// BAD: Blacklist approach (easy to miss something)
fn is_safe_filename_blacklist(name: &str) -> bool {
    !name.contains("..") && !name.contains("/")
}

// GOOD: Whitelist approach (only allow known-safe characters)
fn is_safe_filename_whitelist(name: &str) -> bool {
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && !name.starts_with('.')
        && !name.contains("..")
}
```

### 7.2.3 Path Traversal Prevention

```rust
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum ValidationError {
    NullByte,
    InvalidBasePath,
    InvalidPath,
    PathTraversal,
}

/// Safely resolve a user-provided path within a base directory
pub fn safe_path(base: &Path, user_path: &str) -> Result<PathBuf, ValidationError> {
    // Reject null bytes
    if user_path.contains('\0') {
        return Err(ValidationError::NullByte);
    }
    
    let resolved = base.join(user_path);
    
    // Canonicalize and verify it's still under base
    let canonical_base = base.canonicalize()
        .map_err(|_| ValidationError::InvalidBasePath)?;
    let canonical_resolved = resolved.canonicalize()
        .map_err(|_| ValidationError::InvalidPath)?;
    
    if !canonical_resolved.starts_with(&canonical_base) {
        return Err(ValidationError::PathTraversal);
    }
    
    Ok(canonical_resolved)
}
```

🔒 **Security impact**: Prevents CWE-22 (Path Traversal). The canonicalization approach handles symlinks and `../` sequences correctly.

⚠️ **TOCTOU warning**: There is a time-of-check-to-time-of-use race between `canonicalize` and actually using the path. For maximum security, open the file immediately after validation and use the file descriptor.

### 7.2.4 Integer Input Validation

```rust
#[derive(Debug)]
pub enum ValidationError {
    InvalidInteger,
    ValueTooLarge,
}

pub fn parse_size(input: &str) -> Result<usize, ValidationError> {
    let value: usize = input.parse()
        .map_err(|_| ValidationError::InvalidInteger)?;
    // Apply reasonable limits
    if value > 1024 * 1024 * 1024 {  // 1 GiB max
        return Err(ValidationError::ValueTooLarge);
    }
    Ok(value)
}
```

### 7.2.5 SSRF Prevention Requires Destination Validation

A syntactically valid hostname is not automatically a safe outbound destination. For any server-side fetcher, webhook client, or proxy feature, combine hostname validation with post-resolution IP policy checks:

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4 == Ipv4Addr::BROADCAST
                || v4.is_documentation()
                || v4.is_unspecified()
                // Carrier-grade NAT: 100.64.0.0/10
                || (a == 100 && (64..=127).contains(&b))
                // Benchmarking: 198.18.0.0/15
                || (a == 198 && (b == 18 || b == 19))
                // Reserved/experimental and "this network"
                || a == 0
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }

            let segments = v6.segments();
            !(v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
                // Documentation prefix: 2001:db8::/32
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || v6.is_unspecified()
                || v6 == Ipv6Addr::LOCALHOST)
        }
    }
}
```

Resolve the hostname immediately before connecting, reject loopback/private/link-local ranges, and re-check after redirects. Otherwise, a DNS rebinding attack can turn a "valid" hostname into access to internal services.

This example is deliberately conservative and still not exhaustive. Treat it as a starting policy and add environment-specific deny rules for your own internal ranges, overlay networks, and non-routable service endpoints.

### 7.2.6 Regular Expressions and ReDoS

Regular expressions are useful for token-level validation, but they are still an input-processing engine and therefore part of your denial-of-service surface.

- The `regex` crate deliberately omits backreferences and look-around, so it avoids the catastrophic backtracking behavior that makes many classic ReDoS attacks possible.
- That guarantee does not extend to backtracking engines such as `fancy-regex`, PCRE bindings, or ad hoc recursive parsers wrapped around regex captures.
- Bound both pattern complexity and input size. For security-critical formats, prefer small token regexes or an explicit parser over one giant expression that mixes validation and parsing.

When you fuzz validators, include long "almost matching" inputs. Those cases are often more valuable than obviously invalid garbage because they expose superlinear behavior, excessive backtracking, and accidental quadratic parsing paths.

## 7.3 Validation for Protocol Parsing

When implementing network protocols, validation is critical at every layer:

```rust
#[derive(Debug)]
pub enum ParseError {
    TooShort,
    InvalidContentType(u8),
    InvalidVersion(u16),
    RecordTooLong(u16),
    IncompleteRecord,
}

#[derive(Debug)]
pub struct TlsRecord {
    content_type: ContentType,
    version: TlsRecordVersion,
    length: u16,
    payload: Vec<u8>,
}

#[derive(Debug)]
enum ContentType {
    Handshake,
    Alert,
    ApplicationData,
    ChangeCipherSpec,
}

#[derive(Debug)]
enum TlsRecordVersion {
    Tls10,
    Tls11,
    LegacyTls12,
}

impl TlsRecord {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 5 {
            return Err(ParseError::TooShort);
        }
        
        let content_type = match data[0] {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => return Err(ParseError::InvalidContentType(data[0])),
        };
        
        let version = match u16::from_be_bytes([data[1], data[2]]) {
            0x0301 => TlsRecordVersion::Tls10,
            0x0302 => TlsRecordVersion::Tls11,
            0x0303 => TlsRecordVersion::LegacyTls12,
            v => return Err(ParseError::InvalidVersion(v)),
        };

        // TLS 1.0/1.1 are parsed here only for record-layer archaeology.
        // Real TLS policy should reject them during handshake negotiation
        // per RFC 8996.
        
        let length = u16::from_be_bytes([data[3], data[4]]);
        
        // TLS record length must not exceed 2^14 (16384) per RFC 8446
        if length > 16384 {
            return Err(ParseError::RecordTooLong(length));
        }
        
        if data.len() < 5 + length as usize {
            return Err(ParseError::IncompleteRecord);
        }
        
        let payload = data[5..5 + length as usize].to_vec();
        
        Ok(TlsRecord { content_type, version, length, payload })
    }
}
```

🔒 **Security impact**: Protocol parsing is a primary attack surface. Strict validation of:
- Field ranges (record length limits per spec)
- Unknown values (reject unknown content types)
- Consistency (payload length matches header)
- Legacy version field sanity (TLS 1.3 still uses `0x0303` at the record layer)

This prevents protocol-level attacks including fuzzing, injection, and downgrade attacks. For TLS 1.3 specifically, perform downgrade checks in the handshake (`supported_versions`), not from the record-layer version field alone.

## 7.4 The `serde` Ecosystem — Deserialization Safety

Serde is Rust's serialization framework. While powerful, deserialization of untrusted data requires care:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::serde as serde;
# use rust_secure_systems_book::deps::serde::Deserialize;

#[derive(Deserialize)]
#[serde(crate = "rust_secure_systems_book::deps::serde")]
struct UserInput {
    #[serde(deserialize_with = "validate_username")]
    username: String,
    email: String,
    age: u8,
}

fn validate_username<'de, D>(de: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = String::deserialize(de)?;
    if s.len() > 64 {
        return Err(serde::de::Error::custom("username too long"));
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(serde::de::Error::custom("invalid characters in username"));
    }
    Ok(s)
}
```

⚠️ **Security warnings for serde**:

1. **Depth limits are format-specific**: `serde` provides the framework, but the actual recursion policy comes from the format crate. `serde_json` keeps a default recursion limit enabled; other deserializers or custom formats may not. Verify the behavior of the specific format you expose to untrusted input.

2. **Integer overflow**: When deserializing into a smaller integer type, serde will reject values that don't fit—unlike many JSON parsers in C.

3. **Denial of service**: Large allocations from untrusted input can exhaust memory. Enforce transport-level body size caps and keep parser safeguards enabled:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::serde as serde;
# use rust_secure_systems_book::deps::serde::Deserialize;
# use rust_secure_systems_book::deps::serde_json as serde_json;
# #[derive(Deserialize)]
# #[serde(crate = "rust_secure_systems_book::deps::serde")]
# struct UserInput {
#     username: String,
#     email: String,
#     age: u8,
# }
fn deserialize_with_limit(data: &[u8]) -> Result<UserInput, Box<dyn std::error::Error>> {
    const MAX_JSON_SIZE: usize = 16 * 1024;
    if data.len() > MAX_JSON_SIZE {
        return Err("input too large".into());
    }

    let mut deserializer = serde_json::Deserializer::from_slice(data);
    // serde_json enables a default recursion limit. Leave it enabled unless
    // you replace it with explicit depth tracking.
    let input = UserInput::deserialize(&mut deserializer)?;
    Ok(input)
}
```

⚠️ **Security note**: The example above relies on `serde_json`'s built-in recursion limit and adds an explicit input-size cap before deserialization. Only call `disable_recursion_limit()` if you replace it with another stack-safety mechanism such as `serde_stacker` or an explicit depth-tracked visitor.

4. **Secret types**: Deserializing into a secret-bearing struct creates another live in-memory copy. If the target type derives `ZeroizeOnDrop` or wraps fields in `secrecy`, keep deserialization boundaries narrow and ensure transient copies are dropped promptly.

## 7.5 Summary

- Use the **validation pyramid**: type-level (strongest) → parse-don't-validate → sanitization.
- Create **newtypes** that enforce validity at construction time.
- **Whitelist** allowed inputs; don't blacklist dangerous ones.
- Prevent path traversal with canonicalization and prefix checking.
- Normalize and review Unicode input rules before validating non-ASCII identifiers.
- Treat SSRF as a destination policy problem, not just a hostname syntax problem.
- Validate protocol fields against specification limits.
- Use `std::process::Command` with argument vectors instead of shell escaping.
- Be cautious with serde deserialization of untrusted data—set depth and size limits.

In the next chapter, we cover cryptography and secrets management—how to safely use cryptographic primitives and protect sensitive data in Rust applications.

## 7.6 Exercises

1. **Newtype Validation Library**: Create validated newtypes for `Email`, `Ipv4Address`, and `FilePath` (safe within a base directory). Each should implement `FromStr` and be impossible to construct with invalid data. Write comprehensive tests including null bytes, overlength inputs, and path traversal attempts.

2. **Path Traversal Fuzzer**: Write a function `safe_path(base: &Path, user_input: &str) -> Result<PathBuf>` that canonicalizes the result and verifies it stays within `base`. Then write a `proptest` suite that generates path strings with `..`, symbolic links, mixed separators, and Unicode tricks. Verify your function rejects all escape attempts.

3. **Serde Depth Limit**: Use `serde_json` to deserialize untrusted JSON with a custom visitor that rejects nesting deeper than 10 levels. Write a test that constructs a deeply nested JSON string and verifies it is rejected. Compare memory usage of parsing a 1000-level-deep JSON with and without the limit.

4. **Command Injection Prevention**: Write a program that takes user input and passes it to an external command. First implement the unsafe version using shell interpolation (format string with user data), then rewrite using `std::process::Command` with proper argument separation. Demonstrate that the second version is immune to injection with inputs like `; rm -rf /`.
