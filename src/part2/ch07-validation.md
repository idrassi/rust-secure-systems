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
    SystemPort,
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
        // Reject system ports for non-root processes
        if value < 1024 {
            return Err(ValidationError::SystemPort);
        }
        Ok(Port(value))
    }
    
    pub fn value(&self) -> u16 {
        self.0
    }
}

fn connect(host: Hostname, port: Port) {
    // Guaranteed: host is a valid hostname, port is valid
}
```

🔒 **Security pattern**: "Parse, don't validate." Create types that can only be constructed with valid data. Once you have a `Hostname`, you never need to validate it again. The type itself is proof of validity.

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
        let parts: Vec<&str> = s.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ParseError::InvalidFormat);
        }
        let port: u16 = parts[0].parse()
            .map_err(|_| ParseError::InvalidPort)?;
        let ip: IpAddr = parts[1].trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| ParseError::InvalidIp)?;
        Ok(NetworkAddress { ip, port })
    }
}
```

### Layer 3: Sanitization

For data that must be embedded in a different context (HTML, SQL, shell commands, file paths):

```rust
#[derive(Debug)]
pub enum ValidationError {
    NullByte,
    DangerousCharacter,
}

/// Sanitize for shell argument usage (but prefer avoiding shell entirely)
pub fn sanitize_shell_arg(input: &str) -> Result<String, ValidationError> {
    if input.contains('\0') {
        return Err(ValidationError::NullByte);
    }
    // Reject obviously dangerous characters
    let dangerous = ['|', ';', '&', '$', '`', '(', ')', '<', '>', '\n', '\r'];
    if input.chars().any(|c| dangerous.contains(&c)) {
        return Err(ValidationError::DangerousCharacter);
    }
    // Single-quote and escape internal single quotes
    let escaped = input.replace("'", "'\\''");
    Ok(format!("'{}'", escaped))
}
```

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
    version: TlsVersion,
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
enum TlsVersion {
    Tls10,
    Tls12,
    Tls13,
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
            0x0301 => TlsVersion::Tls10,
            0x0303 => TlsVersion::Tls12,
            0x0304 => TlsVersion::Tls13,
            v => return Err(ParseError::InvalidVersion(v)),
        };
        
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
- Version enforcement (reject downgraded versions)

This prevents protocol-level attacks including fuzzing, injection, and downgrade attacks.

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

## 7.5 Summary

- Use the **validation pyramid**: type-level (strongest) → parse-don't-validate → sanitization.
- Create **newtypes** that enforce validity at construction time.
- **Whitelist** allowed inputs; don't blacklist dangerous ones.
- Prevent path traversal with canonicalization and prefix checking.
- Validate protocol fields against specification limits.
- Use `std::process::Command` with argument vectors instead of shell escaping.
- Be cautious with serde deserialization of untrusted data—set depth and size limits.

In the next chapter, we cover cryptography and secrets management—how to safely use cryptographic primitives and protect sensitive data in Rust applications.

## 7.6 Exercises

1. **Newtype Validation Library**: Create validated newtypes for `Email`, `Ipv4Address`, and `FilePath` (safe within a base directory). Each should implement `FromStr` and be impossible to construct with invalid data. Write comprehensive tests including null bytes, overlength inputs, and path traversal attempts.

2. **Path Traversal Fuzzer**: Write a function `safe_path(base: &Path, user_input: &str) -> Result<PathBuf>` that canonicalizes the result and verifies it stays within `base`. Then write a `proptest` suite that generates path strings with `..`, symbolic links, mixed separators, and Unicode tricks. Verify your function rejects all escape attempts.

3. **Serde Depth Limit**: Use `serde_json` to deserialize untrusted JSON with a custom visitor that rejects nesting deeper than 10 levels. Write a test that constructs a deeply nested JSON string and verifies it is rejected. Compare memory usage of parsing a 1000-level-deep JSON with and without the limit.

4. **Command Injection Prevention**: Write a program that takes user input and passes it to an external command. First implement the unsafe version using shell interpolation (format string with user data), then rewrite using `std::process::Command` with proper argument separation. Demonstrate that the second version is immune to injection with inputs like `; rm -rf /`.
