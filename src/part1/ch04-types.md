# Chapter 4 — Type System and Pattern Matching

> *"Make illegal states unrepresentable."*

Rust's type system is one of its most powerful tools for writing secure code. It combines algebraic data types, exhaustive pattern matching, and a strict stance on implicit conversions to ensure that many classes of bugs simply cannot be expressed. For security developers accustomed to fighting type confusion bugs, integer overflows, and unhandled cases in C/C++ switch statements, Rust's type system is a breath of fresh air.

## 4.1 No Null — Use `Option<T>`

Tony Hoare, the inventor of the null reference, called it his "billion-dollar mistake." In C/C++, any pointer can be null, and dereferencing a null pointer is undefined behavior (CWE-476). Rust eliminates null entirely from the language.

Instead, Rust uses the `Option<T>` enum:

```rust
enum Option<T> {
    Some(T),
    None,
}
```

You **must** explicitly handle the absence of a value:

```rust
fn find_user(id: u32) -> Option<String> {
    if id == 42 {
        Some(String::from("admin"))
    } else {
        None
    }
}

fn main() {
    // You CANNOT use the value without checking
    let user = find_user(100);
    
    // Pattern matching — compiler ensures you handle both cases
    match user {
        Some(name) => println!("Found: {}", name),
        None => println!("User not found"),
    }
    
    // If-let for convenience
    if let Some(name) = find_user(42) {
        println!("Found: {}", name);
    }
    
    // unwrap_or_default provides a safe fallback
    let name = find_user(99).unwrap_or_default();
}
```

🔒 **Security impact**: CWE-476 (NULL Pointer Dereference) is **impossible** in safe Rust. Every potentially-absent value is wrapped in `Option`, and the compiler forces you to handle the `None` case.

⚠️ **Caveat**: `.unwrap()` and `.expect()` will panic if called on `None`. In security-critical code, avoid these and handle the `None` case explicitly.

## 4.2 No Exceptions — Use `Result<T, E>`

Rust does not have exceptions. Instead, recoverable errors are represented by `Result<T, E>`:

```rust
enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

```rust
use std::fs::File;
use std::io::{self, Read};

fn read_config(path: &str) -> Result<String, io::Error> {
    let mut file = File::open(path)?;    // ? operator propagates errors
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn main() {
    match read_config("/etc/app/config.toml") {
        Ok(config) => println!("Config: {}", config),
        Err(e) => eprintln!("Failed to read config: {}", e),
    }
}
```

The `?` operator is Rust's error propagation mechanism. It either returns the `Ok` value or immediately returns the `Err` from the current function. It is the safe equivalent of checking return codes in C, but without the boilerplate.

🔒 **Security impact**: Forces explicit error handling at every level. No error is silently swallowed. Contrast with C, where forgetting to check a return value is a common source of vulnerabilities.

## 4.3 Algebraic Data Types and Enums

Rust enums are far more powerful than C enums. Each variant can carry data:

```rust
enum NetworkEvent {
    Connect { address: std::net::IpAddr, port: u16 },
    Data(Vec<u8>),
    Disconnect { reason: String },
    Timeout,
}

fn handle_event(event: NetworkEvent) {
    match event {
        NetworkEvent::Connect { address, port } => {
            println!("Connection from {}:{}", address, port);
        }
        NetworkEvent::Data(payload) => {
            println!("Received {} bytes", payload.len());
        }
        NetworkEvent::Disconnect { reason } => {
            println!("Disconnected: {}", reason);
        }
        NetworkEvent::Timeout => {
            println!("Connection timed out");
        }
    }
}
```

🔒 **Security pattern**: Use enums to model protocol states. Make invalid transitions unrepresentable:

```rust
enum ConnectionState {
    Closed,
    Handshake,
    Authenticated,
    Encrypted,
}

// You cannot accidentally process data in the Closed state
// because the type system won't allow it
```

### 4.3.1 Exhaustive Matching

The compiler **requires** that every possible case is handled:

```rust,compile_fail
enum Permission {
    Read,
    Write,
    Execute,
    Admin,
}

fn check_permission(perm: Permission) -> bool {
    match perm {
        Permission::Read => true,
        Permission::Write => true,
        // ERROR: non-exhaustive patterns: `Execute` and `Admin` not covered
    }
}
```

🔒 **Security impact**: When you add a new variant to an enum, the compiler will flag every `match` that doesn't handle it. This prevents the "forgotten case" bug class, which in C switch statements can silently fall through or be mishandled.

### 4.3.2 `#[non_exhaustive]` — Future-Proofing Enums

When defining public enums in a library, mark them `#[non_exhaustive]` to force downstream consumers to handle future variants:

```rust
#[non_exhaustive]
#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    AccountLocked,
    TokenExpired,
    RateLimited,
}

fn handle_error(err: AuthError) {
    match err {
        AuthError::InvalidCredentials => println!("Bad credentials"),
        AuthError::AccountLocked => println!("Account locked"),
        AuthError::TokenExpired => println!("Token expired"),
        AuthError::RateLimited => println!("Rate limited"),
        // Downstream crates matching a public `#[non_exhaustive]` enum
        // must include a wildcard arm for future variants.
        _ => println!("Unknown auth error"),
    }
}
```

Inside the crate that defines `AuthError`, the compiler still knows every current variant, so the wildcard above is a style choice rather than an enforcement point. The `#[non_exhaustive]` guarantee matters at the public API boundary: downstream crates importing `AuthError` must include a fallback arm.

🔒 **Security pattern**: Use `#[non_exhaustive]` on public enums in library APIs. If you add a new error variant (e.g., `CertificateRevoked`), downstream code that already has a wildcard arm can continue compiling and handle the new case conservatively. Without `#[non_exhaustive]`, adding a variant is a breaking change: downstream `match` expressions without a wildcard fail to compile, while matches that already use `_` continue compiling and may route the new case through a generic fallback path.

## 4.4 Structs and Tuples

### Structs

```rust
struct User {
    id: u32,
    username: String,
    role: Role,
    active: bool,
}

enum Role {
    Guest,
    Member,
    Admin,
}

impl User {
    fn new(id: u32, username: String, role: Role) -> Self {
        User { id, username, role, active: true }
    }
    
    fn is_admin(&self) -> bool {
        matches!(self.role, Role::Admin)
    }
}
```

### Tuple Structs

```rust
struct UserId(u64);
struct User {
    id: UserId,
}

// Type safety: you can't accidentally mix UserId with a raw u64
fn get_user(id: UserId) -> Option<User> {
    Some(User { id })
}
```

🔒 **Security pattern**: Use newtypes (tuple structs with a single field) to prevent type confusion. A `UserId(u64)` is distinct from a `u64`, and the compiler will catch if you pass the wrong type. This prevents CWE-20 (Improper Input Validation) caused by type confusion.

### Authorization with Role and Capability Types

Authentication tells you **who** the caller is. Authorization decides **what** that caller may do. Rust's type system can make privileged paths harder to misuse by representing authority explicitly instead of threading raw booleans, strings, or ad hoc role checks through the codebase.

```rust
use std::marker::PhantomData;

#[derive(Clone, Copy)]
struct UserId(u64);

struct Guest;
struct Admin;

struct Session<Role> {
    user_id: UserId,
    _role: PhantomData<Role>,
}

struct ReadSecrets;
struct RotateKeys;

struct Capability<P>(PhantomData<P>);

fn view_audit_log(_session: &Session<Admin>) {}

fn read_secret(_cap: &Capability<ReadSecrets>, _key_id: &str) -> Option<String> {
    Some("redacted".to_string())
}

fn rotate_signing_key(_cap: &Capability<RotateKeys>) {}
```

This gives you three useful patterns:

- **RBAC with marker types**: only code that has already checked policy should be able to construct `Session<Admin>`.
- **Capability-based security**: functions accept a narrow authority token such as `Capability<RotateKeys>` instead of a broad "current user" handle.
- **Confused deputy defense**: helpers can only exercise the authority they were explicitly handed, which is safer than reaching into ambient global state or reusing the caller's full identity.

Keep constructors for privileged sessions and capabilities private to the module that performs the actual policy decision. That way, authorization is enforced once at the boundary and then preserved by the type system.

## 4.5 Traits — Defining Shared Behavior

Traits are Rust's answer to interfaces:

```rust
# struct Credentials;
# struct Session;
# struct AuthError;
#
trait Authenticator {
    fn authenticate(&self, credentials: &Credentials) -> Result<Session, AuthError>;
    fn is_valid_session(&self, session: &Session) -> bool;
    fn revoke_session(&self, session: &mut Session);
}
```

### Marker Traits for Security

Rust uses marker traits to enforce properties at compile time:

```rust
// Send: safe to transfer to another thread
// Sync: safe to share between threads via a reference

// By default, a type is Send/Sync if all its fields are.
// The compiler will ERROR if you try to send a non-Send type across threads.

use std::sync::Mutex;

struct SharedState {
    counter: Mutex<u32>,  // Mutex<T> is Send + Sync
    data: Vec<u8>,        // Vec<u8> is Send + Sync
}

// This type can be safely shared between threads.
```

🔒 **Security impact**: The `Send` and `Sync` traits prevent data races at compile time. If a type contains a non-thread-safe component (like `Rc<T>`), the compiler will refuse to let you share it across threads. This removes a major source of CWE-362-style concurrency bugs, but it does not eliminate higher-level logic races such as TOCTOU.

### The `From`/`Into` Traits — Safe Conversions

```rust
struct Port(u16);

impl TryFrom<u32> for Port {
    type Error = &'static str;
    
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value <= 65535 {
            Ok(Port(value as u16))
        } else {
            Err("Port number out of range")
        }
    }
}

fn bind(port: Port) {
    // ...
}
```

🔒 **Security pattern**: Use `TryFrom` for all conversions where the source type is wider than the target type (e.g., `u32` → `u16`, `usize` → `u8`). This prevents CWE-190 (Integer Overflow or Wraparound) and CWE-20 (Improper Input Validation).

When zero has no valid meaning, prefer `NonZeroU32` or `NonZeroUsize` over a plain integer. This lets the type system reject sentinel `0` values up front and can make `Option<NonZeroU32>` more compact than `Option<u32>`.

## 4.6 Pattern Matching Deep Dive

Pattern matching is not limited to `match`. Rust supports patterns in many contexts:

### Destructuring

```rust
struct Packet {
    source: std::net::IpAddr,
    dest: std::net::IpAddr,
    payload: Vec<u8>,
    flags: u8,
}

// Approach 1: Destructure into individual fields
fn analyze_fields(packet: Packet) {
    let Packet { source, dest, payload, flags } = packet;
    println!("Data: {} -> {}, {} bytes, flags={}", source, dest, payload.len(), flags);
}

// Approach 2: Match with destructuring patterns
fn analyze_match(packet: Packet) {
    match packet {
        Packet { flags: 0xFF, payload, .. } => {
            println!("Control packet: {} bytes", payload.len());
        }
        Packet { source, dest, .. } => {
            println!("Data: {} -> {}", source, dest);
        }
    }
}
```

### Guards

```rust
fn classify_packet(size: usize, flags: u8) -> &'static str {
    match (size, flags) {
        (0, _) => "empty",
        (1..=64, 0) => "small-control",
        (1..=64, _) => "small-data",
        (65..=1500, _) => "normal",
        (1501..=9000, _) => "jumbo",
        _ => "oversized",
    }
}
```

### Slice Patterns

```rust,no_run
# #[derive(Debug, PartialEq, Eq)]
# enum Command {
#     Read { offset: u8, length: u8 },
#     Write,
# }
# #[derive(Debug, PartialEq, Eq)]
# enum ParseError {
#     InvalidFormat,
# }
fn parse_command(input: &[u8]) -> Result<Command, ParseError> {
    match input {
        [0x01, len @ 1..=255, data @ ..] if data.len() == *len as usize => {
            Ok(Command::Read { offset: data[0], length: *len })
        }
        [0x02, ..] => Ok(Command::Write),
        _ => Err(ParseError::InvalidFormat),
    }
}
```

## 4.7 Integer Safety

Integer handling is a major source of vulnerabilities in C/C++. Rust provides explicit options:

### Checked Arithmetic

```rust
fn safe_add(a: u64, b: u64) -> Option<u64> {
    a.checked_add(b)  // Returns None on overflow
}

fn safe_multiply(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)
}
```

### Saturating Arithmetic

```rust
fn saturating_increment(counter: u8) -> u8 {
    counter.saturating_add(1)  // Stays at u8::MAX instead of wrapping
}
```

### Wrapping Arithmetic

```rust
fn wrapping_hash(value: u64) -> u64 {
    value.wrapping_mul(0x5851F42D4C957F2D)  // Intentional wrapping for hash functions
}
```

🔒 **Security rule**: In security-critical code, always use `checked_*` or `saturating_*` arithmetic. Only use `wrapping_*` when the algorithm explicitly requires modular arithmetic (e.g., hash functions, ciphers).

### Compiler Configuration

Enable overflow checks globally:

```toml
[profile.release]
overflow-checks = true  # Panic on overflow instead of wrapping
```

With `overflow-checks = true`, standard arithmetic (`+`, `-`, `*`) will panic on overflow rather than silently wrapping.

## 4.8 Const Generics and Type-Level Programming

Rust supports const generics, allowing compile-time values as type parameters:

```rust
struct FixedBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> FixedBuffer<N> {
    fn new() -> Self {
        FixedBuffer { data: [0u8; N] }
    }
    
    fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != N {
            return None;
        }
        let mut buf = Self::new();
        buf.data.copy_from_slice(slice);
        Some(buf)
    }
}

type AesKey = FixedBuffer<32>;    // 256-bit key
type HmacKey = FixedBuffer<64>;  // 512-bit key
```

🔒 **Security pattern**: Use const generics to enforce cryptographic sizes at compile time. A function that takes `FixedBuffer<32>` cannot accidentally receive a 16-byte key.

## 4.9 Summary

- `Option<T>` replaces null, eliminating CWE-476.
- `Result<T, E>` forces explicit error handling, preventing silently swallowed errors.
- Algebraic data types and exhaustive matching ensure all cases are handled.
- Newtypes prevent type confusion (CWE-20).
- Checked arithmetic prevents integer overflow (CWE-190).
- `Send`/`Sync` traits prevent data races at compile time, removing a major source of CWE-362-style concurrency bugs.
- Const generics enforce size constraints at compile time.

The type system is your first and strongest line of defense. In the next chapter, we explore how Rust's error handling model supports secure, robust code.

## 4.10 Exercises

1. **Exhaustive Matching**: Define an enum `HttpStatus` with variants for common HTTP status codes (200, 301, 403, 404, 500). Write a function `classify(status: HttpStatus) -> &'static str` using `match`. Then add a new variant (e.g., `ServiceUnavailable`). Observe how the compiler catches the unhandled case.

2. **Newtype for Safety**: Create two newtypes `UserId(u64)` and `SessionId(u64)`. Implement `FromStr` for both with different validation rules (e.g., `UserId` must be non-zero, `SessionId` must be within a certain range). Write a function that takes `UserId` and verify that passing a `SessionId` is a compile error.

3. **Checked Arithmetic**: Write a function `safe_average(values: &[u64]) -> Option<u64>` that computes the average using only `checked_*` operations. Ensure it returns `None` on overflow or empty input. Test with edge cases: `u64::MAX`, single element, and empty slice.

4. **Const Generic Buffer**: Implement a `CryptoKey<const N: usize>` newtype that enforces key size at compile time. Create type aliases for `Aes128Key = CryptoKey<16>`, `Aes256Key = CryptoKey<32>`, and write a function that accepts only `Aes256Key`. Verify that passing an `Aes128Key` is a compile error.
