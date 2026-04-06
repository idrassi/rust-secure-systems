# Chapter 18 — Secure Parser Construction

> *"Parsers are the gateway to every system. Secure the gateway."*

Binary parsers are among the most security-critical components in any system. History shows that parser bugs account for a disproportionate share of critical vulnerabilities: buffer overflows in image decoders, integer overflows in packet parsers, and logic errors in protocol state machines. This chapter builds a secure binary protocol parser using Rust's type system to prevent common parser vulnerabilities.

## 18.1 The Parser Threat Model

| Vulnerability | CWE | How Rust Helps |
|--------------|-----|----------------|
| Buffer over-read | CWE-125 | Bounds-checked slicing |
| Buffer over-write | CWE-787 | Bounds-checked indexing |
| Integer overflow in length | CWE-190 | Checked arithmetic |
| Uninitialized memory read | CWE-908 | `MaybeUninit` required for unsafe |
| Type confusion | CWE-843 | Strong type system |
| Denial of service (OOM) | CWE-789 | Size limits |
| State machine confusion | CWE-1265 | Type-state pattern |

## 18.2 Design Principles for Secure Parsers

1. **Parse, don't validate**: Transform raw bytes into strongly-typed structures.
2. **Fail fast**: Reject invalid input at the earliest possible point.
3. **No panics**: Use `Result` for all fallible operations.
4. **Bounded allocation**: Never allocate based on untrusted size fields without limits.
5. **No unsafe**: Parsers should be implementable entirely in safe Rust.

### 18.2.1 Parser Combinators with `nom`

This chapter uses a hand-written parser because explicit control flow is easy to audit, makes allocation limits obvious, and keeps every boundary check visible. That is not the only defensible choice. `nom` is a mature parser-combinator library and can be a good fit when you want declarative composition without writing pointer arithmetic by hand.

From a security perspective, three `nom` design choices matter:

- Choose the right mode: `complete` parsers treat missing bytes as hard errors, while `streaming` parsers return `Incomplete`. For sockets and framed protocols, that distinction is part of your threat model.
- Bound input before parsing. A combinator library does not remove the need for maximum message sizes, checked length arithmetic, or duplicate-field policy.
- Keep parsers inspectable. Favor small named combinators and explicit error mapping over deeply nested expressions that hide which branch consumed input.

Use `nom` when it improves clarity; use a hand-written parser when explicit state transitions and bounds checks are easier to review. For security-critical formats, "shorter code" is only a win if the rejection behavior stays obvious.

### 18.2.2 Allocation Failure and Parser Depth

Size limits prevent obvious OOM bugs, but they do not guarantee allocation succeeds under pressure. Rust's default `Vec` growth path still calls `handle_alloc_error`; with `panic = "abort"` elsewhere in your deployment, that can become process termination. When you must buffer attacker-controlled lengths, reserve fallibly and turn memory pressure into a normal parse error:

```rust,no_run
fn copy_value_fallible(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    out.try_reserve_exact(data.len())
        .map_err(|_| "allocation failed while buffering parser input")?;
    out.extend_from_slice(data);
    Ok(out)
}
```

Also distinguish **byte-size limits** from **stack-depth limits**. The TLV parser in this chapter is iterative, so deeply nested input cannot blow the stack. If you write a recursive parser for nested formats, carry an explicit depth counter and reject excessive nesting; otherwise, "valid but deep" input can still crash the process. Helpers such as `stacker` or `serde_stacker` are worth evaluating when recursion is unavoidable.

## 18.3 Example: A Secure TLV (Type-Length-Value) Parser

### 18.3.1 Type Definitions

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate self as thiserror;
# pub use rust_secure_systems_book::deps::thiserror::Error;
# pub use rust_secure_systems_book::deps::thiserror::*;
// src/tlv.rs
use std::fmt;

/// Maximum single TLV value size (1 MiB)
const MAX_VALUE_SIZE: usize = 1024 * 1024;

/// Maximum total message size (16 MiB)
const MAX_TOTAL_SIZE: usize = 16 * 1024 * 1024;

/// TLV type tags with semantic meaning.
///
/// Note: We do **not** use `#[repr(u8)]` for the wire-format mapping here.
/// `Extension(u8)` is a catch-all for many possible extension tag bytes, so the
/// enum's in-memory discriminant is not the same thing as the protocol tag.
/// Instead, the `from_byte` and `as_byte` methods handle the tag↔enum mapping
/// manually.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvTag {
    Padding,
    KeyId,
    Algorithm,
    Iv,
    Ciphertext,
    AuthTag,
    Aad,
    Certificate,
    Signature,
    Timestamp,
    Nonce,
    Extension(u8),
}

impl TlvTag {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => TlvTag::Padding,
            0x01 => TlvTag::KeyId,
            0x02 => TlvTag::Algorithm,
            0x03 => TlvTag::Iv,
            0x04 => TlvTag::Ciphertext,
            0x05 => TlvTag::AuthTag,
            0x06 => TlvTag::Aad,
            0x07 => TlvTag::Certificate,
            0x08 => TlvTag::Signature,
            0x09 => TlvTag::Timestamp,
            0x0A => TlvTag::Nonce,
            other => TlvTag::Extension(other),
        }
    }
    
    fn as_byte(&self) -> u8 {
        match self {
            TlvTag::Padding => 0x00,
            TlvTag::KeyId => 0x01,
            TlvTag::Algorithm => 0x02,
            TlvTag::Iv => 0x03,
            TlvTag::Ciphertext => 0x04,
            TlvTag::AuthTag => 0x05,
            TlvTag::Aad => 0x06,
            TlvTag::Certificate => 0x07,
            TlvTag::Signature => 0x08,
            TlvTag::Timestamp => 0x09,
            TlvTag::Nonce => 0x0A,
            TlvTag::Extension(b) => *b,
        }
    }

    fn is_reserved_extension_value(byte: u8) -> bool {
        matches!(byte, 0x00..=0x0A)
    }
}

/// A parsed TLV record with validated bounds
#[derive(Debug, Clone)]
pub struct TlvRecord {
    tag: TlvTag,
    value: Vec<u8>,
}

impl TlvRecord {
    pub fn tag(&self) -> TlvTag {
        self.tag
    }
    
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    
    /// Construct a TLV record with validation
    pub fn new(tag: TlvTag, value: Vec<u8>) -> Result<Self, ParseError> {
        if value.len() > MAX_VALUE_SIZE {
            return Err(ParseError::ValueTooLarge {
                size: value.len(),
                max: MAX_VALUE_SIZE,
            });
        }
        if let TlvTag::Extension(byte) = tag {
            if TlvTag::is_reserved_extension_value(byte) {
                return Err(ParseError::ReservedExtensionTag { byte });
            }
        }
        Ok(TlvRecord { tag, value })
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5 + self.value.len());
        bytes.push(self.tag.as_byte());
        let len = self.value.len() as u32;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&self.value);
        bytes
    }
}

/// A collection of TLV records (a TLV message)
#[derive(Debug, Clone)]
pub struct TlvMessage {
    records: Vec<TlvRecord>,
}

impl TlvMessage {
    pub fn records(&self) -> &[TlvRecord] {
        &self.records
    }
    
    pub fn get(&self, tag: TlvTag) -> Option<&TlvRecord> {
        self.records.iter().find(|r| r.tag == tag)
    }
    
    /// Parse a TLV message from raw bytes.
    ///
    /// This format treats every non-padding tag as unique. Rejecting duplicates
    /// keeps the representation canonical and avoids higher layers disagreeing
    /// about whether "first wins" or "last wins".
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() > MAX_TOTAL_SIZE {
            return Err(ParseError::MessageTooLarge {
                size: data.len(),
                max: MAX_TOTAL_SIZE,
            });
        }
        
        let mut records: Vec<TlvRecord> = Vec::new();
        let mut offset = 0usize;
        
        while offset < data.len() {
            // Need at least 5 bytes for tag + length
            if offset.checked_add(5).ok_or(ParseError::IntegerOverflow)? > data.len() {
                return Err(ParseError::IncompleteHeader { offset });
            }
            
            let tag = TlvTag::from_byte(data[offset]);
            offset += 1;
            
            // Read 4-byte big-endian length (network byte order)
            let length = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;
            
            // Validate length
            if length > MAX_VALUE_SIZE {
                return Err(ParseError::ValueTooLarge {
                    size: length,
                    max: MAX_VALUE_SIZE,
                });
            }
            
            // Check we have enough data
            let end = offset.checked_add(length).ok_or(ParseError::IntegerOverflow)?;
            if end > data.len() {
                return Err(ParseError::IncompleteValue {
                    expected: end,
                    available: data.len(),
                });
            }
            
            // Extract value (skip padding)
            let value = data[offset..end].to_vec();
            offset = end;
            
            if !matches!(tag, TlvTag::Padding) {
                if records.iter().any(|record| record.tag == tag) {
                    return Err(ParseError::DuplicateTag { tag });
                }
                records.push(TlvRecord::new(tag, value)?);
            }
        }
        
        Ok(TlvMessage { records })
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for record in &self.records {
            bytes.extend_from_slice(&record.to_bytes());
        }
        bytes
    }
}

#[derive(Debug)]
pub enum ParseError {
    MessageTooLarge { size: usize, max: usize },
    IncompleteHeader { offset: usize },
    ValueTooLarge { size: usize, max: usize },
    IncompleteValue { expected: usize, available: usize },
    DuplicateTag { tag: TlvTag },
    ReservedExtensionTag { byte: u8 },
    IntegerOverflow,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::MessageTooLarge { size, max } => {
                write!(f, "message too large: {size} bytes (max {max})")
            }
            ParseError::IncompleteHeader { offset } => {
                write!(f, "incomplete header at offset {offset}")
            }
            ParseError::ValueTooLarge { size, max } => {
                write!(f, "value too large: {size} bytes (max {max})")
            }
            ParseError::IncompleteValue { expected, available } => {
                write!(f, "incomplete value: expected {expected} bytes, have {available}")
            }
            ParseError::DuplicateTag { tag } => {
                write!(f, "duplicate tag not allowed: {tag:?}")
            }
            ParseError::ReservedExtensionTag { byte } => {
                write!(f, "extension tag byte collides with a named tag: 0x{byte:02X}")
            }
            ParseError::IntegerOverflow => f.write_str("integer overflow in length calculation"),
        }
    }
}

impl std::error::Error for ParseError {}
```

Rejecting duplicate non-padding tags is a deliberate security choice. If your protocol genuinely allows repeated fields, model them explicitly as a multi-valued field rather than relying on an accessor like `get()` to silently pick one occurrence.

## 18.4 Type-State Pattern for Protocol State Machines

The type-state pattern uses Rust's type system to encode protocol states, making invalid transitions unrepresentable:

```rust,no_run
// src/protocol.rs
# use std::io;
# use std::net::TcpStream;
# struct Credentials;
# #[derive(Debug)]
# struct AuthError;
# fn verify_credentials(_credentials: &Credentials) -> Result<u64, AuthError> {
#     Ok(7)
# }

/// A connection in the initial (unauthenticated) state
pub struct Unauthenticated;

/// A connection in the authenticated state
pub struct Authenticated {
    user_id: u64,
}

/// A connection in the encrypted state
pub struct Encrypted {
    user_id: u64,
    session_key: [u8; 32],
}

/// A protocol connection that enforces state transitions at compile time
pub struct Connection<S> {
    stream: TcpStream,
    state: S,
}

impl Connection<Unauthenticated> {
    pub fn new(stream: TcpStream) -> Self {
        Connection {
            stream,
            state: Unauthenticated,
        }
    }
    
    /// Authenticate the connection. Only callable in the Unauthenticated state.
    pub fn authenticate(self, credentials: &Credentials) -> Result<Connection<Authenticated>, AuthError> {
        let user_id = verify_credentials(credentials)?;
        Ok(Connection {
            stream: self.stream,
            state: Authenticated { user_id },
        })
    }
}

impl Connection<Authenticated> {
    /// Upgrade to encrypted. Only callable in the Authenticated state.
    pub fn upgrade_to_encrypted(self, key: [u8; 32]) -> Connection<Encrypted> {
        Connection {
            stream: self.stream,
            state: Encrypted {
                user_id: self.state.user_id,
                session_key: key,
            },
        }
    }
    
    /// Send data in the clear (authenticated but not encrypted)
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        // ...
        Ok(())
    }
}

impl Connection<Encrypted> {
    /// Send encrypted data. Only available in Encrypted state.
    pub fn send_encrypted(&mut self, data: &[u8]) -> io::Result<()> {
        // Encrypt with self.state.session_key
        Ok(())
    }
    
    pub fn user_id(&self) -> u64 {
        self.state.user_id
    }
}

// This code will NOT compile:
fn exploit(conn: Connection<Unauthenticated>) {
    // conn.send(b"data");  // ERROR: no method `send` on Connection<Unauthenticated>
    // conn.send_encrypted(b"data");  // ERROR: no method on Unauthenticated
}
```

🔒 **Security impact**: The type-state pattern prevents:
- Sending data before authentication
- Sending unencrypted data after the connection is upgraded
- Accessing encrypted features without establishing a session key
- All enforced at **compile time**, not runtime

## 18.5 Fuzzing the Parser

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate libfuzzer_sys;
# use rust_secure_systems_book::tlv_parser as tlv_parser;
// fuzz/fuzz_targets/tlv_parser.rs
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // The parser should never panic, regardless of input
    let _ = tlv_parser::TlvMessage::parse(data);
});
```

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate arbitrary;
# extern crate libfuzzer_sys;
# use rust_secure_systems_book::tlv_parser as tlv_parser;
// fuzz/fuzz_targets/tlv_roundtrip.rs
use arbitrary::Arbitrary;

#[derive(Debug, arbitrary::Arbitrary)]
struct TlvInput {
    records: Vec<(u8, Vec<u8>)>,
}

libfuzzer_sys::fuzz_target!(|input: TlvInput| {
    // Build a valid TLV message
    let mut bytes = Vec::new();
    for (tag, value) in &input.records {
        if value.len() > 1024 * 1024 { continue; }
        bytes.push(*tag);
        let len = (value.len() as u32).to_be_bytes();
        bytes.extend_from_slice(&len);
        bytes.extend_from_slice(value);
    }
    
    // Parse it back
    if let Ok(msg) = tlv_parser::TlvMessage::parse(&bytes) {
        // Roundtrip: serialize and parse again
        let re_serialized = msg.to_bytes();
        let reparsed = tlv_parser::TlvMessage::parse(&re_serialized).unwrap();
        assert_eq!(msg.records().len(), reparsed.records().len());
    }
});
```

## 18.6 Property-Based Tests

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::proptest as proptest;
# use rust_secure_systems_book::tlv_parser as tlv_parser;
// tests/tlv_properties.rs
use proptest::prelude::*;
use tlv_parser::*;

fn tlv_message_strategy() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
    proptest::collection::btree_map(
        any::<u8>().prop_filter("padding is skipped and duplicates are rejected", |tag| *tag != 0x00),
        proptest::collection::vec(any::<u8>(), 0..1024),
        0..20,
    )
    .prop_map(|records| records.into_iter().collect())
}

proptest! {
    #[test]
    fn parse_roundtrip(records in tlv_message_strategy()) {
        // Build message
        let mut bytes = Vec::new();
        for (tag, value) in &records {
            bytes.push(*tag);
            let len = (value.len() as u32).to_be_bytes();
            bytes.extend_from_slice(&len);
            bytes.extend_from_slice(value);
        }
        
        // Parse
        let msg = TlvMessage::parse(&bytes).unwrap();
        
        // Re-serialize
        let re_bytes = msg.to_bytes();
        
        // Re-parse
        let reparsed = TlvMessage::parse(&re_bytes).unwrap();
        
        assert_eq!(records.len(), reparsed.records().len());
    }
    
    #[test]
    fn parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..65536)) {
        let _ = TlvMessage::parse(&data);  // Should never panic
    }
    
    #[test]
    fn oversized_values_rejected(value in proptest::collection::vec(any::<u8>(), 1024 * 1024 + 1..1024 * 1024 + 100)) {
        let mut bytes = vec![0x01];  // tag
        let len = (value.len() as u32).to_be_bytes();
        bytes.extend_from_slice(&len);
        bytes.extend_from_slice(&value);
        
        assert!(TlvMessage::parse(&bytes).is_err());
    }
}
```

## 18.7 Summary

This parser demonstrates key security principles:

1. **Type-driven parsing**: `TlvTag` enum constrains valid tag values.
2. **Bounded allocation**: Every size field is validated against limits before allocation.
3. **Checked arithmetic**: All offset calculations use `checked_add`.
4. **No panics**: All errors return `Result`, never panic.
5. **Type-state pattern**: Protocol states are encoded in types, preventing invalid transitions.
6. **Fuzzing**: The parser is designed to be fuzzable with no panics on any input.
7. **Canonical encoding**: Duplicate non-padding tags are rejected so higher layers never guess which value "wins".
8. **Roundtrip property**: Serialization followed by parsing produces equivalent results for canonical messages.
9. **Iterative structure**: The parser avoids attacker-controlled recursion depth and the stack-overflow risk that comes with it.

In the final chapter, we cover deployment hardening—how to build, configure, and deploy Rust applications for maximum security in production.

## 18.8 Exercises

1. **Streaming Parser**: Extend the `TlvMessage` parser to support incremental (streaming) parsing — it should accept partial data, return `Incomplete` when more bytes are needed, and resume parsing when more data arrives. This is essential for TCP-based protocols where a message may arrive in multiple `read()` calls.

2. **Parser Combinators with `nom`**: Rewrite the TLV parser using the `nom` crate. Compare the code size, error quality, and performance against the hand-written parser. Discuss which approach is better for security auditing (fewer lines vs. more explicit control).

3. **Fuzzing the Parser**: Create a `cargo-fuzz` target for the `TlvMessage` parser. Run it for at least 30 minutes. If any crashes or hangs are found, minimize the input, analyze the root cause, fix the bug, and add a regression test.
