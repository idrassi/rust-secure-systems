#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

// This crate exists so mdBook snippet tests can resolve the external crates
// used throughout the manuscript.

pub mod deps {
    pub use aes_gcm;
    pub use anyhow;
    pub use arbitrary;
    pub use argon2;
    pub use bindgen;
    pub use bytes;
    pub use cbindgen;
    pub use cc;
    pub use crossbeam_channel;
    pub use ed25519_dalek;
    pub use env_logger;
    pub use hex;
    pub use libc;
    pub use libfuzzer_sys;
    pub use log;
    pub use loom;
    pub use password_hash;
    pub use proptest;
    pub use quickcheck_macros;
    pub use rand;
    pub use rand_core;
    pub use ring;
    pub use rustls;
    pub use secrecy;
    pub use serde;
    pub use serde_json;
    pub use sha2;
    pub use subtle;
    pub use thiserror;
    pub use tokio;
    pub use tokio_rustls;
    pub use tokio_util;
    pub use tracing;
    pub use tracing_subscriber;
    pub use wasmtime;
    pub use webpki_roots;
    pub use windows_sys;
    pub use x25519_dalek;
    pub use zerocopy;
    pub use zeroize;
}

// Re-export `thiserror` at the crate root so doctests can alias this helper
// crate as `thiserror` when demonstrating `#[derive(Error)]`.
pub use deps::thiserror::*;

pub mod companion {
    pub use ch12_networking;
    pub use ch17_hardened_server;
    pub use ch19_hardening;
}

pub mod my_secure_app {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AuthError {
        InvalidCredentials,
        MalformedMessage,
        InvalidPacket,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ValidationError {
        Empty,
        TooLong,
        InvalidCharacters,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Session {
        valid: bool,
    }

    impl Session {
        pub fn new() -> Self {
            Self { valid: true }
        }

        pub fn is_valid(&self) -> bool {
            self.valid
        }
    }

    impl Default for Session {
        fn default() -> Self {
            Self::new()
        }
    }

    pub struct Authenticator;

    impl Authenticator {
        pub fn new() -> Self {
            Self
        }

        pub fn authenticate(&self, username: &str, password: &str) -> Result<Session, AuthError> {
            if username == "admin" && password == "correct_password" {
                Ok(Session::new())
            } else {
                Err(AuthError::InvalidCredentials)
            }
        }
    }

    impl Default for Authenticator {
        fn default() -> Self {
            Self::new()
        }
    }

    pub fn validate_username(username: &str) -> Result<(), ValidationError> {
        if username.is_empty() {
            return Err(ValidationError::Empty);
        }
        if username.len() > 64 {
            return Err(ValidationError::TooLong);
        }
        if !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(ValidationError::InvalidCharacters);
        }
        Ok(())
    }

    pub fn parse_message(data: &[u8]) -> Result<(), AuthError> {
        if data.is_empty() {
            return Err(AuthError::MalformedMessage);
        }
        if data.len() > 64 * 1024 {
            return Err(AuthError::InvalidPacket);
        }
        Ok(())
    }

    pub fn parse_packet(raw: &[u8]) -> Result<(), AuthError> {
        if raw.len() < 4 {
            return Err(AuthError::InvalidPacket);
        }

        let declared_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        if raw.len() - 4 != declared_len {
            return Err(AuthError::InvalidPacket);
        }

        Ok(())
    }

    pub fn authenticate(username: &str, password: &[u8]) -> Result<Session, AuthError> {
        if username == "known_user" && password == b"correct_password" {
            Ok(Session::new())
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader {
    pub name: String,
    pub value: String,
}

pub fn parse_http_header(line: &str) -> Option<ParsedHeader> {
    let (name, value) = line.split_once(':')?;
    Some(ParsedHeader {
        name: name.to_string(),
        value: value.trim_start().to_string(),
    })
}

#[derive(Default)]
pub struct TestServer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestServerError;

impl TestServer {
    pub fn new() -> Self {
        Self
    }

    pub fn process<T>(&mut self, _action: T) -> Result<(), TestServerError> {
        Ok(())
    }
}

pub mod tlv_parser {
    pub const MAX_VALUE_SIZE: usize = 1024 * 1024;
    pub const MAX_TOTAL_SIZE: usize = 16 * 1024 * 1024;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ParseError {
        MessageTooLarge { size: usize, max: usize },
        ValueTooLarge { size: usize, max: usize },
        IncompleteHeader { offset: usize },
        IncompleteValue { expected: usize, available: usize },
        DuplicateTag { tag: u8 },
        IntegerOverflow,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TlvRecord {
        tag: u8,
        value: Vec<u8>,
    }

    impl TlvRecord {
        pub fn new(tag: u8, value: Vec<u8>) -> Result<Self, ParseError> {
            if value.len() > MAX_VALUE_SIZE {
                return Err(ParseError::ValueTooLarge {
                    size: value.len(),
                    max: MAX_VALUE_SIZE,
                });
            }

            Ok(Self { tag, value })
        }

        pub fn tag(&self) -> u8 {
            self.tag
        }

        pub fn value(&self) -> &[u8] {
            &self.value
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(5 + self.value.len());
            bytes.push(self.tag);
            bytes.extend_from_slice(&(self.value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&self.value);
            bytes
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TlvMessage {
        records: Vec<TlvRecord>,
    }

    impl TlvMessage {
        pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
            if data.len() > MAX_TOTAL_SIZE {
                return Err(ParseError::MessageTooLarge {
                    size: data.len(),
                    max: MAX_TOTAL_SIZE,
                });
            }

            let mut offset = 0usize;
            let mut records = Vec::new();

            while offset < data.len() {
                if offset.checked_add(5).ok_or(ParseError::IntegerOverflow)? > data.len() {
                    return Err(ParseError::IncompleteHeader { offset });
                }

                let tag = data[offset];
                offset += 1;

                let len = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as usize;
                offset += 4;

                if len > MAX_VALUE_SIZE {
                    return Err(ParseError::ValueTooLarge {
                        size: len,
                        max: MAX_VALUE_SIZE,
                    });
                }

                let end = offset.checked_add(len).ok_or(ParseError::IntegerOverflow)?;
                if end > data.len() {
                    return Err(ParseError::IncompleteValue {
                        expected: end,
                        available: data.len(),
                    });
                }

                if tag != 0x00 {
                    if records.iter().any(|record: &TlvRecord| record.tag == tag) {
                        return Err(ParseError::DuplicateTag { tag });
                    }
                    records.push(TlvRecord::new(tag, data[offset..end].to_vec())?);
                }
                offset = end;
            }

            Ok(Self { records })
        }

        pub fn records(&self) -> &[TlvRecord] {
            &self.records
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            for record in &self.records {
                bytes.extend_from_slice(&record.to_bytes());
            }
            bytes
        }
    }
}

pub mod zerocopy_examples {
    use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

    #[repr(C)]
    #[derive(Debug, Clone, Copy, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
    pub struct TcpHeader {
        pub src_port: u16,
        pub dst_port: u16,
        pub seq_num: u32,
        pub ack_num: u32,
        pub data_offset: u8,
        pub flags: u8,
        pub window_size: u16,
        pub checksum: u16,
        pub urgent_ptr: u16,
    }
}
