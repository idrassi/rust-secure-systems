use thiserror::Error;

pub const MAX_CONNECTIONS: usize = 1000;
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;
pub const READ_TIMEOUT_SECS: u64 = 30;
pub const WRITE_TIMEOUT_SECS: u64 = 10;
pub const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
pub const MAX_SESSION_SECS: u64 = 300;
pub const CONNECTION_ATTEMPT_RATE_LIMIT: usize = 60;
pub const RATE_LIMIT: usize = 60;

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

        Ok(Self(data[..4 + declared_len].to_vec()))
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[4..]
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn echo_response(payload: &[u8]) -> Vec<u8> {
    debug_assert!(!payload.is_empty());
    debug_assert!(payload.len() <= MAX_MESSAGE_SIZE - 4);
    let len = payload.len() as u32;
    let mut response = len.to_be_bytes().to_vec();
    response.extend_from_slice(payload);
    response
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
