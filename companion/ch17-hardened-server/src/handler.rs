use crate::rate_limiter::RateLimiter;
use crate::types::{
    MAX_CONNECTIONS, MAX_MESSAGE_SIZE, MAX_SESSION_SECS, Message, ProtocolError, READ_TIMEOUT_SECS,
    WRITE_TIMEOUT_SECS, echo_response,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, timeout};

const INVALID_REQUEST_RESPONSE: &[u8] = b"invalid request";
const RATE_LIMIT_RESPONSE: &[u8] = b"rate limit exceeded";

pub struct ConnectionHandler {
    admission_limiter: Arc<RateLimiter>,
    request_limiter: Arc<RateLimiter>,
    connection_count: Arc<AtomicUsize>,
}

pub struct ConnectionPermit {
    connection_count: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.connection_count.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ConnectionHandler {
    pub fn new(admission_limiter: Arc<RateLimiter>, request_limiter: Arc<RateLimiter>) -> Self {
        Self {
            admission_limiter,
            request_limiter,
            connection_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connection_count.load(Ordering::SeqCst)
    }

    pub fn try_admit(&self, addr: SocketAddr) -> Option<ConnectionPermit> {
        let current = self.connection_count.fetch_add(1, Ordering::SeqCst);
        if current >= MAX_CONNECTIONS {
            self.connection_count.fetch_sub(1, Ordering::SeqCst);
            log::warn!("Rejecting connection from {}: limit reached", addr);
            return None;
        }

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

        let result = timeout(
            Duration::from_secs(MAX_SESSION_SECS),
            self.handle_inner(&mut stream, addr),
        )
        .await;

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
        let mut buffered = 0usize;

        loop {
            let n = timeout(
                Duration::from_secs(READ_TIMEOUT_SECS),
                stream.read(&mut buffer[buffered..]),
            )
            .await??;

            if n == 0 {
                if buffered == 0 {
                    break;
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-frame",
                )
                .into());
            }

            buffered += n;

            while buffered > 0 {
                let message = match Message::from_bytes(&buffer[..buffered]) {
                    Ok(msg) => {
                        if !self.request_limiter.check(addr.ip()) {
                            log::warn!("Per-request rate limit exceeded for {}", addr);
                            let error_response = echo_response(RATE_LIMIT_RESPONSE);
                            timeout(
                                Duration::from_secs(WRITE_TIMEOUT_SECS),
                                stream.write_all(&error_response),
                            )
                            .await??;
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "rate limit exceeded",
                            )
                            .into());
                        }
                        msg
                    }
                    Err(ProtocolError::IncompleteHeader)
                    | Err(ProtocolError::IncompleteMessage { .. }) => {
                        break;
                    }
                    Err(e) => {
                        if !self.request_limiter.check(addr.ip()) {
                            log::warn!("Per-request rate limit exceeded for {}", addr);
                            let error_response = echo_response(RATE_LIMIT_RESPONSE);
                            timeout(
                                Duration::from_secs(WRITE_TIMEOUT_SECS),
                                stream.write_all(&error_response),
                            )
                            .await??;
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "rate limit exceeded",
                            )
                            .into());
                        }

                        log::warn!("Invalid message from {}: {}", addr, e);
                        // Keep parser details in logs, not on the wire.
                        let error_response = echo_response(INVALID_REQUEST_RESPONSE);
                        timeout(
                            Duration::from_secs(WRITE_TIMEOUT_SECS),
                            stream.write_all(&error_response),
                        )
                        .await??;
                        buffered = 0;
                        break;
                    }
                };

                let response = echo_response(message.payload());
                timeout(
                    Duration::from_secs(WRITE_TIMEOUT_SECS),
                    stream.write_all(&response),
                )
                .await??;

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
