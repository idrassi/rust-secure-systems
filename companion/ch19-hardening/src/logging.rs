use crate::security_events;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{Instrument, error, info, info_span, warn};
use tracing_subscriber::{EnvFilter, fmt};

static LOGGING_INIT: OnceLock<()> = OnceLock::new();
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventSeverity {
    Info,
    Warning,
    Critical,
}

pub fn init_logging() {
    let _ = LOGGING_INIT.get_or_init(|| {
        let subscriber = fmt()
            .json()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

pub(crate) fn sanitize_log_field(value: &str) -> String {
    value.chars().flat_map(|ch| ch.escape_default()).collect()
}

pub fn log_security_event(
    event_type: &str,
    severity: SecurityEventSeverity,
    source_ip: Option<std::net::IpAddr>,
    user_id: Option<u64>,
    details: &str,
) {
    let details = sanitize_log_field(details);

    match severity {
        SecurityEventSeverity::Info => {
            info!(
                event_type,
                source_ip = ?source_ip,
                user_id = ?user_id,
                details = %details,
                "Security event"
            );
        }
        SecurityEventSeverity::Warning => {
            warn!(
                event_type,
                source_ip = ?source_ip,
                user_id = ?user_id,
                details = %details,
                "Security event"
            );
        }
        SecurityEventSeverity::Critical => {
            error!(
                event_type,
                source_ip = ?source_ip,
                user_id = ?user_id,
                details = %details,
                "Security event"
            );
        }
    }
}

pub fn mask_token(token: &str) -> String {
    let len = token.chars().count();
    match len {
        0..=8 => "****".to_string(),
        9..=16 => {
            let prefix: String = token.chars().take(2).collect();
            let suffix: String = token.chars().skip(len - 2).collect();
            format!("{prefix}****{suffix}")
        }
        _ => {
            let prefix: String = token.chars().take(4).collect();
            let suffix: String = token.chars().skip(len - 4).collect();
            format!("{prefix}****{suffix}")
        }
    }
}

pub async fn handle_connection<S>(
    mut stream: S,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let span = info_span!(
        "connection",
        peer_addr = %addr,
        connection_id = %generate_connection_id(),
    );

    async move {
        tracing::info!("Connection accepted");

        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;

        if n > 0 {
            tracing::info!(message_size = n, "Message received");

            match process_message(&buf[..n]).await {
                Ok(response) => {
                    stream.write_all(&response).await?;
                    tracing::info!(response_size = response.len(), "Response sent");
                }
                Err(e) => {
                    log_security_event(
                        security_events::INPUT_REJECTED,
                        SecurityEventSeverity::Warning,
                        Some(addr.ip()),
                        None,
                        &format!("Message rejected: {}", e),
                    );
                    tracing::warn!(error = %e, "Message processing failed");
                }
            }
        }

        tracing::info!("Connection closed");
        Ok(())
    }
    .instrument(span)
    .await
}

async fn process_message(message: &[u8]) -> std::io::Result<Vec<u8>> {
    if message.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty message",
        ));
    }

    Ok(message.to_vec())
}

fn generate_connection_id() -> u64 {
    NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
}
