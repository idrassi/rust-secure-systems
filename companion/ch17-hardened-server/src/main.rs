use ch17_hardened_server::handler::ConnectionHandler;
use ch17_hardened_server::rate_limiter::RateLimiter;
use ch17_hardened_server::tls;
use ch17_hardened_server::types;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let admission_limiter = Arc::new(RateLimiter::new(
        types::CONNECTION_ATTEMPT_RATE_LIMIT,
        std::time::Duration::from_secs(60),
    ));
    let request_limiter = Arc::new(RateLimiter::new(
        types::RATE_LIMIT,
        std::time::Duration::from_secs(60),
    ));
    let handler = Arc::new(ConnectionHandler::new(
        Arc::clone(&admission_limiter),
        Arc::clone(&request_limiter),
    ));

    let cert_path = std::env::var("TLS_CERT_PATH")
        .map_err(|_| "TLS_CERT_PATH must be set for the hardened server")?;
    let key_path = std::env::var("TLS_KEY_PATH")
        .map_err(|_| "TLS_KEY_PATH must be set for the hardened server")?;
    let config = tls::create_server_config(&cert_path, &key_path)?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(config);

    let listener = TcpListener::bind("0.0.0.0:8443").await?;
    log::info!("Server listening on 0.0.0.0:8443 with TLS enabled");

    let cleanup_admission_limiter = Arc::clone(&admission_limiter);
    let cleanup_request_limiter = Arc::clone(&request_limiter);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_admission_limiter.cleanup();
            cleanup_request_limiter.cleanup();
        }
    });

    loop {
        let (stream, addr) = listener.accept().await?;
        if let Err(e) = stream.set_nodelay(true) {
            log::warn!("Failed to configure TCP_NODELAY for {}: {}", addr, e);
            continue;
        }

        let Some(permit) = handler.try_admit(addr) else {
            continue;
        };

        let handler = Arc::clone(&handler);
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let tls_stream = match timeout(
                Duration::from_secs(types::TLS_HANDSHAKE_TIMEOUT_SECS),
                tls_acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(tls_stream)) => {
                    log::info!("TLS handshake completed for {}", addr);
                    tls_stream
                }
                Ok(Err(e)) => {
                    log::error!("TLS handshake failed for {}: {}", addr, e);
                    return;
                }
                Err(_) => {
                    log::warn!("TLS handshake timeout for {}", addr);
                    return;
                }
            };

            if let Err(e) = handler.handle(tls_stream, addr, permit).await {
                log::error!("Fatal error for {}: {}", addr, e);
            }
        });
    }
}
