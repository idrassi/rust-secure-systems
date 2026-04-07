use ch17_hardened_server::handler::ConnectionHandler;
use ch17_hardened_server::rate_limiter::RateLimiter;
use ch17_hardened_server::tls;
use ch17_hardened_server::types;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let admission_limiter = Arc::new(RateLimiter::new(
        types::CONNECTION_ATTEMPT_RATE_LIMIT,
        std::time::Duration::from_secs(60),
        types::MAX_TRACKED_CLIENTS,
    ));
    let request_limiter = Arc::new(RateLimiter::new(
        types::RATE_LIMIT,
        std::time::Duration::from_secs(60),
        types::MAX_TRACKED_CLIENTS,
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

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    let cleanup_admission_limiter = Arc::clone(&admission_limiter);
    let cleanup_request_limiter = Arc::clone(&request_limiter);
    let mut cleanup_shutdown = shutdown_rx.clone();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    cleanup_admission_limiter.cleanup();
                    cleanup_request_limiter.cleanup();
                }
                changed = cleanup_shutdown.changed() => {
                    if changed.is_err() || *cleanup_shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    });

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;

            result = &mut shutdown => {
                result?;
                log::info!("Shutdown signal received; stopping new accepts");
                break;
            }

            accepted = listener.accept() => {
                let (stream, addr) = accepted?;
                if let Err(e) = stream.set_nodelay(true) {
                    log::warn!("Failed to configure TCP_NODELAY for {}: {}", addr, e);
                    continue;
                }

                let Some(permit) = handler.try_admit(addr) else {
                    continue;
                };

                let handler = Arc::clone(&handler);
                let tls_acceptor = tls_acceptor.clone();

                tasks.spawn(async move {
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
    }

    drop(listener);
    let _ = shutdown_tx.send(true);

    match timeout(
        Duration::from_secs(types::SHUTDOWN_GRACE_SECS),
        wait_for_tasks(&mut tasks),
    )
    .await
    {
        Ok(()) => log::info!("Shutdown completed cleanly"),
        Err(_) => {
            log::warn!(
                "Graceful shutdown timed out after {}s; aborting remaining tasks",
                types::SHUTDOWN_GRACE_SECS
            );
            tasks.abort_all();
            wait_for_tasks(&mut tasks).await;
        }
    }

    Ok(())
}

async fn wait_for_tasks(tasks: &mut JoinSet<()>) {
    while let Some(result) = tasks.join_next().await {
        if let Err(e) = result {
            if e.is_cancelled() {
                log::info!("Task cancelled during shutdown");
            } else {
                log::error!("Task failed during shutdown: {}", e);
            }
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}
