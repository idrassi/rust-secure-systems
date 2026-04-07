pub mod logging;
pub mod metrics;
#[cfg(unix)]
pub mod privileges;
pub mod secrets;
pub mod security_events;

#[cfg(test)]
mod tests {
    use crate::logging::{handle_connection, init_logging, mask_token, sanitize_log_field};
    use crate::metrics::ServerMetrics;
    use crate::secrets::{decode_secret_value, load_secret_from_file};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn mask_token_redacts_the_middle() {
        assert_eq!(mask_token("abcd1234wxyz"), "abcd****wxyz");
        assert_eq!(mask_token("åßçđ1234wxyz"), "åßçđ****wxyz");
        assert_eq!(mask_token("short"), "****");
    }

    #[test]
    fn sanitize_log_field_escapes_control_characters() {
        let sanitized = sanitize_log_field("alice\nAuthentication success\r\t");
        assert_eq!(sanitized, "alice\\nAuthentication success\\r\\t");
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
    }

    #[test]
    fn metrics_snapshot_reads_counters() {
        let metrics = ServerMetrics::new();
        metrics
            .connections_accepted
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        metrics
            .messages_processed
            .fetch_add(5, std::sync::atomic::Ordering::Relaxed);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.connections_accepted, 2);
        assert_eq!(snapshot.messages_processed, 5);
        assert_eq!(snapshot.errors, 0);
    }

    #[test]
    fn secret_decoder_parses_hex() {
        assert_eq!(
            decode_secret_value("68656c6c6f".to_string()).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn secret_file_loader_reads_bytes() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("secret.hex");
        std::fs::write(&path, b"secret-bytes").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms).expect("permissions");
        }

        let bytes = load_secret_from_file(path.to_str().expect("path")).expect("load");
        assert_eq!(bytes, b"secret-bytes");
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_loader_rejects_insecure_permissions() {
        use crate::secrets::SecretError;
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("secret.hex");
        std::fs::write(&path, b"secret-bytes").expect("write");
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&path, perms).expect("permissions");

        let error = load_secret_from_file(path.to_str().expect("path")).expect_err("reject");
        assert!(matches!(error, SecretError::InsecurePermissions { .. }));
    }

    #[tokio::test]
    async fn traced_handler_echoes_messages() {
        init_logging();

        let (mut client, server) = duplex(1024);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let task = tokio::spawn(async move { handle_connection(server, addr).await });

        client.write_all(b"ping").await.expect("write");
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.expect("read");
        assert_eq!(&response, b"ping");

        client.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("handler");
    }
}
