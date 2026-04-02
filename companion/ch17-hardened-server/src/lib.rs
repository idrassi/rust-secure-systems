pub mod handler;
pub mod rate_limiter;
pub mod tls;
pub mod types;

#[cfg(test)]
mod tests {
    use crate::handler::ConnectionHandler;
    use crate::rate_limiter::RateLimiter;
    use crate::types::{MAX_MESSAGE_SIZE, Message, ProtocolError, RATE_LIMIT, echo_response};
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn build_handler(
        admission_limit: usize,
        request_limit: usize,
        window: Duration,
    ) -> Arc<ConnectionHandler> {
        let admission_limiter = Arc::new(RateLimiter::new(admission_limit, window));
        let request_limiter = Arc::new(RateLimiter::new(request_limit, window));
        Arc::new(ConnectionHandler::new(admission_limiter, request_limiter))
    }

    #[test]
    fn message_validation_valid() {
        let payload = b"hello";
        let mut data = (payload.len() as u32).to_be_bytes().to_vec();
        data.extend_from_slice(payload);

        let msg = Message::from_bytes(&data).expect("message");
        assert_eq!(msg.payload(), payload);
    }

    #[test]
    fn message_validation_too_large() {
        let large_size = MAX_MESSAGE_SIZE + 1;
        let data = vec![0u8; large_size];
        assert!(Message::from_bytes(&data).is_err());
    }

    #[test]
    fn message_validation_incomplete() {
        assert!(Message::from_bytes(&[0, 0]).is_err());
    }

    #[test]
    fn zero_length_frame_rejected() {
        assert!(matches!(
            Message::from_bytes(&[0, 0, 0, 0]),
            Err(ProtocolError::EmptyMessage)
        ));
    }

    #[test]
    fn message_validation_declared_length_mismatch() {
        let mut data = 1000u32.to_be_bytes().to_vec();
        data.extend_from_slice(b"short");
        assert!(Message::from_bytes(&data).is_err());
    }

    #[test]
    fn echo_response_format() {
        let response = echo_response(b"test");
        let len = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
        assert_eq!(len, 4);
        assert_eq!(&response[4..], b"test");
    }

    #[test]
    fn empty_message_rejected() {
        assert!(matches!(
            Message::from_bytes(&[0, 0, 0, 0]),
            Err(ProtocolError::EmptyMessage)
        ));
    }

    #[test]
    fn connection_permit_releases_slot_on_drop() {
        let admission_limiter = Arc::new(RateLimiter::new(10, Duration::from_secs(60)));
        let request_limiter = Arc::new(RateLimiter::new(10, Duration::from_secs(60)));
        let handler = ConnectionHandler::new(admission_limiter, request_limiter);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);

        let permit = handler.try_admit(addr).expect("permit");
        assert_eq!(handler.connection_count(), 1);
        drop(permit);
        assert_eq!(handler.connection_count(), 0);
    }

    #[tokio::test]
    async fn handler_echoes_a_valid_message() {
        let handler = build_handler(RATE_LIMIT, RATE_LIMIT, Duration::from_secs(60));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let permit = handler.try_admit(addr).expect("permit");

        let (mut client, server) = duplex(2048);
        let server_handler = Arc::clone(&handler);
        let task = tokio::spawn(async move { server_handler.handle(server, addr, permit).await });

        let frame = echo_response(b"hello");
        client.write_all(&frame).await.expect("write");

        let mut response = vec![0u8; frame.len()];
        client.read_exact(&mut response).await.expect("read");
        assert_eq!(response, frame);

        client.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("handler");
    }

    #[tokio::test]
    async fn handler_echoes_fragmented_and_coalesced_frames() {
        let handler = build_handler(RATE_LIMIT, RATE_LIMIT, Duration::from_secs(60));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let permit = handler.try_admit(addr).expect("permit");

        let (mut client, server) = duplex(4096);
        let server_handler = Arc::clone(&handler);
        let task = tokio::spawn(async move { server_handler.handle(server, addr, permit).await });

        let frame1 = echo_response(b"alpha");
        let frame2 = echo_response(b"beta");
        let frame3 = echo_response(b"gamma");

        client.write_all(&frame1[..3]).await.expect("first chunk");
        client.write_all(&frame1[3..]).await.expect("second chunk");

        let mut combined = frame2.clone();
        combined.extend_from_slice(&frame3);
        client.write_all(&combined).await.expect("coalesced");

        let mut response1 = vec![0u8; frame1.len()];
        client.read_exact(&mut response1).await.expect("response1");
        assert_eq!(response1, frame1);

        let mut response2 = vec![0u8; frame2.len()];
        client.read_exact(&mut response2).await.expect("response2");
        assert_eq!(response2, frame2);

        let mut response3 = vec![0u8; frame3.len()];
        client.read_exact(&mut response3).await.expect("response3");
        assert_eq!(response3, frame3);

        client.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("handler");
    }

    #[tokio::test]
    async fn handler_returns_generic_error_for_invalid_messages() {
        let handler = build_handler(RATE_LIMIT, RATE_LIMIT, Duration::from_secs(60));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let permit = handler.try_admit(addr).expect("permit");

        let (mut client, server) = duplex(2048);
        let server_handler = Arc::clone(&handler);
        let task = tokio::spawn(async move { server_handler.handle(server, addr, permit).await });

        client
            .write_all(&[0, 0, 0, 0])
            .await
            .expect("write invalid frame");

        let expected = echo_response(b"invalid request");
        let mut response = vec![0u8; expected.len()];
        client.read_exact(&mut response).await.expect("read");
        assert_eq!(response, expected);

        client.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("handler");
    }

    #[tokio::test]
    async fn handler_applies_request_rate_limit_per_message() {
        let handler = build_handler(10, 2, Duration::from_secs(60));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let permit = handler.try_admit(addr).expect("permit");

        let (mut client, server) = duplex(4096);
        let server_handler = Arc::clone(&handler);
        let task = tokio::spawn(async move { server_handler.handle(server, addr, permit).await });

        let frame1 = echo_response(b"one");
        let frame2 = echo_response(b"two");
        let frame3 = echo_response(b"three");
        let mut combined = frame1.clone();
        combined.extend_from_slice(&frame2);
        combined.extend_from_slice(&frame3);
        client.write_all(&combined).await.expect("write");

        let mut response1 = vec![0u8; frame1.len()];
        client.read_exact(&mut response1).await.expect("response1");
        assert_eq!(response1, frame1);

        let mut response2 = vec![0u8; frame2.len()];
        client.read_exact(&mut response2).await.expect("response2");
        assert_eq!(response2, frame2);

        let expected = echo_response(b"rate limit exceeded");
        let mut limited = vec![0u8; expected.len()];
        client
            .read_exact(&mut limited)
            .await
            .expect("rate-limited response");
        assert_eq!(limited, expected);

        let mut eof = [0u8; 1];
        assert_eq!(client.read(&mut eof).await.expect("eof"), 0);

        task.await.expect("join").expect("handler");
    }

    #[tokio::test]
    async fn handler_counts_invalid_frames_toward_the_request_limit() {
        let handler = build_handler(10, 1, Duration::from_secs(60));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let permit = handler.try_admit(addr).expect("permit");

        let (mut client, server) = duplex(2048);
        let server_handler = Arc::clone(&handler);
        let task = tokio::spawn(async move { server_handler.handle(server, addr, permit).await });

        client
            .write_all(&[0, 0, 0, 0])
            .await
            .expect("write invalid frame 1");

        let invalid = echo_response(b"invalid request");
        let mut response = vec![0u8; invalid.len()];
        client
            .read_exact(&mut response)
            .await
            .expect("read invalid");
        assert_eq!(response, invalid);

        client
            .write_all(&[0, 0, 0, 0])
            .await
            .expect("write invalid frame 2");

        let limited = echo_response(b"rate limit exceeded");
        let mut limited_response = vec![0u8; limited.len()];
        client
            .read_exact(&mut limited_response)
            .await
            .expect("read limited");
        assert_eq!(limited_response, limited);

        let mut eof = [0u8; 1];
        assert_eq!(client.read(&mut eof).await.expect("eof"), 0);

        task.await.expect("join").expect("handler");
    }

    proptest! {
        #[test]
        fn message_roundtrip(payload in prop::collection::vec(any::<u8>(), 1..1000)) {
            let response = echo_response(&payload);
            let msg = Message::from_bytes(&response).expect("message");

            assert_eq!(msg.payload(), &payload[..]);
        }
    }
}
