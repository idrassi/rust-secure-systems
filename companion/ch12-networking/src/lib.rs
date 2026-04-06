use std::io;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, timeout};

pub const MAX_CONNECTIONS: usize = 1000;
pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024;
pub const MAX_FRAME_SIZE: usize = 4 + MAX_PAYLOAD_SIZE;
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn build_frame(payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "response payload too large",
        ));
    }
    let len = payload.len() as u32;
    let mut frame = len.to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn process_message(data: &[u8]) -> io::Result<Option<(Vec<u8>, usize)>> {
    if data.len() < 4 {
        return Ok(None);
    }

    let declared_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if declared_len > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "declared message length too large",
        ));
    }

    let frame_len = 4usize
        .checked_add(declared_len)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "length overflow"))?;
    if frame_len > MAX_FRAME_SIZE {
        return Err(io::Error::new(ErrorKind::InvalidData, "frame too large"));
    }

    if data.len() < frame_len {
        return Ok(None);
    }

    Ok(Some((data[4..frame_len].to_vec(), frame_len)))
}

pub async fn handle_connection<S>(mut stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; MAX_FRAME_SIZE];
    let mut buffered = 0usize;

    loop {
        let n = timeout(READ_TIMEOUT, stream.read(&mut buffer[buffered..])).await??;

        if n == 0 {
            if buffered == 0 {
                break;
            }
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed mid-frame",
            ));
        }

        buffered += n;

        while let Some((response, consumed)) = process_message(&buffer[..buffered])? {
            let framed_response = build_frame(&response)?;
            timeout(WRITE_TIMEOUT, stream.write_all(&framed_response)).await??;

            buffered -= consumed;
            if buffered > 0 {
                buffer.copy_within(consumed..consumed + buffered, 0);
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    TooLong(usize),
    Incomplete,
}

pub fn parse_length_prefixed_message(data: &[u8]) -> Result<&[u8], ParseError> {
    if data.len() < 4 {
        return Err(ParseError::TooShort);
    }

    let declared_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if declared_len > MAX_PAYLOAD_SIZE {
        return Err(ParseError::TooLong(declared_len));
    }
    if data.len() - 4 < declared_len {
        return Err(ParseError::Incomplete);
    }

    Ok(&data[4..4 + declared_len])
}

pub fn safe_length_add(a: usize, b: usize) -> Option<usize> {
    a.checked_add(b).filter(|&sum| sum <= MAX_PAYLOAD_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn process_message_handles_partial_and_complete_frames() {
        let frame = build_frame(b"hello").expect("frame");
        assert!(process_message(&frame[..2]).unwrap().is_none());

        let (payload, consumed) = process_message(&frame).unwrap().expect("frame");
        assert_eq!(payload, b"hello");
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn coalesced_frames_are_processed_one_by_one() {
        let frame1 = build_frame(b"one").expect("frame1");
        let frame2 = build_frame(b"two").expect("frame2");
        let mut combined = frame1.clone();
        combined.extend_from_slice(&frame2);

        let (payload1, consumed1) = process_message(&combined).unwrap().expect("frame1");
        assert_eq!(payload1, b"one");

        let (payload2, consumed2) = process_message(&combined[consumed1..])
            .unwrap()
            .expect("frame2");
        assert_eq!(payload2, b"two");
        assert_eq!(consumed1 + consumed2, combined.len());
    }

    #[tokio::test]
    async fn handler_echoes_fragmented_and_coalesced_frames() {
        let (mut client, server) = duplex(1024);
        let task = tokio::spawn(async move { handle_connection(server).await });

        let frame1 = build_frame(b"alpha").expect("frame1");
        let frame2 = build_frame(b"beta").expect("frame2");

        client.write_all(&frame1[..3]).await.expect("first chunk");
        client.write_all(&frame1[3..]).await.expect("second chunk");

        let mut combined = frame2.clone();
        combined.extend_from_slice(&build_frame(b"gamma").expect("frame3"));
        client.write_all(&combined).await.expect("coalesced");

        let mut response1 = vec![0u8; frame1.len()];
        client.read_exact(&mut response1).await.expect("response1");
        assert_eq!(response1, frame1);

        let mut response2 = vec![0u8; frame2.len()];
        client.read_exact(&mut response2).await.expect("response2");
        assert_eq!(response2, frame2);

        let frame3 = build_frame(b"gamma").expect("frame3");
        let mut response3 = vec![0u8; frame3.len()];
        client.read_exact(&mut response3).await.expect("response3");
        assert_eq!(response3, frame3);

        client.shutdown().await.expect("shutdown");
        task.await.expect("join").expect("handler");
    }
}
