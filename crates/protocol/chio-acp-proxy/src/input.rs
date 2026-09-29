//! Original-byte ACP messages and bounded newline framing.
use crate::AcpProxyError;
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use std::io::BufRead;

pub const MAX_ACP_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_CAPABILITY_BYTES: usize = 64 * 1024;

/// A message validated from original peer bytes. Fields cannot bypass decoding.
#[derive(Debug)]
pub struct AcpMessage(serde_json::Value);
impl AcpMessage {
    pub fn decode(bytes: &[u8]) -> Result<Self, AcpProxyError> {
        Ok(Self(
            UntrustedJsonText::from_wire(bytes, MAX_ACP_MESSAGE_BYTES)?.decode_signed()?,
        ))
    }
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }
}

/// A framing failure permanently closes this reader. A rejected tail is never
/// interpreted as a new message, even if it contains a newline or valid JSON.
pub struct AcpFrameReader<R> {
    reader: R,
    failed: bool,
}
impl<R: BufRead> AcpFrameReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            failed: false,
        }
    }
    pub fn recv(&mut self) -> Result<Option<AcpMessage>, AcpProxyError> {
        if self.failed {
            return Err(AcpProxyError::ClosedTransport);
        }
        let result = self.read_frame();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn read_frame(&mut self) -> Result<Option<AcpMessage>, AcpProxyError> {
        let mut frame = Vec::new();
        loop {
            let bytes = self.reader.fill_buf()?;
            if bytes.is_empty() {
                return if frame.is_empty() {
                    Ok(None)
                } else {
                    Err(AcpProxyError::TruncatedFrame)
                };
            }
            let newline = bytes.iter().position(|byte| *byte == b'\n');
            let length = newline.unwrap_or(bytes.len());
            if length > MAX_ACP_MESSAGE_BYTES - frame.len() {
                return Err(UntrustedJsonError::TooLarge {
                    bytes: MAX_ACP_MESSAGE_BYTES + 1,
                    bound: MAX_ACP_MESSAGE_BYTES,
                }
                .into());
            }
            frame.extend_from_slice(&bytes[..length]);
            self.reader.consume(length + usize::from(newline.is_some()));
            if newline.is_some() {
                return AcpMessage::decode(&frame).map(Some);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::{
        error::Error,
        io::{BufReader, Cursor},
    };
    #[test]
    fn original_duplicates_and_malformed_bytes_retain_redacted_sources() {
        for bytes in [br#"{"secret_marker":1,"secret_marker":2}"#.as_slice(), b"{"] {
            let error = AcpMessage::decode(bytes).unwrap_err();
            assert!(error.source().is_some());
            assert!(!format!("{error:?} {error}").contains("secret_marker"));
        }
        assert_eq!(
            AcpMessage::decode(br#"{"id":18446744073709551615}"#)
                .unwrap()
                .as_value()["id"]
                .as_u64(),
            Some(u64::MAX)
        );
    }
    #[test]
    fn rejected_frames_poison_reader_without_reinterpreting_tail() {
        for input in [
            b"\n{}\n".to_vec(),
            b"{\n{}\n".to_vec(),
            vec![b' '; MAX_ACP_MESSAGE_BYTES + 1],
        ] {
            let mut reader = AcpFrameReader::new(BufReader::with_capacity(7, Cursor::new(input)));
            assert!(matches!(
                reader.recv(),
                Err(AcpProxyError::UntrustedInput(_))
            ));
            assert!(matches!(reader.recv(), Err(AcpProxyError::ClosedTransport)));
        }
    }
    #[test]
    fn complete_frames_and_clean_eof_are_distinct_from_truncation() {
        let mut reader = AcpFrameReader::new(Cursor::new(b"{}\n{}\r\n"));
        assert!(reader.recv().unwrap().is_some());
        assert!(reader.recv().unwrap().is_some());
        assert!(reader.recv().unwrap().is_none());
        assert!(matches!(
            AcpFrameReader::new(Cursor::new(b"{}")).recv(),
            Err(AcpProxyError::TruncatedFrame)
        ));
    }
}

pub(crate) fn encode(value: &serde_json::Value) -> Result<Vec<u8>, AcpProxyError> {
    struct Bounded {
        bytes: Vec<u8>,
        oversized: bool,
    }
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_ACP_MESSAGE_BYTES - self.bytes.len() {
                self.oversized = true;
                return Err(std::io::Error::other("ACP frame limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded {
        bytes: Vec::new(),
        oversized: false,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if writer.oversized {
        return Err(UntrustedJsonError::TooLarge {
            bytes: MAX_ACP_MESSAGE_BYTES + 1,
            bound: MAX_ACP_MESSAGE_BYTES,
        }
        .into());
    }
    result.map_err(UntrustedJsonError::Decode)?;
    Ok(writer.bytes)
}
