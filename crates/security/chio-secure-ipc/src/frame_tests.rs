use std::io::{Cursor, ErrorKind, Read, Write};

use chio_test_support::prelude::*;
use zeroize::Zeroizing;

use super::*;

const LIMIT: usize = 16;

fn framed(declared: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = declared.to_be_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

/// A reader or writer that fails every call with one error kind.
struct Failing(ErrorKind);

impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(self.0))
    }
}

impl Write for Failing {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(self.0))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::from(self.0))
    }
}

#[test]
fn a_frame_at_the_limit_round_trips_and_consumes_only_itself() {
    let body = [7_u8; LIMIT];
    let mut encoded = Vec::new();
    write_frame(&mut encoded, &body, LIMIT).test_unwrap();
    assert_eq!(encoded, framed(16, &body));
    encoded.extend_from_slice(b"next");
    let mut reader = Cursor::new(encoded);
    assert_eq!(read_frame(&mut reader, LIMIT).test_unwrap(), body);
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).test_unwrap();
    assert_eq!(rest, b"next");
}

#[test]
fn an_empty_frame_is_refused_on_read_and_write() {
    assert!(matches!(
        read_frame(&mut Cursor::new(framed(0, b"")), LIMIT),
        Err(FrameError::Empty)
    ));
    let mut written = Vec::new();
    assert!(matches!(
        write_frame(&mut written, b"", LIMIT),
        Err(FrameError::Empty)
    ));
    assert!(written.is_empty());
}

#[test]
fn a_frame_one_byte_over_the_limit_is_refused_before_its_body_is_read() {
    let mut reader = Cursor::new(framed(17, &[1_u8; 17]));
    assert!(matches!(
        read_frame(&mut reader, LIMIT),
        Err(FrameError::Oversized {
            length: 17,
            maximum: LIMIT
        })
    ));
    assert_eq!(reader.position(), 4);

    let mut written = Vec::new();
    assert!(matches!(
        write_frame(&mut written, &[1_u8; 17], LIMIT),
        Err(FrameError::Oversized {
            length: 17,
            maximum: LIMIT
        })
    ));
    assert!(written.is_empty());
}

#[test]
fn the_largest_declared_length_is_refused_without_allocating_it() {
    let result = read_sensitive_frame(&mut Cursor::new(u32::MAX.to_be_bytes()), LIMIT);
    assert!(matches!(
        result,
        Err(FrameError::Oversized {
            length: 4_294_967_295,
            maximum: LIMIT
        })
    ));
}

#[test]
fn limits_outside_the_prefix_range_are_refused_before_any_io() {
    let mut reader = Cursor::new(framed(1, b"x"));
    assert!(matches!(
        read_frame(&mut reader, 0),
        Err(FrameError::InvalidLimit { maximum: 0 })
    ));
    assert_eq!(reader.position(), 0);
    let mut written = Vec::new();
    assert!(matches!(
        write_frame(&mut written, b"x", 0),
        Err(FrameError::InvalidLimit { maximum: 0 })
    ));
    assert!(written.is_empty());
    if let Some(beyond) = usize::try_from(u32::MAX)
        .ok()
        .and_then(|limit| limit.checked_add(1))
    {
        assert!(matches!(
            read_frame_length(&mut Cursor::new(framed(1, b"x")), beyond),
            Err(FrameError::InvalidLimit { maximum }) if maximum == beyond
        ));
        assert!(matches!(
            encode_frame_length(1, beyond),
            Err(FrameError::InvalidLimit { maximum }) if maximum == beyond
        ));
    }
}

#[test]
fn a_truncated_prefix_and_body_keep_their_io_error() {
    assert!(matches!(
        read_frame(&mut Cursor::new([0_u8, 0]), LIMIT),
        Err(FrameError::Prefix(error)) if error.kind() == ErrorKind::UnexpectedEof
    ));
    assert!(matches!(
        read_frame(&mut Cursor::new(framed(3, b"ab")), LIMIT),
        Err(FrameError::Body(error)) if error.kind() == ErrorKind::UnexpectedEof
    ));
    assert!(matches!(
        read_frame(&mut Failing(ErrorKind::WouldBlock), LIMIT),
        Err(FrameError::Prefix(error)) if error.kind() == ErrorKind::WouldBlock
    ));
    assert!(matches!(
        write_frame(&mut Failing(ErrorKind::BrokenPipe), b"x", LIMIT),
        Err(FrameError::Write(error)) if error.kind() == ErrorKind::BrokenPipe
    ));
}

#[test]
fn a_failed_sensitive_body_read_wipes_the_partial_body() {
    let mut body = Zeroizing::new(vec![0xaa_u8; 8]);
    let result = read_sensitive_frame_body(&mut Cursor::new(b"secret"), &mut body);
    assert!(matches!(
        result,
        Err(FrameError::Body(error)) if error.kind() == ErrorKind::UnexpectedEof
    ));
    assert!(body.is_empty());

    let frame = read_sensitive_frame(&mut Cursor::new(framed(6, b"secret")), LIMIT).test_unwrap();
    assert_eq!(frame.as_slice(), b"secret");
    assert_eq!(frame.capacity(), frame.len());
}

#[test]
fn prefix_encoding_and_decoding_agree_at_the_bounds() {
    for length in [1, LIMIT] {
        let prefix = encode_frame_length(length, LIMIT).test_unwrap();
        assert_eq!(decode_frame_length(prefix, LIMIT).test_unwrap(), length);
    }
    assert!(FrameError::Empty.is_length_refusal());
    assert!(FrameError::Oversized {
        length: 17,
        maximum: LIMIT
    }
    .is_length_refusal());
    assert!(!FrameError::InvalidLimit { maximum: 0 }.is_length_refusal());
}
