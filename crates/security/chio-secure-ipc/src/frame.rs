//! Length-prefixed frames: a four-byte big-endian length, then exactly that
//! many bytes. Every reader and writer takes an explicit limit, refuses empty
//! and oversized frames before allocating or writing, and keeps the I/O error
//! that ended a transfer so callers can tell a deadline from a hangup.

use std::io::{Read, Write};

use zeroize::{Zeroize, Zeroizing};

/// Bytes in the length prefix that precedes every frame.
pub const FRAME_PREFIX_BYTES: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame limit {maximum} is outside 1..=4294967295")]
    InvalidLimit { maximum: usize },
    #[error("frame is empty")]
    Empty,
    #[error("frame of {length} bytes exceeds the {maximum}-byte limit")]
    Oversized { length: u64, maximum: usize },
    #[error("frame prefix read failed: {0}")]
    Prefix(#[source] std::io::Error),
    #[error("frame body read failed: {0}")]
    Body(#[source] std::io::Error),
    #[error("frame write failed: {0}")]
    Write(#[source] std::io::Error),
}

impl FrameError {
    /// True when the frame length itself is refused: empty or over the limit.
    #[must_use]
    pub const fn is_length_refusal(&self) -> bool {
        matches!(self, Self::Empty | Self::Oversized { .. })
    }
}

fn validate_limit(maximum: usize) -> Result<(), FrameError> {
    if maximum == 0 || u32::try_from(maximum).is_err() {
        return Err(FrameError::InvalidLimit { maximum });
    }
    Ok(())
}

fn validate_length(length: u64, maximum: usize) -> Result<usize, FrameError> {
    validate_limit(maximum)?;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    match usize::try_from(length) {
        Ok(length) if length <= maximum => Ok(length),
        _ => Err(FrameError::Oversized { length, maximum }),
    }
}

/// Decode a received length prefix under `maximum`.
pub fn decode_frame_length(
    prefix: [u8; FRAME_PREFIX_BYTES],
    maximum: usize,
) -> Result<usize, FrameError> {
    validate_length(u64::from(u32::from_be_bytes(prefix)), maximum)
}

/// Encode the length prefix for a frame of `length` bytes under `maximum`.
pub fn encode_frame_length(
    length: usize,
    maximum: usize,
) -> Result<[u8; FRAME_PREFIX_BYTES], FrameError> {
    let declared = u64::try_from(length).unwrap_or(u64::MAX);
    let length = validate_length(declared, maximum)?;
    // A valid limit is at most `u32::MAX`, so an accepted length always fits.
    let length = u32::try_from(length).map_err(|_| FrameError::Oversized {
        length: declared,
        maximum,
    })?;
    Ok(length.to_be_bytes())
}

/// Read one length prefix and validate it under `maximum`.
pub fn read_frame_length(reader: &mut impl Read, maximum: usize) -> Result<usize, FrameError> {
    validate_limit(maximum)?;
    let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
    reader.read_exact(&mut prefix).map_err(FrameError::Prefix)?;
    decode_frame_length(prefix, maximum)
}

/// Read one frame. The body is allocated only after its length is accepted.
pub fn read_frame(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>, FrameError> {
    let length = read_frame_length(reader, maximum)?;
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).map_err(FrameError::Body)?;
    Ok(body)
}

/// Read one frame whose body may hold secret bytes. The body is allocated
/// once at its exact length and is wiped if the read fails.
pub fn read_sensitive_frame(
    reader: &mut impl Read,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let length = read_frame_length(reader, maximum)?;
    let mut body = Zeroizing::new(vec![0_u8; length]);
    read_sensitive_frame_body(reader, &mut body)?;
    Ok(body)
}

/// Fill `body` from `reader`. On failure the partial body is wiped and
/// cleared before the error returns.
pub fn read_sensitive_frame_body(
    reader: &mut impl Read,
    body: &mut Zeroizing<Vec<u8>>,
) -> Result<(), FrameError> {
    if let Err(error) = reader.read_exact(body.as_mut_slice()) {
        body.zeroize();
        return Err(FrameError::Body(error));
    }
    Ok(())
}

/// Write one frame and flush it. Nothing is written when the frame is empty
/// or over `maximum`.
pub fn write_frame(
    writer: &mut impl Write,
    frame: &[u8],
    maximum: usize,
) -> Result<(), FrameError> {
    let prefix = encode_frame_length(frame.len(), maximum)?;
    writer
        .write_all(&prefix)
        .and_then(|()| writer.write_all(frame))
        .and_then(|()| writer.flush())
        .map_err(FrameError::Write)
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
