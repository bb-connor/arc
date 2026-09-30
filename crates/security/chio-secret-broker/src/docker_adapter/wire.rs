//! Bounded Docker Engine HTTP upgrade and multiplexed output framing.
use super::*;
use std::io::BufRead;

pub(super) fn send(
    stream: &mut impl Write,
    version: &str,
    method: &str,
    path: &str,
    body: &Value,
    upgrade: bool,
) -> Result<()> {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        canonical_json_bytes(body)?
    };
    let connection = if upgrade {
        "Connection: Upgrade\r\nUpgrade: tcp"
    } else {
        "Connection: close"
    };
    let head = format!("{method} /{version}{path} HTTP/1.1\r\nHost: docker\r\n{connection}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", bytes.len());
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&bytes))
        .and_then(|()| stream.flush())
        .map_err(|_| unavailable())
}

pub(super) fn read_output(reader: &mut impl BufRead, maximum: usize) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16_384 {
            return Err(unavailable());
        }
        let mut byte = [0];
        reader.read_exact(&mut byte).map_err(|_| unavailable())?;
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head).map_err(|_| unavailable())?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("HTTP/1.1 101 UPGRADED") {
        return Err(unavailable());
    }
    let mut headers = std::collections::BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(unavailable)?;
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_ascii_lowercase())
            .is_some()
        {
            return Err(unavailable());
        }
    }
    if headers.get("upgrade").map(String::as_str) != Some("tcp")
        || headers.get("connection").map(String::as_str) != Some("upgrade")
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("content-length")
    {
        return Err(unavailable());
    }
    let mut output = Vec::new();
    loop {
        let mut frame = [0; 8];
        let first = reader.read(&mut frame[..1]).map_err(|_| unavailable())?;
        if first == 0 {
            return Ok(output);
        }
        reader
            .read_exact(&mut frame[1..])
            .map_err(|_| unavailable())?;
        if !matches!(frame[0], 1 | 2) || frame[1..4] != [0; 3] {
            return Err(unavailable());
        }
        let size = usize::try_from(u32::from_be_bytes(
            frame[4..8].try_into().map_err(|_| unavailable())?,
        ))
        .map_err(|_| unavailable())?;
        if size == 0 || size > maximum.saturating_sub(output.len()) {
            return Err(unavailable());
        }
        let start = output.len();
        output.resize(start + size, 0);
        reader
            .read_exact(output.get_mut(start..).ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stream() -> Vec<u8> {
        let mut bytes =
            b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n".to_vec();
        bytes.extend([1, 0, 0, 0, 0, 0, 0, 3]);
        bytes.extend(b"one");
        bytes.extend([2, 0, 0, 0, 0, 0, 0, 3]);
        bytes.extend(b"two");
        bytes
    }
    #[test]
    fn complete_frames_keep_both_streams_and_incomplete_output_never_completes() -> Result<()> {
        let bytes = stream();
        assert_eq!(read_output(&mut bytes.as_slice(), 6)?, b"onetwo");
        assert!(matches!(
            read_output(&mut bytes.as_slice(), 5),
            Err(BrokerError::Upstream(_))
        ));
        for truncated in [1, 3, 7, 10] {
            assert!(matches!(
                read_output(&mut &bytes[..bytes.len() - truncated], 6),
                Err(BrokerError::Upstream(_))
            ));
        }
        let mut unknown = bytes.clone();
        let start = unknown
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(unavailable)?
            + 4;
        unknown[start] = 3;
        assert!(matches!(
            read_output(&mut unknown.as_slice(), 6),
            Err(BrokerError::Upstream(_))
        ));
        Ok(())
    }
}
