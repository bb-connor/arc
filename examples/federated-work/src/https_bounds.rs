//! Bound one HTTP request before the general parser receives any plaintext.
use crate::common::Result;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const MAX_HEADERS: usize = 8192;

fn length(raw: &[u8], limit: usize) -> Result<usize> {
    if raw.len() > MAX_HEADERS || !raw.ends_with(b"\r\n\r\n") {
        return Err("invalid bounded HTTP headers".into());
    }
    let text = std::str::from_utf8(&raw[..raw.len() - 4])?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or("missing HTTP request line")?;
    if !first.ends_with(" HTTP/1.1") || first.bytes().any(|b| b.is_ascii_control()) {
        return Err("unsupported HTTP request version".into());
    }
    let is_get = first.starts_with("GET ");
    let mut size = None;
    let mut close = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b.is_ascii_control())
        {
            return Err("invalid bounded HTTP header".into());
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                let length: usize = value.parse()?;
                if size.is_some()
                    || length > limit
                    || length.to_string() != value
                    || (is_get && length != 0)
                    || (!is_get && length == 0)
                {
                    return Err("invalid bounded HTTP length".into());
                }
                size = Some(length);
            }
            "connection" => {
                if close || !value.eq_ignore_ascii_case("close") {
                    return Err("bounded HTTP requires one request per connection".into());
                }
                close = true;
            }
            "transfer-encoding" | "content-encoding" | "expect" => {
                return Err("unsupported bounded HTTP framing".into())
            }
            _ => {}
        }
    }
    if !close {
        return Err("bounded HTTP requires connection close".into());
    }
    if is_get {
        Ok(size.unwrap_or(0))
    } else {
        size.ok_or_else(|| "missing bounded HTTP length".into())
    }
}

pub(crate) async fn read(reader: &mut (impl AsyncRead + Unpin), limit: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() == MAX_HEADERS {
            return Err("HTTP headers exceed bound".into());
        }
        raw.push(reader.read_u8().await?);
    }
    let size = length(&raw, limit)?;
    let header_size = raw.len();
    raw.resize(header_size + size, 0);
    reader.read_exact(&mut raw[header_size..]).await?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_cannot_receive_unbounded_or_ambiguous_request_framing() -> Result<()> {
        let good = "POST /route HTTP/1.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n";
        assert_eq!(length(good.as_bytes(), 2)?, 2);
        for raw in [
            good.replace("Content-Length: 2", "Content-Length: 3"),
            good.replace("Content-Length: 2", "Content-Length: 02"),
            good.replace(
                "Content-Length: 2",
                "Content-Length: 2\r\nContent-Length: 2",
            ),
            good.replace(
                "Content-Length: 2",
                "Content-Length: 2\r\nTransfer-Encoding: chunked",
            ),
            good.replace("Connection: close", "Connection: keep-alive"),
            good.replace(
                "Connection: close",
                "Connection: close\r\nExpect: 100-continue",
            ),
            good.replace(
                "Connection: close",
                "Connection: close\r\nContent-Encoding: gzip",
            ),
            good.replace("HTTP/1.1", "HTTP/1.0"),
            good.replace("Content-Length", "Content-Length "),
            good.replace("Connection: close", "X-Test: a\nb\r\nConnection: close"),
            "a".repeat(MAX_HEADERS + 1),
        ] {
            assert!(length(raw.as_bytes(), 2).is_err());
        }
        Ok(())
    }

    #[test]
    fn only_one_complete_bounded_request_is_forwarded() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let first = b"POST /route HTTP/1.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
            let bytes = [first.as_slice(), first.as_slice()].concat();
            let mut input = bytes.as_slice();
            assert_eq!(read(&mut input, 2).await?, first);
            assert_eq!(input, first);
            assert!(read(&mut &first[..first.len() - 1], 2).await.is_err());
            Ok(())
        })
    }

    #[test]
    fn discovery_and_rpc_are_bounded_before_backend_parsing() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(async {
            for content_length in ["", "Content-Length: 0\r\n"] {
                let card = format!("GET /.well-known/agent-card.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{content_length}\r\n");
                assert_eq!(read(&mut card.as_bytes(), 16).await?, card.as_bytes());
            }
            for headers in [
                format!("X-Fill: {}\r\n", "a".repeat(MAX_HEADERS)),
                "X-Fill: a\r\n".repeat(MAX_HEADERS / 8),
            ] {
                let raw = format!("POST /rpc HTTP/1.1\r\n{headers}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}");
                let mut input = raw.as_bytes();
                let error = read(&mut input, 16).await.err().ok_or("oversized headers accepted")?;
                assert_eq!(error.to_string(), "HTTP headers exceed bound");
                assert_eq!(input.len(), raw.len() - MAX_HEADERS);
            }
            for raw in [
                "GET / HTTP/1.1\r\nConnection: close\r\nContent-Length: 1\r\n\r\na",
                "POST /rpc HTTP/1.1\r\nConnection: close\r\n\r\n",
            ] {
                assert!(read(&mut raw.as_bytes(), 16).await.is_err());
            }
            Ok(())
        })
    }
}
