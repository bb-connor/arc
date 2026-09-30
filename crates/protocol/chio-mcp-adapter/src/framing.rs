use std::io::BufRead;

use serde_json::Value;

use crate::edge::AdapterError;

pub(crate) const MAX_STDIO_MCP_FRAME_BYTES: usize = 1024 * 1024;
// Broker structured responses encode admitted upstream bytes as JSON arrays.
// Keep the outgoing request bound independent of this response envelope budget.
pub(crate) const MAX_STDIO_MCP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Read one newline-delimited JSON-RPC frame.
///
/// Empty or whitespace-only frames are skipped. A clean EOF before any frame is
/// returned as `Ok(None)` so callers can map it to their own connection state.
/// A non-empty EOF before the newline delimiter is a parse error because MCP
/// stdio framing is line-delimited.
pub(crate) fn read_jsonrpc_frame(reader: &mut impl BufRead) -> Result<Option<Value>, AdapterError> {
    loop {
        let Some(line) = read_bounded_line(reader, MAX_STDIO_MCP_RESPONSE_BYTES)? else {
            return Ok(None);
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        return chio_core::canonical::UntrustedJsonText::from_wire(
            trimmed.as_bytes(),
            MAX_STDIO_MCP_RESPONSE_BYTES,
        )?
        .decode_signed()
        .map(Some)
        .map_err(Into::into);
    }
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    max_bytes: usize,
) -> Result<Option<String>, AdapterError> {
    let mut bytes = Vec::new();
    loop {
        let (take, has_newline, exceeds_limit) = {
            let available = reader.fill_buf().map_err(|e| {
                AdapterError::ConnectionFailed(format!("failed to read from stdout: {e}"))
            })?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                return Err(AdapterError::ParseError(
                    "MCP JSON-RPC frame ended before newline delimiter".into(),
                ));
            }

            let take = match available.iter().position(|byte| *byte == b'\n') {
                Some(index) => index + 1,
                None => available.len(),
            };
            let has_newline = available.get(take.saturating_sub(1)) == Some(&b'\n');
            let exceeds_limit = bytes.len().saturating_add(take) > max_bytes;
            if !exceeds_limit {
                bytes.extend_from_slice(&available[..take]);
            }
            (take, has_newline, exceeds_limit)
        };

        reader.consume(take);
        if exceeds_limit {
            // The connection is terminal. Draining an attacker-controlled tail
            // could block forever and would discard the original size bound.
            return Err(chio_core::canonical::UntrustedJsonError::TooLarge {
                bytes: bytes.len().saturating_add(take),
                bound: max_bytes,
            }
            .into());
        }

        if has_newline {
            break;
        }
    }

    String::from_utf8(bytes).map(Some).map_err(|error| {
        chio_core::canonical::UntrustedJsonError::NotUtf8(error.utf8_error()).into()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::BufReader;

    use super::*;

    #[test]
    fn protocol_boundary_rejects_duplicate_authority_keys() {
        let bytes = br#"{"jsonrpc":"2.0","params":{"_meta":{"chioRequestId":"first","chioRequestId":"second"}}}
"#;
        let error = read_jsonrpc_frame(&mut &bytes[..]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "urn:chio:error:attest:signed-json-invalid-input"
        );
    }

    #[test]
    fn frame_reader_returns_none_on_clean_eof() {
        let input = b"";
        let mut reader = BufReader::new(&input[..]);
        assert!(read_jsonrpc_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn frame_reader_rejects_delimiterless_non_empty_eof() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        let mut reader = BufReader::new(&input[..]);
        let err = read_jsonrpc_frame(&mut reader).unwrap_err();
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError, got: {err}"
        );
    }

    #[test]
    fn frame_reader_skips_blank_frames_before_json() {
        let input = b"\n  \r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
        let mut reader = BufReader::new(&input[..]);
        let frame = read_jsonrpc_frame(&mut reader)
            .unwrap()
            .unwrap_or_else(|| panic!("expected frame"));
        assert_eq!(frame["id"], 1);
    }

    #[test]
    fn frame_reader_rejects_oversized_frame() {
        let input = format!("{}\n", "x".repeat(MAX_STDIO_MCP_RESPONSE_BYTES + 1));
        let mut reader = BufReader::new(input.as_bytes());
        let err = read_jsonrpc_frame(&mut reader).unwrap_err();
        assert!(
            matches!(
                err,
                AdapterError::UntrustedInput(
                    chio_core::canonical::UntrustedJsonError::TooLarge { .. }
                )
            ),
            "expected ParseError, got: {err}"
        );
    }

    #[test]
    fn structured_response_can_exceed_the_request_budget() {
        let body = vec![255_u8; 524_288];
        let input = serde_json::to_string(&serde_json::json!({
            "jsonrpc":"2.0", "id":1, "result":{"structuredContent":{"body":body}}
        }))
        .unwrap()
            + "\n";
        assert!(input.len() > MAX_STDIO_MCP_FRAME_BYTES);
        let frame = read_jsonrpc_frame(&mut input.as_bytes()).unwrap().unwrap();
        assert_eq!(
            frame["result"]["structuredContent"]["body"]
                .as_array()
                .unwrap()
                .len(),
            524_288
        );
    }
}
