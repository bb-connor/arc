use std::io::BufRead;

use serde_json::Value;

use crate::AdapterError;

pub(crate) const MAX_STDIO_MCP_FRAME_BYTES: usize = 1024 * 1024;

/// Read one newline-delimited JSON-RPC frame from MCP stdio input.
///
/// Empty frames are skipped. Clean EOF before any bytes returns `Ok(None)` so
/// the caller can close the session. EOF after partial bytes is a parse error
/// because MCP stdio frames are newline-delimited.
pub(crate) fn read_jsonrpc_frame(reader: &mut impl BufRead) -> Result<Option<Value>, AdapterError> {
    loop {
        let Some(line) = read_bounded_line(reader, MAX_STDIO_MCP_FRAME_BYTES)? else {
            return Ok(None);
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        return chio_core::canonical::UntrustedJsonText::from_wire(
            trimmed.as_bytes(),
            MAX_STDIO_MCP_FRAME_BYTES,
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
            let available = reader.fill_buf().map_err(|error| {
                AdapterError::ConnectionFailed(format!("failed to read MCP edge request: {error}"))
            })?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                return Err(AdapterError::ParseError(
                    "MCP edge JSON-RPC frame ended before newline delimiter".to_string(),
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
        let mut reader = BufReader::new(&b""[..]);
        assert!(read_jsonrpc_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn frame_reader_rejects_non_empty_eof_before_newline() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
        let mut reader = BufReader::new(&input[..]);
        let err = read_jsonrpc_frame(&mut reader).unwrap_err();
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError, got: {err}"
        );
    }

    #[test]
    fn frame_reader_skips_blank_lines_before_frame() {
        let input = b"\n  \r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut reader = BufReader::new(&input[..]);
        let frame = read_jsonrpc_frame(&mut reader)
            .unwrap()
            .unwrap_or_else(|| panic!("expected frame"));
        assert_eq!(frame["method"], "ping");
    }

    #[test]
    fn frame_reader_rejects_oversized_frame() {
        let input = format!("{}\n", "x".repeat(MAX_STDIO_MCP_FRAME_BYTES + 1));
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
    fn protocol_boundary_oversized_frame_refuses_without_draining_tail() {
        let input = vec![b'x'; MAX_STDIO_MCP_FRAME_BYTES + 50];
        let mut reader = BufReader::with_capacity(1, input.as_slice());
        let error = read_jsonrpc_frame(&mut reader).unwrap_err();
        assert!(matches!(
            error,
            AdapterError::UntrustedInput(chio_core::canonical::UntrustedJsonError::TooLarge { .. })
        ));
        assert_eq!(reader.buffer(), b"");
        assert_eq!(
            reader.get_ref().len(),
            49,
            "reader drained attacker-controlled tail"
        );
    }
}
