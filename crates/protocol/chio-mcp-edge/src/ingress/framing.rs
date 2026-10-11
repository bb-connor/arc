use crate::AdapterError;
use serde_json::Value;
use std::io::BufRead;

pub(crate) fn read_bounded_line(
    reader: &mut impl BufRead,
    bound: usize,
) -> Result<Option<String>, AdapterError> {
    let mut bytes = Vec::new();
    loop {
        let (take, newline, excessive) = {
            let available = reader.fill_buf().map_err(|error| {
                AdapterError::ConnectionFailed(format!("failed to read MCP frame: {error}"))
            })?;
            if available.is_empty() {
                return if bytes.is_empty() {
                    Ok(None)
                } else {
                    Err(AdapterError::ParseError(
                        "MCP frame ended before newline delimiter".into(),
                    ))
                };
            }
            let take = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |position| position + 1);
            let excessive = bytes.len().saturating_add(take) > bound;
            if !excessive {
                bytes.extend_from_slice(&available[..take]);
            }
            (
                take,
                available.get(take.saturating_sub(1)) == Some(&b'\n'),
                excessive,
            )
        };
        reader.consume(take);
        if excessive {
            return Err(chio_core::canonical::UntrustedJsonError::TooLarge {
                bytes: bytes.len().saturating_add(take),
                bound,
            }
            .into());
        }
        if newline {
            break;
        }
    }
    String::from_utf8(bytes).map(Some).map_err(|error| {
        chio_core::canonical::UntrustedJsonError::NotUtf8(error.utf8_error()).into()
    })
}

pub(super) fn read_document_frame_with_admission<T>(
    reader: &mut impl BufRead,
    bound: usize,
    mut admit: impl FnMut(&str) -> Result<T, AdapterError>,
) -> Result<Option<(Value, T)>, AdapterError> {
    loop {
        let Some(line) = read_bounded_line(reader, bound)? else {
            return Ok(None);
        };
        if line.trim().is_empty() {
            continue;
        }
        let reservation = admit(&line)?;
        let value =
            chio_core::canonical::UntrustedJsonText::from_wire(line.trim().as_bytes(), bound)?
                .decode_document()?;
        return Ok(Some((value, reservation)));
    }
}
