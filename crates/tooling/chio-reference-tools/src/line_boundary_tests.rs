use super::*;
use std::io::{BufReader, Cursor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Echo;

impl ToolServer for Echo {
    fn name(&self) -> &str {
        "boundary-echo"
    }

    fn version(&self) -> &str {
        "1"
    }

    fn tools(&self) -> Vec<ToolDescriptor> {
        vec![ToolDescriptor {
            name: "echo",
            description: "Return the message",
            input_schema: json!({"type": "object"}),
            read_only: true,
        }]
    }

    fn call(&mut self, _name: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::text(string_argument(arguments, "message")?))
    }
}

fn padded_request(length: usize) -> TestResult<Vec<u8>> {
    let mut request = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "pad": ""});
    let base = serde_json::to_vec(&request)?.len();
    let padding = length.checked_sub(base).ok_or("request length too short")?;
    request["pad"] = Value::String("x".repeat(padding));
    let bytes = serde_json::to_vec(&request)?;
    assert_eq!(bytes.len(), length);
    Ok(bytes)
}

fn responses(input: Vec<u8>, capacity: usize) -> TestResult<Vec<Value>> {
    let mut output = Vec::new();
    serve(
        Echo,
        BufReader::with_capacity(capacity, Cursor::new(input)),
        &mut output,
    )?;
    String::from_utf8(output)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn append_echo(input: &mut Vec<u8>) -> TestResult {
    input.extend(serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "preserved"}}
    }))?);
    input.push(b'\n');
    Ok(())
}

fn assert_oversize_then_echo(actual: &[Value]) {
    assert_eq!(
        actual,
        &[
            error_response(
                Value::Null,
                PARSE_ERROR,
                "request line exceeds the size limit"
            ),
            result_response(
                json!(2),
                json!({"content": [{"type": "text", "text": "preserved"}], "isError": false}),
            ),
        ],
        "reject only the oversized frame and preserve the next request"
    );
}

#[test]
fn oversized_line_with_delimiter_in_limit_read_preserves_next_request() -> TestResult {
    for capacity in [7, 4096, MAX_LINE_BYTES + 128] {
        let mut input = padded_request(MAX_LINE_BYTES)?;
        input.push(b'\n');
        append_echo(&mut input)?;
        assert_oversize_then_echo(&responses(input, capacity)?);
    }
    Ok(())
}

#[test]
fn fragmented_oversized_line_drains_only_its_remaining_frame() -> TestResult {
    for capacity in [7, 4096] {
        let mut input = padded_request(MAX_LINE_BYTES * 2 + 17)?;
        input.push(b'\n');
        append_echo(&mut input)?;
        assert_oversize_then_echo(&responses(input, capacity)?);
    }
    Ok(())
}

#[test]
fn exact_line_limit_and_eof_preserve_normal_requests() -> TestResult {
    for (length, newline) in [(MAX_LINE_BYTES - 1, true), (MAX_LINE_BYTES, false)] {
        let mut input = padded_request(length)?;
        if newline {
            input.push(b'\n');
            append_echo(&mut input)?;
        }
        let actual = responses(input, 4096)?;
        assert_eq!(actual.first(), Some(&result_response(json!(1), json!({}))));
        assert_eq!(actual.len(), if newline { 2 } else { 1 });
        if newline {
            assert_eq!(actual[1]["id"], 2);
            assert_eq!(actual[1]["result"]["content"][0]["text"], "preserved");
        }
    }
    Ok(())
}

#[test]
fn oversized_eof_emits_one_refusal_without_an_extra_frame() -> TestResult {
    for length in [MAX_LINE_BYTES + 1, MAX_LINE_BYTES * 2 + 17] {
        assert_eq!(
            responses(padded_request(length)?, 4096)?,
            vec![error_response(
                Value::Null,
                PARSE_ERROR,
                "request line exceeds the size limit"
            )]
        );
    }
    assert!(responses(Vec::new(), 7)?.is_empty());
    assert!(responses(b"\n \t\n".to_vec(), 7)?.is_empty());
    Ok(())
}
