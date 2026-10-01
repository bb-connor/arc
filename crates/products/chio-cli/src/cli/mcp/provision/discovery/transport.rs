use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RESPONSE_LINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;

pub(super) fn exchange(stdin: File, stdout: File, stderr: File) -> Result<Value, String> {
    exchange_with_timeout(stdin, stdout, stderr, DISCOVERY_TIMEOUT)
}

fn exchange_with_timeout(
    mut stdin: File,
    mut stdout: File,
    mut stderr: File,
    timeout: Duration,
) -> Result<Value, String> {
    for pipe in [&stdin, &stdout, &stderr] {
        // SAFETY: each borrowed FD remains open and owned by this function.
        let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: F_SETFL changes flags on our own live pipe descriptor.
        if flags < 0
            || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(format!(
                "could not make discovery I/O nonblocking: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params": {
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"chio-provisioner","version":env!("CARGO_PKG_VERSION")}
        }}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ];
    let mut request = serde_json::to_vec(&requests[0]).map_err(|error| error.to_string())?;
    request.push(b'\n');
    let mut after_initialize = Vec::new();
    for message in &requests[1..] {
        serde_json::to_writer(&mut after_initialize, message).map_err(|error| error.to_string())?;
        after_initialize.push(b'\n');
    }
    let mut initialized = false;
    let mut sent = 0;
    let mut line = Vec::new();
    let mut diagnostic = Vec::new();
    let deadline = Instant::now() + timeout;
    let outcome = loop {
        if Instant::now() >= deadline {
            break Err(format!(
                "the target did not answer tools/list within {timeout:?}"
            ));
        }
        if sent < request.len() {
            match stdin.write(&request[sent..]) {
                Ok(0) => {
                    break Err("the target closed its input before the MCP handshake".to_string())
                }
                Ok(count) => sent += count,
                Err(error) if retryable(&error) => {}
                Err(error) => break Err(format!("MCP handshake write failed: {error}")),
            }
        }
        let mut bytes = [0; 8192];
        if let Ok(count) = stderr.read(&mut bytes) {
            let retain = count.min(MAX_STDERR_BYTES.saturating_sub(diagnostic.len()));
            diagnostic.extend_from_slice(&bytes[..retain]);
        }
        match stdout.read(&mut bytes) {
            Ok(0) => {
                break Err("the target closed its output before answering tools/list".to_string())
            }
            Ok(count) => {
                let mut result = None;
                for byte in &bytes[..count] {
                    line.push(*byte);
                    if line.len() > MAX_RESPONSE_LINE_BYTES {
                        result = Some(Err("MCP response exceeds the size limit".to_string()));
                        break;
                    }
                    if *byte == b'\n' {
                        match parse_message(&line) {
                            Ok(None) => line.clear(),
                            Ok(Some(DiscoveryReply::Initialized)) if !initialized => {
                                initialized = true;
                                request.extend_from_slice(&after_initialize);
                                line.clear();
                            }
                            Ok(Some(DiscoveryReply::Tools(tools))) if initialized => {
                                result = Some(Ok(tools));
                                break;
                            }
                            Ok(Some(_)) => {
                                result =
                                    Some(Err("out-of-order MCP discovery response".to_string()));
                                break;
                            }
                            Err(error) => {
                                result = Some(Err(error));
                                break;
                            }
                        }
                    }
                }
                if let Some(result) = result {
                    break result;
                }
            }
            Err(error) if retryable(&error) => {
                // No reader thread can outlive the deadline, even if a legacy
                // descendant retains a pipe after its parent exits.
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => break Err(format!("MCP response read failed: {error}")),
        }
    };
    outcome.map_err(|error| {
        if diagnostic.is_empty() {
            error
        } else {
            format!(
                "{error}; target stderr: {}",
                String::from_utf8_lossy(&diagnostic).trim()
            )
        }
    })
}

fn retryable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

enum DiscoveryReply {
    Initialized,
    Tools(Value),
}

fn parse_message(line: &[u8]) -> Result<Option<DiscoveryReply>, String> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let message: Value = serde_json::from_slice(line)
        .map_err(|error| format!("the target sent invalid JSON-RPC: {error}"))?;
    let id = message.get("id").and_then(Value::as_u64);
    if !matches!(id, Some(1 | 2)) {
        return Ok(None);
    }
    if let Some(error) = message.get("error") {
        return Err(format!("the target rejected MCP discovery: {error}"));
    }
    if id == Some(2) {
        return message
            .get("result")
            .and_then(|result| result.get("tools"))
            .cloned()
            .map(|tools| Some(DiscoveryReply::Tools(tools)))
            .ok_or_else(|| "the tools/list response carries no tools array".to_string());
    }
    if !message.get("result").is_some_and(Value::is_object) {
        return Err("the initialize response carries no result".to_string());
    }
    Ok(Some(DiscoveryReply::Initialized))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn blocked_handshake_and_open_descendant_pipes_respect_the_deadline() -> std::io::Result<()> {
        let (mut stdin, _silent_target) = UnixStream::pair()?;
        stdin.set_nonblocking(true)?;
        while stdin.write(&[0; 8192]).is_ok() {}
        let (stdout, _descendant_stdout) = UnixStream::pair()?;
        let (stderr, _descendant_stderr) = UnixStream::pair()?;
        let started = Instant::now();
        let outcome = exchange_with_timeout(
            File::from(OwnedFd::from(stdin)),
            File::from(OwnedFd::from(stdout)),
            File::from(OwnedFd::from(stderr)),
            Duration::from_millis(20),
        );
        assert!(outcome.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }
}
