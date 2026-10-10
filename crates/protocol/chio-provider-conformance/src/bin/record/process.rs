//! Bounded AWS CLI capture with concurrent pipe draining and a total deadline.
use crate::RecordError;
use std::{
    process::{Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) fn capture(command: Command) -> Result<Vec<u8>, RecordError> {
    capture_with_limits(
        command,
        chio_provider_conformance::input::MAX_DOCUMENT_BYTES,
        64 * 1024,
        Duration::from_secs(60),
    )
}

fn capture_with_limits(
    mut command: Command,
    stdout_limit: usize,
    stderr_limit: usize,
    deadline: Duration,
) -> Result<Vec<u8>, RecordError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .env("AWS_PAGER", "")
        .env("AWS_CLI_AUTO_PROMPT", "off");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let mut child = command.spawn()?;
        #[cfg(unix)]
        let group = ProcessGroup(
            child
                .id()
                .and_then(|pid| i32::try_from(pid).ok())
                .and_then(rustix::process::Pid::from_raw),
        );
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("capture stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("capture stderr unavailable"))?;
        let operation = async {
            let (stdout, _) = tokio::try_join!(
                read_capped(stdout, stdout_limit),
                read_capped(stderr, stderr_limit)
            )?;
            let status = child.wait().await?;
            if !status.success() {
                return Err(RecordError::ProcessFailed {
                    code: status.code(),
                });
            }
            Ok(stdout)
        };
        let result = tokio::time::timeout(deadline, operation)
            .await
            .unwrap_or(Err(RecordError::ProcessTimeout));
        // Capture owns the entire process group, including children that closed their pipes.
        #[cfg(unix)]
        drop(group);
        if result.is_err() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
        }
        result
    })
}

async fn read_capped(
    mut reader: impl AsyncRead + Unpin,
    maximum: usize,
) -> Result<Vec<u8>, RecordError> {
    let mut output = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            return Ok(output);
        }
        if count > maximum.saturating_sub(output.len()) {
            return Err(RecordError::ProcessOutputLimit);
        }
        output.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(unix)]
struct ProcessGroup(Option<rustix::process::Pid>);
#[cfg(unix)]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn shell(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd
    }
    #[test]
    fn capture_bounds_both_pipes_and_never_echoes_failed_payloads() {
        assert!(matches!(
            capture_with_limits(shell("printf abcde"), 4, 4, Duration::from_secs(1)),
            Err(RecordError::ProcessOutputLimit)
        ));
        assert!(matches!(
            capture_with_limits(shell("printf abcde >&2"), 4, 4, Duration::from_secs(1)),
            Err(RecordError::ProcessOutputLimit)
        ));
        let error = capture_with_limits(
            shell("printf secret >&2; exit 7"),
            16,
            16,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            RecordError::ProcessFailed { code: Some(7) }
        ));
        assert!(!format!("{error:?} {error}").contains("secret"));
        assert_eq!(
            capture_with_limits(
                shell("printf ok; printf note >&2"),
                4,
                4,
                Duration::from_secs(1)
            )
            .unwrap(),
            b"ok"
        );
    }
    #[test]
    fn capture_deadline_stops_a_descendant_holding_pipes() {
        let start = std::time::Instant::now();
        assert!(matches!(
            capture_with_limits(shell("sleep 30 & wait"), 4, 4, Duration::from_millis(30)),
            Err(RecordError::ProcessTimeout)
        ));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used)]
mod descendant_tests {
    use super::*;
    #[test]
    fn closed_pipe_descendants_are_stopped_on_success_and_failure() {
        for code in [0, 7] {
            let file = tempfile::NamedTempFile::new().unwrap();
            let mut command = Command::new("sh");
            command.args([
                "-c",
                "sleep 30 >/dev/null 2>&1 & printf '%s' \"$!\" >\"$1\"; printf ok; exit \"$2\"",
                "capture-test",
            ]);
            command.arg(file.path()).arg(code.to_string());
            let result = capture_with_limits(command, 16, 16, Duration::from_secs(2));
            if code == 0 {
                assert_eq!(result.unwrap(), b"ok");
            } else {
                assert!(matches!(
                    result,
                    Err(RecordError::ProcessFailed { code: Some(7) })
                ));
            }
            let pid = std::fs::read_to_string(file.path())
                .unwrap()
                .parse::<u32>()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            loop {
                let state = std::fs::read_to_string(format!("/proc/{pid}/stat"));
                if state.as_ref().map_or(true, |line| {
                    line.split_once(") ")
                        .is_some_and(|(_, tail)| tail.starts_with('Z'))
                }) {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "capture left its descendant running"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}
