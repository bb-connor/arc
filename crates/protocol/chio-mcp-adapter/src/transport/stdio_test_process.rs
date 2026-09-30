//! Test-only subprocess transport fixtures. Production launches require cage authority.
use super::super::utils::remove_chio_auth_env;
use super::*;
use std::process::{Command, Stdio};

#[cfg(test)]
impl StdioMcpTransport {
    pub(crate) fn spawn_test_process(command: &str, args: &[&str]) -> Result<Self, AdapterError> {
        Self::spawn_test_process_with_timeouts(command, args, StdioRequestTimeouts::default())
    }
    pub(super) fn spawn_test_process_with_timeouts(
        command: &str,
        args: &[&str],
        request_timeouts: StdioRequestTimeouts,
    ) -> Result<Self, AdapterError> {
        Self::spawn_test_process_with_stdout(command, args, request_timeouts, |stdout| {
            Box::new(stdout)
        })
    }

    pub(super) fn spawn_test_process_with_stdout(
        command: &str,
        args: &[&str],
        request_timeouts: StdioRequestTimeouts,
        wrap: impl FnOnce(std::process::ChildStdout) -> Box<dyn Read + Send>,
    ) -> Result<Self, AdapterError> {
        let mut child_command = Command::new(command);
        child_command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        remove_chio_auth_env(&mut child_command);

        let mut child = child_command.spawn().map_err(|error| {
            AdapterError::ConnectionFailed(format!("failed to spawn stdio test fixture: {error}"))
        })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AdapterError::ConnectionFailed("child stdout not captured".into()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AdapterError::ConnectionFailed("child stdin not captured".into()))?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| AdapterError::ConnectionFailed("child stderr not captured".into()))?;

        Self::from_launched_process(
            ManagedChild::TestProcess(child),
            Box::new(stdin),
            wrap(stdout),
            Box::new(stderr),
            None,
            None,
            request_timeouts,
        )
    }
}
