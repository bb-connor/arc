use std::io::{BufReader, Write};
use std::process::{Child, Command, Stdio};

/// Manages the stdio transport to a spawned ACP agent subprocess.
///
/// Messages are exchanged as newline-delimited JSON over the child
/// process's stdin/stdout.
pub struct AcpTransport {
    child: Child,
    reader: AcpFrameReader<BufReader<std::process::ChildStdout>>,
}

impl AcpTransport {
    /// Spawn the ACP agent as a subprocess and return a transport
    /// handle for bidirectional JSON-RPC communication.
    pub fn spawn(
        command: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<Self, AcpProxyError> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AcpProxyError::PipeUnavailable)?;

        let reader = AcpFrameReader::new(BufReader::new(stdout));

        Ok(Self { child, reader })
    }

    /// Send a JSON-RPC message to the agent's stdin.
    pub fn send(&mut self, message: &serde_json::Value) -> Result<(), AcpProxyError> {
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| AcpProxyError::PipeUnavailable)?;

        let serialized = input::encode(message)?;
        stdin.write_all(&serialized)?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;

        Ok(())
    }

    /// Read the next JSON-RPC message from the agent's stdout.
    ///
    /// Returns `Ok(None)` when the agent has closed its stdout (EOF).
    pub fn recv(&mut self) -> Result<Option<AcpMessage>, AcpProxyError> {
        self.reader.recv()
    }

    /// Attempt to kill the agent subprocess.
    pub fn kill(&mut self) -> Result<(), AcpProxyError> {
        self.child.kill().map_err(AcpProxyError::from)
    }

    /// Wait for the agent subprocess to exit and return its status code.
    pub fn wait(&mut self) -> Result<Option<i32>, AcpProxyError> {
        let status = self.child.wait()?;
        Ok(status.code())
    }
}
