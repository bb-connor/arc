//! Bounded subprocess writer admission and supervisor dispatch.
use super::{AdapterError, MAX_STDIO_MCP_FRAME_BYTES, UPSTREAM_REQUEST_POLL_INTERVAL};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tracing::warn;

pub(super) struct WriterCommand {
    pub(super) bytes: Vec<u8>,
    pub(super) deadline: Option<Instant>,
    pub(super) completion: Option<mpsc::SyncSender<Result<(), String>>>,
}

pub(super) struct BoundedStdioWriter {
    writer_tx: mpsc::SyncSender<WriterCommand>,
    shutdown_requested: Arc<AtomicBool>,
    buffer: Vec<u8>,
    deadline: Instant,
}

impl BoundedStdioWriter {
    pub(super) fn new(
        writer_tx: mpsc::SyncSender<WriterCommand>,
        shutdown_requested: Arc<AtomicBool>,
        timeout: Duration,
    ) -> Result<Self, AdapterError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(chio_security_types::clock::ClockError::Overflow)?;
        Ok(Self {
            writer_tx,
            shutdown_requested,
            buffer: Vec::new(),
            deadline,
        })
    }
}

impl Write for BoundedStdioWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.buffer.len().saturating_add(bytes.len()) > MAX_STDIO_MCP_FRAME_BYTES + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound MCP JSON-RPC frame exceeded the transport limit",
            ));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MCP stdin write exceeded its deadline",
            ));
        }
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "MCP stdin write cancelled by shutdown",
            ));
        }
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let command = WriterCommand {
            bytes: std::mem::take(&mut self.buffer),
            deadline: Some(self.deadline),
            completion: Some(completion_tx),
        };
        self.writer_tx
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "MCP stdin writer queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "MCP stdin writer supervisor disconnected",
                ),
            })?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MCP stdin write exceeded its deadline",
            ));
        }
        loop {
            if self.shutdown_requested.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "MCP stdin write cancelled by shutdown",
                ));
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MCP stdin write exceeded its deadline",
                ));
            }
            let poll = std::cmp::min(UPSTREAM_REQUEST_POLL_INTERVAL, remaining);
            match completion_rx.recv_timeout(poll) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, error)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "MCP stdin writer completion disconnected",
                    ))
                }
            }
        }
    }
}

pub(super) fn run_stdio_writer(
    mut writer: Box<dyn Write + Send>,
    writer_rx: mpsc::Receiver<WriterCommand>,
) {
    while let Ok(command) = writer_rx.recv() {
        if command
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            if let Some(completion) = command.completion {
                let _ = completion
                    .try_send(Err("MCP stdin command expired before dispatch".to_string()));
            }
            continue;
        }
        let result = writer
            .write_all(&command.bytes)
            .and_then(|()| writer.flush())
            .map_err(|error| error.to_string());
        let failed = result.is_err();
        if let Some(completion) = command.completion {
            let _ = completion.try_send(result);
        } else if let Err(error) = result {
            warn!(
                target: "chio_mcp_adapter::transport",
                "asynchronous MCP stdin write failed: {error}"
            );
        }
        if failed {
            break;
        }
    }
}

#[cfg(test)]
#[path = "stdio_writer_tests.rs"]
mod tests;
