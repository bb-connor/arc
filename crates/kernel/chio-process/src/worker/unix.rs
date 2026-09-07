use std::future::Future;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;

use super::{error_frame, WorkerService, MAX_REQUEST_BYTES};

const MAX_CONNECTIONS: usize = 32;
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// A local worker listener. The host supplies a private socket directory,
/// protected separately from its journal and keys by the worker sandbox.
/// Existing filesystem entries are never removed or reused by bind.
pub struct WorkerServer {
    listener: UnixListener,
    service: WorkerService,
    _path: SocketPath,
}

impl WorkerServer {
    pub fn bind(path: impl AsRef<Path>, service: WorkerService) -> io::Result<Self> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = std::fs::canonicalize(parent)?;
        let metadata = std::fs::metadata(&parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "worker socket directory must be private (0700)",
            ));
        }
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing socket filename")
        })?;
        let path = parent.join(name);
        let listener = UnixListener::bind(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let guard = SocketPath {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        std::fs::set_permissions(&guard.path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            service,
            _path: guard,
        })
    }

    /// Stop accepting when shutdown resolves, then drain admitted calls.
    /// Client disconnect never cancels a running kernel call. Host process
    /// death or forcibly dropping this future uses durable admission recovery.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);
        let mut failure = None;
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => break,
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result { failure = Some(io::Error::other(error)); break; }
                }
                accepted = self.listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(value) => value,
                        Err(error) => { failure = Some(error); break; }
                    };
                    // No unbounded queue of allocated tasks or request bodies.
                    if tasks.len() >= MAX_CONNECTIONS { drop(stream); continue; }
                    let service = self.service.clone();
                    tasks.spawn(async move { handle_connection(stream, service).await });
                }
            }
        }
        drop(self.listener);
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                failure = Some(io::Error::other(error));
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

async fn handle_connection(mut stream: UnixStream, service: WorkerService) {
    let response = match tokio::time::timeout(FRAME_TIMEOUT, read_frame(&mut stream)).await {
        Ok(Ok(frame)) => service.handle_frame(&frame).await,
        Ok(Err(_)) => error_frame("invalid_frame"),
        Err(_) => error_frame("frame_timeout"),
    };
    // The kernel call above completes even when this write cannot be delivered.
    let _ = tokio::time::timeout(FRAME_TIMEOUT, stream.write_all(&response)).await;
}

async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut frame = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unterminated frame",
            ));
        }
        let end = buffer[..count].iter().position(|b| *b == b'\n');
        let bytes = &buffer[..end.unwrap_or(count)];
        if bytes.len() >= MAX_REQUEST_BYTES.saturating_sub(frame.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds limit",
            ));
        }
        frame.extend_from_slice(bytes);
        if end.is_some() {
            return Ok(frame);
        }
    }
}

struct SocketPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        // Never unlink a replacement installed at the same path by the host.
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.dev() == self.device && metadata.ino() == self.inode {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}
