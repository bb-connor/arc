use crate::{Error, Result};
use rustix::process::{kill_process_group, Pid, Signal};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) struct Group(Pid);

impl Group {
    pub(super) fn new(child: &tokio::process::Child) -> Result<Self> {
        child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(Pid::from_raw)
            .map(Self)
            .ok_or_else(|| Error::Invalid("model process group unavailable".into()))
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        let _ = kill_process_group(self.0, Signal::KILL);
    }
}

pub(super) async fn read(reader: impl AsyncRead + Unpin, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(std::io::Error::other(
            "Claude Code output exceeded its limit",
        ));
    }
    Ok(bytes)
}
