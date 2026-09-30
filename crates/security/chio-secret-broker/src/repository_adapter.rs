//! Host-owned repository service custody. Credentials stay in the Rust endpoint;
//! the selected child receives bounded commands over private inherited pipes.
use crate::host_https::{
    denied, private_bytes, unavailable, HostHttpsServer, HttpsEndpoint, JsonAdapter,
};
use crate::Result;
use chio_core_types::sha256_hex;
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

mod launch;
mod pipes;
#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryHttpsConfig {
    pub schema: String,
    pub bind: std::net::SocketAddr,
    pub certificate_der: Vec<u8>,
    pub private_key_file: PathBuf,
    pub bearer_file: PathBuf,
    pub repository: RepositoryAdapterConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAdapterConfig {
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub state: PathBuf,
    pub configuration_sha256: String,
    pub timeout_ms: u64,
}

pub struct RepositoryHttpsServer(HostHttpsServer);

impl RepositoryHttpsConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = private_bytes(path, 65_536)?;
        chio_core_types::canonical::UntrustedJsonText::from_wire(&bytes, 65_536)
            .and_then(|text| text.decode_signed())
            .map_err(|_| denied())
    }
}

impl RepositoryHttpsServer {
    pub fn bind(config: RepositoryHttpsConfig) -> Result<Self> {
        if config.schema != "chio.repository-https-adapter.v1" {
            return Err(denied());
        }
        HostHttpsServer::bind(
            HttpsEndpoint {
                bind: config.bind,
                certificate_der: config.certificate_der,
                private_key_file: config.private_key_file,
                bearer_file: config.bearer_file,
            },
            RepositoryAdapter::start(config.repository)?,
        )
        .map(Self)
    }
    pub fn serve(self) -> Result<()> {
        self.0.serve()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryCommand {
    command: String,
    tool_call_id: Option<String>,
    configuration_sha256: String,
}

struct RepositoryAdapter {
    child: Mutex<Option<RepositoryChild>>,
    configuration_sha256: String,
    timeout_ms: u64,
}

struct RepositoryChild {
    process: Child,
    input: ChildStdin,
    output: ChildStdout,
}

impl Drop for RepositoryChild {
    fn drop(&mut self) {
        // An uncertain exchange permanently retires this adapter. Reaping the
        // selected child never retries a command or promotes repository state.
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl RepositoryAdapter {
    fn start(config: RepositoryAdapterConfig) -> Result<Self> {
        if !(1..=120_000).contains(&config.timeout_ms)
            || !is_digest(&config.configuration_sha256)
            || !is_digest(&config.executable_sha256)
            || !config.executable.is_absolute()
            || !config.state.is_absolute()
        {
            return Err(denied());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&config.executable)
            .map_err(|_| denied())?;
        let info = file.metadata().map_err(|_| denied())?;
        if !info.is_file()
            || info.mode() & 0o022 != 0
            || info.mode() & 0o111 == 0
            || ![0, rustix::process::geteuid().as_raw()].contains(&info.uid())
            || info.len() == 0
            || info.len() > 64 * 1024 * 1024
        {
            return Err(denied());
        }
        let mut bytes = Vec::new();
        file.take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| denied())?;
        if sha256_hex(&bytes) != config.executable_sha256 {
            return Err(denied());
        }
        let state = std::fs::symlink_metadata(&config.state).map_err(|_| denied())?;
        if !state.is_dir()
            || state.mode() & 0o077 != 0
            || state.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(denied());
        }
        let launcher = launch::capture(&bytes)?;
        let mut process = launch::command(&launcher)?
            .arg("adapter")
            .arg("--state")
            .arg(&config.state)
            .arg("--configuration-sha256")
            .arg(&config.configuration_sha256)
            .current_dir(&config.state)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("MSWEA_SILENT_STARTUP", "1")
            .env("MSWEA_GLOBAL_CONFIG_DIR", config.state.join("mini-config"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| unavailable())?;
        let (Some(input), Some(output)) = (process.stdin.take(), process.stdout.take()) else {
            let _ = process.kill();
            let _ = process.wait();
            return Err(unavailable());
        };
        let mut child = RepositoryChild {
            process,
            input,
            output,
        };
        pipes::nonblocking(&child.input)?;
        pipes::nonblocking(&child.output)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(config.timeout_ms))
            .ok_or_else(unavailable)?;
        let ready = child.read_frame(deadline)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ready {
            schema: String,
            configuration_sha256: String,
        }
        let ready: Ready =
            chio_core_types::canonical::UntrustedJsonText::from_wire(&ready, 524_288)
                .and_then(|text| text.decode_signed())
                .map_err(|_| unavailable())?;
        if ready.schema != "chio.repository-adapter-ready.v1"
            || ready.configuration_sha256 != config.configuration_sha256
        {
            return Err(denied());
        }
        Ok(Self {
            child: Mutex::new(Some(child)),
            configuration_sha256: config.configuration_sha256,
            timeout_ms: config.timeout_ms,
        })
    }
}

impl JsonAdapter for RepositoryAdapter {
    fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
    fn execute_json(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        // One command owns the repository. Concurrent or uncertain calls never
        // queue behind a hidden retry or restart of the privileged child.
        let mut slot = self.child.try_lock().map_err(|_| unavailable())?;
        let child = slot.as_mut().ok_or_else(unavailable)?;
        let result = (|| {
            let command: RepositoryCommand =
                chio_core_types::canonical::UntrustedJsonText::from_wire(bytes, 131_072)
                    .and_then(|text| text.decode_signed())
                    .map_err(|_| denied())?;
            if command.configuration_sha256 != self.configuration_sha256
                || command.command.is_empty()
                || command.command.len() > 65_536
                || command.command.contains('\0')
                || command
                    .tool_call_id
                    .as_ref()
                    .is_some_and(|id| id.len() > 1024 || id.contains('\0'))
            {
                return Err(denied());
            }
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(self.timeout_ms))
                .ok_or_else(unavailable)?;
            child.write_frame(bytes, deadline)?;
            let body = child.read_frame(deadline)?;
            let output: serde_json::Value =
                chio_core_types::canonical::UntrustedJsonText::from_wire(&body, 524_288)
                    .and_then(|text| text.decode_signed())
                    .map_err(|_| unavailable())?;
            if output
                .pointer("/workspace/configuration_sha256")
                .and_then(serde_json::Value::as_str)
                != Some(self.configuration_sha256.as_str())
            {
                return Err(unavailable());
            }
            Ok(body)
        })();
        if result.is_err() {
            *slot = None;
        }
        result
    }
}
