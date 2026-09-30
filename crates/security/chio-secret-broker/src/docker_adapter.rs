//! Host-owned Docker execution through a pinned daemon and immutable container.
//!
//! The HTTPS adapter invokes this owner only after broker authentication. The
//! broker retains original admission/capture and never retries an uncertain
//! response. No Docker socket, host command runner or engine selector is exposed
//! to a caged process.
use crate::{BrokerError, Result};
use chio_core_types::sha256_hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{self, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::PathBuf,
    time::{Duration, Instant},
};

pub mod server;
fn canonical_json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    chio_core_types::canonical_json_bytes(value).map_err(|error| {
        BrokerError::UntrustedInput(
            chio_core_types::canonical::UntrustedJsonError::Canonicalization(error),
        )
    })
}

mod wire;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerAdapterConfig {
    pub socket_path: PathBuf,
    pub peer: crate::ipc_client::BrokerPeerIdentity,
    pub api_version: String,
    pub daemon_id: String,
    pub container_id: String,
    pub container_configuration_sha256: String,
    pub container_started_at: String,
    pub timeout_ms: u64,
    pub maximum_output_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerCommand {
    pub command: String,
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerCommandResult {
    pub output: String,
    pub returncode: i32,
    pub exception_info: String,
}

pub struct DockerAdapter {
    config: DockerAdapterConfig,
    socket_identity: (u64, u64),
}

fn denied() -> BrokerError {
    BrokerError::AuthorizationDenied("Docker adapter identity or request refused".into())
}
fn unavailable() -> BrokerError {
    BrokerError::Upstream("Docker outcome unavailable; automatic retry forbidden".into())
}
fn hexadecimal(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl DockerAdapter {
    pub fn new(config: DockerAdapterConfig) -> Result<Self> {
        if !config.socket_path.is_absolute()
            || !hexadecimal(&config.container_id)
            || !hexadecimal(&config.container_configuration_sha256)
            || !(1..=120_000).contains(&config.timeout_ms)
            || !(1..=524_288).contains(&config.maximum_output_bytes)
            || !config
                .api_version
                .strip_prefix("v1.")
                .is_some_and(|v| v.len() == 2 && v.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(denied());
        }
        crate::validate_identifier(&config.daemon_id, "Docker daemon identity", 128)?;
        crate::validate_identifier(
            &config.container_started_at,
            "Docker container lifetime",
            128,
        )?;
        config.peer.validate().map_err(|_| denied())?;
        let metadata = std::fs::symlink_metadata(&config.socket_path).map_err(|_| denied())?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != config.peer.user_id
            || metadata.mode() & 0o007 != 0
        {
            return Err(denied());
        }
        let selected = Self {
            config,
            socket_identity: (metadata.dev(), metadata.ino()),
        };
        let deadline = selected.deadline()?;
        selected.validate_resource(deadline)?;
        Ok(selected)
    }

    fn deadline(&self) -> Result<Instant> {
        Instant::now()
            .checked_add(Duration::from_millis(self.config.timeout_ms))
            .ok_or_else(unavailable)
    }

    fn connection(&self, deadline: Instant) -> Result<DeadlineStream> {
        let metadata = std::fs::symlink_metadata(&self.config.socket_path).map_err(|_| denied())?;
        if (metadata.dev(), metadata.ino()) != self.socket_identity
            || !metadata.file_type().is_socket()
        {
            return Err(denied());
        }
        let address =
            rustix::net::SocketAddrUnix::new(&self.config.socket_path).map_err(|_| denied())?;
        let descriptor = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| unavailable())?;
        // Local backlog exhaustion is a refusal, never an unbounded connect or
        // implicit effect retry. Peer authentication follows successful connect.
        rustix::net::connect(&descriptor, &address).map_err(|_| unavailable())?;
        let stream = UnixStream::from(descriptor);
        stream.set_nonblocking(false).map_err(|_| unavailable())?;
        if chio_secure_ipc::peer_identity(&stream).map_err(|_| denied())? != self.config.peer {
            return Err(denied());
        }
        Ok(DeadlineStream { stream, deadline })
    }

    fn json(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        status: u16,
        deadline: Instant,
    ) -> Result<Value> {
        let mut stream = self.connection(deadline)?;
        wire::send(
            &mut stream,
            &self.config.api_version,
            method,
            path,
            body,
            false,
        )?;
        let response = crate::generic_https::rustls_transport::parse_http_response(
            &mut BufReader::new(stream),
            method,
            131_072,
        )?;
        if response.status != status {
            return Err(unavailable());
        }
        chio_core_types::canonical::UntrustedJsonText::from_wire(&response.body, 131_072)
            .and_then(|text| text.decode_signed())
            .map_err(|_| unavailable())
    }

    fn validate_resource(&self, deadline: Instant) -> Result<()> {
        let engine = self.json("GET", "/info", &Value::Null, 200, deadline)?;
        if engine.get("ID").and_then(Value::as_str) != Some(&self.config.daemon_id) {
            return Err(denied());
        }
        let container = self.json(
            "GET",
            &format!("/containers/{}/json", self.config.container_id),
            &Value::Null,
            200,
            deadline,
        )?;
        if container.get("Id").and_then(Value::as_str) != Some(&self.config.container_id)
            || container.pointer("/State/Running").and_then(Value::as_bool) != Some(true)
            || container.pointer("/State/Paused").and_then(Value::as_bool) != Some(false)
            || container
                .pointer("/State/StartedAt")
                .and_then(Value::as_str)
                != Some(&self.config.container_started_at)
            || container
                .pointer("/HostConfig/Privileged")
                .and_then(Value::as_bool)
                != Some(false)
            || container
                .pointer("/HostConfig/NetworkMode")
                .and_then(Value::as_str)
                != Some("none")
            || container
                .pointer("/HostConfig/ReadonlyRootfs")
                .and_then(Value::as_bool)
                != Some(true)
            || container
                .pointer("/Config/User")
                .and_then(Value::as_str)
                .is_none_or(|user| {
                    user.is_empty()
                        || user == "0"
                        || user == "root"
                        || user.starts_with("0:")
                        || user.starts_with("root:")
                })
            || container_configuration_digest(&container)?
                != self.config.container_configuration_sha256
        {
            return Err(denied());
        }
        Ok(())
    }

    /// Execute exactly once. Any lost/truncated response or deadline is an
    /// uncertain result, including a daemon error after exec creation.
    pub fn execute(&self, command: &DockerCommand) -> Result<DockerCommandResult> {
        if command.command.is_empty()
            || command.command.len() > 65_536
            || command.command.contains('\0')
            || command
                .tool_call_id
                .as_ref()
                .is_some_and(|id| id.len() > 1024 || id.contains('\0'))
        {
            return Err(denied());
        }
        let deadline = self.deadline()?;
        self.validate_resource(deadline)?;
        let created = self.json("POST", &format!("/containers/{}/exec", self.config.container_id),
            &json!({"AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Tty":false,"Privileged":false,"WorkingDir":"/workspace","Cmd":["/bin/bash","-lc", command.command]}), 201, deadline)?;
        let exec = created
            .get("Id")
            .and_then(Value::as_str)
            .filter(|id| hexadecimal(id))
            .ok_or_else(unavailable)?;
        // Exec creation is not execution. Refuse a changed lifetime before
        // starting it, and never report success across a concurrent restart.
        self.validate_resource(deadline)?;
        let mut stream = self.connection(deadline)?;
        wire::send(
            &mut stream,
            &self.config.api_version,
            "POST",
            &format!("/exec/{exec}/start"),
            &json!({"Detach":false,"Tty":false}),
            true,
        )?;
        let bytes = wire::read_output(
            &mut BufReader::new(stream),
            self.config.maximum_output_bytes,
        )?;
        let status = self.json(
            "GET",
            &format!("/exec/{exec}/json"),
            &Value::Null,
            200,
            deadline,
        )?;
        if status.get("ID").and_then(Value::as_str) != Some(exec)
            || status.get("ContainerID").and_then(Value::as_str) != Some(&self.config.container_id)
            || status.get("Running").and_then(Value::as_bool) != Some(false)
        {
            return Err(unavailable());
        }
        let returncode = status
            .get("ExitCode")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .filter(|code| *code >= 0)
            .ok_or_else(unavailable)?;
        self.validate_resource(deadline)
            .map_err(|_| unavailable())?;
        Ok(DockerCommandResult {
            output: String::from_utf8_lossy(&bytes).into_owned(),
            returncode,
            exception_info: String::new(),
        })
    }
}

/// Pin the complete operator-selected immutable configuration, including all
/// mounts and environment variables. Runtime state and accounting are excluded.
pub fn container_configuration_digest(container: &Value) -> Result<String> {
    let selected = ["Config", "HostConfig", "Mounts", "Image"]
        .into_iter()
        .map(|key| Ok((key, container.get(key).ok_or_else(denied)?)))
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    Ok(sha256_hex(&canonical_json_bytes(&selected)?))
}

struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Docker deadline"))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests;
