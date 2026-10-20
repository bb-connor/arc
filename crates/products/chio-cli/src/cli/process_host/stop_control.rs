//! Operator stop for a process host: a control socket while it serves, and
//! an offline append through the serving-owner lock while it is down.
//!
//! The socket lives in the private state directory. A peer must run as the
//! host's user and present the control token the serving host writes beside
//! it. Both paths drive the same durable stop chain.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use chio_kernel::stop::{
    ResumeCommand, ResumeRequestBody, StopAuthorizer, StopCommand, StopControl, StopControlError,
    StopEpochId, StopRequestBody, StopRequestPath,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use super::state::{error, Lease};
use crate::CliError;

const SOCKET_FILE: &str = "control.sock";
const TOKEN_FILE: &str = "control.token";
const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const SOCKET_CREDENTIAL_ID: &str = "process-host:control-socket";
const OFFLINE_CREDENTIAL_ID: &str = "process-host:offline-cli";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum ControlOp {
    Stop(StopRequestBody),
    Resume(ResumeRequestBody),
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    token: String,
    request: ControlOp,
}

/// One operator action, as the CLI states it.
pub(super) enum Action {
    Stop {
        reason: String,
        allow_containment: bool,
    },
    Resume {
        expected_epoch: u64,
    },
    Status,
}

impl Action {
    fn op(self) -> ControlOp {
        match self {
            Self::Stop {
                reason,
                allow_containment,
            } => ControlOp::Stop(StopRequestBody {
                reason,
                allow_containment,
            }),
            Self::Resume { expected_epoch } => ControlOp::Resume(ResumeRequestBody {
                expected_epoch: StopEpochId {
                    chain_generation: 1,
                    epoch: expected_epoch,
                },
            }),
            Self::Status => ControlOp::Status,
        }
    }
}

fn apply(
    control: &StopControl,
    op: ControlOp,
    authorizer: StopAuthorizer,
    requested_via: StopRequestPath,
) -> serde_json::Value {
    let result = match op {
        ControlOp::Stop(body) => control.stop(StopCommand {
            reason: body.reason,
            authorizer,
            requested_via,
            allow_containment: body.allow_containment,
        }),
        ControlOp::Resume(body) => control.resume(ResumeCommand {
            expected_epoch: Some(body.expected_epoch),
            authorizer,
            requested_via,
        }),
        ControlOp::Status => Ok(control.status()),
    };
    match result {
        Ok(status) => serde_json::json!({ "ok": true, "status": status }),
        Err(error) => refusal(&error),
    }
}

fn refusal(error: &StopControlError) -> serde_json::Value {
    let mut body = error.body();
    if let Some(object) = body.as_object_mut() {
        object.insert("ok".into(), serde_json::Value::Bool(false));
    }
    body
}

/// A bound control socket and the token a peer must present.
pub(super) struct ControlServer {
    listener: UnixListener,
    token: String,
    socket: PathBuf,
}

impl ControlServer {
    /// Bind the socket and write a fresh token. Call only under the host lease.
    pub(super) fn bind(lease: &Lease) -> Result<Self, CliError> {
        let directory = lease.directory.path();
        let socket = directory.join(SOCKET_FILE);
        match std::fs::remove_file(&socket) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut bytes = [0_u8; 32];
        OsRng.try_fill_bytes(&mut bytes).map_err(error)?;
        let token = hex::encode(bytes);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(TOKEN_FILE))?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        let listener = UnixListener::bind(&socket)?;
        lease.directory.validate_path_identity()?;
        Ok(Self {
            listener,
            token,
            socket,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.socket
    }

    /// Serve requests until the task is dropped.
    pub(super) async fn serve(self, control: StopControl) {
        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _)) => stream,
                Err(error) => {
                    tracing::warn!(error = %error, "process host control socket accept failed");
                    continue;
                }
            };
            let control = control.clone();
            let token = self.token.clone();
            tokio::spawn(async move {
                if let Err(error) = handle(stream, &token, &control).await {
                    tracing::warn!(error = %error, "process host control request failed");
                }
            });
        }
    }
}

async fn handle(stream: UnixStream, token: &str, control: &StopControl) -> std::io::Result<()> {
    let peer = stream.peer_cred()?;
    let (reader, mut writer) = stream.into_split();
    let response = if peer.uid() != rustix::process::geteuid().as_raw() {
        serde_json::json!({ "ok": false, "error": "unauthorized", "message": "peer is not the host user" })
    } else {
        let mut line = String::new();
        BufReader::new(reader.take(MAX_REQUEST_BYTES))
            .read_line(&mut line)
            .await?;
        match chio_core::canonical::UntrustedJsonText::new(&line)
            .decode_external::<ControlRequest>()
        {
            Err(_) => {
                serde_json::json!({ "ok": false, "error": "bad_request", "message": "invalid control request" })
            }
            Ok(request) if !bool::from(request.token.as_bytes().ct_eq(token.as_bytes())) => {
                serde_json::json!({ "ok": false, "error": "unauthorized", "message": "invalid control token" })
            }
            Ok(request) => {
                let control = control.clone();
                tokio::task::spawn_blocking(move || {
                    apply(
                        &control,
                        request.request,
                        StopAuthorizer::shared_credential(SOCKET_CREDENTIAL_ID),
                        StopRequestPath::ControlSocket,
                    )
                })
                .await
                .map_err(std::io::Error::other)?
            }
        }
    };
    let mut bytes = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.shutdown().await
}

fn via_socket(state: &Path, op: ControlOp) -> Result<Option<serde_json::Value>, CliError> {
    let socket = state.join(SOCKET_FILE);
    let mut stream = match std::os::unix::net::UnixStream::connect(&socket) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error.into()),
    };
    let token = std::fs::read_to_string(state.join(TOKEN_FILE))?;
    let mut request = serde_json::to_vec(&ControlRequest {
        token: token.trim().to_owned(),
        request: op,
    })
    .map_err(error)?;
    request.push(b'\n');
    stream.write_all(&request)?;
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(std::io::Read::take(stream, 64 * 1024)),
        &mut line,
    )?;
    chio_core::canonical::UntrustedJsonText::new(&line)
        .decode_external()
        .map(Some)
        .map_err(error)
}

fn offline(state: &Path, op: ControlOp) -> Result<serde_json::Value, CliError> {
    let lease = Lease::acquire(state, false)?;
    let database = lease.directory.path().join("authority.db");
    if !std::fs::symlink_metadata(&database)?.is_file() {
        return Err(error("host authority database is not a regular file"));
    }
    let authority = chio_control_plane::DurableAdmissionRuntime::open(&database)?;
    Ok(apply(
        &authority.stop_control(),
        op,
        StopAuthorizer::shared_credential(OFFLINE_CREDENTIAL_ID),
        StopRequestPath::OfflineCli,
    ))
}

/// Drive a serving host through its control socket, or append offline when
/// no host is serving.
pub(super) fn run(state: &Path, action: Action) -> Result<(), CliError> {
    let op = action.op();
    let (via, response) = match via_socket(state, op.clone())? {
        Some(response) => ("control_socket", response),
        None => ("offline", offline(state, op)?),
    };
    println!("{}", serde_json::json!({ "via": via, "response": &response }));
    if response.get("ok") == Some(&serde_json::Value::Bool(true)) {
        Ok(())
    } else {
        Err(error(format!(
            "stop control refused: {}",
            response
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
        )))
    }
}

#[cfg(test)]
#[path = "stop_control_tests.rs"]
mod tests;
