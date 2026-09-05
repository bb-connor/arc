//! Authenticated, process-scoped worker API. Credentials are bearer secrets;
//! the host must protect them with OS isolation and private delivery.
//! This protocol supplies no capability issuance or kernel administration.

use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_kernel::{ToolCallOutput, Verdict};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{ProcessError, ProcessRuntime};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::WorkerServer;

pub const PROTOCOL: &str = "chio.process.v1";
/// Frame ceilings include the terminating newline.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Returned only to the trusted host. Debug output never includes the secret.
pub struct WorkerCredential(String);

impl WorkerCredential {
    /// Deliver privately to exactly the worker bound at issuance.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for WorkerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkerCredential([REDACTED])")
    }
}

#[derive(Clone)]
pub struct WorkerService {
    runtime: ProcessRuntime,
}

// Deliberately no Debug derive on requests containing bearer credentials.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    credential: String,
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Inspect {},
    Invoke {
        operation_key: String,
        server_id: String,
        tool_name: String,
        arguments: Value,
    },
    Checkpoint {
        expected_revision: String,
        value: Value,
    },
    Cancel {},
}

impl WorkerService {
    pub fn new(runtime: ProcessRuntime) -> Self {
        Self { runtime }
    }

    /// Issue a 256-bit OS-random bearer credential for an existing process.
    /// Only its SHA-256 digest is retained in the private process journal.
    pub fn issue_credential(
        &self,
        process_id: &str,
        expires_at: u64,
    ) -> Result<WorkerCredential, ProcessError> {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| ProcessError::Configuration("OS randomness unavailable"))?;
        let secret = hex::encode(bytes);
        self.runtime.with_store(|store| {
            store.issue_worker_credential(
                process_id,
                &sha256_hex(secret.as_bytes()),
                expires_at,
                now()?,
            )
        })?;
        Ok(WorkerCredential(secret))
    }

    /// Revoke all credentials for this exact process. Calls already admitted
    /// may finish; subsequent authentication and output release are rejected.
    pub fn revoke_credentials(&self, process_id: &str) -> Result<usize, ProcessError> {
        self.runtime
            .with_store(|store| store.revoke_worker_credentials(process_id))
    }

    fn authenticate(&self, credential: &str) -> Result<String, ProcessError> {
        if credential.len() != 64
            || !credential
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProcessError::Unauthenticated);
        }
        self.runtime.with_store(|store| {
            store.authenticate_worker(&sha256_hex(credential.as_bytes()), now()?)
        })
    }

    async fn execute(&self, frame: &[u8]) -> Result<Value, ProcessError> {
        if frame.len() >= MAX_REQUEST_BYTES {
            return Err(ProcessError::Invalid("request too large"));
        }
        let request: Request = serde_json::from_slice(frame)?;
        if request.protocol != PROTOCOL {
            return Err(ProcessError::Invalid("unsupported protocol"));
        }
        let id = self.authenticate(&request.credential)?;
        let result = match request.operation {
            Operation::Inspect {} => {
                let process = self.runtime.process(&id)?;
                json!({"process_id": process.id, "parent_id": process.parent_id, "root_id": process.root_id,
                    "state": process.state, "depth": process.depth, "limits": process.limits,
                    "tree_calls": process.tree_calls,
                    "checkpoint": {"revision": process.checkpoint.revision.to_string(), "value": process.checkpoint.value}})
            }
            Operation::Invoke {
                operation_key,
                server_id,
                tool_name,
                arguments,
            } => {
                let call = self.runtime.tool_request(
                    &id,
                    &operation_key,
                    &server_id,
                    &tool_name,
                    arguments,
                )?;
                let response = self.runtime.invoke(&id, &operation_key, &call).await?;
                let output = response.output.map(|output| match output {
                    ToolCallOutput::Value(value) => json!({"kind": "value", "value": value}),
                    ToolCallOutput::Stream(stream) => json!({"kind": "stream", "chunks": stream.chunks.into_iter().map(|c| c.data).collect::<Vec<_>>()}),
                });
                // Keep signed integers lossless in JavaScript. Consumers must
                // preserve this text and use a Chio verifier, not JSON.stringify.
                let receipt_json = String::from_utf8(canonical_json_bytes(&response.receipt)?)
                    .map_err(|_| ProcessError::Invalid("invalid receipt encoding"))?;
                let verdict = match response.verdict {
                    Verdict::Allow => "allow",
                    Verdict::Deny => "deny",
                    Verdict::PendingApproval => "pending_approval",
                };
                let execution_nonce_json = response
                    .execution_nonce
                    .map(|nonce| serde_json::to_string(&nonce))
                    .transpose()?;
                json!({"request_id": response.request_id, "verdict": verdict,
                    "output": output, "reason": response.reason, "terminal_state": response.terminal_state,
                    "receipt_json": receipt_json, "execution_nonce_json": execution_nonce_json})
            }
            Operation::Checkpoint {
                expected_revision,
                value,
            } => {
                let revision: u64 = expected_revision
                    .parse()
                    .map_err(|_| ProcessError::Invalid("invalid revision"))?;
                if revision.to_string() != expected_revision {
                    return Err(ProcessError::Invalid("invalid revision"));
                }
                let checkpoint = self.runtime.checkpoint(&id, revision, value)?;
                json!({"revision": checkpoint.revision.to_string(), "value": checkpoint.value})
            }
            Operation::Cancel {} => json!({"cancelled_processes": self.runtime.cancel(&id)?}),
        };
        self.authenticate(&request.credential)?;
        Ok(result)
    }

    /// Handle one bounded JSON frame without its newline. Transport errors do
    /// not authorize a new operation key: retry the original request exactly.
    pub async fn handle_frame(&self, frame: &[u8]) -> Vec<u8> {
        let result = match self.execute(frame).await {
            Ok(value) => json!({"protocol": PROTOCOL, "ok": true, "result": value}),
            Err(error) => failure(error_code(&error)),
        };
        // A bounded writer avoids an unbounded second copy of large outputs.
        let mut bytes = BoundedBytes(Vec::new());
        if serde_json::to_writer(&mut bytes, &result).is_err() {
            return error_frame("response_too_large");
        }
        bytes.0.push(b'\n');
        bytes.0
    }
}

fn now() -> Result<u64, ProcessError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ProcessError::Configuration("system time precedes Unix epoch"))
}

fn error_code(error: &ProcessError) -> &'static str {
    match error {
        ProcessError::Unauthenticated => "unauthenticated",
        ProcessError::Invalid(_) | ProcessError::Json(_) => "invalid_request",
        ProcessError::Cancelled(_) => "cancelled",
        ProcessError::Conflict => "conflict",
        ProcessError::CheckpointConflict => "checkpoint_conflict",
        ProcessError::Limit(_) => "limit_reached",
        _ => "runtime_error",
    }
}

fn failure(code: &str) -> Value {
    json!({"protocol": PROTOCOL, "ok": false, "error": {"code": code}})
}

fn error_frame(code: &str) -> Vec<u8> {
    // All callers supply static protocol codes. No guest-controlled error text.
    format!("{{\"protocol\":\"{PROTOCOL}\",\"ok\":false,\"error\":{{\"code\":\"{code}\"}}}}\n")
        .into_bytes()
}

struct BoundedBytes(Vec<u8>);
impl std::io::Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() >= MAX_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("response exceeds frame limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
