//! Effect-free authentication has bounded workers independent of native work.
use crate::recovery::{authentication_error, RecoveryRuntime, RecoveryRuntimeError};
use chio_core_types::capability::{scope::Operation, token::CapabilityToken};
use chio_kernel::recovery::{AuthenticatedRecoveryActor, RecoveryPermission};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{mpsc, Arc},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

type AuthenticationResult = Result<AuthenticatedRecoveryActor, RecoveryRuntimeError>;
type Verification = Box<dyn FnOnce() -> AuthenticationResult + Send>;
struct Job {
    verify: Verification,
    reply: oneshot::Sender<AuthenticationResult>,
    _permit: OwnedSemaphorePermit,
}

/// One dedicated thread and two outstanding jobs include queued, active and
/// disconnected verification. No authentication uses effect or planner workers.
pub(in crate::recovery) struct AuthenticationLane {
    sender: mpsc::SyncSender<Job>,
    capacity: Arc<Semaphore>,
    _worker: thread::JoinHandle<()>,
}
impl AuthenticationLane {
    #[cfg(test)]
    pub(in crate::recovery) fn outstanding_jobs_for_test(&self) -> usize {
        2 - self.capacity.available_permits()
    }

    pub(in crate::recovery) fn new(name: &'static str) -> Result<Arc<Self>, RecoveryRuntimeError> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(2);
        let worker = thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    let Job {
                        verify,
                        reply,
                        _permit,
                    } = job;
                    // No command transition or native effect belongs to this
                    // stage. A disconnected caller needs no verification work.
                    if reply.is_closed() {
                        continue;
                    }
                    let result = catch_unwind(AssertUnwindSafe(verify))
                        .unwrap_or(Err(RecoveryRuntimeError::Unavailable));
                    let _ = reply.send(result);
                }
            })
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        Ok(Arc::new(Self {
            sender,
            capacity: Arc::new(Semaphore::new(2)),
            _worker: worker,
        }))
    }

    /// Current native actor authentication precedes every native permit. The
    /// native worker independently authenticates again before its own work.
    pub(in crate::recovery) async fn authenticate(
        &self,
        runtime: Arc<RecoveryRuntime>,
        capability: &CapabilityToken,
        permission: RecoveryPermission,
    ) -> AuthenticationResult {
        require_exact_scope(capability, permission)?;
        require_credential(&runtime, capability)?;
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        let capability = capability.clone();
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(Job {
                verify: Box::new(move || {
                    runtime
                        .kernel
                        .authenticate_recovery_actor(runtime.scope(), &capability, permission)
                        .map_err(authentication_error)
                }),
                reply,
                _permit: permit,
            })
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        response
            .await
            .unwrap_or(Err(RecoveryRuntimeError::Unavailable))
    }
}
// Dropping the last lane closes its sender and detaches the worker. It never
// joins a verifier that may be waiting on the native store. At most two accepted
// effect-free jobs remain; a closed reply discards queued verification.

fn require_credential(
    runtime: &RecoveryRuntime,
    capability: &CapabilityToken,
) -> Result<(), RecoveryRuntimeError> {
    // This bounded effect-free check can only refuse before scarce current
    // native verification. It grants no actor, assignment, revocation, profile
    // or workflow authority; the worker still runs the complete native verifier.
    if !runtime
        .kernel
        .capability_issuer_is_trusted(&capability.issuer)
    {
        return Err(authentication_error(
            chio_kernel::KernelError::RecoveryAuthorityDenied,
        ));
    }
    let now = match chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
        Some(now) => now,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RecoveryRuntimeError::Unavailable)?
            .as_secs(),
    };
    let verified = capability.verify_signature_at(now).map_err(|error| {
        let error = match error {
            chio_core_types::Error::InvalidSignature(_)
            | chio_core_types::Error::SignatureVerificationFailed
            | chio_core_types::Error::CapabilityExpired { .. }
            | chio_core_types::Error::CapabilityNotYetValid { .. } => {
                chio_kernel::KernelError::RecoveryAuthorityDenied
            }
            _ => chio_kernel::KernelError::Internal(
                "recovery credential verification unavailable".into(),
            ),
        };
        authentication_error(error)
    })?;
    if !verified {
        return Err(authentication_error(
            chio_kernel::KernelError::RecoveryAuthorityDenied,
        ));
    }
    Ok(())
}

fn require_exact_scope(
    capability: &CapabilityToken,
    permission: RecoveryPermission,
) -> Result<(), RecoveryRuntimeError> {
    // This bounded filter only refuses. It cannot authenticate a claimed
    // subject, signature, assignment, revocation state, deadline or authority.
    let mut found = false;
    for grant in &capability.scope.grants {
        if matches!(grant.server_id.as_str(), "chio.recovery" | "*")
            && (grant.tool_name == permission.wire_name() || grant.tool_name == "*")
        {
            found = true;
            if grant.server_id != "chio.recovery"
                || grant.tool_name != permission.wire_name()
                || !grant.constraints.is_empty()
                || grant.max_invocations.is_some()
                || grant.max_cost_per_invocation.is_some()
                || grant.max_total_cost.is_some()
                || grant.dpop_required == Some(true)
                || !grant.operations.contains(&Operation::Invoke)
            {
                return Err(RecoveryRuntimeError::AuthorityDenied);
            }
        }
    }
    if !found {
        return Err(RecoveryRuntimeError::AuthorityDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::StatusCode};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn typed_native_authority_refusal_keeps_permanent_public_category() -> TestResult {
        let response = crate::recovery::transport::response::<()>(Err(authentication_error(
            chio_kernel::KernelError::RecoveryAuthorityDenied,
        )));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            to_bytes(response.into_body(), 262144).await?.as_ref(),
            b"recovery.authority_denied"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_authentication_failure_is_unavailable_without_diagnostics() -> TestResult {
        let connection = rusqlite::Connection::open_in_memory()?;
        let error = match connection.prepare("SELECT * FROM private_native_auth_canary") {
            Err(error) => error,
            Ok(_) => return Err("native SQLite error fixture unexpectedly succeeded".into()),
        };
        let error = chio_kernel::KernelError::RevocationStore(error.into());
        let response = crate::recovery::transport::response::<()>(Err(authentication_error(error)));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 262144).await?.as_ref(),
            b"recovery.unavailable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unclassified_native_ownership_failure_is_unavailable_without_diagnostics() -> TestResult
    {
        let error = chio_kernel::admission_operation::AdmissionOperationStoreError::Unavailable(
            "private-native-owner-canary".into(),
        );
        let error = chio_kernel::KernelError::DurableAdmission(error.to_string());
        let response = crate::recovery::transport::response::<()>(Err(authentication_error(error)));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 262144).await?.as_ref(),
            b"recovery.unavailable"
        );
        Ok(())
    }
}
