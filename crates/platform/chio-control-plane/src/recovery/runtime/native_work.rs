//! Bounded native phases owned independently of the caller's async driver.
use super::RecoveryRuntimeError;
use chio_core_types::capability::token::CapabilityToken;
use chio_kernel::ChioKernel;
use chio_security_types::recovery::RecoveryScopeV1;
use std::future::Future;

pub(super) fn checked_principal(
    kernel: &ChioKernel,
    scope: &RecoveryScopeV1,
    capability: &CapabilityToken,
    fixed_time: Option<u64>,
) -> Result<String, RecoveryRuntimeError> {
    let now = match fixed_time {
        Some(now) => now,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?
            .as_secs(),
    };
    // This check selects bounded fairness data. Full actor, profile,
    // revocation and native checks remain in each owning native phase.
    if !kernel.capability_issuer_is_trusted(&capability.issuer)
        || !capability
            .verify_signature_at(now)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?
    {
        return Err(RecoveryRuntimeError::AuthorityDenied);
    }
    Ok(format!(
        "{}:{}",
        scope.authority_domain.as_str(),
        capability.subject.to_hex()
    ))
}

pub(super) async fn execute<T: Send + 'static>(
    principal: String,
    fixed_time: Option<u64>,
    work: impl Future<Output = Result<T, RecoveryRuntimeError>> + Send + 'static,
) -> Result<T, RecoveryRuntimeError> {
    let reply = crate::recovery::command_executor::CommandExecutor::shared()
        .await?
        .try_submit(principal, fixed_time, work)?;
    reply.await.map_err(|_| RecoveryRuntimeError::Unavailable)?
}
