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

pub(super) async fn execute_settlement<T: Send + 'static>(
    principal: String,
    fixed_time: Option<u64>,
    work: impl Future<Output = Result<T, RecoveryRuntimeError>> + Send + 'static,
) -> Result<T, RecoveryRuntimeError> {
    let reply = crate::recovery::command_executor::CommandExecutor::shared_provider_finality()
        .await?
        .try_submit(principal, fixed_time, work)?;
    reply.await.map_err(|_| RecoveryRuntimeError::Unavailable)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::command_executor::CommandExecutor;
    use std::{error::Error, time::Duration};
    use tokio::sync::oneshot;

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    #[tokio::test(flavor = "current_thread")]
    async fn saturated_commands_keep_reserved_native_data_work_available() -> TestResult {
        // This allocator-only case runs real owned futures, using opaque data
        // keys. Owning actor checks and provider evidence belong to the TLS case.
        let commands = CommandExecutor::shared().await?;
        let mut releases = Vec::new();
        let mut replies = Vec::new();
        for key in [
            "data-domain-a",
            "data-domain-a",
            "data-domain-b",
            "data-domain-b",
        ] {
            let (release, pending) = oneshot::channel();
            let (entered, started) = oneshot::channel();
            replies.push(commands.try_submit(key.to_owned(), None, async move {
                let _ = entered.send(());
                pending
                    .await
                    .map_err(|_| RecoveryRuntimeError::Unavailable)?;
                Ok(())
            })?);
            releases.push(release);
            tokio::time::timeout(Duration::from_secs(2), started).await??;
        }
        let excess = commands.try_submit("data-domain-excess".to_owned(), None, async { Ok(()) });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            execute_settlement("data-finality-domain".to_owned(), None, async { Ok(79) }),
        )
        .await;
        for release in releases {
            let _ = release.send(());
        }
        for reply in replies {
            tokio::time::timeout(Duration::from_secs(2), reply).await???;
        }
        eprintln!("RESERVED_NATIVE_DATA_WORK allocation_only_result={result:?}");
        assert!(matches!(excess, Err(RecoveryRuntimeError::Unavailable)));
        assert_eq!(
            result?,
            Ok(79),
            "native finality selected saturated command capacity"
        );
        Ok(())
    }
}
