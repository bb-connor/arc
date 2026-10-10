//! Rust-owned recovery commands. SDKs transport the same bounded protocol.
//! The host driver never edits a frozen request or supplies dispatch authority.
#![forbid(unsafe_code)]

mod actor_authentication;
mod command_executor;
pub(crate) use actor_authentication::authentication_error;
mod maintenance;
mod materialize;
mod native_store_errors;
mod runtime;
mod setup;
pub use maintenance::{recovery_maintenance_router, RecoveryMaintenanceRuntime};
pub use setup::{protected_recovery_router, RecoverySetupHost, RecoverySetupService};
mod settlement;
mod transport;
pub use transport::{recovery_router, RecoveryTransportRequestV1};
mod connector;
mod explanation;
pub use connector::PinnedSupportIssueConnector;
pub use explanation::{
    recovery_explanation_router, ProtectedRecoveryExplanationV1, RecoveryExplanationService,
};
pub use runtime::{
    RecoveryCommandResultV1, RecoveryResultProjectionV1, RecoveryRuntime, RecoveryRuntimeError,
};

// Test-only process death. Production builds contain neither an environment
// switch nor a recovery fault API.
#[cfg(test)]
pub(crate) fn test_cutpoint(stage: &str) {
    tests::record_host_port_cutpoint(stage);
    if std::env::var_os("CHIO_RECOVERY_CRASH_CHILD").is_some()
        && std::env::var("CHIO_RECOVERY_CRASH_POINT").is_ok_and(|point| point == stage)
    {
        eprintln!("recovery crash cutpoint: {stage}");
        std::process::abort();
    }
}

#[cfg(test)]
pub(crate) fn freeze_original_for_test(
    runtime: &RecoveryRuntime,
    capability: &chio_core_types::capability::token::CapabilityToken,
    workflow: &chio_security_types::recovery::WorkflowId,
) -> Result<chio_kernel::RecoveryRequestCustody, RecoveryRuntimeError> {
    let actor = runtime
        .kernel
        .authenticate_recovery_actor(
            &runtime.scope,
            capability,
            chio_kernel::recovery::RecoveryPermission::Resume,
        )
        .map_err(authentication_error)?;
    let reservation = runtime.prepare_original(&actor, workflow)?;
    let custody = runtime
        .kernel
        .load_recovery_request_custody(&actor, workflow)
        .map_err(|_| RecoveryRuntimeError::Unavailable)?;
    runtime
        .process
        .finalize_recovery_call(&reservation, &custody)
        .map_err(|_| RecoveryRuntimeError::Conflict)?;
    Ok(custody)
}

#[cfg(test)]
mod tests;
