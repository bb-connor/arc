//! Retained descriptor preparation before the measured cage launch.
#[cfg(feature = "enforcement-mutants")]
use super::unsealed_memfd;
use super::{
    exact_required_enforcement, random_digest, sealed_memfd, validate_compiled_plan,
    validate_prepared_launch_contract, verify_bootstrap_fd_capacity, CompiledPlanValidation,
    LaunchEnvelope, PreparedLaunchContract, LAUNCH_ENVELOPE_SCHEMA, MAX_ENVELOPE_BYTES,
};
use crate::{
    CageEnforcementFailureCode, CageLaunchError, CageLaunchOptions, CageLaunchPreparationEvidence,
    CageReceiptBindings, CompiledCage,
};

pub(in crate::launch) fn prepare_launch(
    mut compiled: CompiledCage,
    options: CageLaunchOptions,
) -> Result<PreparedLaunchContract, CageLaunchError> {
    let base_profile_digest = compiled.profile_digest().to_string();
    let base_plan_digest = compiled.plan_digest().to_string();
    let target_stdio = crate::CompiledTargetStdio::create().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "target_stdio_create",
        )
    })?;
    compiled.bind_target_stdio(target_stdio).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "target_stdio_bind",
        )
    })?;
    let receipt_bindings = CageReceiptBindings::from_compiled(&compiled);
    prepare_bound(compiled, options, base_profile_digest, base_plan_digest)
        .map_err(|error| error.with_receipt_bindings_if_missing(receipt_bindings))
}

fn prepare_bound(
    compiled: CompiledCage,
    options: CageLaunchOptions,
    base_profile_digest: String,
    base_plan_digest: String,
) -> Result<PreparedLaunchContract, CageLaunchError> {
    #[cfg(not(feature = "enforcement-mutants"))]
    let _ = options;
    compiled.verify_retained_bindings().map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::DescriptorIdentityMismatch,
            "retained_bindings",
        )
    })?;
    validate_compiled_plan(CompiledPlanValidation::from_compiled(&compiled))?;
    let exact_requirements_match =
        exact_required_enforcement(&compiled.profile().required_enforcement);
    if !exact_requirements_match {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "required_enforcement",
        ));
    }
    verify_bootstrap_fd_capacity(compiled.plan().fd_table.len())?;

    let trace_session_digest = random_digest()?;
    let envelope = LaunchEnvelope {
        schema: LAUNCH_ENVELOPE_SCHEMA.to_string(),
        parent_process_id: std::process::id(),
        trace_session_digest,
        plan_digest: compiled.plan_digest().to_string(),
        fd_table_digest: compiled.profile().fd_table_digest.clone(),
        helper_binding_digest: compiled.profile().helper_binding_digest.clone(),
        target_binding_digest: compiled.profile().target_binding_digest.clone(),
        plan: compiled.plan().clone(),
    };
    #[cfg(feature = "enforcement-mutants")]
    let envelope = {
        let mut envelope = envelope;
        if matches!(
            options.enforcement_mutation(),
            Some(crate::launch::EnforcementMutation::CorruptPlanDigest)
        ) {
            envelope.plan_digest = "0".repeat(64);
        }
        envelope
    };
    let envelope_bytes = chio_core::canonical_json_bytes(&envelope).map_err(|_| {
        CageLaunchError::bootstrap_failed(CageEnforcementFailureCode::InvalidPlan, "plan_encoding")
    })?;
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::InvalidPlan,
            "plan_size",
        ));
    }
    #[cfg(feature = "enforcement-mutants")]
    let plan_memfd = if matches!(
        options.enforcement_mutation(),
        Some(crate::launch::EnforcementMutation::UnsealedPlan)
    ) {
        unsealed_memfd(&envelope_bytes)?
    } else {
        sealed_memfd(&envelope_bytes)?
    };
    #[cfg(not(feature = "enforcement-mutants"))]
    let plan_memfd = sealed_memfd(&envelope_bytes)?;

    let seal_mask =
        validate_prepared_launch_contract(&compiled, &envelope, &envelope_bytes, &plan_memfd)?;
    let evidence = CageLaunchPreparationEvidence {
        base_profile_digest,
        base_plan_digest,
        manifest_digest: envelope.plan.manifest_digest.clone(),
        profile_digest: envelope.plan.profile_digest.clone(),
        plan_digest: envelope.plan_digest.clone(),
        fd_table_digest: envelope.fd_table_digest.clone(),
        helper_binding_digest: envelope.helper_binding_digest.clone(),
        target_binding_digest: envelope.target_binding_digest.clone(),
        seal_mask,
        exact_requirements_match,
        target_launch_count: 0,
    };
    Ok(PreparedLaunchContract {
        compiled,
        envelope,
        plan_memfd,
        evidence,
        #[cfg(feature = "enforcement-mutants")]
        preparation_mutation: options.enforcement_mutation(),
    })
}
