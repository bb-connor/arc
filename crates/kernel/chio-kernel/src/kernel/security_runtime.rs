use std::sync::Arc;

use chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS;
use chio_core::PublicKey;

use crate::approval::{ApprovalStore, ApprovalStoreProfile};
use crate::budget_store::{BudgetGuaranteeLevel, BudgetStore};
use crate::post_invocation::PostInvocationPipeline;
use crate::security_admission_operation::{
    AdmissionOperationKind, AdmissionOperationStore, AdmissionOperationStoreProfile,
};
use crate::threshold_approval::ThresholdApprovalRequirementResolver;
use crate::{
    CapabilityIssuanceAdmissionAuthority, Guard, SecurityPreDispatchHook, SecurityPreDispatchPolicy,
};

use super::active_response_admission::ActiveResponseFindingAuthority;
use super::active_response_executor::{
    ActiveResponseExecutorAuthority, ActiveResponseExecutorAuthorityIdentity,
    InstalledActiveResponseExecutor,
};
use super::active_response_policy::ActiveResponseRequirementResolver;
use super::{ChioKernel, KernelError};

/// Complete, preflighted security authority and pipeline replacement.
///
/// The kernel validates every fallible dependency before publishing any field.
/// Successful publication replaces the complete governed runtime in one
/// exclusive mutation and activates threshold admission and active response
/// together.
pub struct GovernedSecurityRuntimePublication {
    pub active_response_requirement_resolver: Arc<dyn ActiveResponseRequirementResolver>,
    pub threshold_approval_requirement_resolver: Arc<dyn ThresholdApprovalRequirementResolver>,
    pub admission_operation_store: Arc<dyn AdmissionOperationStore>,
    pub approval_store: Arc<dyn ApprovalStore>,
    pub budget_store: Arc<dyn BudgetStore>,
    pub finding_authority: Arc<dyn ActiveResponseFindingAuthority>,
    pub executor_authority: Arc<dyn ActiveResponseExecutorAuthority>,
    pub capability_issuance_admission_authority: Arc<dyn CapabilityIssuanceAdmissionAuthority>,
    pub threshold_policy_authorities: Vec<PublicKey>,
    pub guards: Vec<Box<dyn Guard>>,
    pub pre_dispatch_hook: Arc<dyn SecurityPreDispatchHook>,
    pub post_invocation_pipeline: PostInvocationPipeline,
}

/// Read-only identity of the currently published governed security runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedSecurityRuntimeStatus {
    pub publication_generation: u64,
    pub active_response_enabled: bool,
    pub threshold_approval_enabled: bool,
    pub capability_issuance_admission_enabled: bool,
    pub executor_authority: Option<ActiveResponseExecutorAuthorityIdentity>,
    pub active_response_submission_authority: Option<PublicKey>,
    pub threshold_policy_authorities: Vec<PublicKey>,
    pub admission_operation_store_profile: Option<AdmissionOperationStoreProfile>,
    pub approval_store_profile: Option<ApprovalStoreProfile>,
    pub budget_store_profile: BudgetGuaranteeLevel,
}

impl ChioKernel {
    /// Preflight and publish one complete governed security runtime.
    ///
    /// No kernel field is changed unless every authority, durability profile,
    /// topology constraint, and executor rotation check succeeds.
    pub fn publish_governed_security_runtime(
        &mut self,
        publication: GovernedSecurityRuntimePublication,
    ) -> Result<(), KernelError> {
        let next_generation = self
            .governed_security_runtime_generation
            .checked_add(1)
            .ok_or_else(|| {
                KernelError::Internal(
                    "governed security runtime publication generation overflowed".to_string(),
                )
            })?;
        let threshold_policy_authorities =
            Self::validate_threshold_policy_authorities(&publication.threshold_policy_authorities)?;
        self.ensure_active_response_submission_authority_configured()?;
        if !publication
            .admission_operation_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(KernelError::Internal(
                "durable admission operation store cannot coordinate the configured worker topology"
                    .to_string(),
            ));
        }
        if !publication
            .approval_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(KernelError::Internal(
                "durable approval store cannot coordinate the configured worker topology"
                    .to_string(),
            ));
        }
        let budget_profile = publication.budget_store.budget_guarantee_level();
        let budget_profile_supports_topology = match budget_profile {
            BudgetGuaranteeLevel::SingleNodeAtomic => self.dispatch_worker_count == 1,
            BudgetGuaranteeLevel::HaLinearizable | BudgetGuaranteeLevel::PartitionEscrowed => {
                self.dispatch_worker_count > 0
            }
            BudgetGuaranteeLevel::AdvisoryPosthoc => false,
        };
        if !budget_profile_supports_topology {
            return Err(KernelError::Internal(
                "durable budget store authority is required for threshold admission".to_string(),
            ));
        }
        publication
            .finding_authority
            .ensure_ready()
            .map_err(|error| {
                KernelError::Internal(format!(
                    "active-response finding authority is not ready: {error}"
                ))
            })?;
        publication
            .executor_authority
            .ensure_ready()
            .map_err(|error| {
                KernelError::Internal(format!(
                    "active-response executor authority is not ready: {error}"
                ))
            })?;
        publication
            .capability_issuance_admission_authority
            .ensure_ready()
            .map_err(|error| {
                KernelError::Internal(format!(
                    "capability issuance admission authority is not ready: {error}"
                ))
            })?;
        let executor_identity = publication.executor_authority.identity();
        if executor_identity.generation() <= self.active_response_executor_generation_floor {
            return Err(KernelError::Internal(
                "active-response executor authority generation must increase on replacement"
                    .to_string(),
            ));
        }
        if let Some(installed) = self.active_response_executor.as_ref() {
            let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "active-response executor rotation requires the durable operation store"
                        .to_string(),
                )
            })?;
            let incomplete = operation_store
                .count_unresolved_by_authority(
                    AdmissionOperationKind::GovernedActiveResponse,
                    installed.identity.authority_id(),
                )
                .map_err(|error| {
                    KernelError::Internal(format!(
                        "active-response executor rotation audit failed: {error}"
                    ))
                })?;
            if incomplete != 0 {
                return Err(KernelError::Internal(format!(
                    "active-response executor rotation would strand {incomplete} incomplete admission operations"
                )));
            }
        }

        // A cold bootstrap may preinstall the exact candidate stores so every
        // kernel path is already fail-closed before atomic publication. Those
        // rows belong to the candidate runtime and must be recovered below.
        // Any distinct current authority set remains a real replacement and
        // must be drained before publication.
        let candidate_stores_preinstalled = self
            .admission_operation_store
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &publication.admission_operation_store))
            && self
                .approval_store
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &publication.approval_store))
            && Arc::ptr_eq(&self.budget_store, &publication.budget_store);
        if !candidate_stores_preinstalled {
            self.prepare_current_admission_authority_replacement()?;
        }

        // Recover against the candidate durable stores and the currently
        // installed ancillary participant authorities before any publication
        // field changes. Cleanup is operation-bound and idempotent, so durable
        // progress is safe if publication later aborts while the kernel remains
        // on the old generation.
        self.drain_compensated_active_response_operations(
            publication.admission_operation_store.as_ref(),
            Some(publication.approval_store.as_ref()),
        )?;
        self.recover_nonterminal_active_response_operations_with_authorities(
            publication.admission_operation_store.as_ref(),
            Some(publication.approval_store.as_ref()),
            executor_identity.authority_id(),
        )?;

        self.guards = Arc::new(publication.guards.into_iter().map(Arc::from).collect());
        self.post_invocation_pipeline = publication.post_invocation_pipeline;
        self.security_pre_dispatch_hook = Some(publication.pre_dispatch_hook);
        self.security_pre_dispatch_policy = SecurityPreDispatchPolicy::Enforce;
        self.budget_store = publication.budget_store;
        self.admission_operation_store = Some(publication.admission_operation_store);
        self.approval_store = Some(publication.approval_store);
        self.active_response_requirement_resolver =
            Some(publication.active_response_requirement_resolver);
        self.active_response_finding_authority = Some(publication.finding_authority);
        self.capability_issuance_admission_authority =
            Some(publication.capability_issuance_admission_authority);
        self.active_response_executor_generation_floor = executor_identity.generation();
        self.active_response_executor = Some(InstalledActiveResponseExecutor {
            authority: publication.executor_authority,
            identity: executor_identity,
            dispatch_gate: std::sync::Mutex::new(()),
        });
        self.threshold_approval_requirement_resolver =
            Some(publication.threshold_approval_requirement_resolver);
        self.threshold_approval_policy_configured = true;
        self.threshold_approval_policy_authorities = threshold_policy_authorities;
        self.governed_active_response_plans_enabled = true;
        self.threshold_governed_approvals_enabled = true;
        self.governed_security_runtime_generation = next_generation;
        Ok(())
    }

    #[must_use]
    pub fn governed_security_runtime_status(&self) -> GovernedSecurityRuntimeStatus {
        GovernedSecurityRuntimeStatus {
            publication_generation: self.governed_security_runtime_generation,
            active_response_enabled: self.governed_active_response_plans_enabled,
            threshold_approval_enabled: self.threshold_governed_approvals_enabled,
            capability_issuance_admission_enabled: self
                .capability_issuance_admission_authority
                .is_some(),
            executor_authority: self
                .active_response_executor
                .as_ref()
                .map(|installed| installed.identity.clone()),
            active_response_submission_authority: self.active_response_submission_authority.clone(),
            threshold_policy_authorities: self.threshold_approval_policy_authorities.clone(),
            admission_operation_store_profile: self
                .admission_operation_store
                .as_ref()
                .map(|store| store.authority_profile()),
            approval_store_profile: self
                .approval_store
                .as_ref()
                .map(|store| store.authority_profile()),
            budget_store_profile: self.budget_store.budget_guarantee_level(),
        }
    }

    /// Return whether one complete governed runtime publication protects tool
    /// dispatch. The publication operation installs the flow pre-dispatch hook
    /// and switches the kernel to enforced pre-dispatch policy atomically.
    #[must_use]
    pub const fn has_installed_flow_runtime(&self) -> bool {
        self.governed_security_runtime_generation != 0
    }

    pub(super) fn require_manifest_flow_runtime(
        &self,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<(), KernelError> {
        if registry.requires_flow_runtime() && !self.has_installed_flow_runtime() {
            return Err(KernelError::FlowRuntimeUnavailable);
        }
        Ok(())
    }

    pub(super) fn require_no_atomic_security_runtime_publication(&self) -> Result<(), KernelError> {
        if self.has_atomic_security_runtime_publication() {
            return Err(KernelError::Internal(
                "partial security authority mutation is disabled after atomic runtime publication"
                    .to_string(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub(super) const fn has_atomic_security_runtime_publication(&self) -> bool {
        self.governed_security_runtime_generation != 0
    }

    fn validate_threshold_policy_authorities(
        authorities: &[PublicKey],
    ) -> Result<Vec<PublicKey>, KernelError> {
        if authorities.is_empty() || authorities.len() > MAX_THRESHOLD_APPROVAL_TOKENS {
            return Err(KernelError::InvalidConstraint(
                "threshold proposal policy authorities must be nonempty and bounded".to_string(),
            ));
        }
        let mut deduplicated = Vec::with_capacity(authorities.len());
        for authority in authorities {
            if !deduplicated.contains(authority) {
                deduplicated.push(authority.clone());
            }
        }
        Ok(deduplicated)
    }
}
