use std::sync::Arc;

use chio_core::receipt::metadata::GuardEvidence;
use chio_core::PublicKey;
use chio_guards::{GuardPipeline, RuntimeGuardProfile};
use chio_kernel::admission_operation::AdmissionOperationStore;
use chio_kernel::approval::ApprovalStore;
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::threshold_approval::ThresholdApprovalRequirementResolver;
use chio_kernel::{
    ActiveResponseExecutorAuthority, ActiveResponseFindingAuthority,
    ActiveResponseRequirementResolver, CapabilityIssuanceAdmissionAuthority, ChioKernel,
    GovernedSecurityRuntimePublication, Guard, GuardContext, GuardDecision,
    IndexedSecurityEvidenceStore, KernelError, PostInvocationContext, PostInvocationHook,
    PostInvocationInspection, PostInvocationPipeline, PostInvocationVerdict,
    SecurityPreDispatchHook, SecurityPreDispatchPolicy, Verdict,
};
use chio_manifest::VerifiedManifestRegistry;
use chio_security_kernel::{
    CapabilitySetSuspensionGuard, IssuanceFreezeAdmission, MissingContextPolicy,
    SessionThrottleGuard,
};
use chio_security_types::ports::{
    CapabilitySetSuspensionStore, IssuanceFreezeStore, SessionThrottleStore,
};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::adapters::NativeActiveResponseFindingAuthority;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveDefenseMode {
    #[default]
    Disabled,
    Shadow,
    Enforce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityDurability {
    Ephemeral,
    FilesystemBacked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityDurability {
    flow: AuthorityDurability,
    declassification: AuthorityDurability,
    decoy: AuthorityDurability,
    event: AuthorityDurability,
    response: AuthorityDurability,
    overlay: AuthorityDurability,
}

impl SecurityDurability {
    #[must_use]
    pub const fn new(
        flow: AuthorityDurability,
        declassification: AuthorityDurability,
        decoy: AuthorityDurability,
        event: AuthorityDurability,
        response: AuthorityDurability,
        overlay: AuthorityDurability,
    ) -> Self {
        Self {
            flow,
            declassification,
            decoy,
            event,
            response,
            overlay,
        }
    }

    #[must_use]
    pub const fn persistent() -> Self {
        Self::new(
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
        )
    }

    #[must_use]
    pub const fn is_persistent(self) -> bool {
        matches!(self.flow, AuthorityDurability::FilesystemBacked)
            && matches!(self.declassification, AuthorityDurability::FilesystemBacked)
            && matches!(self.decoy, AuthorityDurability::FilesystemBacked)
            && matches!(self.event, AuthorityDurability::FilesystemBacked)
            && matches!(self.response, AuthorityDurability::FilesystemBacked)
            && matches!(self.overlay, AuthorityDurability::FilesystemBacked)
    }
}

pub struct SecurityRuntimeParts {
    session_throttle: Box<dyn Guard>,
    tripwire: Box<dyn Guard>,
    containment: Box<dyn Guard>,
    flow_pre: Box<dyn Guard>,
    flow_pre_dispatch: Arc<dyn SecurityPreDispatchHook>,
    raw_tripwire: Box<dyn PostInvocationHook>,
    flow_post: Box<dyn PostInvocationHook>,
}

impl SecurityRuntimeParts {
    #[must_use]
    pub fn new(
        session_throttle: Box<dyn Guard>,
        tripwire: Box<dyn Guard>,
        containment: Box<dyn Guard>,
        flow_pre: Box<dyn Guard>,
        flow_pre_dispatch: Arc<dyn SecurityPreDispatchHook>,
        raw_tripwire: Box<dyn PostInvocationHook>,
        flow_post: Box<dyn PostInvocationHook>,
    ) -> Self {
        Self {
            session_throttle,
            tripwire,
            containment,
            flow_pre,
            flow_pre_dispatch,
            raw_tripwire,
            flow_post,
        }
    }
}

pub struct SecurityRuntimeAuthorityBundle {
    active_response_requirement_resolver: Arc<dyn ActiveResponseRequirementResolver>,
    admission_operation_store: Arc<dyn AdmissionOperationStore>,
    approval_store: Arc<dyn ApprovalStore>,
    budget_store: Arc<dyn BudgetStore>,
    session_throttle_store: Arc<SqliteSecurityStateStore>,
    capability_issuance_admission_authority: Arc<dyn CapabilityIssuanceAdmissionAuthority>,
    finding_authority: Arc<dyn ActiveResponseFindingAuthority>,
    executor_authority: Arc<dyn ActiveResponseExecutorAuthority>,
}

#[derive(Default)]
pub struct SecurityRuntimeAuthorityBundleBuilder {
    active_response_requirement_resolver: Option<Arc<dyn ActiveResponseRequirementResolver>>,
    admission_operation_store: Option<Arc<dyn AdmissionOperationStore>>,
    approval_store: Option<Arc<dyn ApprovalStore>>,
    budget_store: Option<Arc<dyn BudgetStore>>,
    session_throttle_store: Option<Arc<SqliteSecurityStateStore>>,
    indexed_finding_store: Option<Arc<dyn IndexedSecurityEvidenceStore>>,
    trusted_receipt_signers: Option<Vec<PublicKey>>,
    executor_authority: Option<Arc<dyn ActiveResponseExecutorAuthority>>,
}

impl SecurityRuntimeAuthorityBundleBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_active_response_requirement_resolver(
        mut self,
        resolver: Arc<dyn ActiveResponseRequirementResolver>,
    ) -> Self {
        self.active_response_requirement_resolver = Some(resolver);
        self
    }

    #[must_use]
    pub fn with_admission_operation_store(
        mut self,
        store: Arc<dyn AdmissionOperationStore>,
    ) -> Self {
        self.admission_operation_store = Some(store);
        self
    }

    #[must_use]
    pub fn with_approval_store(mut self, store: Arc<dyn ApprovalStore>) -> Self {
        self.approval_store = Some(store);
        self
    }

    #[must_use]
    pub fn with_budget_store(mut self, store: Arc<dyn BudgetStore>) -> Self {
        self.budget_store = Some(store);
        self
    }

    #[must_use]
    pub fn with_session_throttle_store(mut self, store: Arc<SqliteSecurityStateStore>) -> Self {
        self.session_throttle_store = Some(store);
        self
    }

    #[must_use]
    pub fn with_indexed_finding_store(
        mut self,
        store: Arc<dyn IndexedSecurityEvidenceStore>,
    ) -> Self {
        self.indexed_finding_store = Some(store);
        self
    }

    #[must_use]
    pub fn with_trusted_receipt_signers(mut self, signers: Vec<PublicKey>) -> Self {
        self.trusted_receipt_signers = Some(signers);
        self
    }

    #[must_use]
    pub fn with_executor_authority(
        mut self,
        authority: Arc<dyn ActiveResponseExecutorAuthority>,
    ) -> Self {
        self.executor_authority = Some(authority);
        self
    }

    pub fn build(self) -> Result<SecurityRuntimeAuthorityBundle, SecurityRuntimeBuildError> {
        let active_response_requirement_resolver = self
            .active_response_requirement_resolver
            .ok_or(SecurityRuntimeBuildError::ActiveResponseRequirementResolverMissing)?;
        let admission_operation_store = self
            .admission_operation_store
            .ok_or(SecurityRuntimeBuildError::AdmissionOperationStoreMissing)?;
        if !admission_operation_store
            .authority_profile()
            .supports_dispatch_workers(1)
        {
            return Err(SecurityRuntimeBuildError::AdmissionOperationStoreEphemeral);
        }
        let approval_store = self
            .approval_store
            .ok_or(SecurityRuntimeBuildError::ApprovalStoreMissing)?;
        if !approval_store
            .authority_profile()
            .supports_dispatch_workers(1)
        {
            return Err(SecurityRuntimeBuildError::ApprovalStoreEphemeral);
        }
        let budget_store = self
            .budget_store
            .ok_or(SecurityRuntimeBuildError::BudgetStoreMissing)?;
        if !budget_store
            .authority_profile()
            .supports_dispatch_workers(1)
        {
            return Err(SecurityRuntimeBuildError::BudgetStoreEphemeral);
        }
        let session_throttle_store = self
            .session_throttle_store
            .ok_or(SecurityRuntimeBuildError::SessionThrottleStoreMissing)?;
        session_throttle_store
            .ensure_session_throttles_ready()
            .map_err(|_| SecurityRuntimeBuildError::SessionThrottleStoreUnavailable)?;
        session_throttle_store
            .ensure_capability_set_suspensions_ready()
            .map_err(|_| SecurityRuntimeBuildError::CapabilitySetSuspensionStoreUnavailable)?;
        session_throttle_store
            .ensure_issuance_freezes_ready()
            .map_err(|_| SecurityRuntimeBuildError::IssuanceFreezeStoreUnavailable)?;
        let issuance_freeze_store =
            Arc::clone(&session_throttle_store) as Arc<dyn IssuanceFreezeStore>;
        let capability_issuance_admission_authority: Arc<dyn CapabilityIssuanceAdmissionAuthority> =
            Arc::new(IssuanceFreezeAdmission::new(issuance_freeze_store));
        capability_issuance_admission_authority
            .ensure_ready()
            .map_err(|_| SecurityRuntimeBuildError::IssuanceFreezeAdmissionUnavailable)?;
        let indexed_finding_store = self
            .indexed_finding_store
            .ok_or(SecurityRuntimeBuildError::IndexedFindingStoreMissing)?;
        let trusted_receipt_signers = self
            .trusted_receipt_signers
            .ok_or(SecurityRuntimeBuildError::TrustedReceiptSignerMissing)?;
        let finding_authority = Arc::new(
            NativeActiveResponseFindingAuthority::new(
                indexed_finding_store,
                trusted_receipt_signers,
            )
            .map_err(|_| SecurityRuntimeBuildError::TrustedReceiptSignerMissing)?,
        );
        finding_authority
            .ensure_ready()
            .map_err(|_| SecurityRuntimeBuildError::FindingAuthorityUnavailable)?;
        let executor_authority = self
            .executor_authority
            .ok_or(SecurityRuntimeBuildError::ExecutorMissing)?;
        executor_authority
            .ensure_ready()
            .map_err(|_| SecurityRuntimeBuildError::ExecutorUnavailable)?;
        Ok(SecurityRuntimeAuthorityBundle {
            active_response_requirement_resolver,
            admission_operation_store,
            approval_store,
            budget_store,
            session_throttle_store,
            capability_issuance_admission_authority,
            finding_authority,
            executor_authority,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SecurityRuntimeBuildError {
    #[error("active-response requirement resolver is missing")]
    ActiveResponseRequirementResolverMissing,
    #[error("durable admission operation store is missing")]
    AdmissionOperationStoreMissing,
    #[error("admission operation store is ephemeral")]
    AdmissionOperationStoreEphemeral,
    #[error("durable approval store is missing")]
    ApprovalStoreMissing,
    #[error("approval store is ephemeral")]
    ApprovalStoreEphemeral,
    #[error("durable budget store is missing")]
    BudgetStoreMissing,
    #[error("budget store is ephemeral")]
    BudgetStoreEphemeral,
    #[error("durable session-throttle store is missing")]
    SessionThrottleStoreMissing,
    #[error("durable session-throttle store is unavailable")]
    SessionThrottleStoreUnavailable,
    #[error("durable capability-set suspension store is unavailable")]
    CapabilitySetSuspensionStoreUnavailable,
    #[error("durable issuance-freeze store is unavailable")]
    IssuanceFreezeStoreUnavailable,
    #[error("capability issuance admission authority is unavailable")]
    IssuanceFreezeAdmissionUnavailable,
    #[error("durable indexed finding store is missing")]
    IndexedFindingStoreMissing,
    #[error("trusted native receipt signer is missing")]
    TrustedReceiptSignerMissing,
    #[error("authoritative signed-finding authority is unavailable")]
    FindingAuthorityUnavailable,
    #[error("active-response executor authority is missing")]
    ExecutorMissing,
    #[error("active-response executor authority is unavailable")]
    ExecutorUnavailable,
    #[error("production security runtime requires filesystem-backed authorities")]
    EphemeralAuthority,
}

pub struct SecurityRuntime {
    manifests: Arc<VerifiedManifestRegistry>,
    durability: SecurityDurability,
    parts: SecurityRuntimeParts,
    capability_set_suspension: Option<Box<dyn Guard>>,
    authorities: Option<SecurityRuntimeAuthorityBundle>,
}

impl SecurityRuntime {
    #[must_use]
    #[cfg(test)]
    pub(crate) fn new(
        manifests: Arc<VerifiedManifestRegistry>,
        durability: SecurityDurability,
        parts: SecurityRuntimeParts,
    ) -> Self {
        Self {
            manifests,
            durability,
            parts,
            capability_set_suspension: None,
            authorities: None,
        }
    }

    pub(crate) fn production(
        manifests: Arc<VerifiedManifestRegistry>,
        durability: SecurityDurability,
        mut parts: SecurityRuntimeParts,
        authorities: SecurityRuntimeAuthorityBundle,
    ) -> Result<Self, SecurityRuntimeBuildError> {
        if !durability.is_persistent() {
            return Err(SecurityRuntimeBuildError::EphemeralAuthority);
        }
        let session_throttle_store =
            Arc::clone(&authorities.session_throttle_store) as Arc<dyn SessionThrottleStore>;
        let capability_set_suspension_store = Arc::clone(&authorities.session_throttle_store)
            as Arc<dyn CapabilitySetSuspensionStore>;
        parts.session_throttle = Box::new(SessionThrottleGuard::with_system_clock(
            session_throttle_store,
            MissingContextPolicy::Deny,
        ));
        Ok(Self {
            manifests,
            durability,
            parts,
            capability_set_suspension: Some(Box::new(CapabilitySetSuspensionGuard::new(
                capability_set_suspension_store,
                MissingContextPolicy::Deny,
            ))),
            authorities: Some(authorities),
        })
    }

    #[must_use]
    pub fn manifests(&self) -> &Arc<VerifiedManifestRegistry> {
        &self.manifests
    }

    #[must_use]
    pub const fn durability(&self) -> SecurityDurability {
        self.durability
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SecurityInstallError {
    #[error("active defense runtime is required for the configured mode")]
    RuntimeMissing,
    #[error("active defense runtime is invalid while security is disabled")]
    RuntimeUnexpected,
    #[error("enforce mode requires filesystem-backed security authorities")]
    EphemeralAuthority,
    #[error(
        "admitted manifest flow policy or topology requires an installed active defense runtime"
    )]
    FlowManifestRequiresRuntime,
    #[error("enforce mode requires a complete governed security authority bundle")]
    AuthorityBundleMissing,
    #[error("enforce mode requires the loaded threshold-approval policy resolver")]
    ThresholdResolverMissing,
    #[error("enforce mode requires an authenticated threshold policy authority")]
    ThresholdPolicyAuthorityMissing,
    #[error("the durable session-throttle authority is unavailable")]
    SessionThrottleStoreUnavailable,
    #[error("the durable capability-set suspension authority is unavailable")]
    CapabilitySetSuspensionStoreUnavailable,
    #[error("the durable issuance-freeze authority is unavailable")]
    IssuanceFreezeStoreUnavailable,
    #[error("the capability issuance admission authority is unavailable")]
    IssuanceFreezeAdmissionUnavailable,
    #[error("governed security runtime publication failed: {0}")]
    AtomicPublication(String),
}

/// Rejects admitted flow policy or topology when no runtime will mediate it.
///
/// Verified publisher declarations, operator policy, and runtime topology are
/// authoritative dispatch inputs. Compatibility mode is limited to admissions
/// whose effective security remains local and unconstrained.
pub fn reject_unprotected_flow_manifest(
    manifests: &VerifiedManifestRegistry,
) -> Result<(), SecurityInstallError> {
    if manifests.requires_flow_runtime() {
        Err(SecurityInstallError::FlowManifestRequiresRuntime)
    } else {
        Ok(())
    }
}

pub(crate) fn install_security_runtime(
    kernel: &mut ChioKernel,
    mode: ActiveDefenseMode,
    runtime: Option<SecurityRuntime>,
    threshold_resolver: Option<Arc<dyn ThresholdApprovalRequirementResolver>>,
    threshold_policy_authorities: Vec<PublicKey>,
    default_profile: RuntimeGuardProfile,
    configured_pre: GuardPipeline,
    configured_post: PostInvocationPipeline,
) -> Result<(), SecurityInstallError> {
    match mode {
        ActiveDefenseMode::Disabled => {
            if runtime.is_some() {
                return Err(SecurityInstallError::RuntimeUnexpected);
            }
            install_existing(kernel, default_profile, configured_pre, configured_post);
            Ok(())
        }
        ActiveDefenseMode::Shadow | ActiveDefenseMode::Enforce => {
            let runtime = runtime.ok_or(SecurityInstallError::RuntimeMissing)?;
            if matches!(mode, ActiveDefenseMode::Enforce) && !runtime.durability.is_persistent() {
                return Err(SecurityInstallError::EphemeralAuthority);
            }
            install_enabled(
                kernel,
                mode,
                runtime,
                threshold_resolver,
                threshold_policy_authorities,
                default_profile,
                configured_pre,
                configured_post,
            )
        }
    }
}

fn install_existing(
    kernel: &mut ChioKernel,
    default_profile: RuntimeGuardProfile,
    configured_pre: GuardPipeline,
    mut configured_post: PostInvocationPipeline,
) {
    for guard in default_profile.pre_invocation_guards {
        kernel.add_guard(guard);
    }
    if !configured_pre.is_empty() {
        kernel.add_guard(Box::new(configured_pre));
    }
    configured_post.append(default_profile.post_invocation_pipeline);
    if !configured_post.is_empty() {
        kernel.set_post_invocation_pipeline(configured_post);
    }
}

fn install_enabled(
    kernel: &mut ChioKernel,
    mode: ActiveDefenseMode,
    runtime: SecurityRuntime,
    threshold_resolver: Option<Arc<dyn ThresholdApprovalRequirementResolver>>,
    threshold_policy_authorities: Vec<PublicKey>,
    default_profile: RuntimeGuardProfile,
    configured_pre: GuardPipeline,
    configured_post: PostInvocationPipeline,
) -> Result<(), SecurityInstallError> {
    let SecurityRuntime {
        manifests,
        parts,
        capability_set_suspension,
        authorities,
        durability: _,
    } = runtime;
    let SecurityRuntimeParts {
        session_throttle,
        tripwire,
        containment,
        flow_pre,
        flow_pre_dispatch,
        raw_tripwire,
        flow_post,
    } = parts;
    let mut guards = vec![
        security_guard(mode, tripwire, Some(manifests)),
        security_guard(mode, containment, None),
        security_guard(mode, flow_pre, None),
    ];
    if let Some(capability_set_suspension) = capability_set_suspension {
        guards.push(security_guard(mode, capability_set_suspension, None));
    }
    guards.push(security_guard(mode, session_throttle, None));
    for guard in default_profile.pre_invocation_guards {
        guards.push(guard);
    }
    if !configured_pre.is_empty() {
        guards.push(Box::new(configured_pre));
    }

    let mut post = PostInvocationPipeline::new();
    add_security_hook(&mut post, mode, raw_tripwire);
    post.append(configured_post);
    post.append(default_profile.post_invocation_pipeline);
    add_security_hook(&mut post, mode, flow_post);
    if matches!(mode, ActiveDefenseMode::Enforce) {
        let authorities = authorities.ok_or(SecurityInstallError::AuthorityBundleMissing)?;
        authorities
            .session_throttle_store
            .ensure_session_throttles_ready()
            .map_err(|_| SecurityInstallError::SessionThrottleStoreUnavailable)?;
        authorities
            .session_throttle_store
            .ensure_capability_set_suspensions_ready()
            .map_err(|_| SecurityInstallError::CapabilitySetSuspensionStoreUnavailable)?;
        authorities
            .session_throttle_store
            .ensure_issuance_freezes_ready()
            .map_err(|_| SecurityInstallError::IssuanceFreezeStoreUnavailable)?;
        authorities
            .capability_issuance_admission_authority
            .ensure_ready()
            .map_err(|_| SecurityInstallError::IssuanceFreezeAdmissionUnavailable)?;
        let threshold_approval_requirement_resolver =
            threshold_resolver.ok_or(SecurityInstallError::ThresholdResolverMissing)?;
        if threshold_policy_authorities.is_empty() {
            return Err(SecurityInstallError::ThresholdPolicyAuthorityMissing);
        }
        kernel
            .publish_governed_security_runtime(GovernedSecurityRuntimePublication {
                active_response_requirement_resolver: authorities
                    .active_response_requirement_resolver,
                threshold_approval_requirement_resolver,
                admission_operation_store: authorities.admission_operation_store,
                approval_store: authorities.approval_store,
                budget_store: authorities.budget_store,
                finding_authority: authorities.finding_authority,
                executor_authority: authorities.executor_authority,
                capability_issuance_admission_authority: authorities
                    .capability_issuance_admission_authority,
                threshold_policy_authorities,
                guards,
                pre_dispatch_hook: flow_pre_dispatch,
                post_invocation_pipeline: post,
            })
            .map_err(|error| SecurityInstallError::AtomicPublication(error.to_string()))?;
    } else {
        kernel.clear_security_pre_dispatch_hook();
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Optional);
        for guard in guards {
            kernel.add_guard(guard);
        }
        kernel.set_post_invocation_pipeline(post);
    }
    Ok(())
}

fn security_guard(
    mode: ActiveDefenseMode,
    guard: Box<dyn Guard>,
    manifests: Option<Arc<VerifiedManifestRegistry>>,
) -> Box<dyn Guard> {
    let retained: Box<dyn Guard> = match manifests {
        Some(manifests) => Box::new(RetainedManifestGuard {
            inner: guard,
            _manifests: manifests,
        }),
        None => guard,
    };
    if matches!(mode, ActiveDefenseMode::Shadow) {
        Box::new(ShadowGuard(retained))
    } else {
        retained
    }
}

fn add_security_hook(
    pipeline: &mut PostInvocationPipeline,
    mode: ActiveDefenseMode,
    hook: Box<dyn PostInvocationHook>,
) {
    if matches!(mode, ActiveDefenseMode::Shadow) {
        pipeline.add(Box::new(ShadowHook(hook)));
    } else {
        pipeline.add(hook);
    }
}

struct RetainedManifestGuard {
    inner: Box<dyn Guard>,
    _manifests: Arc<VerifiedManifestRegistry>,
}

impl Guard for RetainedManifestGuard {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        self.inner.evaluate(context)
    }
}

struct ShadowGuard(Box<dyn Guard>);

impl Guard for ShadowGuard {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        match self.0.evaluate(context) {
            Ok(mut decision) => {
                if !matches!(decision.verdict, Verdict::Allow) {
                    decision.evidence.push(shadow_evidence(self.name()));
                    decision.verdict = Verdict::Allow;
                }
                Ok(decision)
            }
            Err(_) => Ok(GuardDecision::allow_with_evidence(vec![shadow_evidence(
                self.name(),
            )])),
        }
    }
}

struct ShadowHook(Box<dyn PostInvocationHook>);

impl PostInvocationHook for ShadowHook {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn inspect(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationVerdict {
        self.inspect_with_evidence(context, response).verdict
    }

    fn inspect_with_evidence(
        &self,
        context: &PostInvocationContext<'_>,
        response: &Value,
    ) -> PostInvocationInspection {
        let mut inspection = self.0.inspect_with_evidence(context, response);
        if !matches!(inspection.verdict, PostInvocationVerdict::Allow) {
            inspection.evidence.push(shadow_evidence(self.name()));
            inspection.verdict = PostInvocationVerdict::Escalate(format!(
                "{} produced a shadow-mode decision",
                self.name()
            ));
        }
        inspection
    }
}

fn shadow_evidence(name: &str) -> GuardEvidence {
    GuardEvidence {
        guard_name: name.to_string(),
        verdict: true,
        details: Some("shadow_mode=true; enforcement=unchanged".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{reject_unprotected_flow_manifest, SecurityInstallError, ShadowGuard, ShadowHook};
    use chio_core::capability::scope::ChioScope;
    use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        Guard, GuardContext, GuardDecision, KernelError, PostInvocationContext, PostInvocationHook,
        PostInvocationVerdict, ToolCallRequest, Verdict,
    };
    use serde_json::Value;

    fn manifest_registry(
        flow: Option<chio_security_types::flow::ToolFlowDeclaration>,
        topology: chio_manifest::RuntimeToolTopology,
    ) -> chio_manifest::VerifiedManifestRegistry {
        let signer = Keypair::generate();
        let manifest = chio_manifest::ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "runtime-security-server".to_string(),
            name: "Runtime security server".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![chio_manifest::ToolDefinition {
                name: "invoke".to_string(),
                description: "Invoke".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: true,
                    requires_approval: false,
                },
                latency_hint: None,
                flow,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &signer)
            .unwrap_or_else(|error| panic!("sign manifest: {error}"));
        let mut registry = chio_manifest::VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &signer.public_key(), topology)
            .unwrap_or_else(|error| panic!("register manifest: {error}"));
        registry
    }

    #[test]
    fn unprotected_kernel_rejects_flow_manifest_but_accepts_manifest_without_flow() {
        let flow_registry = manifest_registry(
            Some(chio_security_types::flow::ToolFlowDeclaration::public_egress()),
            chio_manifest::RuntimeToolTopology::local(),
        );
        assert_eq!(
            reject_unprotected_flow_manifest(&flow_registry),
            Err(SecurityInstallError::FlowManifestRequiresRuntime)
        );

        let topology_registry =
            manifest_registry(None, chio_manifest::RuntimeToolTopology::remote());
        assert_eq!(
            reject_unprotected_flow_manifest(&topology_registry),
            Err(SecurityInstallError::FlowManifestRequiresRuntime)
        );

        let compatibility_registry =
            manifest_registry(None, chio_manifest::RuntimeToolTopology::local());
        assert_eq!(
            reject_unprotected_flow_manifest(&compatibility_registry),
            Ok(())
        );
    }

    struct DenyGuard;

    impl Guard for DenyGuard {
        fn name(&self) -> &str {
            "deny-security"
        }

        fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }

    struct ErrorGuard;

    impl Guard for ErrorGuard {
        fn name(&self) -> &str {
            "error-security"
        }

        fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            Err(KernelError::Internal(
                "security authority unavailable".to_string(),
            ))
        }
    }

    struct BlockHook;

    impl PostInvocationHook for BlockHook {
        fn name(&self) -> &str {
            "block-security"
        }

        fn inspect(&self, _: &PostInvocationContext<'_>, _: &Value) -> PostInvocationVerdict {
            PostInvocationVerdict::Block("blocked".to_string())
        }
    }

    struct RedactHook;

    impl PostInvocationHook for RedactHook {
        fn name(&self) -> &str {
            "redact-security"
        }

        fn inspect(&self, _: &PostInvocationContext<'_>, _: &Value) -> PostInvocationVerdict {
            PostInvocationVerdict::Redact(serde_json::json!({"redacted": true}))
        }
    }

    fn request() -> ToolCallRequest {
        let keypair = Keypair::generate();
        let scope = ChioScope::default();
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "capability-shadow".to_string(),
                issuer: keypair.public_key(),
                subject: keypair.public_key(),
                scope,
                issued_at: 1,
                expires_at: u64::MAX,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &keypair,
        )
        .unwrap_or_else(|error| panic!("sign capability: {error}"));
        ToolCallRequest {
            request_id: "request-shadow".to_string(),
            capability,
            tool_name: "tool-shadow".to_string(),
            server_id: "server-shadow".to_string(),
            agent_id: keypair.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        }
    }

    #[test]
    fn shadow_guard_preserves_denial_evidence_without_enforcement() {
        let request = request();
        let scope = request.capability.scope.clone();
        let context = GuardContext::new(&request, &scope);
        let decision = ShadowGuard(Box::new(DenyGuard))
            .evaluate(&context)
            .unwrap_or_else(|error| panic!("shadow guard: {error}"));
        assert_eq!(decision.verdict, Verdict::Allow);
        assert!(decision.evidence.iter().any(|evidence| {
            evidence.guard_name == "deny-security"
                && evidence.details.as_deref() == Some("shadow_mode=true; enforcement=unchanged")
        }));
    }

    #[test]
    fn shadow_guard_authority_error_does_not_change_the_call() {
        let request = request();
        let scope = request.capability.scope.clone();
        let context = GuardContext::new(&request, &scope);
        let decision = ShadowGuard(Box::new(ErrorGuard))
            .evaluate(&context)
            .unwrap_or_else(|error| panic!("shadow guard: {error}"));
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.evidence.len(), 1);
    }

    #[test]
    fn shadow_post_hooks_never_block_or_rewrite_output() {
        let context = PostInvocationContext::synthetic("tool-shadow");
        let response = serde_json::json!({"secret": "retained"});
        for hook in [
            ShadowHook(Box::new(BlockHook)),
            ShadowHook(Box::new(RedactHook)),
        ] {
            let inspection = hook.inspect_with_evidence(&context, &response);
            assert!(matches!(
                inspection.verdict,
                PostInvocationVerdict::Escalate(_)
            ));
            assert_eq!(inspection.evidence.len(), 1);
        }
    }
}
