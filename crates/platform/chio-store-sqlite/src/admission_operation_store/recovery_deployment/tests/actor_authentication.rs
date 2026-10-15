//! Kernel recovery actor authentication over an actual installed deployment:
//! the public installer, the authenticated store read, and the kernel's
//! capability, assignment, binding, policy and effect-contract checks.

use std::sync::atomic::{AtomicU64, Ordering};

use chio_core::capability::scope::{ChioScope, Constraint, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_kernel::admission_operation::{AdmissionOperationStoreError, AdmissionRecoveryError};
use chio_kernel::recovery::{AuthenticatedRecoveryActor, RecoveryToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, RevocationStore,
    SecurityDispatchOutcomeHandle, SecurityPreDispatchContext, SecurityPreDispatchHook,
    ToolServerConnection,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};

use super::*;

mod issuer_lifecycle;

const KERNEL_SEED: u8 = 42;
const SUBJECT_SEED: u8 = 3;
const SERVER_ID: &str = "support-server";

struct BindingHook(NativeSecurityAuthorityBindingV1);

impl SecurityPreDispatchHook for BindingHook {
    fn name(&self) -> &str {
        "recovery-actor-binding"
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.0.clone()))
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "recovery actor authentication never dispatches".into(),
        ))
    }
}

/// The recovery-capable support server; any invocation is counted.
struct SupportServer {
    contract: RecoveryEffectContractV1,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for SupportServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["create-issue".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal(
            "recovery actor authentication never invokes".into(),
        ))
    }
}

impl RecoveryToolServerConnection for SupportServer {
    fn recovery_effect_contract(&self) -> RecoveryEffectContractV1 {
        self.contract.clone()
    }
}

/// An ordinary connection registered under the support server's id.
struct OrdinaryServer;

#[async_trait::async_trait]
impl ToolServerConnection for OrdinaryServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["create-issue".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "ordinary server is never invoked".into(),
        ))
    }
}

fn policy_hash(profile: &RecoveryDeploymentV1) -> String {
    profile
        .policy_digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One installed deployment, its revocation store and a kernel bound to the
/// same serving authority, native binding, policy and support server.
struct Harness {
    fixture: Authority,
    binding: NativeSecurityAuthorityBindingV1,
    profile: RecoveryDeploymentV1,
    revocations: Arc<crate::SqliteRevocationStore>,
    invocations: Arc<AtomicU64>,
    kernel: ChioKernel,
}

fn kernel(fixture: &Authority, policy_hash: String) -> TestResult<ChioKernel> {
    kernel_at(fixture, policy_hash, fixture.fence.clone())
}

/// A kernel serving `fixture` through `fence`.
fn kernel_at(
    fixture: &Authority,
    policy_hash: String,
    fence: StoreMutationFence,
) -> TestResult<ChioKernel> {
    kernel_with(
        fixture,
        policy_hash,
        fence,
        chio_test_support::clock::clock(),
    )
}

/// A kernel serving `fixture` through `fence` on the trusted clock `clock`.
fn kernel_with(
    fixture: &Authority,
    policy_hash: String,
    fence: StoreMutationFence,
    clock: Arc<dyn Clock>,
) -> TestResult<ChioKernel> {
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: key_pair(KERNEL_SEED),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash,
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        },
        clock,
    );
    kernel.set_durable_admission_store(
        Arc::new(fixture.store.clone()),
        Arc::new(fixture.authority.tool_outcome_store()),
        fence,
    )?;
    Ok(kernel)
}

fn harness_with(
    profile: impl FnOnce(RecoveryDeploymentV1) -> TestResult<RecoveryDeploymentV1>,
) -> TestResult<Harness> {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = profile(deployment(&fixture.fence, &binding, "process:primary")?)?;
    fixture.store.configure_recovery_deployment(&profile)?;
    let mut kernel = kernel(&fixture, policy_hash(&profile))?;
    let revocations = Arc::new(fixture.authority.revocation_store());
    kernel.set_revocation_store_handle(revocations.clone());
    kernel.set_security_pre_dispatch_hook(Arc::new(BindingHook(binding.clone())));
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_recovery_tool_server(SupportServer {
        contract: profile.effect_contract.clone(),
        invocations: invocations.clone(),
    });
    Ok(Harness {
        fixture,
        binding,
        profile,
        revocations,
        invocations,
        kernel,
    })
}

fn harness() -> TestResult<Harness> {
    harness_with(Ok)
}

fn recovery_grant(tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: "chio.recovery".into(),
        tool_name: tool.into(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

fn issued(harness: &Harness, subject: u8, grants: Vec<ToolGrant>) -> TestResult<CapabilityToken> {
    Ok(harness
        .kernel
        .issue_capability(&key_pair(subject).public_key(), scope(grants), 300)?)
}

/// A capability signed directly by `issuer` with the given validity window.
fn signed(
    issuer: u8,
    id: &str,
    window: (u64, u64),
    aggregate: Option<chio_core::capability::aggregate_invocation::AggregateInvocationBudget>,
) -> TestResult<CapabilityToken> {
    let issuer = key_pair(issuer);
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.into(),
            issuer: issuer.public_key(),
            subject: key_pair(SUBJECT_SEED).public_key(),
            scope: scope(vec![recovery_grant("inspect")]),
            issued_at: window.0,
            expires_at: window.1,
            delegation_chain: vec![],
            aggregate_invocation_budget: aggregate,
        },
        &issuer,
    )?)
}

fn now_secs() -> TestResult<u64> {
    Ok(now_ms()? / 1_000)
}

fn denied<T: std::fmt::Debug>(result: Result<T, KernelError>) -> TestResult {
    match result {
        Err(KernelError::RecoveryAuthorityDenied) => Ok(()),
        other => Err(format!("expected the recovery authority refusal, got {other:?}").into()),
    }
}

fn unsupported<T: std::fmt::Debug>(result: Result<T, KernelError>) -> TestResult {
    match result {
        Err(KernelError::DurableAdmission(reason))
            if reason == "native recovery profile is unsupported" =>
        {
            Ok(())
        }
        other => Err(format!("expected the unsupported recovery profile, got {other:?}").into()),
    }
}

fn store_refusal<T: std::fmt::Debug>(
    result: Result<T, KernelError>,
    expected: AdmissionOperationStoreError,
) -> TestResult {
    match result {
        Err(KernelError::AdmissionRecovery(error)) => match *error {
            AdmissionRecoveryError::Store(actual) if actual == expected => Ok(()),
            other => Err(format!("expected store refusal {expected:?}, got {other:?}").into()),
        },
        other => Err(format!("expected store refusal {expected:?}, got {other:?}").into()),
    }
}

fn authenticate(
    harness: &Harness,
    capability: &CapabilityToken,
    permission: RecoveryPermission,
) -> Result<AuthenticatedRecoveryActor, KernelError> {
    harness
        .kernel
        .authenticate_recovery_actor(&harness.profile.scope, capability, permission)
}

/// Records, events and recovery commits, and every global commit.
fn writes(fixture: &Authority) -> TestResult<(Counts, i64)> {
    let raw = Connection::open(&fixture.database)?;
    let global = raw.query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
        row.get(0)
    })?;
    Ok((fixture.counts()?, global))
}

const EVERY_PERMISSION: [RecoveryPermission; 17] = [
    RecoveryPermission::Create,
    RecoveryPermission::Inspect,
    RecoveryPermission::Select,
    RecoveryPermission::Approve,
    RecoveryPermission::Resume,
    RecoveryPermission::Cancel,
    RecoveryPermission::Report,
    RecoveryPermission::Settle,
    RecoveryPermission::KnowledgeRead,
    RecoveryPermission::KnowledgeWrite,
    RecoveryPermission::KnowledgeAdopt,
    RecoveryPermission::KnowledgeAdmin,
    RecoveryPermission::ConfinedLaunch,
    RecoveryPermission::ConfinedReturn,
    RecoveryPermission::ConfinedCancel,
    RecoveryPermission::Maintain,
    RecoveryPermission::InspectExplanationGraph,
];

fn every_permission(profile: RecoveryDeploymentV1) -> TestResult<RecoveryDeploymentV1> {
    let mut profile = profile;
    let mut actor = profile
        .actors
        .as_slice()
        .first()
        .cloned()
        .ok_or("fixture actor absent")?;
    actor.permissions = BoundedList::new(EVERY_PERMISSION.to_vec())?;
    profile.actors = NonEmptyBoundedList::new(vec![actor])?;
    sealed(profile)
}

#[test]
fn every_permission_authenticates_and_revalidates_without_writing() -> TestResult {
    let harness = harness_with(every_permission)?;
    let grants = EVERY_PERMISSION
        .iter()
        .map(|permission| recovery_grant(permission.wire_name()))
        .collect();
    let capability = issued(&harness, SUBJECT_SEED, grants)?;
    let before = writes(&harness.fixture)?;
    for permission in EVERY_PERMISSION {
        let actor = authenticate(&harness, &capability, permission)?;
        assert_eq!(actor.permission(), permission);
        assert_eq!(actor.principal(), &PrincipalId::new("operator")?);
        assert_eq!(actor.scope(), &harness.profile.scope);
        assert_eq!(actor.capability().id, capability.id);
        harness.kernel.revalidate_recovery_actor(&actor)?;
    }
    let inspection = authenticate(
        &harness,
        &capability,
        RecoveryPermission::InspectExplanationGraph,
    )?;
    assert_eq!(inspection.permission().wire_name(), "explanation.inspect");
    assert_eq!(writes(&harness.fixture)?, before);
    assert_eq!(harness.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn unassigned_subject_and_absent_permission_are_denied() -> TestResult {
    let harness = harness()?;
    let stranger = issued(&harness, 9, vec![recovery_grant("inspect")])?;
    denied(authenticate(
        &harness,
        &stranger,
        RecoveryPermission::Inspect,
    ))?;
    let assigned = issued(&harness, SUBJECT_SEED, vec![recovery_grant("approve")])?;
    denied(authenticate(
        &harness,
        &assigned,
        RecoveryPermission::Approve,
    ))?;
    Ok(())
}

#[test]
fn only_the_exact_unconstrained_recovery_grant_permits() -> TestResult {
    let harness = harness()?;
    let mut other_server = recovery_grant("inspect");
    other_server.server_id = "other-server".into();
    let mut wildcard_tool = recovery_grant("inspect");
    wildcard_tool.tool_name = "*".into();
    let mut wildcard_server = recovery_grant("inspect");
    wildcard_server.server_id = "*".into();
    let mut limited = recovery_grant("inspect");
    limited.max_invocations = Some(1);
    let mut read_only = recovery_grant("inspect");
    read_only.operations = vec![Operation::Read];
    let refused = [
        vec![other_server],
        vec![wildcard_tool],
        vec![recovery_grant("inspect"), wildcard_server],
        vec![limited],
        vec![read_only],
        vec![recovery_grant("create")],
    ];
    for grants in refused {
        let capability = issued(&harness, SUBJECT_SEED, grants)?;
        denied(authenticate(
            &harness,
            &capability,
            RecoveryPermission::Inspect,
        ))?;
    }
    let exact = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    authenticate(&harness, &exact, RecoveryPermission::Inspect)?;
    Ok(())
}

#[test]
fn capability_time_issuer_and_unsupported_fields_are_denied() -> TestResult {
    let harness = harness()?;
    let now = now_secs()?;
    let expired = signed(
        KERNEL_SEED,
        "cap-recovery-expired",
        (now - 7_200, now - 3_600),
        None,
    )?;
    denied(authenticate(
        &harness,
        &expired,
        RecoveryPermission::Inspect,
    ))?;
    let early = signed(
        KERNEL_SEED,
        "cap-recovery-early",
        (now + 3_600, now + 7_200),
        None,
    )?;
    denied(authenticate(&harness, &early, RecoveryPermission::Inspect))?;
    let untrusted = signed(77, "cap-recovery-untrusted", (now - 60, now + 300), None)?;
    denied(authenticate(
        &harness,
        &untrusted,
        RecoveryPermission::Inspect,
    ))?;
    let budgeted = signed(
        KERNEL_SEED,
        "cap-recovery-budgeted",
        (now - 60, now + 300),
        Some(chio_core::capability::aggregate_invocation::AggregateInvocationBudget {
            scope: chio_core::capability::aggregate_invocation::AggregateInvocationScope::Capability,
            max_invocations: 5,
            root_binding: None,
        }),
    )?;
    denied(authenticate(
        &harness,
        &budgeted,
        RecoveryPermission::Inspect,
    ))?;
    let current = signed(
        KERNEL_SEED,
        "cap-recovery-current",
        (now - 60, now + 300),
        None,
    )?;
    authenticate(&harness, &current, RecoveryPermission::Inspect)?;
    Ok(())
}

#[test]
fn revocation_denies_authentication_and_revalidation() -> TestResult {
    let harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let actor = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    assert!(harness.revocations.revoke(&capability.id)?);
    denied(harness.kernel.revalidate_recovery_actor(&actor))?;
    denied(authenticate(
        &harness,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    Ok(())
}

#[test]
fn absent_mismatched_or_withdrawn_effect_contract_is_unsupported() -> TestResult {
    let mut harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    harness
        .kernel
        .register_tool_server(Box::new(OrdinaryServer));
    unsupported(authenticate(
        &harness,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    let mut other = harness.profile.effect_contract.clone();
    other.resource = ProtectedText::new("https://support.example/other")?;
    harness.kernel.register_recovery_tool_server(SupportServer {
        contract: other,
        invocations: harness.invocations.clone(),
    });
    unsupported(authenticate(
        &harness,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    let mut absent = kernel(&harness.fixture, policy_hash(&harness.profile))?;
    absent.set_security_pre_dispatch_hook(Arc::new(BindingHook(harness.binding.clone())));
    unsupported(absent.authenticate_recovery_actor(
        &harness.profile.scope,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    Ok(())
}

#[test]
fn replacing_the_registered_connection_refuses_revalidation() -> TestResult {
    let mut harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let original = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    harness.kernel.register_recovery_tool_server(SupportServer {
        contract: harness.profile.effect_contract.clone(),
        invocations: harness.invocations.clone(),
    });
    denied(harness.kernel.revalidate_recovery_actor(&original))?;
    let replacement = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    harness.kernel.revalidate_recovery_actor(&replacement)?;
    harness
        .kernel
        .register_tool_server(Box::new(OrdinaryServer));
    unsupported(harness.kernel.revalidate_recovery_actor(&replacement))?;
    assert_eq!(harness.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_binding_and_policy_must_match_the_deployment() -> TestResult {
    let harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let support = || SupportServer {
        contract: harness.profile.effect_contract.clone(),
        invocations: harness.invocations.clone(),
    };
    let mut unbound = kernel(&harness.fixture, policy_hash(&harness.profile))?;
    unbound.register_recovery_tool_server(support());
    unsupported(unbound.authenticate_recovery_actor(
        &harness.profile.scope,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    let secondary = harness.fixture.initialized_binding("native-secondary")?;
    let mut rebound = kernel(&harness.fixture, policy_hash(&harness.profile))?;
    rebound.set_security_pre_dispatch_hook(Arc::new(BindingHook(secondary)));
    rebound.register_recovery_tool_server(support());
    unsupported(rebound.authenticate_recovery_actor(
        &harness.profile.scope,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    let mut repolicied = kernel(&harness.fixture, "02".repeat(32))?;
    repolicied.set_security_pre_dispatch_hook(Arc::new(BindingHook(harness.binding.clone())));
    repolicied.register_recovery_tool_server(support());
    unsupported(repolicied.authenticate_recovery_actor(
        &harness.profile.scope,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    Ok(())
}

#[test]
fn profile_rotation_refuses_revalidation_of_earlier_actors() -> TestResult {
    let harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let original = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    let mut rotated = harness.profile.clone();
    rotated.aggregate_issuer = key_pair(12).public_key();
    harness
        .fixture
        .store
        .configure_recovery_deployment(&sealed(rotated.clone())?)?;
    denied(harness.kernel.revalidate_recovery_actor(&original))?;
    let current = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    harness.kernel.revalidate_recovery_actor(&current)?;
    let mut withdrawn = rotated;
    let mut actor = withdrawn
        .actors
        .as_slice()
        .first()
        .cloned()
        .ok_or("fixture actor absent")?;
    actor.permissions = BoundedList::new(vec![RecoveryPermission::Create])?;
    withdrawn.actors = NonEmptyBoundedList::new(vec![actor])?;
    harness
        .fixture
        .store
        .configure_recovery_deployment(&sealed(withdrawn)?)?;
    denied(harness.kernel.revalidate_recovery_actor(&current))?;
    denied(authenticate(
        &harness,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    Ok(())
}

#[test]
fn foreign_scope_and_stale_kernel_fence_are_refused() -> TestResult {
    let harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let mut foreign = harness.profile.scope.clone();
    foreign.authority_domain = AuthorityDomainId::new("foreign-authority")?;
    unsupported(harness.kernel.authenticate_recovery_actor(
        &foreign,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    let mut stale = harness.fixture.fence.clone();
    stale.owner_epoch += 1;
    let mut fenced = kernel_at(&harness.fixture, policy_hash(&harness.profile), stale)?;
    fenced.set_security_pre_dispatch_hook(Arc::new(BindingHook(harness.binding.clone())));
    store_refusal(
        fenced.authenticate_recovery_actor(
            &harness.profile.scope,
            &capability,
            RecoveryPermission::Inspect,
        ),
        AdmissionOperationStoreError::Fenced,
    )?;
    Ok(())
}

#[test]
fn retained_corruption_refuses_authentication() -> TestResult {
    let harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let actor = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    delete_projection_through_owner(
        &harness.fixture.store,
        &harness.fixture.fence,
        &current_record_key(&harness.profile)?,
    )?;
    let expected = invariant("recovery record disappeared with retained history");
    store_refusal(
        harness.kernel.revalidate_recovery_actor(&actor),
        expected.clone(),
    )?;
    store_refusal(
        authenticate(&harness, &capability, RecoveryPermission::Inspect),
        expected,
    )?;
    Ok(())
}

/// A kernel trusted clock at a settable wall time with one monotonic instant.
struct SettableClock(AtomicU64);

impl Clock for SettableClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        Ok(ClockReading::new(
            UnixMillis::new(self.0.load(Ordering::SeqCst)),
            MonotonicInstant::from_nanos(0),
        ))
    }
}

/// A fully bound kernel for the harness deployment whose trusted clock starts
/// at `millis`.
fn clocked_kernel(harness: &Harness, millis: u64) -> TestResult<(ChioKernel, Arc<SettableClock>)> {
    let clock = Arc::new(SettableClock(AtomicU64::new(millis)));
    let mut kernel = kernel_with(
        &harness.fixture,
        policy_hash(&harness.profile),
        harness.fixture.fence.clone(),
        clock.clone(),
    )?;
    kernel.set_security_pre_dispatch_hook(Arc::new(BindingHook(harness.binding.clone())));
    kernel.register_recovery_tool_server(SupportServer {
        contract: harness.profile.effect_contract.clone(),
        invocations: harness.invocations.clone(),
    });
    Ok((kernel, clock))
}

fn clock_regression<T: std::fmt::Debug>(result: Result<T, KernelError>) -> TestResult {
    match result {
        Err(KernelError::Clock(ClockError::WallClockRegression)) => Ok(()),
        other => Err(format!("expected the wall-clock regression, got {other:?}").into()),
    }
}

#[test]
fn dpop_bound_and_constrained_recovery_grants_are_denied() -> TestResult {
    let harness = harness()?;
    let mut dpop = recovery_grant("inspect");
    dpop.dpop_required = Some(true);
    let mut constrained = recovery_grant("inspect");
    constrained.constraints = vec![Constraint::MaxLength(64)];
    let mut dpop_optional = recovery_grant("inspect");
    dpop_optional.dpop_required = Some(false);
    let before = writes(&harness.fixture)?;
    for grants in [
        vec![dpop.clone()],
        vec![constrained],
        vec![recovery_grant("inspect"), dpop],
    ] {
        let capability = issued(&harness, SUBJECT_SEED, grants)?;
        denied(authenticate(
            &harness,
            &capability,
            RecoveryPermission::Inspect,
        ))?;
    }
    for grants in [vec![recovery_grant("inspect")], vec![dpop_optional]] {
        let capability = issued(&harness, SUBJECT_SEED, grants)?;
        let actor = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
        harness.kernel.revalidate_recovery_actor(&actor)?;
    }
    assert_eq!(writes(&harness.fixture)?, before);
    assert_eq!(harness.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

/// The kernel's fenced authority clock stepping back refuses before any
/// capability, store or server check, for fresh and earlier actors alike.
#[test]
fn kernel_authority_clock_regression_refuses_without_writing() -> TestResult {
    let harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let now = now_ms()?;
    let (kernel, clock) = clocked_kernel(&harness, now)?;
    let actor = kernel.authenticate_recovery_actor(
        &harness.profile.scope,
        &capability,
        RecoveryPermission::Inspect,
    )?;
    kernel.revalidate_recovery_actor(&actor)?;
    let before = writes(&harness.fixture)?;
    clock.0.store(now - 1_000, Ordering::SeqCst);
    clock_regression(kernel.authenticate_recovery_actor(
        &harness.profile.scope,
        &capability,
        RecoveryPermission::Inspect,
    ))?;
    clock_regression(kernel.revalidate_recovery_actor(&actor))?;
    assert_eq!(writes(&harness.fixture)?, before);
    assert_eq!(harness.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

/// A kernel whose trusted time trails the serving authority by more than the
/// permitted skew passes capability verification at its own time and is then
/// refused by the store's authority time check.
#[test]
fn kernel_authority_time_behind_the_serving_authority_is_refused() -> TestResult {
    let harness = harness()?;
    let now = now_secs()?;
    let capability = signed(
        KERNEL_SEED,
        "cap-recovery-skewed",
        (now - 900, now + 300),
        None,
    )?;
    authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    let (behind, _clock) = clocked_kernel(&harness, (now - 600) * 1_000)?;
    let before = writes(&harness.fixture)?;
    store_refusal(
        behind.authenticate_recovery_actor(
            &harness.profile.scope,
            &capability,
            RecoveryPermission::Inspect,
        ),
        invariant("trusted_now_unix_ms exceeds the permitted system-clock skew"),
    )?;
    assert_eq!(writes(&harness.fixture)?, before);
    assert_eq!(harness.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn missing_global_reference_refuses_authentication_and_revalidation() -> TestResult {
    let harness = harness()?;
    let capability = issued(&harness, SUBJECT_SEED, vec![recovery_grant("inspect")])?;
    let actor = authenticate(&harness, &capability, RecoveryPermission::Inspect)?;
    super::authenticated_read::install_second_scope(&harness.fixture, &harness.profile)?;
    harness.kernel.revalidate_recovery_actor(&actor)?;
    super::authenticated_read::drop_current_global_reference(&harness.fixture, &harness.profile)?;
    let before = writes(&harness.fixture)?;
    let expected = invariant("historical deployment lost its global reference");
    store_refusal(
        harness.kernel.revalidate_recovery_actor(&actor),
        expected.clone(),
    )?;
    store_refusal(
        authenticate(&harness, &capability, RecoveryPermission::Inspect),
        expected,
    )?;
    assert_eq!(writes(&harness.fixture)?, before);
    assert_eq!(harness.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
