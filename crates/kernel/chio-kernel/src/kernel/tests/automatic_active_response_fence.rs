use super::*;

use chio_core::capability::governance::GovernedResponsePlanIntentBody;
use chio_core::{canonical_json_bytes, sha256, Keypair};
use chio_security_types::ports::{
    ActionId, CanonicalBody, Digest32, EffectId, OpaqueReceiptRef,
    PreparedActiveResponseDispatchBinding, RecordId, RecordIdSet, ResponseDispatchApproval,
    SessionId, TenantId, PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::{
    OperatorCapabilityBinding, PlannedResponseEffect, PlannedResponseEffects,
    ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec, ResponsePlan,
    ResponseTarget,
};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use crate::kernel::{
    ActiveResponseExecutionApproval, ActiveResponseExecutionEvidence,
    ActiveResponseExecutionRequest, ActiveResponseExecutionRequestParts,
    ActiveResponseExecutorAuthority, ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseExecutorError, AutomaticActiveResponseDispatchFenceOutcome,
};

const AFFECTED_SET_HASH_DOMAIN: &[u8] = b"chio.response-affected-set.v1\0";
const RESPONSE_EFFECT_ID_DOMAIN: &[u8] = b"chio.response-effect.v1\0";

#[derive(Clone)]
struct Pause {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl Pause {
    fn new() -> Self {
        Self {
            entered: Arc::new(Barrier::new(2)),
            release: Arc::new(Barrier::new(2)),
        }
    }

    fn pause(&self) {
        self.entered.wait();
        self.release.wait();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableDispatchState {
    Open,
    Fenced,
    Committed,
}

struct RacingAutomaticExecutorAuthority {
    identity: ActiveResponseExecutorAuthorityIdentity,
    expected_plan: ResponsePlan,
    expected_binding: PreparedActiveResponseDispatchBinding,
    state: Mutex<DurableDispatchState>,
    before_commit: Option<Pause>,
    before_fence: Option<Pause>,
}

impl RacingAutomaticExecutorAuthority {
    fn state(&self) -> DurableDispatchState {
        *self.state.lock().expect("durable dispatch state lock")
    }
}

impl ActiveResponseExecutorAuthority for RacingAutomaticExecutorAuthority {
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
        self.identity.clone()
    }

    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        Ok(())
    }

    fn fence_uncommitted_automatic_dispatch(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<AutomaticActiveResponseDispatchFenceOutcome, ActiveResponseExecutorError> {
        if response_plan != &self.expected_plan || binding != &self.expected_binding {
            return Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                "automatic fence binding mismatch".to_string(),
            ));
        }
        if let Some(pause) = self.before_fence.as_ref() {
            pause.pause();
        }
        let mut state = self.state.lock().map_err(|_| {
            ActiveResponseExecutorError::OutcomeUnknown(
                "durable dispatch state lock is poisoned".to_string(),
            )
        })?;
        match *state {
            DurableDispatchState::Open => {
                *state = DurableDispatchState::Fenced;
                Ok(AutomaticActiveResponseDispatchFenceOutcome::Fenced)
            }
            DurableDispatchState::Fenced => Ok(AutomaticActiveResponseDispatchFenceOutcome::Fenced),
            DurableDispatchState::Committed => {
                Ok(AutomaticActiveResponseDispatchFenceOutcome::DispatchCommitted)
            }
        }
    }

    fn execute_active_response(
        &self,
        request: &ActiveResponseExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        if request.response_plan() != &self.expected_plan
            || request.dispatch_id() != &self.expected_binding.dispatch_id
            || request.executor_authority() != &self.identity
        {
            return Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                "automatic execution binding mismatch".to_string(),
            ));
        }
        if let Some(pause) = self.before_commit.as_ref() {
            pause.pause();
        }
        let mut state = self.state.lock().map_err(|_| {
            ActiveResponseExecutorError::OutcomeUnknown(
                "durable dispatch state lock is poisoned".to_string(),
            )
        })?;
        match *state {
            DurableDispatchState::Open => {
                *state = DurableDispatchState::Committed;
                Err(ActiveResponseExecutorError::OutcomeUnknown(
                    "dispatch commit persisted before result delivery".to_string(),
                ))
            }
            DurableDispatchState::Fenced => Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                "automatic dispatch is durably fenced".to_string(),
            )),
            DurableDispatchState::Committed => Err(ActiveResponseExecutorError::OutcomeUnknown(
                "dispatch was already committed".to_string(),
            )),
        }
    }
}

struct TwoKernelFixture {
    termination_kernel: Arc<ChioKernel>,
    execution_kernel: Arc<ChioKernel>,
    authority: Arc<RacingAutomaticExecutorAuthority>,
    response_plan: ResponsePlan,
    binding: PreparedActiveResponseDispatchBinding,
    execution: ActiveResponseExecutionRequest,
}

fn two_kernel_fixture(
    before_commit: Option<Pause>,
    before_fence: Option<Pause>,
) -> TwoKernelFixture {
    let executor = Keypair::generate();
    let identity = ActiveResponseExecutorAuthorityIdentity::new(executor.public_key(), 1)
        .expect("executor authority identity");
    let response_plan = automatic_response_plan(&identity);
    let authorized_at_unix_ms = response_plan.created_at_unix_ms + 1;
    let authorization_capability_hash = response_plan.operator_capability.capability_digest;
    let governed_intent_hash = Digest32::new([0x61; 32]);
    let policy_decision_hash = Digest32::new([0x62; 32]);
    let execution_approval = ActiveResponseExecutionApproval::Automatic;
    let dispatch_id = crate::derive_active_response_dispatch_id(
        &response_plan,
        &identity,
        &digest_hex(&authorization_capability_hash),
        &digest_hex(&governed_intent_hash),
        &digest_hex(&policy_decision_hash),
        authorized_at_unix_ms,
        &execution_approval,
    )
    .expect("automatic dispatch id");
    let binding = PreparedActiveResponseDispatchBinding {
        schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
        tenant_id: response_plan.tenant_id.clone(),
        action_id: response_plan.action_id.clone(),
        plan_hash: response_plan.plan_hash,
        dispatch_id: dispatch_id.clone(),
        executor_authority_id: RecordId::new(identity.authority_id().to_string())
            .expect("executor authority id"),
        executor_authority_generation: identity.generation(),
        authorized_at_unix_ms,
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        approval: ResponseDispatchApproval::Automatic,
    };
    let execution = ActiveResponseExecutionRequest::new(ActiveResponseExecutionRequestParts {
        response_plan: response_plan.clone(),
        dispatch_id,
        executor_authority: identity.clone(),
        request_id: response_plan.action_id.as_str().to_string(),
        plan_body_hash: digest_hex(&response_plan.plan_hash),
        authorization_capability_hash: digest_hex(&authorization_capability_hash),
        governed_intent_hash: digest_hex(&governed_intent_hash),
        policy_decision_hash: digest_hex(&policy_decision_hash),
        approval: execution_approval,
        authorized_at_unix_ms,
        expires_at_unix_ms: response_plan.expires_at_unix_ms,
        dispatch_committed_resume: false,
    });
    let authority = Arc::new(RacingAutomaticExecutorAuthority {
        identity,
        expected_plan: response_plan.clone(),
        expected_binding: binding.clone(),
        state: Mutex::new(DurableDispatchState::Open),
        before_commit,
        before_fence,
    });
    let mut termination_kernel = make_kernel(make_config());
    termination_kernel
        .set_active_response_executor_authority(authority.clone())
        .expect("termination kernel executor authority");
    let mut execution_kernel = make_kernel(make_config());
    execution_kernel
        .set_active_response_executor_authority(authority.clone())
        .expect("execution kernel executor authority");
    TwoKernelFixture {
        termination_kernel: Arc::new(termination_kernel),
        execution_kernel: Arc::new(execution_kernel),
        authority,
        response_plan,
        binding,
        execution,
    }
}

#[test]
fn two_kernels_fence_wins_against_an_inflight_automatic_commit() {
    let before_commit = Pause::new();
    let fixture = two_kernel_fixture(Some(before_commit.clone()), None);
    let execution_kernel = Arc::clone(&fixture.execution_kernel);
    let execution = fixture.execution.clone();
    let execution_thread =
        thread::spawn(move || execution_kernel.execute_active_response_with_authority(&execution));

    before_commit.entered.wait();
    let termination = fixture
        .termination_kernel
        .terminate_never_committed_active_response(&fixture.response_plan, &fixture.binding, None);
    before_commit.release.wait();
    let execution = execution_thread.join().expect("execution thread");

    assert!(termination.is_ok());
    assert!(execution.is_err());
    assert_eq!(fixture.authority.state(), DurableDispatchState::Fenced);
}

#[test]
fn two_kernels_commit_wins_before_the_automatic_fence() {
    let before_fence = Pause::new();
    let fixture = two_kernel_fixture(None, Some(before_fence.clone()));
    let termination_kernel = Arc::clone(&fixture.termination_kernel);
    let response_plan = fixture.response_plan.clone();
    let binding = fixture.binding.clone();
    let termination_thread = thread::spawn(move || {
        termination_kernel.terminate_never_committed_active_response(&response_plan, &binding, None)
    });

    before_fence.entered.wait();
    let execution = fixture
        .execution_kernel
        .execute_active_response_with_authority(&fixture.execution);
    before_fence.release.wait();
    let termination = termination_thread.join().expect("termination thread");

    assert!(execution.is_err());
    assert!(termination.is_err());
    assert_eq!(fixture.authority.state(), DurableDispatchState::Committed);
}

fn automatic_response_plan(identity: &ActiveResponseExecutorAuthorityIdentity) -> ResponsePlan {
    let tenant_id = TenantId::new("tenant-two-kernel-fence").expect("tenant id");
    let action_id = ActionId::new("action-two-kernel-fence").expect("action id");
    let affected_ids = RecordIdSet::new(vec![
        RecordId::new("affected-two-kernel-fence").expect("affected id")
    ])
    .expect("affected ids");
    let affected_set_hash = domain_digest(
        AFFECTED_SET_HASH_DOMAIN,
        &AffectedSetCommitment {
            tenant_id: tenant_id.as_str(),
            affected_ids: affected_ids.as_slice(),
        },
    );
    let contribution_bytes =
        canonical_json_bytes(&serde_json::json!({"posture_rank": 3})).expect("contribution");
    let canonical_contribution =
        CanonicalBody::new(contribution_bytes.clone()).expect("canonical contribution");
    let contribution_hash = Digest32::new(*sha256(&contribution_bytes).as_bytes());
    let spec = ResponseEffectSpec {
        kind: ResponseEffectKind::ThrottleSession,
        target: ResponseTarget::Session {
            session_id: SessionId::new("session-two-kernel-fence").expect("session id"),
        },
        canonical_contribution: canonical_contribution.clone(),
        contribution_hash,
        observed_base_version_hash: Digest32::new([0x31; 32]),
    };
    let effect_hash = domain_digest(
        RESPONSE_EFFECT_ID_DOMAIN,
        &EffectCommitment {
            action_id: action_id.as_str(),
            ordinal: 0,
            spec: &spec,
        },
    );
    let effects = PlannedResponseEffects::new(vec![PlannedResponseEffect {
        effect_id: EffectId::new(format!("response_effect_{}", digest_hex(&effect_hash)))
            .expect("effect id"),
        ordinal: 0,
        kind: spec.kind,
        target: spec.target,
        canonical_contribution,
        contribution_hash,
        observed_base_version_hash: spec.observed_base_version_hash,
    }])
    .expect("planned effects");
    let created_at_unix_ms = 1_700_000_000_000;
    let expires_at_unix_ms = created_at_unix_ms + 10_000;
    let mut plan = ResponsePlan {
        action_id,
        trigger_finding_id: RecordId::new("finding-two-kernel-fence").expect("finding id"),
        trigger_finding_hash: Digest32::new([0x41; 32]),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("receipt-two-kernel-fence")
            .expect("finding receipt id"),
        tenant_id,
        policy_version: RecordId::new("policy-two-kernel-fence").expect("policy version"),
        policy_hash: Digest32::new([0x42; 32]),
        affected_ids,
        affected_set_hash,
        effects,
        ttl_ms: expires_at_unix_ms - created_at_unix_ms,
        created_at_unix_ms,
        expires_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: RecordId::new("capability-two-kernel-fence").expect("capability id"),
            capability_digest: Digest32::new([0x43; 32]),
            expires_at_unix_ms,
            executor_subject: RecordId::new(identity.subject().to_hex()).expect("executor subject"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: RecordId::new("submitter-two-kernel-fence").expect("submitter"),
        reason_hash: Digest32::new([0x44; 32]),
        plan_hash: Digest32::new([0; 32]),
    };
    let canonical_plan_body =
        serde_json::to_value(plan.authorization_body()).expect("plan authorization body");
    plan.plan_hash = Digest32::new(
        *GovernedResponsePlanIntentBody::compute_plan_body_digest(&canonical_plan_body)
            .expect("plan hash")
            .as_bytes(),
    );
    plan
}

#[derive(serde::Serialize)]
struct AffectedSetCommitment<'a> {
    tenant_id: &'a str,
    affected_ids: &'a [RecordId],
}

#[derive(serde::Serialize)]
struct EffectCommitment<'a> {
    action_id: &'a str,
    ordinal: u16,
    spec: &'a ResponseEffectSpec,
}

fn domain_digest<T: serde::Serialize>(domain: &[u8], value: &T) -> Digest32 {
    let canonical = canonical_json_bytes(value).expect("canonical commitment");
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Digest32::new(*sha256(&preimage).as_bytes())
}

fn digest_hex(digest: &Digest32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
