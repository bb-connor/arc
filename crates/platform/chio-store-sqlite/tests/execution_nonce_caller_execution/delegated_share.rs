use crate::*;
use chio_core::capability::{
    attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};
use std::sync::Arc;

#[path = "delegated_share/boundaries.rs"]
mod boundaries;
#[path = "delegated_share/outcome_unknown.rs"]
mod outcome_unknown;
#[path = "delegated_share/pending.rs"]
mod pending;

struct Siblings {
    parent: CapabilityToken,
    first: CapabilityToken,
    second: CapabilityToken,
}

impl Siblings {
    fn new(fixture: &Fixture, runtime: &mut Runtime) -> TestResult<Self> {
        let parent_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: SERVER_ID.into(),
                tool_name: TOOL_NAME.into(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: Some(2),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        };
        let parent = runtime.kernel.issue_capability(
            &fixture.agent.public_key(),
            parent_scope.clone(),
            600,
        )?;
        let mut child_scope = parent_scope;
        child_scope.grants[0].operations = vec![Operation::Invoke];
        let child = |id: &str| -> TestResult<CapabilityToken> {
            let agent = Keypair::generate();
            let parent_scope_hash = scope_hash(&parent.scope)?;
            let link = DelegationLink::sign(
                DelegationLinkBody {
                    capability_id: parent.id.clone(),
                    delegator: fixture.agent.public_key(),
                    delegatee: agent.public_key(),
                    attenuations: Vec::new(),
                    timestamp: parent.issued_at,
                    scope_hash: Some(parent_scope_hash.clone()),
                    aggregate_budget: None,
                    cumulative_approval: None,
                },
                &fixture.agent,
            )?;
            Ok(CapabilityToken::sign_attenuated(
                CapabilityTokenAttenuationBody {
                    body: CapabilityTokenBody {
                        id: format!("{}:{id}", parent.id),
                        issuer: fixture.signer.public_key(),
                        subject: agent.public_key(),
                        scope: child_scope.clone(),
                        issued_at: parent.issued_at,
                        expires_at: parent.expires_at,
                        delegation_chain: vec![link],
                        aggregate_invocation_budget: None,
                    },
                    caveats: Vec::new(),
                    scope_attenuations: Vec::new(),
                    attenuation_proof: AttenuationProof {
                        parent_scope_hash,
                        child_scope_hash: scope_hash(&child_scope)?,
                        normalized_subset_proof: compute_attenuation_witness(
                            &parent.scope,
                            &child_scope,
                        )?,
                    },
                    budget_share_bps: Some(4_000),
                },
                &fixture.signer,
            )?)
        };
        let first = child("caller-share-child-a")?;
        let second = child("caller-share-child-b")?;
        let siblings = Self {
            parent,
            first,
            second,
        };
        siblings.configure(fixture, runtime)?;
        Ok(siblings)
    }

    fn configure(&self, fixture: &Fixture, runtime: &mut Runtime) -> TestResult {
        let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("exclusive test kernel")?;
        kernel
            .register_budget_parent(self.parent.id.clone(), 5_000)
            .map_err(|error| error.to_string())?;
        kernel.set_capability_trust_root(
            fixture.signer.public_key(),
            scope_hash(&self.parent.scope)?,
        );
        Ok(())
    }
}

fn request(capability: &CapabilityToken, id: &str) -> TestResult<ToolCallRequest> {
    Ok(serde_json::from_value(serde_json::json!({
        "request_id": id,
        "capability": capability,
        "tool_name": TOOL_NAME,
        "server_id": SERVER_ID,
        "agent_id": capability.subject.to_hex(),
        "arguments": {"record": id}
    }))?)
}

fn reserve_child(runtime: &Runtime, request: &ToolCallRequest) -> TestResult<ToolCallRequest> {
    let response = runtime.kernel.reserve_caller_execution_blocking(request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    Ok(with_nonce(
        request,
        response
            .execution_nonce
            .as_deref()
            .ok_or("reserved nonce")?,
    ))
}

#[test]
fn settling_a_durable_caller_reservation_releases_its_delegated_share() -> TestResult {
    let fixture = Fixture::new()?;
    let mut runtime = fixture.open()?;
    let siblings = Siblings::new(&fixture, &mut runtime)?;
    let first = reserve_child(&runtime, &request(&siblings.first, "share-first")?)?;
    let blocked = runtime
        .kernel
        .reserve_caller_execution_blocking(&request(&siblings.second, "share-blocked")?)?;
    assert_eq!(blocked.verdict, Verdict::Deny, "{:?}", blocked.reason);
    assert!(blocked
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("sibling-sum")));
    let settled = reconcile(&runtime, &first)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_state(&fixture, &first, "completed")?;
    let _second = reserve_child(&runtime, &request(&siblings.second, "share-after-settle")?)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn restart_preserves_the_delegated_share_of_a_live_caller_reservation() -> TestResult {
    let fixture = Fixture::new()?;
    let (siblings, first) = {
        let mut runtime = fixture.open()?;
        let siblings = Siblings::new(&fixture, &mut runtime)?;
        let first = reserve_child(&runtime, &request(&siblings.first, "share-restart-first")?)?;
        (siblings, first)
    };
    let mut runtime = fixture.open_with_reconcile(false)?;
    siblings.configure(&fixture, &mut runtime)?;
    runtime.kernel.reconcile_durable_admission_startup()?;
    assert_state(&fixture, &first, "ready_to_dispatch")?;
    let blocked = runtime
        .kernel
        .reserve_caller_execution_blocking(&request(&siblings.second, "share-restart-blocked")?)?;
    assert_eq!(blocked.verdict, Verdict::Deny, "{:?}", blocked.reason);
    let settled = reconcile(&runtime, &first)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    let _second = reserve_child(
        &runtime,
        &request(&siblings.second, "share-restart-settled")?,
    )?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn two_caller_operations_share_one_child_edge_until_both_settle() -> TestResult {
    let fixture = Fixture::new()?;
    let mut runtime = fixture.open()?;
    let siblings = Siblings::new(&fixture, &mut runtime)?;
    let first = reserve_child(&runtime, &request(&siblings.first, "same-child-first")?)?;
    let second = reserve_child(&runtime, &request(&siblings.first, "same-child-second")?)?;
    assert_eq!(grant_quota(&runtime, &first)?, (2, 0));
    let settled = reconcile(&runtime, &first)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_eq!(grant_quota(&runtime, &second)?, (1, 1));
    let blocked = runtime
        .kernel
        .reserve_caller_execution_blocking(&request(&siblings.second, "same-child-still-held")?)?;
    assert_eq!(blocked.verdict, Verdict::Deny, "{:?}", blocked.reason);
    let settled = reconcile(&runtime, &second)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_eq!(grant_quota(&runtime, &first)?, (0, 2));
    let _sibling = reserve_child(&runtime, &request(&siblings.second, "same-child-released")?)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn caller_share_snapshot_is_complete_scoped_and_fenced() -> TestResult {
    let fixture = Fixture::new()?;
    let mut runtime = fixture.open()?;
    let siblings = Siblings::new(&fixture, &mut runtime)?;
    let first = reserve_child(&runtime, &request(&siblings.first, "snapshot-first")?)?;
    let store = runtime.authority.admission_operation_store();
    let parent = AdmissionIdentifier::try_new("parent_id", siblings.parent.id.clone())?;
    let fence = runtime.authority.mutation_fence();
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let shares = store.load_caller_budget_shares(&parent, 1, &fence, now)?;
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].child_id().as_str(), first.capability.id);
    assert_eq!(shares[0].share_bps(), 4_000);
    assert!(shares[0].is_reserved_for_caller());
    assert!(
        store
            .load_caller_budget_shares(&parent, 0, &fence, now)
            .is_err(),
        "a bounded query must not truncate"
    );
    let other = AdmissionIdentifier::try_new("parent_id", "another-parent")?;
    assert!(store
        .load_caller_budget_shares(&other, 1, &fence, now)?
        .is_empty());
    let mut wrong_fence = fence.clone();
    wrong_fence.owner_epoch = wrong_fence
        .owner_epoch
        .checked_add(1)
        .ok_or("owner epoch overflow")?;
    assert!(store
        .load_caller_budget_shares(&parent, 1, &wrong_fence, now)
        .is_err());
    assert!(store
        .load_caller_budget_shares(&parent, 1, &fence, 0)
        .is_err());
    assert_eq!(
        store
            .load_caller_budget_shares(&parent, 1, &fence, now)?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn an_expired_caller_share_stays_owned_until_recovery_compensates_it() -> TestResult {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(now, []);
    let fixture = Fixture::with_nonce_ttl(1)?;
    let (siblings, first) = {
        let mut runtime = fixture.open()?;
        let siblings = Siblings::new(&fixture, &mut runtime)?;
        let first = reserve_child(&runtime, &request(&siblings.first, "share-expiry-first")?)?;
        (siblings, first)
    };
    let expiry = u64::try_from(
        first
            .execution_nonce
            .as_ref()
            .ok_or("reserved nonce")?
            .expires_at(),
    )?;
    let _expired = chio_kernel::scope_fixed_runtime_for_current_thread(expiry, []);
    let mut runtime = fixture.open_with_reconcile(false)?;
    siblings.configure(&fixture, &mut runtime)?;
    let parent = AdmissionIdentifier::try_new("parent_id", siblings.parent.id.clone())?;
    let shares = runtime
        .authority
        .admission_operation_store()
        .load_caller_budget_shares(
            &parent,
            1,
            &runtime.authority.mutation_fence(),
            expiry.checked_mul(1_000).ok_or("clock overflow")?,
        )?;
    assert_eq!(shares.len(), 1, "expiry is not compensation");
    runtime.kernel.reconcile_durable_admission_startup()?;
    assert_state(&fixture, &first, "compensated_before_dispatch")?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 0));
    let _sibling = reserve_child(&runtime, &request(&siblings.second, "share-after-expiry")?)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
