use super::*;
#[path = "claims/dispatch_snapshot.rs"]
mod dispatch_snapshot;
use chio_kernel::admission_operation::dpop_claim::*;
use chio_kernel::dpop::authority::{
    verify_authority_dpop_proof_stateless, DpopReplayAuthorityV1, DPOP_AUTHORITY_SCHEMA,
};
use chio_kernel::dpop::{DpopProof, DpopProofBody};

#[path = "claims/budget.rs"]
mod budget;
#[path = "claims/capacity.rs"]
mod capacity;
#[path = "claims/concurrency.rs"]
mod concurrency;
#[path = "claims/faults.rs"]
mod faults;
#[path = "claims/kernel_routes.rs"]
mod kernel_routes;
#[path = "claims/lifecycle.rs"]
mod lifecycle;
#[path = "claims/migration.rs"]
pub(super) mod migration;
#[path = "claims/preflight.rs"]
mod preflight;

fn activate(fixture: &Fixture, source: &Source) -> AnchoredTestResult<DpopReplayAuthorityV1> {
    let imported = import(fixture, source, &pin(fixture, source)?)?;
    let original = super::activation::domain(&imported)?;
    let authority =
        DpopReplayAuthorityV1::new(chio_kernel::dpop::authority::DpopReplayAuthorityInputV1 {
            destination_store_uuid: original.destination_store_uuid().clone(),
            dpop_authority_id: original.dpop_authority_id().clone(),
            expectation_id: original.expectation_id().clone(),
            proof_ttl_secs: 60,
            max_clock_skew_secs: 30,
        })?;
    assert!(fixture
        .store
        .activate_dpop_replay_source(&authority, source, &fixture.fence, now_ms())?
        .is_active());
    Ok(authority)
}

fn setup(
    fixture: &Fixture,
    authority: &DpopReplayAuthorityV1,
    name: &str,
    nonce: &str,
    phase: DpopReplayClaimPhase,
) -> AnchoredTestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    DpopReplayCredentialV1,
)> {
    let key = Keypair::generate();
    let (operation, retained) = super::super::retained_request::original_with_intent_and_signer(
        &fixture.fence,
        name,
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            execution_nonce: phase == DpopReplayClaimPhase::NoncePreflight,
            ..AdmissionParticipantRequirements::NONE
        },
        None,
        &key,
    )?;
    let profile = super::super::retained_request::authority_profile::selection(
        None,
        None,
        Some(authority.clone()),
    )?;
    let (operation, retained) =
        super::super::retained_request::authority_profile::prepare_with_profile(
            operation, retained, profile,
        )?;
    let request = retained.request_for_revalidation();
    let action_hash = sha256_hex(&canonical_json_bytes(&request.arguments)?);
    let proof = DpopProof::sign(
        DpopProofBody {
            schema: DPOP_AUTHORITY_SCHEMA.into(),
            replay_authority: Some(authority.clone()),
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action_hash: action_hash.clone(),
            nonce: nonce.into(),
            issued_at: now_ms() / 1000,
            agent_key: key.public_key(),
        },
        &key,
    )?;
    let credential = DpopReplayCredentialV1::from_verified(verify_authority_dpop_proof_stateless(
        &proof,
        &request.capability,
        &request.server_id,
        &request.tool_name,
        &action_hash,
        authority,
        now_ms() / 1000,
    )?);
    fixture.store.begin_with_retained_tool_request(
        &operation,
        &retained,
        &fixture.fence,
        now_ms(),
    )?;
    let lease = claim(fixture, &operation, name, now_ms());
    if phase == DpopReplayClaimPhase::NoncePreflight {
        return Ok((operation, lease, credential));
    }
    let updated = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease.clone(),
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation, name,
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now_ms(),
        )?
        .into_operation();
    let lease = renew(fixture, &updated, &lease, now_ms())?;
    Ok((updated, lease, credential))
}

fn renew(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    now: u64,
) -> AnchoredTestResult<AdmissionRecoveryLease> {
    Ok(fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        lease.untrusted_claim().claimant_id(),
        now,
        now + 120_000,
        &fixture.fence,
    )?)
}
fn candidate(
    operation: &AdmissionOperationV1,
    episode: &str,
    credential: DpopReplayCredentialV1,
    phase: DpopReplayClaimPhase,
) -> AnchoredTestResult<DpopReplayClaimIntentV1> {
    Ok(DpopReplayClaimIntentV1::new(
        DpopReplayClaimIntentInputV1 {
            episode_id: identifier("episode", episode),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            grant_index: 0,
            phase,
            credential,
        },
    )?)
}

fn capture_pending(
    fixture: &Fixture,
    mut operation: AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
) -> AnchoredTestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    // State-machine custody fixture, not evidence of physical budget settlement.
    // The budget module exercises the actual joint authorization/capture ports.
    for (state, attachments) in [
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "hold",
                "dpop-hold",
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, vec![]),
        (AdmissionOperationState::CapturePending, vec![]),
    ] {
        operation = fixture
            .store
            .compare_and_swap(
                &command(
                    &operation,
                    renew(fixture, &operation, lease, now_ms())?,
                    attachments,
                    state,
                    None,
                ),
                now_ms(),
            )?
            .into_operation();
    }
    let lease = renew(fixture, &operation, lease, now_ms())?;
    Ok((operation, lease))
}
