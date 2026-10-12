//! One unverifiable funded operation under a delegation parent must not deny
//! the caller-share snapshot of an unrelated parent.

use super::*;
use chio_core::capability::{
    attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_kernel::admission_operation::AdmissionCallerBudgetShare;

const PARENT_A: &str = "caller-share-parent-a";
const PARENT_B: &str = "caller-share-parent-b";

fn delegated_capability(key: &Keypair, id: &str, parent_id: &str) -> TestResult<CapabilityToken> {
    let grant =
        serde_json::json!({"server_id": "server", "tool_name": "tool", "operations": ["invoke"]});
    let scope: ChioScope = serde_json::from_value(serde_json::json!({"grants": [grant]}))?;
    let issued_at = now_ms() / 1000;
    let parent_scope_hash = scope_hash(&scope)?;
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent_id.into(),
            delegator: key.public_key(),
            delegatee: key.public_key(),
            attenuations: Vec::new(),
            timestamp: issued_at,
            scope_hash: Some(parent_scope_hash.clone()),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        key,
    )?;
    Ok(CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: id.into(),
                issuer: key.public_key(),
                subject: key.public_key(),
                scope: scope.clone(),
                issued_at,
                expires_at: issued_at + 300,
                delegation_chain: vec![link],
                aggregate_invocation_budget: None,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash,
                child_scope_hash: scope_hash(&scope)?,
                normalized_subset_proof: compute_attenuation_witness(&scope, &scope)?,
            },
            budget_share_bps: Some(4_000),
        },
        key,
    )?)
}

fn funded_under(fixture: Fixture, label: &str, parent_id: &str) -> TestResult<NonceFixture> {
    let key = Keypair::generate();
    let capability = delegated_capability(&key, &format!("{label}-capability"), parent_id)?;
    let (base, original) = retained_request::original_with_capability(
        &fixture.fence,
        &format!("{label}-request"),
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            approval: true,
            ..AdmissionParticipantRequirements::NONE
        },
        None,
        &key,
        capability,
    )?;
    let prepared = own_prepared(unowned_prepared_nonce_fixture_in(
        fixture, base, original, None,
    )?)?;
    let mut funded = advance_nonce_fixture_with_budget_ids(
        prepared,
        true,
        None,
        true,
        Some("caller-report:test-server"),
        (&format!("{label}-hold"), &format!("{label}-authorize")),
    )?;
    funded.operation = funded
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&funded)?,
            &funded.reservation,
            now_ms(),
        )?
        .into_operation();
    Ok(funded)
}

fn two_funded_parents() -> TestResult<(NonceFixture, AdmissionOperationV1)> {
    let first = funded_under(fixture(), "caller-share-a", PARENT_A)?;
    let NonceFixture {
        fixture, operation, ..
    } = first;
    let second = funded_under(fixture, "caller-share-b", PARENT_B)?;
    Ok((second, operation))
}

fn parent(id: &str) -> AdmissionIdentifier {
    identifier("parent_id", id)
}

// Owner-connection corruption is outside the external-writer threat model.
#[test]
fn an_unverifiable_operation_under_one_parent_does_not_deny_another_parents_snapshot() -> TestResult
{
    let (second, first_operation) = two_funded_parents()?;
    let fixture = &second.fixture;
    let first_id = first_operation.binding().operation_id();
    let second_id = second.operation.binding().operation_id();
    assert!(AdmissionCallerBudgetShare::is_owned_by(&first_operation));
    for (id, operation_id) in [(PARENT_A, first_id), (PARENT_B, second_id)] {
        let shares =
            fixture
                .store
                .load_caller_budget_shares(&parent(id), 16, &fixture.fence, now_ms())?;
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].parent_id(), &parent(id));
        assert_eq!(shares[0].operation_id(), operation_id);
    }
    fixture.store.connection()?.execute(
        "UPDATE admission_operations SET operation_json = X'7b', version = version + 1 WHERE operation_id = ?1",
        [first_id.as_str()],
    )?;
    assert!(fixture
        .store
        .load_caller_budget_shares(&parent(PARENT_A), 16, &fixture.fence, now_ms())
        .is_err());
    let shares =
        fixture
            .store
            .load_caller_budget_shares(&parent(PARENT_B), 16, &fixture.fence, now_ms())?;
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].parent_id(), &parent(PARENT_B));
    assert_eq!(shares[0].operation_id(), second_id);
    Ok(())
}
