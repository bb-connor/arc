use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_view, EconomicContentV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorError,
    EconomicStateAnchorPins, EconomicStateAnchorViewV1, EconomicStateBatchV1,
    EconomicStateTransitionV1, EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationCommand, AdmissionOperationKind,
    AdmissionOperationStore, AdmissionOperationV1, AdmissionParticipantRequirements,
    AdmissionRequestBindingV1, AuthenticatedRequestNamespace, QualifiedAdmissionOperationStoreExt,
    SideEffectClass,
};
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    _temp: TempDir,
    _authority: SqliteAuthorityStore,
    cache: SqliteEconomicStateCache,
    fence: chio_core::StoreMutationFence,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
    let fence = authority.mutation_fence();
    let cache = authority.economic_state_cache();
    Fixture {
        _temp: temp,
        _authority: authority,
        cache,
        fence,
    }
}

fn digest(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: Keypair::from_seed(&[0x41; 32]).public_key(),
    }
}

fn key() -> EconomicResourceKeyV1 {
    EconomicResourceKeyV1 {
        resource_family: "clearing_round".to_owned(),
        scope_id: "market-1".to_owned(),
        resource_id: "round-1".to_owned(),
    }
}

fn head() -> TestResult<EconomicResourceHeadV1> {
    let state = EconomicContentV1::Inline {
        value: json!({"roundId": "round-1", "state": "open"}),
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "open".to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 100,
        predecessor_digest: None,
    })
}

fn signed_view(
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    heads: Vec<EconomicResourceHeadV1>,
    absent_resource_keys: Vec<EconomicResourceKeyV1>,
) -> TestResult<EconomicStateAnchorViewV1> {
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence,
        checkpoint_digest,
        heads_root: String::new(),
        heads,
        absent_resource_keys,
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at: 100 + checkpoint_sequence,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&Keypair::from_seed(&[0x41; 32]))?;
    Ok(view)
}

#[derive(Debug)]
struct DirectVerifier;

impl EconomicTransitionProofVerifier for DirectVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        _transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }
}

fn verified_advance() -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)>
{
    verified_advance_for_operation(None)
}

fn verified_advance_for_operation(
    operation_id: Option<String>,
) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
    let resource_head = head()?;
    let current = verify_economic_state_view(
        signed_view(1, digest("checkpoint-1"), Vec::new(), vec![key()])?,
        &pins(),
    )?;
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: 2,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: vec![EconomicStateTransitionV1 {
            resource_key: key(),
            expected_head_digest: None,
            next_head: resource_head.clone(),
            transition_proof_digest: digest("transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id,
        issued_at: 101,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
    let advance = verify_economic_state_batch_advance(&current, batch, &pins(), &DirectVerifier)?;
    let committed = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![resource_head],
            Vec::new(),
        )?,
        &pins(),
    )?;
    Ok((advance, committed))
}

fn verified_successor(
    current: &VerifiedEconomicStateView,
) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
    let current_head = current
        .view()
        .heads
        .first()
        .ok_or("current head is missing")?;
    let mut next_head = current_head.clone();
    next_head.head_version += 1;
    next_head.resource_version += 1;
    next_head.lifecycle_fence += 1;
    next_head.trusted_clock_high_water += 1;
    next_head.predecessor_digest = Some(current_head.digest()?);
    let state = EconomicContentV1::Inline {
        value: json!({"roundId": "round-1", "state": "finalized"}),
    };
    next_head.state_digest = state.digest()?;
    next_head.state = state;
    next_head.lifecycle_state = "finalized".to_owned();
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: current.view().checkpoint_sequence + 1,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: vec![EconomicStateTransitionV1 {
            resource_key: key(),
            expected_head_digest: Some(current_head.digest()?),
            next_head: next_head.clone(),
            transition_proof_digest: digest("successor-transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: None,
        issued_at: 102,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
    let advance = verify_economic_state_batch_advance(current, batch, &pins(), &DirectVerifier)?;
    let committed = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            advance.batch().checkpoint_digest.clone(),
            vec![next_head],
            Vec::new(),
        )?,
        &pins(),
    )?;
    Ok((advance, committed))
}

fn identifier(field: &'static str, value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new(field, value).expect("valid identifier")
}

fn admission_digest(field: &'static str, byte: char) -> AdmissionDigest {
    AdmissionDigest::try_new(field, byte.to_string().repeat(64)).expect("valid digest")
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("system time fits u64")
}

fn prepared_economic_operation(
    fence: &chio_core::StoreMutationFence,
    request_id: &str,
) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "economic-cache-test",
    ))
    .expect("request namespace");
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::GovernedEconomicMutation,
        namespace,
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", "economic-cache-capability"),
        authorization_capability_hash: admission_digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            admission_digest("immutable_request_hash", 'b'),
            AdmissionParticipantRequirements::NONE,
        )
        .expect("request binding"),
        policy_hash: admission_digest("policy_hash", 'c'),
        effect_class: SideEffectClass::Monetary,
    })
    .expect("operation binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

#[test]
fn stage_retains_exact_bytes_and_rejects_a_stale_serving_fence() -> TestResult {
    let fixture = fixture();
    let (advance, _) = verified_advance()?;
    let staged = fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    assert_eq!(staged.status(), EconomicStateStageStatus::DbStaged);
    assert_eq!(staged.batch(), advance.batch());
    assert_eq!(staged.base_view(), advance.current().view());
    assert_eq!(staged.version(), 1);

    let replay = fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_001)?;
    assert_eq!(replay, staged);

    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert!(matches!(
        fixture.cache.stage_batch(&advance, None, &stale, 1_002),
        Err(EconomicStateCacheError::Fenced)
    ));
    Ok(())
}

#[test]
fn only_an_anchor_advanced_stage_can_publish_cached_heads() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    let batch_id = advance.batch().batch_id.clone();
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());
    assert!(matches!(
        fixture
            .cache
            .finalize_stage(&batch_id, &fixture.fence, 1_001),
        Err(EconomicStateCacheError::InvalidTransition { .. })
    ));

    let advanced = fixture.cache.record_anchor_advanced(
        &advance,
        &committed,
        &pins(),
        &fixture.fence,
        1_002,
    )?;
    assert_eq!(
        advanced.status(),
        EconomicStateStageStatus::EconomicAnchorAdvanced
    );
    assert_eq!(advanced.committed_view(), Some(committed.view()));
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());

    let finalized = fixture
        .cache
        .finalize_stage(&batch_id, &fixture.fence, 1_003)?;
    assert_eq!(finalized.status(), EconomicStateStageStatus::DbFinalized);
    assert_eq!(fixture.cache.load_finalized_head(&key())?, Some(head()?));
    Ok(())
}

#[test]
fn discarded_unanchored_stage_never_exposes_or_reopens_state() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    let batch_id = advance.batch().batch_id.clone();
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    let discarded = fixture.cache.discard_unanchored_stage(
        &batch_id,
        "operation no longer authorizes recovery",
        &fixture.fence,
        1_001,
    )?;
    assert_eq!(discarded.status(), EconomicStateStageStatus::Discarded);
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());
    assert!(fixture
        .cache
        .record_anchor_advanced(&advance, &committed, &pins(), &fixture.fence, 1_002,)
        .is_err());
    Ok(())
}

#[test]
fn late_finalize_of_an_older_stage_cannot_regress_the_current_head() -> TestResult {
    let fixture = fixture();
    let (older, older_committed) = verified_advance()?;
    fixture
        .cache
        .stage_batch(&older, None, &fixture.fence, 1_000)?;
    fixture.cache.record_anchor_advanced(
        &older,
        &older_committed,
        &pins(),
        &fixture.fence,
        1_001,
    )?;

    let (newer, newer_committed) = verified_successor(&older_committed)?;
    fixture
        .cache
        .stage_batch(&newer, None, &fixture.fence, 1_002)?;
    fixture.cache.record_anchor_advanced(
        &newer,
        &newer_committed,
        &pins(),
        &fixture.fence,
        1_003,
    )?;
    fixture
        .cache
        .finalize_stage(&newer.batch().batch_id, &fixture.fence, 1_004)?;
    let newest_head = newer.batch().transitions[0].next_head.clone();
    assert_eq!(
        fixture.cache.load_finalized_head(&key())?,
        Some(newest_head.clone())
    );

    fixture
        .cache
        .finalize_stage(&older.batch().batch_id, &fixture.fence, 1_005)?;
    assert_eq!(
        fixture.cache.load_finalized_head(&key())?,
        Some(newest_head)
    );
    Ok(())
}

#[test]
fn finalized_stage_recomputes_retained_head_digests() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    let batch_id = advance.batch().batch_id.clone();
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    fixture
        .cache
        .record_anchor_advanced(&advance, &committed, &pins(), &fixture.fence, 1_001)?;
    fixture
        .cache
        .finalize_stage(&batch_id, &fixture.fence, 1_002)?;

    let mut tampered = head()?;
    let state = EconomicContentV1::Inline {
        value: json!({"roundId": "round-1", "state": "tampered"}),
    };
    tampered.lifecycle_state = "tampered".to_owned();
    tampered.state_digest = state.digest()?;
    tampered.state = state;
    let tampered_bytes = canonical_json_bytes(&tampered)?;
    {
        let connection = fixture.cache.connection()?;
        connection.execute_batch("DROP TRIGGER economic_state_stage_heads_immutable")?;
        connection.execute(
            "UPDATE economic_state_stage_heads SET head_json = ?1 WHERE batch_id = ?2",
            rusqlite::params![&tampered_bytes, &batch_id],
        )?;
        connection.execute(
            "UPDATE economic_state_heads SET head_json = ?1 WHERE source_batch_id = ?2",
            rusqlite::params![&tampered_bytes, &batch_id],
        )?;
    }

    assert!(matches!(
        fixture.cache.load_stage(&batch_id),
        Err(EconomicStateCacheError::Invariant(_))
    ));
    Ok(())
}

#[test]
fn operation_bound_stage_requires_the_exact_current_recovery_claim() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_economic_operation(&fixture.fence, "request-stage-1");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let claimant = identifier("claimant_id", "economic-stage-recovery");
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;

    let staged = fixture.cache.stage_batch(
        &advance,
        Some(EconomicOperationStageContext::new(&operation, &lease)),
        &fixture.fence,
        now + 2,
    )?;
    let binding = staged
        .operation_binding()
        .ok_or("operation binding is missing")?;
    assert_eq!(
        binding.operation_id(),
        operation.binding().operation_id().as_str()
    );
    assert_eq!(binding.operation_version(), operation.version());
    assert_eq!(binding.operation_state(), operation.state());
    Ok(())
}

#[test]
fn operation_bound_stage_replay_rechecks_the_current_recovery_claim() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_economic_operation(&fixture.fence, "request-stage-replay-race");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let claimant = identifier("claimant_id", "economic-stage-recovery");
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    let context = EconomicOperationStageContext::new(&operation, &lease);
    fixture
        .cache
        .stage_batch(&advance, Some(context), &fixture.fence, now + 2)?;

    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease.clone(),
        Vec::new(),
        Some(chio_kernel::admission_operation::AdmissionOperationState::MutationReady),
        None,
        None,
    )?;
    operations.compare_and_swap(&command, now + 3)?;

    assert!(matches!(
        fixture
            .cache
            .stage_batch(&advance, Some(context), &fixture.fence, now + 4),
        Err(EconomicStateCacheError::Fenced)
    ));
    Ok(())
}

#[test]
fn operation_version_race_fences_stage_before_any_resource_is_visible() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_economic_operation(&fixture.fence, "request-stage-race");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let claimant = identifier("claimant_id", "economic-stage-recovery");
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease.clone(),
        Vec::new(),
        Some(chio_kernel::admission_operation::AdmissionOperationState::MutationReady),
        None,
        None,
    )?;
    operations.compare_and_swap(&command, now + 2)?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;

    assert!(matches!(
        fixture.cache.stage_batch(
            &advance,
            Some(EconomicOperationStageContext::new(&operation, &lease)),
            &fixture.fence,
            now + 3,
        ),
        Err(EconomicStateCacheError::Fenced)
    ));
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());
    Ok(())
}
