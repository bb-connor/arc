//! The reserved threshold witness binds its exact original operation, nonce
//! and serving fence, and once qualified answers only signed-time checks.
use super::*;
use chio_core::capability::governance::{
    ApprovalSetBody, GovernedApprovalDecision, GovernedApprovalTokenBody,
    ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::crypto::Keypair;
use chio_kernel::admission_operation::{
    AdmissionAttachment, AdmissionOperationBindingInputV1, AdmissionOperationBindingV1,
    AdmissionOperationCommand, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore, AdmissionParticipantRequirements, AdmissionRequestBindingV1,
    AuthenticatedRequestNamespace, QualifiedAdmissionOperationStoreExt, SideEffectClass,
};
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUEST_ID: &str = "witness-threshold-request";
const WINDOW_INVARIANT: &str = "threshold reservation requires currently valid proposal and tokens";
const RESERVED_INVARIANT: &str = "threshold replay lost its exact durable proposal reservation";
const CAPABILITY_DIGEST: char = 'a';
const POLICY_DIGEST: char = 'c';

fn digest(field: &'static str, byte: char) -> TestResult<AdmissionDigest> {
    Ok(AdmissionDigest::try_new(
        field,
        byte.to_string().repeat(64),
    )?)
}

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn open(database: &Path, locks: &Path) -> TestResult<crate::SqliteAuthorityStore> {
    Ok(crate::test_authority::open_serving(database, locks)?)
}

fn provision() -> TestResult<(tempfile::TempDir, PathBuf, PathBuf)> {
    let temp = tempfile::tempdir()?;
    crate::test_authority::secure_directory(temp.path());
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    std::fs::create_dir(&locks)?;
    crate::test_authority::secure_directory(&locks);
    crate::SqliteAuthorityStore::provision(&database, &locks)?;
    Ok((temp, database, locks))
}

fn prepared(fence: &StoreMutationFence) -> TestResult<AdmissionOperationV1> {
    let namespace = AuthenticatedRequestNamespace::for_local_system(AdmissionIdentifier::try_new(
        "coordinator_authority_id",
        "local-test-authority",
    )?)?;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        namespace,
        request_id: AdmissionIdentifier::try_new("request_id", REQUEST_ID)?,
        capability_id: AdmissionIdentifier::try_new("capability_id", "witness-capability")?,
        authorization_capability_hash: digest("authorization_capability_hash", CAPABILITY_DIGEST)?,
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", 'b')?,
            AdmissionParticipantRequirements {
                approval: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )?,
        policy_hash: digest("policy_hash", POLICY_DIGEST)?,
        effect_class: SideEffectClass::SideEffecting,
    })?;
    Ok(AdmissionOperationV1::prepare(binding, fence.owner_epoch)?)
}

/// Two distinct approvals whose own windows end `token_secs` after creation,
/// inside a proposal window of 300 seconds.
fn threshold_reservation(
    created_at: u64,
    token_secs: u64,
) -> TestResult<ThresholdApprovalReplayReservationV1> {
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "witness-threshold-proposal".to_owned(),
            request_id: REQUEST_ID.to_owned(),
            governed_intent_hash: chio_core::sha256_hex(b"witness-intent"),
            subject: subject.public_key(),
            authorizing_capability_digest: CAPABILITY_DIGEST.to_string().repeat(64),
            policy_hash: POLICY_DIGEST.to_string().repeat(64),
            threshold: 2,
            eligible_set_digest: chio_core::sha256_hex(b"witness-eligible-set"),
            proposal_created_at: created_at,
            proposal_deadline: created_at + 300,
            policy_authority: authority.public_key(),
        },
        &authority,
    )?;
    let proposal_hash = proposal.artifact_digest()?;
    let tokens = ["witness-token-a", "witness-token-b"]
        .into_iter()
        .map(|id| {
            let approver = Keypair::generate();
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: id.to_owned(),
                    approver: approver.public_key(),
                    subject: subject.public_key(),
                    governed_intent_hash: chio_core::sha256_hex(b"witness-intent"),
                    request_id: REQUEST_ID.to_owned(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    issued_at: created_at,
                    expires_at: created_at + token_secs,
                    decision: GovernedApprovalDecision::Approved,
                },
                &approver,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let digests = tokens
        .iter()
        .map(GovernedApprovalToken::artifact_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let set = ApprovalSetBody::new(digests, &proposal)?;
    Ok(ThresholdApprovalReplayReservationV1::new(
        proposal, tokens, set,
    )?)
}

fn advance(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    operation: &AdmissionOperationV1,
    attachments: Vec<AdmissionAttachment>,
    state: AdmissionOperationState,
    now: u64,
    reservation: Option<&ThresholdApprovalReplayReservationV1>,
) -> TestResult<AdmissionOperationV1> {
    let lease = store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &AdmissionIdentifier::try_new("claimant_id", "witness-worker")?,
        now,
        now + 10_000,
        fence,
    )?;
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(state),
        None,
        None,
    )?;
    Ok(match reservation {
        Some(reservation) => {
            store.reserve_threshold_approval_and_commit_admission(&command, reservation, now)?
        }
        None => store.compare_and_swap(&command, now)?,
    }
    .into_operation())
}

fn qualify(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    operation: &AdmissionOperationV1,
    now: u64,
    nonce_id: Option<&AdmissionIdentifier>,
) -> Result<Option<ReservedThresholdApproval>, AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let transaction = store.begin_write(&mut connection, Some(fence))?;
    reserved_nonce_capture_approval(&transaction, operation, now, &store.serving_owner, nonce_id)
}

fn verify_unit(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    operation: &AdmissionOperationV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let transaction = store.begin_write(&mut connection, Some(fence))?;
    verify_nonce_capture_approval(&transaction, operation, now, &store.serving_owner)
}

/// Whether `result` is exactly the named store invariant refusal.
fn refused_by<T>(result: Result<T, AdmissionOperationStoreError>, invariant: &str) -> bool {
    matches!(result, Err(AdmissionOperationStoreError::Invariant(detail)) if detail == invariant)
}

fn rows(store: &SqliteAdmissionOperationStore) -> TestResult<(i64, i64, i64)> {
    Ok(store.connection()?.query_row(
        "SELECT (SELECT COUNT(*) FROM threshold_approval_proposals),
                (SELECT COUNT(*) FROM threshold_approval_tokens),
                (SELECT COUNT(*) FROM admission_operation_commits)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

#[test]
fn reserved_threshold_witness_binds_its_original_and_checks_only_signed_time() -> TestResult {
    let (_temp, database, locks) = provision()?;
    let authority = open(&database, &locks)?;
    let store = authority.admission_operation_store();
    let fence = store.serving_owner.fence.clone();
    let now = now_ms()?;
    let created_at = now / 1_000;
    let operation = prepared(&fence)?;
    store.begin(&operation, &fence, now)?;
    let reservation = threshold_reservation(created_at, 60)?;
    let reserved = advance(
        &store,
        &fence,
        &operation,
        vec![
            AdmissionAttachment::ThresholdProposalHash(AdmissionDigest::try_new(
                "threshold_proposal_hash",
                reservation.proposal().artifact_digest()?,
            )?),
            AdmissionAttachment::ApprovalSetHash(AdmissionDigest::try_new(
                "approval_set_hash",
                reservation.verified_set().approval_set_hash()?,
            )?),
        ],
        AdmissionOperationState::ApprovalReserved,
        now + 1,
        Some(&reservation),
    )?;

    // Qualification reads and verifies; it acquires and records nothing.
    let before = rows(&store)?;
    let witness = qualify(&store, &fence, &reserved, now + 2, None)?.ok_or("reserved witness")?;
    assert_eq!(rows(&store)?, before);
    assert!(witness.binds(&reserved, &store.serving_owner));
    let foreign_nonce = AdmissionIdentifier::try_new("execution_nonce_id", "foreign-nonce")?;
    assert!(
        !qualify(&store, &fence, &reserved, now + 2, Some(&foreign_nonce))?
            .ok_or("nonce-bound witness")?
            .binds(&reserved, &store.serving_owner)
    );
    assert!(verify_unit(&store, &fence, &reserved, now + 2).is_ok());

    // Only the original signed proposal and token windows remain to compare.
    let created_ms = created_at * 1_000;
    assert!(refused_by(
        witness.validate_at(created_ms - 1),
        WINDOW_INVARIANT
    ));
    assert!(witness.validate_at(created_ms).is_ok());
    assert!(witness.validate_at((created_at + 60) * 1_000 - 1).is_ok());
    assert!(refused_by(
        witness.validate_at((created_at + 60) * 1_000),
        WINDOW_INVARIANT
    ));
    assert!(refused_by(
        witness.validate_at((created_at + 300) * 1_000),
        WINDOW_INVARIANT
    ));

    // The committed lifecycle row never qualifies a fresh reservation, and a
    // witness never binds the committed successor or another serving fence.
    let ready = advance(
        &store,
        &fence,
        &reserved,
        Vec::new(),
        AdmissionOperationState::ReadyToDispatch,
        now + 3,
        None,
    )?;
    assert!(!witness.binds(&ready, &store.serving_owner));
    let committed = advance(
        &store,
        &fence,
        &ready,
        Vec::new(),
        AdmissionOperationState::DispatchCommitted,
        now + 4,
        None,
    )?;
    assert!(refused_by(
        qualify(&store, &fence, &committed, now + 5, None),
        RESERVED_INVARIANT
    ));
    assert!(refused_by(
        verify_unit(&store, &fence, &committed, now + 5),
        RESERVED_INVARIANT
    ));
    assert!(!witness.binds(&committed, &store.serving_owner));
    assert!(witness.validate_at(now + 5).is_ok());
    drop(store);
    drop(authority);
    let reopened = open(&database, &locks)?.admission_operation_store();
    assert_ne!(reopened.serving_owner.fence, fence);
    assert!(!witness.binds(&reserved, &reopened.serving_owner));
    Ok(())
}
