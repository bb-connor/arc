use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use chio_cage::{
    validate_cage_execution_identity_binding, validate_cage_target_fd_binding, CageInitPlan,
    EnforcementPrepared, ExecTransitionObserved, ExecutionIdentity, FdPurpose,
    FullyEnforcedEvidence, ObservedRulesetStatus,
};
#[cfg(target_os = "linux")]
use chio_cage::{validate_cage_target_fd_binding_production_paths, CageTargetFdBindingMutation};
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequest,
    ThresholdApprovalRequirement,
};
use chio_core::crypto::{Ed25519Backend, Keypair, Signature, SigningAlgorithm, SigningBackend};
use chio_kernel::approval::{ApprovalStore, ApprovalStoreError};
use chio_kernel::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetInvocationQuota, BudgetInvocationReservationState,
    BudgetQuotaKey, BudgetQuotaProfile,
};
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::threshold_approval::{
    verify_threshold_approval_set, ThresholdApprovalVerificationInput, VerifiedThresholdApprovalSet,
};
use chio_keyring::{
    derive_key_id, AuthorityId, BootstrapAuthorization, EventId, EventReason, KeyLogAuthorizations,
    KeyLogEventBody, KeyLogOperation, KeyLogPolicy, KeyLogPolicyConfig, KeyringError, LogId,
    NewKeyProofOfPossession, OldKeyAuthorization, RecoveryPolicyId, SignedKeyLogCheckpoint,
    SignedKeyLogEvent, SigningTopology, SqliteKeyLogStore, SqliteKeyLogWitness,
    SqlitePinnedKeyLogVerifier, TrustedClock, WitnessId, WitnessRosterId, WitnessSignature,
    KEY_LOG_EVENT_SCHEMA,
};
use chio_secret_broker::budget::ExecutionQuota;
use chio_secret_broker::capability::issue_capability;
use chio_secret_broker::proof::{body_digest, issue_request_proof, verify_request_proof};
use chio_secret_broker::protocol::{
    AttemptConsumption, BrokerCapabilityBody, BrokerDestination, BrokerRequest, CallerOptions,
    CredentialRef, HeaderField, ProofBinding, ProofMode, RedirectPolicy, RequestConstraints,
    SignedBrokerCapability, BROKER_CAPABILITY_SCHEMA,
};
use chio_secret_broker::sqlite::SqliteAttemptStore;
use chio_secret_broker::store::{
    derive_attempt_ids, AttemptRegistration, AttemptStore, RegisterAttemptOutcome,
};
use chio_store_sqlite::budget_store::{SqliteBudgetStore, SqliteCompositeAuthorizeInput};
use chio_store_sqlite::SqliteApprovalStore;

use super::NativeAssertionKind;

type BehaviorResult<T = ()> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EnterpriseFixture {
    Keyring,
    Broker,
    Cage,
    Protocol,
}

pub(super) fn execute_behavior(
    fixture: EnterpriseFixture,
    kind: NativeAssertionKind,
    repo_root: &Path,
) -> BehaviorResult {
    match (fixture, kind) {
        (EnterpriseFixture::Keyring, NativeAssertionKind::KeyLogSignatureSeparation) => {
            key_log_signature_separation()
        }
        (EnterpriseFixture::Keyring, NativeAssertionKind::KeyLogContiguousSyncApplies) => {
            key_log_contiguous_sync_applies()
        }
        (
            EnterpriseFixture::Keyring,
            NativeAssertionKind::KeyLogOmittedNoncontiguousGapRejected,
        ) => key_log_omitted_noncontiguous_gap_rejected(),
        (EnterpriseFixture::Keyring, NativeAssertionKind::KeyLogWitnessConflictRejected) => {
            key_log_witness_conflict_rejected()
        }
        (EnterpriseFixture::Broker, NativeAssertionKind::BrokerProofCompleteRequestBinding) => {
            broker_proof_complete_request_binding()
        }
        (EnterpriseFixture::Broker, NativeAssertionKind::BrokerNonceReplayRefused) => {
            broker_nonce_replay_refused()
        }
        (EnterpriseFixture::Broker, NativeAssertionKind::BrokerCombinedQuotaNoDoubleCharge) => {
            broker_combined_quota_no_double_charge()
        }
        (EnterpriseFixture::Broker, NativeAssertionKind::BrokerEncryptedCredentialCustody) => {
            broker_encrypted_credential_custody()
        }
        (EnterpriseFixture::Cage, NativeAssertionKind::CagePlanTargetFdIdentityBound) => {
            cage_plan_target_fd_identity_bound(repo_root)
        }
        (EnterpriseFixture::Cage, NativeAssertionKind::CagePreparedMutationRejected) => {
            cage_prepared_mutation_rejected(repo_root)
        }
        (EnterpriseFixture::Cage, NativeAssertionKind::CageExecTransitionMutationRejected) => {
            cage_exec_transition_mutation_rejected(repo_root)
        }
        (EnterpriseFixture::Cage, NativeAssertionKind::CageEnforcementEvidenceMutationRejected) => {
            cage_enforcement_evidence_mutation_rejected(repo_root)
        }
        (
            EnterpriseFixture::Protocol,
            NativeAssertionKind::ProtocolAggregateMultiKeyAtomicExhaustion,
        ) => protocol_aggregate_multi_key_atomic_exhaustion(),
        (
            EnterpriseFixture::Protocol,
            NativeAssertionKind::ProtocolThresholdDistinctSignersRequired,
        ) => protocol_threshold_distinct_signers_required(),
        (
            EnterpriseFixture::Protocol,
            NativeAssertionKind::ProtocolThresholdApprovalReplayRefused,
        ) => protocol_threshold_approval_replay_refused(),
        _ => Err(format!(
            "enterprise fixture {fixture:?} does not implement assertion {kind:?}"
        )),
    }
}

fn checked<T, E: Display>(result: Result<T, E>, action: &str) -> BehaviorResult<T> {
    result.map_err(|error| format!("{action}: {error}"))
}

fn require(condition: bool, reason: impl Into<String>) -> BehaviorResult {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}

fn trusted_temp_path(
    directory: &tempfile::TempDir,
    name: &str,
) -> BehaviorResult<std::path::PathBuf> {
    checked(
        fs::canonicalize(directory.path()),
        "canonicalize temporary directory",
    )
    .map(|path| path.join(name))
}

fn keyring_backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

#[derive(Clone)]
struct FixedKeyringClock(u64);

impl TrustedClock for FixedKeyringClock {
    fn now(&self) -> chio_keyring::Result<u64> {
        Ok(self.0)
    }
}

struct KeyringBehaviorFixture {
    bootstrap: Ed25519Backend,
    operator: Ed25519Backend,
    old: Ed25519Backend,
    new: Ed25519Backend,
    witnesses: [Ed25519Backend; 3],
    policy: KeyLogPolicy,
}

impl KeyringBehaviorFixture {
    fn new() -> BehaviorResult<Self> {
        let bootstrap = keyring_backend(1);
        let operator = keyring_backend(10);
        let old = keyring_backend(2);
        let new = keyring_backend(3);
        let witnesses = [
            keyring_backend(20),
            keyring_backend(21),
            keyring_backend(22),
        ];
        let policy = checked(
            KeyLogPolicy::new(KeyLogPolicyConfig {
                log_id: checked(LogId::new("log.native.conformance"), "construct key-log ID")?,
                authority_id: checked(
                    AuthorityId::new("authority.native.conformance"),
                    "construct key-log authority ID",
                )?,
                bootstrap_key: bootstrap.public_key(),
                operator_key: operator.public_key(),
                witness_roster_id: checked(
                    WitnessRosterId::new("roster.native.conformance.v1"),
                    "construct witness roster ID",
                )?,
                witness_keys: BTreeMap::from([
                    (
                        checked(WitnessId::new("witness.a"), "construct witness A ID")?,
                        witnesses[0].public_key(),
                    ),
                    (
                        checked(WitnessId::new("witness.b"), "construct witness B ID")?,
                        witnesses[1].public_key(),
                    ),
                    (
                        checked(WitnessId::new("witness.c"), "construct witness C ID")?,
                        witnesses[2].public_key(),
                    ),
                ]),
                recovery_policy_id: checked(
                    RecoveryPolicyId::new("recovery.native.conformance.v1"),
                    "construct recovery policy ID",
                )?,
                recovery_keys: BTreeMap::new(),
                recovery_threshold: 0,
                max_checkpoint_future_skew: 100,
            }),
            "construct key-log policy",
        )?;
        Ok(Self {
            bootstrap,
            operator,
            old,
            new,
            witnesses,
            policy,
        })
    }

    fn genesis(&self) -> BehaviorResult<SignedKeyLogEvent> {
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: self.policy.log_id().clone(),
            sequence: 0,
            event_id: checked(EventId::new("event.genesis"), "construct genesis event ID")?,
            previous_event_hash: None,
            authority_id: self.policy.authority_id().clone(),
            key_id: checked(
                derive_key_id(self.old.algorithm(), &self.old.public_key()),
                "derive genesis key ID",
            )?,
            algorithm: self.old.algorithm(),
            public_key: self.old.public_key(),
            operation: KeyLogOperation::Genesis,
            effective_at: 1_000,
            verify_until: None,
            reason: Some(checked(
                EventReason::new("native conformance genesis"),
                "construct genesis reason",
            )?),
            issued_at: 1_000,
        };
        Ok(SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::bootstrap(checked(
                BootstrapAuthorization::sign(&body, &self.bootstrap),
                "sign genesis authorization",
            )?),
            body,
        })
    }

    fn rotation(&self, genesis: &SignedKeyLogEvent) -> BehaviorResult<SignedKeyLogEvent> {
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: genesis.body.log_id.clone(),
            sequence: 1,
            event_id: checked(
                EventId::new("event.rotation.1"),
                "construct rotation event ID",
            )?,
            previous_event_hash: Some(checked(
                genesis.envelope_hash(),
                "hash genesis event envelope",
            )?),
            authority_id: genesis.body.authority_id.clone(),
            key_id: checked(
                derive_key_id(self.new.algorithm(), &self.new.public_key()),
                "derive rotation key ID",
            )?,
            algorithm: self.new.algorithm(),
            public_key: self.new.public_key(),
            operation: KeyLogOperation::Rotate {
                previous_key_id: genesis.body.key_id,
                witness_roster_id: checked(
                    WitnessRosterId::new("roster.native.conformance.v1"),
                    "construct rotation witness roster ID",
                )?,
                witness_roster_binding: checked(
                    self.policy.witness_roster_binding(),
                    "bind rotation witness roster",
                )?,
            },
            effective_at: 2_000,
            verify_until: Some(9_000),
            reason: Some(checked(
                EventReason::new("native conformance rotation"),
                "construct rotation reason",
            )?),
            issued_at: 2_000,
        };
        Ok(SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::rotation(
                checked(
                    OldKeyAuthorization::sign(&body, &self.old),
                    "sign old-key rotation authorization",
                )?,
                checked(
                    NewKeyProofOfPossession::sign(&body, &self.new),
                    "sign new-key proof of possession",
                )?,
            ),
            body,
        })
    }

    fn store(&self, path: &Path) -> BehaviorResult<Arc<SqliteKeyLogStore>> {
        checked(
            SqliteKeyLogStore::open_with_clock(
                path,
                self.policy.clone(),
                SigningTopology::LocalSingleWriter,
                Arc::new(FixedKeyringClock(5_000)),
            ),
            "open key-log store",
        )
        .map(Arc::new)
    }

    fn witness(&self, path: &Path, index: usize) -> BehaviorResult<SqliteKeyLogWitness> {
        let suffix = match index {
            0 => "a",
            1 => "b",
            2 => "c",
            _ => return Err("witness index is outside the deterministic roster".to_string()),
        };
        let witness_id = checked(
            WitnessId::new(format!("witness.{suffix}")),
            "construct witness ID",
        )?;
        let backend = self
            .witnesses
            .get(index)
            .ok_or_else(|| "witness index is outside the deterministic roster".to_string())?
            .clone();
        checked(
            SqliteKeyLogWitness::provision(
                path,
                self.policy.clone(),
                witness_id,
                Box::new(backend),
                Arc::new(FixedKeyringClock(5_000)),
            ),
            "provision key-log witness",
        )
    }

    fn witness_keys(&self) -> BehaviorResult<BTreeMap<WitnessId, chio_core::crypto::PublicKey>> {
        Ok(BTreeMap::from([
            (
                checked(WitnessId::new("witness.a"), "construct witness A ID")?,
                self.witnesses[0].public_key(),
            ),
            (
                checked(WitnessId::new("witness.b"), "construct witness B ID")?,
                self.witnesses[1].public_key(),
            ),
            (
                checked(WitnessId::new("witness.c"), "construct witness C ID")?,
                self.witnesses[2].public_key(),
            ),
        ]))
    }
}

fn witness_checkpoint(
    store: &SqliteKeyLogStore,
    checkpoint: &SignedKeyLogCheckpoint,
    witnesses: &[&SqliteKeyLogWitness],
) -> BehaviorResult {
    for witness in witnesses {
        let response = checked(
            store.synchronization_response(checked(witness.pin(), "load witness pin")?.as_ref()),
            "build contiguous synchronization response",
        )?;
        let signature = checked(
            witness.sign_candidate(checkpoint, &response),
            "witness checkpoint candidate",
        )?;
        checked(
            store.store_witness_signature(
                &checked(checkpoint.checkpoint_hash(), "hash checkpoint")?,
                &signature,
            ),
            "store witness signature",
        )?;
    }
    Ok(())
}

fn key_log_signature_separation() -> BehaviorResult {
    let directory = checked(tempfile::tempdir(), "create key-log temporary directory")?;
    let fixture = KeyringBehaviorFixture::new()?;
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite")?)?;
    let genesis = fixture.genesis()?;
    checked(
        store.append_event(&genesis, &fixture.operator),
        "append genesis event",
    )?;
    let rotation = fixture.rotation(&genesis)?;
    checked(
        rotation.verify_rotation(&fixture.old.public_key()),
        "verify dual-signed rotation",
    )?;
    let body_bytes = checked(
        rotation.body.signing_bytes(),
        "encode rotation signing body",
    )?;
    let envelope_bytes = checked(
        rotation.canonical_envelope_bytes(),
        "encode complete rotation envelope",
    )?;
    let old_signature = rotation
        .authorizations
        .old_key
        .as_ref()
        .ok_or_else(|| "rotation omitted old-key authorization".to_string())?
        .signature
        .to_hex();
    let new_signature = rotation
        .authorizations
        .new_key
        .as_ref()
        .ok_or_else(|| "rotation omitted new-key proof of possession".to_string())?
        .signature
        .to_hex();
    require(
        !body_bytes
            .windows(old_signature.len())
            .any(|window| window == old_signature.as_bytes())
            && !body_bytes
                .windows(new_signature.len())
                .any(|window| window == new_signature.as_bytes())
            && envelope_bytes
                .windows(old_signature.len())
                .any(|window| window == old_signature.as_bytes())
            && envelope_bytes
                .windows(new_signature.len())
                .any(|window| window == new_signature.as_bytes()),
        "authorization signatures were not separated from the signed body",
    )?;

    let original_envelope_hash = checked(rotation.envelope_hash(), "hash rotation envelope")?;
    let original_leaf_hash = checked(rotation.merkle_leaf_hash(), "hash rotation leaf")?;
    let mut corrupted = rotation.clone();
    let old_authorization = corrupted
        .authorizations
        .old_key
        .as_mut()
        .ok_or_else(|| "rotation omitted old-key authorization".to_string())?;
    let claimed_key_id = old_authorization.key_id.clone();
    let claimed_algorithm = old_authorization.algorithm;
    let mut corrupted_signature_bytes = old_authorization.signature.to_bytes();
    corrupted_signature_bytes[0] ^= 1;
    old_authorization.signature = Signature::from_bytes(&corrupted_signature_bytes);
    let claim_preserved = old_authorization.key_id == claimed_key_id
        && old_authorization.algorithm == claimed_algorithm
        && old_authorization.signature.algorithm() == claimed_algorithm;
    let corrupted_rejected = matches!(
        store.append_event(&corrupted, &fixture.operator),
        Err(KeyringError::InvalidSignature)
    );
    require(
        claim_preserved
            && checked(
                corrupted.body.signing_bytes(),
                "encode corrupted rotation signing body",
            )? == body_bytes
            && checked(
                corrupted.envelope_hash(),
                "hash corrupted rotation envelope",
            )? != original_envelope_hash
            && checked(corrupted.merkle_leaf_hash(), "hash corrupted rotation leaf")?
                != original_leaf_hash
            && corrupted_rejected,
        "signature corruption changed its claim or escaped cryptographic validation",
    )?;
    checked(
        store.append_event(&rotation, &fixture.operator),
        "append valid separated-signature rotation",
    )?;
    Ok(())
}

fn key_log_contiguous_sync_applies() -> BehaviorResult {
    let directory = checked(tempfile::tempdir(), "create key-log temporary directory")?;
    let fixture = KeyringBehaviorFixture::new()?;
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite")?)?;
    let witness_a = fixture.witness(&trusted_temp_path(&directory, "witness-a.sqlite")?, 0)?;
    let witness_b = fixture.witness(&trusted_temp_path(&directory, "witness-b.sqlite")?, 1)?;
    let genesis = fixture.genesis()?;
    let genesis_checkpoint = checked(
        store.append_event(&genesis, &fixture.operator),
        "append genesis event",
    )?;
    witness_checkpoint(&store, &genesis_checkpoint, &[&witness_a, &witness_b])?;

    let rotation = fixture.rotation(&genesis)?;
    let rotation_checkpoint = checked(
        store.append_event(&rotation, &fixture.operator),
        "append rotation event",
    )?;
    witness_checkpoint(&store, &rotation_checkpoint, &[&witness_a, &witness_b])?;
    let checkpoints = checked(store.load_checkpoints(), "reload witnessed checkpoints")?;
    let witnessed_rotation = checkpoints
        .get(1)
        .ok_or_else(|| "rotation checkpoint was not persisted".to_string())?
        .checkpoint
        .clone();
    checked(
        store.activate_rotation(
            &rotation.body.event_id,
            &checked(
                witnessed_rotation.checkpoint_hash(),
                "hash witnessed rotation",
            )?,
            &fixture.operator,
        ),
        "activate witnessed rotation",
    )?;
    for witness in [&witness_a, &witness_b] {
        let response = checked(
            store.synchronization_response(checked(witness.pin(), "load witness pin")?.as_ref()),
            "synchronize activation commit",
        )?;
        checked(
            witness.sign_candidate(&witnessed_rotation, &response),
            "apply activation commit at witness",
        )?;
    }

    let verifier = checked(
        SqlitePinnedKeyLogVerifier::provision(
            trusted_temp_path(&directory, "verifier.sqlite")?,
            fixture.policy.clone(),
            Arc::new(FixedKeyringClock(5_000)),
        ),
        "provision pinned key-log verifier",
    )?;
    let full = checked(
        store.synchronization_response(None),
        "build full synchronization response",
    )?;
    let pin = checked(
        verifier.apply_sync(&full),
        "apply full contiguous synchronization",
    )?;
    require(
        pin.tree_size == 2 && pin.checkpoint_sequence == 1 && pin.signing_epoch == 1,
        format!(
            "contiguous sync produced tree size {}, checkpoint {}, epoch {}",
            pin.tree_size, pin.checkpoint_sequence, pin.signing_epoch
        ),
    )
}

fn key_log_omitted_noncontiguous_gap_rejected() -> BehaviorResult {
    let directory = checked(tempfile::tempdir(), "create key-log temporary directory")?;
    let fixture = KeyringBehaviorFixture::new()?;
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite")?)?;
    let witness = fixture.witness(&trusted_temp_path(&directory, "witness.sqlite")?, 0)?;
    let genesis = fixture.genesis()?;
    let genesis_checkpoint = checked(
        store.append_event(&genesis, &fixture.operator),
        "append genesis event",
    )?;
    let genesis_sync = checked(
        store.synchronization_response(None),
        "build genesis synchronization response",
    )?;
    checked(
        witness.sign_candidate(&genesis_checkpoint, &genesis_sync),
        "pin genesis checkpoint",
    )?;
    let original_pin = checked(witness.pin(), "load original witness pin")?;

    let rotation = fixture.rotation(&genesis)?;
    let mut noncontiguous = rotation.clone();
    noncontiguous.body.sequence = 2;
    noncontiguous.authorizations = KeyLogAuthorizations::rotation(
        checked(
            OldKeyAuthorization::sign(&noncontiguous.body, &fixture.old),
            "sign noncontiguous old-key authorization",
        )?,
        checked(
            NewKeyProofOfPossession::sign(&noncontiguous.body, &fixture.new),
            "sign noncontiguous new-key proof",
        )?,
    );
    let sequence_gap_rejected = matches!(
        store.append_event(&noncontiguous, &fixture.operator),
        Err(KeyringError::SequenceMismatch {
            expected: 1,
            actual: 2
        })
    );
    let rotation_checkpoint = checked(
        store.append_event(&rotation, &fixture.operator),
        "append rotation event",
    )?;
    let valid = checked(
        store.synchronization_response(original_pin.as_ref()),
        "build incremental synchronization response",
    )?;

    let mut omitted = valid.clone();
    omitted.event_envelopes.clear();
    let omission_rejected = matches!(
        witness.sign_candidate(&rotation_checkpoint, &omitted),
        Err(KeyringError::InvalidCheckpoint(
            "synchronization ranges are not contiguous"
        ))
    );
    let pin_after_omission = checked(witness.pin(), "reload witness pin after omission")?;

    let mut gapped = valid.clone();
    let event = gapped
        .event_envelopes
        .first_mut()
        .ok_or_else(|| "incremental sync omitted its rotation event".to_string())?;
    *event = noncontiguous;
    let noncontiguous_sync_rejected = witness
        .sign_candidate(&rotation_checkpoint, &gapped)
        .is_err();
    let pin_after_gap = checked(witness.pin(), "reload witness pin after sequence gap")?;

    let mut mutated = valid;
    let proof = mutated
        .consistency_proof
        .as_mut()
        .ok_or_else(|| "incremental sync omitted its consistency proof".to_string())?;
    proof.audit_path.push(chio_core::Hash::zero());
    let proof_rejected = witness
        .sign_candidate(&rotation_checkpoint, &mutated)
        .is_err();
    let pin_after_proof = checked(witness.pin(), "reload witness pin after proof rejection")?;
    require(
        sequence_gap_rejected
            && omission_rejected
            && noncontiguous_sync_rejected
            && proof_rejected
            && pin_after_omission == original_pin
            && pin_after_gap == original_pin
            && pin_after_proof == original_pin,
        "an omitted, noncontiguous, or proof-mutated sync advanced the witness pin",
    )
}

fn key_log_witness_conflict_rejected() -> BehaviorResult {
    let directory = checked(tempfile::tempdir(), "create key-log temporary directory")?;
    let fixture = KeyringBehaviorFixture::new()?;
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite")?)?;
    let witness = fixture.witness(&trusted_temp_path(&directory, "witness.sqlite")?, 0)?;
    let checkpoint = checked(
        store.append_event(&fixture.genesis()?, &fixture.operator),
        "append genesis event",
    )?;
    let response = checked(
        store.synchronization_response(None),
        "build genesis synchronization response",
    )?;
    checked(
        witness.sign_candidate(&checkpoint, &response),
        "pin genesis checkpoint",
    )?;
    let accepted_pin = checked(witness.pin(), "load accepted witness pin")?;

    let mut fork_body = checkpoint.body.clone();
    fork_body.root_hash = chio_core::sha256(b"native-conformance-split-view");
    let fork = checked(
        SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator),
        "sign conflicting checkpoint",
    )?;
    let mut conflicting = response;
    let first = conflicting
        .checkpoints
        .first_mut()
        .ok_or_else(|| "genesis sync omitted its checkpoint".to_string())?;
    *first = fork;
    let rejected = matches!(
        witness.sign_candidate(&checkpoint, &conflicting),
        Err(KeyringError::EquivocationDetected)
    );
    require(
        rejected
            && !checked(witness.conflicts(), "load durable witness conflicts")?.is_empty()
            && checked(witness.pin(), "reload witness pin after conflict")? == accepted_pin,
        "witness conflict was accepted or changed the pinned checkpoint",
    )?;
    insufficient_witness_quorum_refused()
}

fn insufficient_witness_quorum_refused() -> BehaviorResult {
    let directory = checked(tempfile::tempdir(), "create key-log temporary directory")?;
    let fixture = KeyringBehaviorFixture::new()?;
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite")?)?;
    let mut checkpoint = checked(
        store.append_event(&fixture.genesis()?, &fixture.operator),
        "append genesis event",
    )?;
    checkpoint.witness_signatures = vec![
        checked(
            WitnessSignature::sign(
                &checkpoint,
                checked(WitnessId::new("witness.a"), "construct witness A ID")?,
                &fixture.witnesses[0],
            ),
            "sign checkpoint as witness A",
        )?,
        checked(
            WitnessSignature::sign(
                &checkpoint,
                checked(WitnessId::new("witness.b"), "construct witness B ID")?,
                &fixture.witnesses[1],
            ),
            "sign checkpoint as witness B",
        )?,
    ];
    let keys = fixture.witness_keys()?;
    let sufficient = checked(
        checkpoint.verify_witnesses(&keys),
        "verify strict-majority witness quorum",
    )?;
    require(
        sufficient.len() == 2,
        "strict-majority witness quorum did not verify",
    )?;
    checkpoint.witness_signatures.pop();
    require(
        checkpoint.verify_witnesses(&keys).is_err(),
        "checkpoint with one of three witnesses was accepted",
    )
}

fn broker_proof_fixture() -> BehaviorResult<(SignedBrokerCapability, BrokerRequest, Keypair)> {
    let issuer = Keypair::from_seed(&[31; 32]);
    let caller = Keypair::from_seed(&[32; 32]);
    let destination = checked(
        BrokerDestination::parse("https://example.com/v1?x=1", "post", false),
        "construct broker destination",
    )?;
    let request = BrokerRequest {
        destination: destination.clone(),
        headers: vec![checked(
            HeaderField::normalized("content-type", b"application/json"),
            "normalize broker caller header",
        )?],
        body: b"body".to_vec(),
        approved_preview_sha256: None,
        options: CallerOptions {
            timeout_ms: 1_000,
            streaming: false,
            response_limit_bytes: 256,
        },
    };
    let capability = checked(
        issue_capability(
            BrokerCapabilityBody {
                schema: BROKER_CAPABILITY_SCHEMA.to_string(),
                issuer: issuer.public_key(),
                capability_id: "broker-capability-native".to_string(),
                parent_capability_id: "parent-capability-native".to_string(),
                subject: caller.public_key(),
                audience: "native-conformance-broker".to_string(),
                issued_at_unix_seconds: 10,
                not_before_unix_seconds: 10,
                expires_at_unix_seconds: 100,
                credential: CredentialRef {
                    provider: "generic-https".to_string(),
                    credential_id: "credential-native".to_string(),
                    version: 1,
                },
                provider_adapter_id: "generic-bearer".to_string(),
                provider_adapter_version: 1,
                destination,
                constraints: RequestConstraints {
                    allowed_caller_headers: vec!["content-type".to_string()],
                    provider_owned_headers: vec!["authorization".to_string()],
                    maximum_body_bytes: 128,
                    required_body_sha256: body_digest(b"body"),
                    required_preview_sha256: None,
                    redirect_policy: RedirectPolicy::Disabled,
                    maximum_response_bytes: 256,
                    streaming_allowed: false,
                    maximum_timeout_ms: 1_000,
                },
                broker_quota_key_id: "broker-quota-native".to_string(),
                maximum_executions: 2,
                consumption: AttemptConsumption::CaptureBeforeDispatch,
                revocation_id: "broker-revocation-native".to_string(),
                proof: ProofBinding {
                    mode: ProofMode::PublicKey,
                    caller_public_key: caller.public_key(),
                    nonce_ttl_seconds: 30,
                },
            },
            &Ed25519Backend::new(issuer),
            true,
        ),
        "issue broker capability",
    )?;
    Ok((capability, request, caller))
}

fn broker_proof_complete_request_binding() -> BehaviorResult {
    let (capability, request, caller) = broker_proof_fixture()?;
    let proof = checked(
        issue_request_proof(
            &capability,
            &request,
            "nonce-native-abcdefghijkl".to_string(),
            20,
            &caller,
        ),
        "issue complete broker request proof",
    )?;
    checked(
        verify_request_proof(&proof, &capability, &request, 20, 0),
        "verify complete broker request proof",
    )?;

    let mut changed_body = request.clone();
    changed_body.body.push(b'!');
    let mut changed_header = request.clone();
    changed_header.headers = vec![checked(
        HeaderField::normalized("content-type", b"text/plain"),
        "normalize mutated broker header",
    )?];
    let mut changed_options = request.clone();
    changed_options.options.timeout_ms = 999;
    let mut changed_destination = request.clone();
    changed_destination.destination.exact_path_and_query = "/v2?x=1".to_string();
    let mutants = [
        ("body", changed_body),
        ("header", changed_header),
        ("options", changed_options),
        ("destination", changed_destination),
    ];
    for (field, mutant) in mutants {
        if verify_request_proof(&proof, &capability, &mutant, 20, 0).is_ok() {
            return Err(format!(
                "broker proof accepted a request with mutated {field} binding"
            ));
        }
    }
    Ok(())
}

fn broker_registration(
    invocation_id: &str,
    request_digest: &str,
    nonce: &str,
) -> BehaviorResult<AttemptRegistration> {
    Ok(AttemptRegistration {
        ids: checked(
            derive_attempt_ids(
                "broker-capability-native",
                invocation_id,
                nonce,
                request_digest,
            ),
            "derive broker attempt identifiers",
        )?,
        invocation_id: invocation_id.to_string(),
        parent_capability_id: "parent-capability-native".to_string(),
        broker_capability_id: "broker-capability-native".to_string(),
        request_digest: request_digest.to_string(),
        request_canonical_digest: "d".repeat(64),
        proof_digest: "b".repeat(64),
        proof_key_id: "proof-key-native".to_string(),
        proof_nonce: nonce.to_string(),
        nonce_expires_at_unix_seconds: 100,
        quotas: vec![ExecutionQuota {
            key_id: "broker-quota-native".to_string(),
            maximum_executions: 2,
        }],
        authority_metadata_digest: "c".repeat(64),
        revocation_authority_domain: "combined-authority-native".to_string(),
    })
}

fn broker_nonce_replay_refused() -> BehaviorResult {
    let directory = checked(tempfile::tempdir(), "create broker temporary directory")?;
    let path = trusted_temp_path(&directory, "attempts.sqlite")?;
    let store = checked(
        SqliteAttemptStore::open(&path),
        "open durable broker attempt store",
    )?;
    let nonce = "nonce-native-abcdefghijkl";
    let first = broker_registration("invocation-native-1", &"a".repeat(64), nonce)?;
    require(
        matches!(
            checked(
                store.register_attempt(&first, 20),
                "register broker attempt"
            )?,
            RegisterAttemptOutcome::Inserted(_)
        ),
        "first broker nonce registration was not inserted",
    )?;
    require(
        matches!(
            checked(
                store.register_attempt(&first, 21),
                "retry exact broker attempt"
            )?,
            RegisterAttemptOutcome::ExactRetry(_)
        ),
        "exact broker retry did not return the frozen attempt",
    )?;

    let replay = broker_registration("invocation-native-2", &"e".repeat(64), nonce)?;
    let error = store
        .register_attempt(&replay, 22)
        .err()
        .ok_or_else(|| "broker accepted nonce replay for different request input".to_string())?;
    require(
        error.to_string().contains("nonce was already consumed"),
        format!("nonce replay failed for an unrelated reason: {error}"),
    )
}

fn invocation_quota(
    profile: BudgetQuotaProfile,
    owner_id: &str,
    grant_index: Option<u32>,
    maximum: u32,
) -> BehaviorResult<BudgetInvocationQuota> {
    let key = checked(
        BudgetQuotaKey::from_persisted_parts(profile, owner_id.to_string(), grant_index),
        "construct invocation quota key",
    )?;
    checked(
        BudgetInvocationQuota::from_persisted_parts(key, maximum),
        "construct invocation quota",
    )
}

fn composite_budget_request(
    hold_id: &str,
    event_id: &str,
    aggregate_maximum: u32,
) -> BehaviorResult<SqliteCompositeAuthorizeInput> {
    Ok(SqliteCompositeAuthorizeInput {
        operation_id: format!("operation:{hold_id}"),
        request_binding_hash: "11".repeat(32),
        capability_id: "leaf-native".to_string(),
        grant_index: 0,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1_000),
        hold_id: hold_id.to_string(),
        event_id: event_id.to_string(),
        authority: None,
        invocation_quotas: vec![
            invocation_quota(
                BudgetQuotaProfile::GrantInvocation,
                "leaf-native",
                Some(0),
                2,
            )?,
            invocation_quota(
                BudgetQuotaProfile::AggregateCapabilityInvocation,
                "leaf-native",
                None,
                aggregate_maximum,
            )?,
            invocation_quota(
                BudgetQuotaProfile::SupplementalBrokerExecution,
                &"22".repeat(32),
                None,
                2,
            )?,
        ],
        revocation_set: checked(
            CanonicalRevocationSet::new("leaf-native", &[], &[]),
            "construct canonical budget revocation set",
        )?,
        authorization_artifact_digests: Vec::new(),
    })
}

fn all_invocation_counts_equal(
    decision: &BudgetAuthorizeHoldDecision,
    expected: u32,
) -> BehaviorResult<bool> {
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        return Ok(false);
    };
    for usage in &authorized.invocation_counts_after {
        if checked(
            usage.invocation_count_after(),
            "read invocation count after authorization",
        )? != expected
        {
            return Ok(false);
        }
    }
    Ok(authorized.invocation_counts_after.len() == 3)
}

fn broker_combined_quota_no_double_charge() -> BehaviorResult {
    let directory = checked(
        tempfile::tempdir(),
        "create broker service temporary directory",
    )?;
    let trusted_directory = checked(
        fs::canonicalize(directory.path()),
        "canonicalize broker service temporary directory",
    )?;
    checked(
        chio_secret_broker::conformance::combined_quota_no_double_charge(&trusted_directory),
        "exercise broker service capture without a second quota charge",
    )
}

fn broker_encrypted_credential_custody() -> BehaviorResult {
    let directory = checked(tempfile::tempdir(), "create custody temporary directory")?;
    let trusted_directory = checked(
        fs::canonicalize(directory.path()),
        "canonicalize custody temporary directory",
    )?;
    checked(
        chio_secret_broker::conformance::encrypted_credential_custody(&trusted_directory),
        "exercise sealed, versioned, tenant-scoped broker credential custody",
    )
}

fn load_cage_vector<T: serde::de::DeserializeOwned>(
    repo_root: &Path,
    file_name: &str,
) -> BehaviorResult<T> {
    let path = repo_root
        .join("tests/bindings/vectors/security/cage/positive")
        .join(file_name);
    let bytes = checked(fs::read(&path), "read cage behavior vector")?;
    checked(
        serde_json::from_slice(&bytes),
        &format!("decode production cage type from {}", path.display()),
    )
}

fn cage_plan_target_fd_identity_bound(repo_root: &Path) -> BehaviorResult {
    let plan: CageInitPlan = load_cage_vector(repo_root, "cage-init-plan-native-v2.json")?;
    let prepared: EnforcementPrepared =
        load_cage_vector(repo_root, "cage-enforcement-prepared-v1.json")?;
    checked(prepared.validate(), "validate prepared cage evidence")?;
    checked(
        validate_cage_target_fd_binding(
            &plan,
            &prepared.target_binding_digest,
            prepared.target_identity,
        ),
        "validate production cage target FD binding",
    )?;

    let target_index = plan
        .fd_table
        .iter()
        .position(|entry| matches!(entry.purpose, FdPurpose::TargetExecutable))
        .ok_or_else(|| "cage plan omitted its target executable descriptor".to_string())?;
    let mut changed_slot = plan.clone();
    let changed_slot_entry = changed_slot
        .fd_table
        .get_mut(target_index)
        .ok_or_else(|| "target descriptor index changed during mutation".to_string())?;
    changed_slot_entry.slot = changed_slot_entry.slot.saturating_sub(1);
    let mut changed_binding = plan.clone();
    let changed_binding_entry = changed_binding
        .fd_table
        .get_mut(target_index)
        .ok_or_else(|| "target descriptor index changed during mutation".to_string())?;
    changed_binding_entry.binding_digest = Some("9".repeat(64));
    let replacement_identity = plan
        .fd_table
        .iter()
        .find(|entry| matches!(entry.purpose, FdPurpose::CageInitHelper))
        .map(|entry| entry.identity)
        .ok_or_else(|| "cage plan omitted its helper executable descriptor".to_string())?;
    let mut changed_identity = plan.clone();
    changed_identity
        .fd_table
        .get_mut(target_index)
        .ok_or_else(|| "target descriptor index changed during identity mutation".to_string())?
        .identity = replacement_identity;
    let mut changed_execveat_target = plan.clone();
    changed_execveat_target
        .seccomp
        .argument_constraints
        .get_mut("execveat")
        .and_then(|constraints| {
            constraints
                .iter_mut()
                .find(|constraint| constraint.argument_index == 0)
        })
        .ok_or_else(|| "cage plan omitted its execveat target constraint".to_string())?
        .value = 254;
    require(
        validate_cage_target_fd_binding(
            &changed_slot,
            &prepared.target_binding_digest,
            prepared.target_identity,
        )
        .is_err()
            && validate_cage_target_fd_binding(
                &changed_binding,
                &prepared.target_binding_digest,
                prepared.target_identity,
            )
            .is_err()
            && validate_cage_target_fd_binding(
                &changed_identity,
                &prepared.target_binding_digest,
                prepared.target_identity,
            )
            .is_err()
            && validate_cage_target_fd_binding(
                &changed_execveat_target,
                &prepared.target_binding_digest,
                prepared.target_identity,
            )
            .is_err(),
        "cage plan accepted a mutated target FD slot, digest, identity, or execveat constraint",
    )?;

    #[cfg(target_os = "linux")]
    {
        let executable_path = checked(
            std::env::current_exe(),
            "resolve live conformance executable",
        )?;
        let executable = checked(
            fs::File::open(&executable_path),
            "open live conformance executable descriptor",
        )?;
        let valid = checked(
            validate_cage_target_fd_binding_production_paths(
                &plan,
                &executable,
                CageTargetFdBindingMutation::None,
            ),
            "exercise live cage target FD production validators",
        )?;
        require(
            valid.parent_accepted() && valid.child_accepted(),
            "live cage target FD production validators rejected the valid descriptor",
        )?;
        for mutation in [
            CageTargetFdBindingMutation::Slot,
            CageTargetFdBindingMutation::BindingDigest,
            CageTargetFdBindingMutation::Identity,
            CageTargetFdBindingMutation::ExecveatTarget,
        ] {
            let result = checked(
                validate_cage_target_fd_binding_production_paths(&plan, &executable, mutation),
                "exercise mutated live cage target FD production validators",
            )?;
            require(
                !result.parent_accepted() && !result.child_accepted(),
                &format!("live cage target FD production path accepted mutation {mutation:?}"),
            )?;
        }
    }
    Ok(())
}

fn cage_prepared_mutation_rejected(repo_root: &Path) -> BehaviorResult {
    let plan: CageInitPlan = load_cage_vector(repo_root, "cage-init-plan-native-v2.json")?;
    let prepared: EnforcementPrepared =
        load_cage_vector(repo_root, "cage-enforcement-prepared-v1.json")?;
    checked(prepared.validate(), "validate prepared cage evidence")?;
    checked(
        validate_cage_execution_identity_binding(&plan, &prepared),
        "bind applied execution identity to sealed cage plan",
    )?;
    let mut partial = prepared.clone();
    partial.landlock_network_status = ObservedRulesetStatus::PartiallyEnforced;
    let mut identity_mismatch = prepared;
    identity_mismatch.applied_execution_identity = checked(
        ExecutionIdentity::new(10003, 10001, vec![10002]),
        "construct mismatched execution identity",
    )?;
    require(
        partial.validate().is_err()
            && validate_cage_execution_identity_binding(&plan, &identity_mismatch).is_err(),
        "prepared evidence accepted partial isolation or a mismatched execution identity",
    )
}

fn cage_exec_transition_mutation_rejected(repo_root: &Path) -> BehaviorResult {
    let prepared: EnforcementPrepared =
        load_cage_vector(repo_root, "cage-enforcement-prepared-v1.json")?;
    let transition: ExecTransitionObserved =
        load_cage_vector(repo_root, "cage-exec-transition-observed-v1.json")?;
    checked(
        FullyEnforcedEvidence::new(prepared.clone(), transition.clone(), true),
        "bind prepared evidence to observed exec transition",
    )?;
    let mut mutated = transition;
    mutated.target_binding_digest = "9".repeat(64);
    require(
        FullyEnforcedEvidence::new(prepared, mutated, true).is_err(),
        "exec transition accepted a different target artifact binding",
    )
}

fn cage_enforcement_evidence_mutation_rejected(repo_root: &Path) -> BehaviorResult {
    let evidence: FullyEnforcedEvidence =
        load_cage_vector(repo_root, "cage-fully-enforced-evidence-v1.json")?;
    checked(evidence.validate(), "validate fully enforced cage evidence")?;
    let mut missing_descriptor_transition = evidence.clone();
    missing_descriptor_transition.status_eof_observed = false;
    let mut time_rebound = evidence;
    time_rebound.exec_transition.observed_at_unix_ms =
        time_rebound.prepared.prepared_at_unix_ms.saturating_sub(1);
    require(
        missing_descriptor_transition.validate().is_err() && time_rebound.validate().is_err(),
        "fully enforced evidence accepted missing CLOEXEC EOF or a pre-prepare exec transition",
    )
}

fn protocol_aggregate_multi_key_atomic_exhaustion() -> BehaviorResult {
    let directory = checked(tempfile::tempdir(), "create budget temporary directory")?;
    let path = trusted_temp_path(&directory, "protocol-budget.sqlite")?;
    let store = checked(SqliteBudgetStore::open(&path), "open SQLite budget store")?;
    let first_request =
        composite_budget_request("hold-protocol-native-1", "event-protocol-native-1", 1)?;
    let first = checked(
        store.authorize_composite_hold(first_request.clone()),
        "authorize first multi-key protocol hold",
    )?;
    require(
        all_invocation_counts_equal(&first, 1)?,
        "first multi-key protocol hold did not reserve all keys atomically",
    )?;
    let second = checked(
        store.authorize_composite_hold(composite_budget_request(
            "hold-protocol-native-2",
            "event-protocol-native-2",
            1,
        )?),
        "attempt exhausted multi-key protocol hold",
    )?;
    let BudgetAuthorizeHoldDecision::Denied(denied) = second else {
        return Err("exhausted aggregate key authorized a second multi-key hold".to_string());
    };
    require(
        denied.invocation_state == BudgetInvocationReservationState::Denied
            && denied.invocation_counts_after.len() == 3
            && denied.invocation_counts_after.iter().all(|usage| {
                usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
            })
            && checked(
                store.authorize_composite_hold(first_request),
                "retry first multi-key protocol hold",
            )? == first,
        "aggregate exhaustion partially mutated another quota key or changed the frozen first hold",
    )
}

struct ThresholdBehaviorFixture {
    authority: Keypair,
    subject: Keypair,
    approvers: [Keypair; 2],
    requirement: ThresholdApprovalRequirement,
    proposal: ThresholdApprovalProposal,
    intent_hash: String,
    capability_hash: String,
}

impl ThresholdBehaviorFixture {
    fn new() -> BehaviorResult<Self> {
        let authority = Keypair::from_seed(&[51; 32]);
        let subject = Keypair::from_seed(&[52; 32]);
        let approvers = [Keypair::from_seed(&[53; 32]), Keypair::from_seed(&[54; 32])];
        let policy_hash = "33".repeat(32);
        let intent_hash = "11".repeat(32);
        let capability_hash = "22".repeat(32);
        let requirement = checked(
            ThresholdApprovalRequirement::new(
                2,
                BTreeMap::from([
                    ("alice".to_string(), approvers[0].public_key()),
                    ("bob".to_string(), approvers[1].public_key()),
                ]),
                900,
                policy_hash.clone(),
                1,
            ),
            "construct threshold approval requirement",
        )?;
        let proposal = checked(
            ThresholdApprovalProposal::sign(
                checked(
                    ThresholdApprovalProposalBody::new(
                        "proposal-native-1",
                        "request-native-1",
                        intent_hash.clone(),
                        subject.public_key(),
                        capability_hash.clone(),
                        policy_hash,
                        requirement.required(),
                        requirement.eligible_set_digest(),
                        1_000,
                        requirement.proposal_timeout_seconds(),
                        1_900,
                        1_900,
                    ),
                    "construct threshold approval proposal body",
                )?,
                &authority,
            ),
            "sign threshold approval proposal",
        )?;
        Ok(Self {
            authority,
            subject,
            approvers,
            requirement,
            proposal,
            intent_hash,
            capability_hash,
        })
    }

    fn token(&self, signer_index: usize, id: &str) -> BehaviorResult<GovernedApprovalToken> {
        let signer = self
            .approvers
            .get(signer_index)
            .ok_or_else(|| "threshold signer index is outside the eligible set".to_string())?;
        checked(
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: id.to_string(),
                    approver: signer.public_key(),
                    subject: self.subject.public_key(),
                    governed_intent_hash: self.intent_hash.clone(),
                    threshold_proposal_hash: Some(checked(
                        self.proposal.proposal_hash(),
                        "hash threshold proposal",
                    )?),
                    request_id: "request-native-1".to_string(),
                    issued_at: 1_100,
                    expires_at: 1_800,
                    decision: GovernedApprovalDecision::Approved,
                },
                signer,
            ),
            "sign governed approval token",
        )
    }

    fn verify(
        &self,
        tokens: &[GovernedApprovalToken],
    ) -> BehaviorResult<VerifiedThresholdApprovalSet> {
        let subject = self.subject.public_key();
        let trusted_authorities = [self.authority.public_key()];
        checked(
            verify_threshold_approval_set(
                &ThresholdApprovalVerificationInput {
                    request_id: "request-native-1",
                    server_id: "payments",
                    tool_name: "transfer",
                    governed_intent_hash: &self.intent_hash,
                    subject: &subject,
                    authorization_capability_hash: &self.capability_hash,
                    authorizing_capability_expires_at: 1_900,
                    governed_operation_expires_at: 1_900,
                    policy_hash: self.requirement.policy_hash(),
                    proposal: &self.proposal,
                    approval_tokens: tokens,
                    trusted_policy_authorities: &trusted_authorities,
                    allowed_token_algorithms: &[SigningAlgorithm::Ed25519],
                    now: 1_200,
                },
                &|_: &ThresholdApprovalRequest, _: &str| Ok(self.requirement.clone()),
            ),
            "verify threshold approval set",
        )
    }
}

fn protocol_threshold_distinct_signers_required() -> BehaviorResult {
    let fixture = ThresholdBehaviorFixture::new()?;
    let first = fixture.token(0, "approval-native-a")?;
    let second = fixture.token(1, "approval-native-b")?;
    let verified = fixture.verify(&[first.clone(), second])?;
    require(
        verified.members().len() == 2,
        "two distinct eligible threshold signers did not satisfy the requirement",
    )?;
    let duplicate_signer = fixture.token(0, "approval-native-c")?;
    let error = fixture
        .verify(&[first, duplicate_signer])
        .err()
        .ok_or_else(|| "threshold counted one signer twice".to_string())?;
    require(
        error.contains("signer is duplicated"),
        format!("duplicate threshold signer failed for an unrelated reason: {error}"),
    )
}

fn protocol_threshold_approval_replay_refused() -> BehaviorResult {
    let fixture = ThresholdBehaviorFixture::new()?;
    let tokens = [
        fixture.token(0, "approval-native-a")?,
        fixture.token(1, "approval-native-b")?,
    ];
    let verified = fixture.verify(&tokens)?;
    let reservation = checked(
        verified.reservation_input(),
        "construct threshold approval replay reservation",
    )?;
    let directory = checked(tempfile::tempdir(), "create approval temporary directory")?;
    let path = trusted_temp_path(&directory, "approvals.sqlite")?;
    let operation_a = "a".repeat(64);
    let operation_b = "b".repeat(64);
    let first = {
        let store = checked(
            SqliteApprovalStore::open(&path),
            "open approval replay store",
        )?;
        let reserved = checked(
            store.reserve_approval_set(&operation_a, &reservation),
            "reserve threshold approval set",
        )?;
        let retry = checked(
            store.reserve_approval_set(&operation_a, &reservation),
            "retry exact threshold approval reservation",
        )?;
        require(
            retry == reserved,
            "exact threshold reservation retry changed its frozen ownership",
        )?;
        reserved
    };
    let reopened = checked(
        SqliteApprovalStore::open(&path),
        "reopen durable approval replay store",
    )?;
    let replay = reopened.reserve_approval_set(&operation_b, &reservation);
    require(
        matches!(replay, Err(ApprovalStoreError::Replay(_)))
            && checked(
                reopened.reserve_approval_set(&operation_a, &reservation),
                "reload exact threshold approval reservation",
            )? == first,
        "threshold approval set replay was not durably refused for a second operation",
    )
}
