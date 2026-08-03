use chio_test_support::prelude::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_core_types::{canonical_json_bytes, Ed25519Backend, Keypair, SigningBackend};
use chio_keyring::{
    AnchorId, AuthorityId, KeyLogPin, KeyLogPolicy, KeyLogPolicyConfig, KeyLogState,
    KeyLogSyncResponse, KeyringError, LogId, RecoveryPolicyId, SignedKeyActivationCommit,
    SignedKeyEnterpriseReceipt, SignedKeyLogCheckpoint, SignedKeyLogEvent,
    SqlitePinnedKeyLogVerifier, TrustedClock, WitnessId, WitnessRosterId, WitnessSignature,
    WitnessedActivationSet,
};
use serde::Deserialize;
use serde_json::Value;

mod support;

use support::trusted_temp_path;

const EXPECTED_SCHEMA_VALID_CASES: [&str; 8] = [
    "activation_witness_set_hash_tampered",
    "checkpoint_complete_envelope_root_tampered",
    "checkpoint_witnesses_not_sorted",
    "event_old_signature_tampered",
    "receipt_noncanonical_trailing_newline",
    "receipt_operator_signature_tampered",
    "receipt_tree_size_tampered",
    "sync_consistency_path_tampered",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationCorpus {
    schema: String,
    operation_format: String,
    cases: Vec<MutationCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationCase {
    id: String,
    base: String,
    mutation: Mutation,
    expected: MutationExpectation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    op: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationExpectation {
    json_parse_valid: bool,
    json_schema_valid: bool,
    semantic_valid: bool,
    failure: String,
}

struct FixedClock(u64);

impl TrustedClock for FixedClock {
    fn now(&self) -> chio_keyring::Result<u64> {
        Ok(self.0)
    }
}

struct DeterministicKeys {
    bootstrap: Ed25519Backend,
    operator: Ed25519Backend,
    old_artifact: Ed25519Backend,
    new_artifact: Ed25519Backend,
    witnesses: [Ed25519Backend; 3],
    policy: KeyLogPolicy,
}

impl DeterministicKeys {
    fn new() -> Self {
        let bootstrap = backend(1);
        let operator = backend(10);
        let old_artifact = backend(2);
        let new_artifact = backend(3);
        let witnesses = [backend(20), backend(21), backend(22)];
        let artifact_time = backend(70);
        let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: LogId::new("log.enterprise.receipt").test_unwrap(),
            authority_id: AuthorityId::new("authority.enterprise.receipt").test_unwrap(),
            bootstrap_key: bootstrap.public_key(),
            operator_key: operator.public_key(),
            witness_roster_id: WitnessRosterId::new("roster.enterprise.receipt.v1").test_unwrap(),
            witness_keys: BTreeMap::from([
                (
                    WitnessId::new("witness.a").test_unwrap(),
                    witnesses[0].public_key(),
                ),
                (
                    WitnessId::new("witness.b").test_unwrap(),
                    witnesses[1].public_key(),
                ),
                (
                    WitnessId::new("witness.c").test_unwrap(),
                    witnesses[2].public_key(),
                ),
            ]),
            recovery_policy_id: RecoveryPolicyId::new("recovery.enterprise.receipt.v1")
                .test_unwrap(),
            recovery_keys: BTreeMap::new(),
            recovery_threshold: 0,
            max_checkpoint_future_skew: 100,
        })
        .test_unwrap()
        .with_artifact_time_roots(BTreeMap::from([(
            AnchorId::new("timestamp.enterprise.receipt.v1").test_unwrap(),
            artifact_time.public_key(),
        )]))
        .test_unwrap();
        Self {
            bootstrap,
            operator,
            old_artifact,
            new_artifact,
            witnesses,
            policy,
        }
    }
}

struct PositiveContext {
    genesis: SignedKeyLogEvent,
    rotation: SignedKeyLogEvent,
    genesis_checkpoint: SignedKeyLogCheckpoint,
    witnessed_checkpoint: SignedKeyLogCheckpoint,
    activation: SignedKeyActivationCommit,
}

impl PositiveContext {
    fn load(keys: &DeterministicKeys) -> Self {
        let genesis = load_event("positive/key-log-event-envelope-genesis-v1.json");
        let rotation = load_event("positive/key-log-event-envelope-rotation-v1.json");
        let genesis_checkpoint =
            load_checkpoint("positive/key-log-checkpoint-envelope-genesis-v1.json");
        let witnessed_checkpoint =
            load_checkpoint("positive/key-log-checkpoint-envelope-witnessed-v1.json");
        let activation = load_activation("positive/key-log-activation-commit-envelope-v1.json");
        let active_receipt =
            load_receipt("positive/key-log-enterprise-receipt-envelope-active-v1.json");

        assert_eq!(genesis.body.public_key, keys.old_artifact.public_key());
        assert_eq!(rotation.body.public_key, keys.new_artifact.public_key());
        genesis
            .validate_common(
                0,
                None,
                keys.policy.log_id(),
                keys.policy.authority_id(),
                None,
            )
            .test_unwrap();
        genesis
            .verify_genesis(&keys.bootstrap.public_key())
            .test_unwrap();
        let genesis_hash = genesis.envelope_hash().test_unwrap();
        rotation
            .validate_common(
                1,
                Some(&genesis_hash),
                keys.policy.log_id(),
                keys.policy.authority_id(),
                Some(genesis.body.issued_at),
            )
            .test_unwrap();
        rotation
            .verify_rotation(&keys.old_artifact.public_key())
            .test_unwrap();

        genesis_checkpoint
            .verify_operator(&keys.operator.public_key())
            .test_unwrap();
        witnessed_checkpoint
            .verify_operator(&keys.operator.public_key())
            .test_unwrap();
        witnessed_checkpoint
            .verify_witnesses(keys.policy.witness_public_keys())
            .test_unwrap();

        let events = [genesis.clone(), rotation.clone()];
        let checkpoints = [genesis_checkpoint.clone(), witnessed_checkpoint.clone()];
        let activations = [activation.clone()];
        let verified = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoints,
            &activations,
            &keys.policy,
        )
        .test_unwrap();
        KeyLogState::replay(events.iter(), &verified, &keys.policy).test_unwrap();
        active_receipt
            .verify_against(
                &rotation,
                &witnessed_checkpoint,
                &keys.policy,
                Some(&activation),
            )
            .test_unwrap();

        Self {
            genesis,
            rotation,
            genesis_checkpoint,
            witnessed_checkpoint,
            activation,
        }
    }

    fn events(&self) -> [SignedKeyLogEvent; 2] {
        [self.genesis.clone(), self.rotation.clone()]
    }

    fn checkpoints(&self) -> [SignedKeyLogCheckpoint; 2] {
        [
            self.genesis_checkpoint.clone(),
            self.witnessed_checkpoint.clone(),
        ]
    }
}

#[test]
fn schema_valid_key_log_mutations_are_rejected_by_native_semantics() {
    let corpus: MutationCorpus =
        serde_json::from_slice(&read_vector("mutations-v1.json")).test_unwrap();
    assert_eq!(corpus.schema, "chio.test-vector.key-log.mutations.v1");
    assert_eq!(
        corpus.operation_format,
        "RFC 6902 single-operation subset plus append_bytes"
    );

    let expected_ids = EXPECTED_SCHEMA_VALID_CASES
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual_ids = corpus
        .cases
        .iter()
        .filter(|case| case.expected.json_schema_valid)
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_ids, expected_ids);

    let keys = DeterministicKeys::new();
    let positive = PositiveContext::load(&keys);
    verify_sync_page(
        &keys,
        &positive,
        &read_vector("positive/key-log-sync-response-paged-v1.json"),
    )
    .test_unwrap();

    let mut rejected_ids = BTreeSet::new();
    for case in corpus
        .cases
        .iter()
        .filter(|case| case.expected.json_schema_valid)
    {
        assert!(case.expected.json_parse_valid, "case {}", case.id);
        assert!(!case.expected.semantic_valid, "case {}", case.id);
        assert!(rejected_ids.insert(case.id.as_str()), "case {}", case.id);
        let mutated = apply_mutation(case);
        assert!(
            serde_json::from_slice::<Value>(&mutated).is_ok(),
            "schema-valid case {} stopped being JSON-parseable",
            case.id
        );

        match case.id.as_str() {
            "receipt_noncanonical_trailing_newline" => {
                assert_case_contract(
                    case,
                    "positive/key-log-enterprise-receipt-envelope-active-v1.json",
                    "noncanonical_envelope_bytes",
                );
                assert!(matches!(
                    SignedKeyEnterpriseReceipt::from_canonical_bytes(&mutated),
                    Err(KeyringError::Canonical(_))
                ));
            }
            "event_old_signature_tampered" => {
                assert_case_contract(
                    case,
                    "positive/key-log-event-envelope-rotation-v1.json",
                    "invalid_old_key_signature",
                );
                let candidate =
                    SignedKeyLogEvent::from_canonical_envelope_bytes(&mutated).test_unwrap();
                assert!(matches!(
                    candidate.verify_rotation(&keys.old_artifact.public_key()),
                    Err(KeyringError::InvalidSignature)
                ));
            }
            "checkpoint_complete_envelope_root_tampered" => {
                assert_case_contract(
                    case,
                    "positive/key-log-checkpoint-envelope-witnessed-v1.json",
                    "checkpoint_signature_or_tree_binding",
                );
                let candidate =
                    SignedKeyLogCheckpoint::from_canonical_bytes(&mutated).test_unwrap();
                assert!(matches!(
                    candidate.verify_operator(&keys.operator.public_key()),
                    Err(KeyringError::InvalidSignature)
                ));
            }
            "checkpoint_witnesses_not_sorted" => {
                assert_case_contract(
                    case,
                    "positive/key-log-checkpoint-envelope-witnessed-v1.json",
                    "noncanonical_witness_order",
                );
                assert!(matches!(
                    SignedKeyLogCheckpoint::from_canonical_bytes(&mutated),
                    Err(KeyringError::Canonical(_))
                ));
            }
            "activation_witness_set_hash_tampered" => {
                assert_case_contract(
                    case,
                    "positive/key-log-activation-commit-envelope-v1.json",
                    "activation_signature_or_witness_binding",
                );
                let candidate =
                    SignedKeyActivationCommit::from_canonical_bytes(&mutated).test_unwrap();
                assert!(matches!(
                    WitnessedActivationSet::verify_complete(
                        &positive.events(),
                        &positive.checkpoints(),
                        &[candidate],
                        &keys.policy,
                    ),
                    Err(KeyringError::InvalidWitnessActivation)
                ));
            }
            "sync_consistency_path_tampered" => {
                assert_case_contract(
                    case,
                    "positive/key-log-sync-response-paged-v1.json",
                    "invalid_consistency_proof",
                );
                let error = verify_sync_page(&keys, &positive, &mutated).test_unwrap_err();
                assert!(matches!(
                    error,
                    KeyringError::Canonical(message)
                        if message == "merkle proof verification failed"
                ));
            }
            "receipt_tree_size_tampered" => {
                assert_case_contract(
                    case,
                    "positive/key-log-enterprise-receipt-envelope-active-v1.json",
                    "event_tree_size_binding",
                );
                let candidate: SignedKeyEnterpriseReceipt =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(matches!(
                    candidate.verify_against(
                        &positive.rotation,
                        &positive.witnessed_checkpoint,
                        &keys.policy,
                        Some(&positive.activation),
                    ),
                    Err(KeyringError::StateInvariant(_))
                ));
            }
            "receipt_operator_signature_tampered" => {
                assert_case_contract(
                    case,
                    "positive/key-log-enterprise-receipt-envelope-active-v1.json",
                    "invalid_operator_signature",
                );
                let candidate: SignedKeyEnterpriseReceipt =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(matches!(
                    candidate.verify_against(
                        &positive.rotation,
                        &positive.witnessed_checkpoint,
                        &keys.policy,
                        Some(&positive.activation),
                    ),
                    Err(KeyringError::InvalidSignature)
                ));
            }
            unexpected => panic!("unmapped schema-valid key-log mutation case: {unexpected}"),
        }
    }
    assert_eq!(rejected_ids, expected_ids);
}

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/bindings/vectors/security/key-log")
}

fn read_vector(relative: &str) -> Vec<u8> {
    std::fs::read(vector_root().join(relative)).test_unwrap()
}

fn load_event(relative: &str) -> SignedKeyLogEvent {
    let bytes = read_vector(relative);
    let event = SignedKeyLogEvent::from_canonical_envelope_bytes(&bytes).test_unwrap();
    assert_eq!(event.canonical_envelope_bytes().test_unwrap(), bytes);
    event
}

fn load_checkpoint(relative: &str) -> SignedKeyLogCheckpoint {
    let bytes = read_vector(relative);
    let checkpoint = SignedKeyLogCheckpoint::from_canonical_bytes(&bytes).test_unwrap();
    assert_eq!(canonical_json_bytes(&checkpoint).test_unwrap(), bytes);
    checkpoint
}

fn load_activation(relative: &str) -> SignedKeyActivationCommit {
    let bytes = read_vector(relative);
    let activation = SignedKeyActivationCommit::from_canonical_bytes(&bytes).test_unwrap();
    assert_eq!(activation.canonical_bytes().test_unwrap(), bytes);
    activation
}

fn load_receipt(relative: &str) -> SignedKeyEnterpriseReceipt {
    SignedKeyEnterpriseReceipt::from_canonical_bytes(&read_vector(relative)).test_unwrap()
}

fn verify_sync_page(
    keys: &DeterministicKeys,
    positive: &PositiveContext,
    page_bytes: &[u8],
) -> chio_keyring::Result<KeyLogPin> {
    let directory = tempfile::tempdir().map_err(KeyringError::Io)?;
    let verifier = SqlitePinnedKeyLogVerifier::provision(
        trusted_temp_path(&directory, "semantic-vector-verifier.sqlite"),
        keys.policy.clone(),
        Arc::new(FixedClock(3_000)),
    )?;
    let mut genesis_checkpoint = positive.genesis_checkpoint.clone();
    genesis_checkpoint.witness_signatures = vec![
        WitnessSignature::sign(
            &genesis_checkpoint,
            WitnessId::new("witness.a")?,
            &keys.witnesses[0],
        )?,
        WitnessSignature::sign(
            &genesis_checkpoint,
            WitnessId::new("witness.b")?,
            &keys.witnesses[1],
        )?,
    ];
    verifier.apply_sync(&KeyLogSyncResponse {
        base_checkpoint_hash: None,
        checkpoints: vec![genesis_checkpoint],
        event_envelopes: vec![positive.genesis.clone()],
        activation_commits: Vec::new(),
        consistency_proof: None,
    })?;
    let page = KeyLogSyncResponse::from_canonical_bytes(page_bytes)?;
    if canonical_json_bytes(&page)? != page_bytes {
        return Err(KeyringError::Canonical(
            "key-log synchronization vector is not canonical JSON".to_string(),
        ));
    }
    verifier.apply_sync(&page)
}

fn assert_case_contract(case: &MutationCase, base: &str, failure: &str) {
    assert_eq!(case.base, base, "case {} changed base", case.id);
    assert_eq!(
        case.expected.failure, failure,
        "case {} changed expected semantic boundary",
        case.id
    );
}

fn apply_mutation(case: &MutationCase) -> Vec<u8> {
    let mut bytes = read_vector(&case.base);
    match case.mutation.op.as_str() {
        "append_bytes" => {
            assert!(case.mutation.path.is_none(), "case {}", case.id);
            assert!(case.mutation.value.is_none(), "case {}", case.id);
            bytes.extend(decode_hex(
                case.mutation.hex.as_deref().test_expect("append_bytes hex"),
            ));
            bytes
        }
        "replace" => {
            assert!(case.mutation.hex.is_none(), "case {}", case.id);
            let mut document: Value = serde_json::from_slice(&bytes).test_unwrap();
            let path = case.mutation.path.as_deref().test_expect("replace path");
            let target = document
                .pointer_mut(path)
                .unwrap_or_else(|| panic!("case {} has missing path {path}", case.id));
            *target = case.mutation.value.clone().test_expect("replace value");
            canonical_json_bytes(&document).test_unwrap()
        }
        unsupported => panic!(
            "schema-valid case {} uses unsupported mutation operation {unsupported}",
            case.id
        ),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "odd-length hex mutation");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex mutation byte"),
    }
}
