use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::sync::Arc;

use chio_core_types::{canonical_json_bytes, Ed25519Backend, Keypair, SigningBackend};
use chio_keyring::{
    derive_key_id, AuthorityId, BootstrapAuthorization, EventId, EventReason,
    KeyEnterpriseReceiptOutcome, KeyEnterpriseReceiptStage, KeyLogAuthorizations, KeyLogEventBody,
    KeyLogOperation, KeyLogPolicy, KeyLogPolicyConfig, LogId, NewKeyProofOfPossession,
    OldKeyAuthorization, RecoveryPolicyId, SignedKeyEnterpriseReceipt, SignedKeyLogEvent,
    SigningTopology, SqliteKeyLogStore, TrustedClock, WitnessId, WitnessRosterId, WitnessSignature,
    KEY_LOG_EVENT_SCHEMA,
};
use serde_json::Value;

mod support;

use support::{private_tempdir, trusted_temp_path};

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

struct FixedClock(u64);

impl TrustedClock for FixedClock {
    fn now(&self) -> chio_keyring::Result<u64> {
        Ok(self.0)
    }
}

struct Fixture {
    bootstrap: Ed25519Backend,
    operator: Ed25519Backend,
    old: Ed25519Backend,
    witness_a: Ed25519Backend,
    witness_b: Ed25519Backend,
    witness_c: Ed25519Backend,
}

impl Fixture {
    fn new() -> Self {
        Self {
            bootstrap: backend(1),
            operator: backend(10),
            old: backend(2),
            witness_a: backend(20),
            witness_b: backend(21),
            witness_c: backend(22),
        }
    }

    fn policy(&self) -> KeyLogPolicy {
        KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: LogId::new("log.enterprise.receipt").test_unwrap(),
            authority_id: AuthorityId::new("authority.enterprise.receipt").test_unwrap(),
            bootstrap_key: self.bootstrap.public_key(),
            operator_key: self.operator.public_key(),
            witness_roster_id: WitnessRosterId::new("roster.enterprise.receipt.v1").test_unwrap(),
            witness_keys: BTreeMap::from([
                (
                    WitnessId::new("witness.a").test_unwrap(),
                    self.witness_a.public_key(),
                ),
                (
                    WitnessId::new("witness.b").test_unwrap(),
                    self.witness_b.public_key(),
                ),
                (
                    WitnessId::new("witness.c").test_unwrap(),
                    self.witness_c.public_key(),
                ),
            ]),
            recovery_policy_id: RecoveryPolicyId::new("recovery.enterprise.receipt.v1")
                .test_unwrap(),
            recovery_keys: BTreeMap::new(),
            recovery_threshold: 0,
            max_checkpoint_future_skew: 100,
        })
        .test_unwrap()
    }

    fn genesis(&self) -> SignedKeyLogEvent {
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: LogId::new("log.enterprise.receipt").test_unwrap(),
            sequence: 0,
            event_id: EventId::new("event.receipt.genesis").test_unwrap(),
            previous_event_hash: None,
            authority_id: AuthorityId::new("authority.enterprise.receipt").test_unwrap(),
            key_id: derive_key_id(self.old.algorithm(), &self.old.public_key()).test_unwrap(),
            algorithm: self.old.algorithm(),
            public_key: self.old.public_key(),
            operation: KeyLogOperation::Genesis,
            effective_at: 1_000,
            verify_until: None,
            reason: Some(EventReason::new("receipt-secret-canary-7a9e").test_unwrap()),
            issued_at: 1_000,
        };
        SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::bootstrap(
                BootstrapAuthorization::sign(&body, &self.bootstrap).test_unwrap(),
            ),
            body,
        }
    }

    fn rotation(&self, genesis: &SignedKeyLogEvent, new: &Ed25519Backend) -> SignedKeyLogEvent {
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: genesis.body.log_id.clone(),
            sequence: 1,
            event_id: EventId::new("event.receipt.rotation").test_unwrap(),
            previous_event_hash: Some(genesis.envelope_hash().test_unwrap()),
            authority_id: genesis.body.authority_id.clone(),
            key_id: derive_key_id(new.algorithm(), &new.public_key()).test_unwrap(),
            algorithm: new.algorithm(),
            public_key: new.public_key(),
            operation: KeyLogOperation::Rotate {
                previous_key_id: genesis.body.key_id,
                witness_roster_id: WitnessRosterId::new("roster.enterprise.receipt.v1")
                    .test_unwrap(),
                witness_roster_binding: self.policy().witness_roster_binding().test_unwrap(),
            },
            effective_at: 2_000,
            verify_until: Some(9_000),
            reason: Some(EventReason::new("witnessed receipt rotation").test_unwrap()),
            issued_at: 2_000,
        };
        SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::rotation(
                OldKeyAuthorization::sign(&body, &self.old).test_unwrap(),
                NewKeyProofOfPossession::sign(&body, new).test_unwrap(),
            ),
            body,
        }
    }
}

#[test]
fn production_store_emits_pending_and_active_enterprise_receipts_atomically() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "enterprise-receipts.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let store = SqliteKeyLogStore::open_with_clock(
        &path,
        policy.clone(),
        SigningTopology::LocalSingleWriter,
        Arc::new(FixedClock(3_000)),
    )
    .test_unwrap();
    let genesis = fixture.genesis();
    let new = backend(3);
    let rotation = fixture.rotation(&genesis, &new);

    let genesis_checkpoint = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let receipts = store.load_enterprise_receipts().test_unwrap();
    assert_eq!(receipts.len(), 1);
    let genesis_pending = &receipts[0];
    assert_eq!(
        genesis_pending.body.stage,
        KeyEnterpriseReceiptStage::Pending
    );
    assert_eq!(
        genesis_pending.body.outcome,
        KeyEnterpriseReceiptOutcome::PendingCommitted
    );
    assert!(genesis_pending.body.source_receipt_ids.is_empty());
    genesis_pending
        .verify_against(&genesis, &genesis_checkpoint, &policy, None)
        .test_unwrap();

    let rotation_checkpoint = store
        .append_event(&rotation, &fixture.operator)
        .test_unwrap();
    let receipts = store.load_enterprise_receipts().test_unwrap();
    assert_eq!(receipts.len(), 2);
    let rotation_pending = &receipts[1];
    assert_eq!(
        rotation_pending.body.source_receipt_ids,
        vec![genesis_pending.body.receipt_id.clone()]
    );
    assert_eq!(
        rotation_pending.body.event_envelope_hash,
        rotation.envelope_hash().test_unwrap()
    );
    assert_eq!(
        rotation_pending.body.checkpoint_hash,
        rotation_checkpoint.checkpoint_hash().test_unwrap()
    );
    rotation_pending
        .verify_against(&rotation, &rotation_checkpoint, &policy, None)
        .test_unwrap();

    let checkpoint_hash = rotation_checkpoint.checkpoint_hash().test_unwrap();
    for (witness_id, witness) in [
        ("witness.a", &fixture.witness_a),
        ("witness.b", &fixture.witness_b),
    ] {
        store
            .store_witness_signature(
                &checkpoint_hash,
                &WitnessSignature::sign(
                    &rotation_checkpoint,
                    WitnessId::new(witness_id).test_unwrap(),
                    witness,
                )
                .test_unwrap(),
            )
            .test_unwrap();
    }
    store
        .activate_rotation(&rotation.body.event_id, &checkpoint_hash, &fixture.operator)
        .test_unwrap();

    let receipts = store.load_enterprise_receipts().test_unwrap();
    assert_eq!(receipts.len(), 3);
    let active = &receipts[2];
    let synchronization = store.synchronization_response(None).test_unwrap();
    let activation = synchronization.activation_commits.last().test_unwrap();
    let witnessed_checkpoint = store
        .load_checkpoints()
        .test_unwrap()
        .pop()
        .test_unwrap()
        .checkpoint;
    assert_eq!(active.body.stage, KeyEnterpriseReceiptStage::Active);
    assert_eq!(active.body.outcome, KeyEnterpriseReceiptOutcome::Activated);
    assert_eq!(
        active.body.transaction_id,
        rotation_pending.body.transaction_id
    );
    assert_eq!(
        active.body.source_receipt_ids,
        vec![rotation_pending.body.receipt_id.clone()]
    );
    assert_eq!(active.body.witness_signatures.len(), 2);
    assert_eq!(active.body.signing_epoch, Some(1));
    active
        .verify_against(&rotation, &witnessed_checkpoint, &policy, Some(activation))
        .test_unwrap();

    let retry = store
        .activate_rotation(&rotation.body.event_id, &checkpoint_hash, &fixture.operator)
        .test_unwrap();
    assert_eq!(retry.signing_epoch(), 1);
    assert_eq!(store.load_enterprise_receipts().test_unwrap(), receipts);

    drop(store);
    let reopened = SqliteKeyLogStore::open(&path, policy).test_unwrap();
    assert_eq!(reopened.load_enterprise_receipts().test_unwrap(), receipts);
}

#[test]
fn enterprise_receipt_is_canonical_secret_free_and_rejects_every_leaf_tamper() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "enterprise-receipt-tamper.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let store = SqliteKeyLogStore::open_with_clock(
        &path,
        policy.clone(),
        SigningTopology::LocalSingleWriter,
        Arc::new(FixedClock(3_000)),
    )
    .test_unwrap();
    let event = fixture.genesis();
    let checkpoint = store.append_event(&event, &fixture.operator).test_unwrap();
    let receipt = store.load_enterprise_receipts().test_unwrap().remove(0);

    let canonical = receipt.canonical_bytes().test_unwrap();
    assert_eq!(canonical, canonical_json_bytes(&receipt).test_unwrap());
    assert_eq!(
        SignedKeyEnterpriseReceipt::from_canonical_bytes(&canonical).test_unwrap(),
        receipt
    );
    let pretty = serde_json::to_vec_pretty(&receipt).test_unwrap();
    assert!(SignedKeyEnterpriseReceipt::from_canonical_bytes(&pretty).is_err());
    assert!(!String::from_utf8(canonical.clone())
        .test_unwrap()
        .contains("receipt-secret-canary-7a9e"));

    let document = serde_json::to_value(&receipt).test_unwrap();
    let mutations = mutate_every_leaf(&document);
    assert_eq!(mutations.len(), terminal_leaf_count(&document));
    assert!(!mutations.is_empty());
    for mutation in mutations {
        let encoded = canonical_json_bytes(&mutation).test_unwrap();
        if let Ok(candidate) = SignedKeyEnterpriseReceipt::from_canonical_bytes(&encoded) {
            assert!(
                candidate
                    .verify_against(&event, &checkpoint, &policy, None)
                    .is_err(),
                "mutated receipt was accepted: {}",
                serde_json::to_string(&mutation).test_unwrap()
            );
        }
    }
}

fn mutate_every_leaf(value: &Value) -> Vec<Value> {
    let mut mutations = Vec::new();
    collect_leaf_mutations(value, &mut Vec::new(), &mut mutations);
    mutations
}

fn terminal_leaf_count(value: &Value) -> usize {
    match value {
        Value::Object(fields) if !fields.is_empty() => {
            fields.values().map(terminal_leaf_count).sum()
        }
        Value::Array(items) if !items.is_empty() => items.iter().map(terminal_leaf_count).sum(),
        _ => 1,
    }
}

#[derive(Clone, Copy)]
enum Segment<'a> {
    Key(&'a str),
    Index(usize),
}

fn collect_leaf_mutations<'a>(
    root: &'a Value,
    path: &mut Vec<Segment<'a>>,
    output: &mut Vec<Value>,
) {
    let current = value_at(root, path);
    match current {
        Value::Object(fields) if !fields.is_empty() => {
            for key in fields.keys() {
                path.push(Segment::Key(key));
                collect_leaf_mutations(root, path, output);
                path.pop();
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for index in 0..items.len() {
                path.push(Segment::Index(index));
                collect_leaf_mutations(root, path, output);
                path.pop();
            }
        }
        _ => {
            let mut mutation = root.clone();
            *value_at_mut(&mut mutation, path) = mutate_scalar(current);
            output.push(mutation);
        }
    }
}

fn value_at<'a>(root: &'a Value, path: &[Segment<'_>]) -> &'a Value {
    let mut current = root;
    for segment in path {
        current = match segment {
            Segment::Key(key) => &current[*key],
            Segment::Index(index) => &current[*index],
        };
    }
    current
}

fn value_at_mut<'a>(root: &'a mut Value, path: &[Segment<'_>]) -> &'a mut Value {
    let mut current = root;
    for segment in path {
        current = match segment {
            Segment::Key(key) => current.get_mut(*key).test_unwrap(),
            Segment::Index(index) => current.get_mut(*index).test_unwrap(),
        };
    }
    current
}

fn mutate_scalar(value: &Value) -> Value {
    match value {
        Value::String(text) => {
            let mut bytes = text.as_bytes().to_vec();
            if let Some(last) = bytes.last_mut() {
                *last = if *last == b'a' { b'b' } else { b'a' };
            } else {
                bytes.push(b'a');
            }
            Value::String(String::from_utf8(bytes).test_unwrap())
        }
        Value::Number(number) => Value::from(number.as_u64().test_unwrap().saturating_add(1)),
        Value::Bool(value) => Value::Bool(!value),
        Value::Null => Value::String("unexpected".to_string()),
        Value::Array(_) => Value::Array(vec![Value::Null]),
        Value::Object(_) => Value::Object(serde_json::Map::from_iter([(
            "unexpected".to_string(),
            Value::Bool(true),
        )])),
    }
}
