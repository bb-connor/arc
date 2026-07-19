use std::{fs, path::Path, path::PathBuf};

use chio_core_types::{canonical_json_bytes, Keypair, SignedDeclassificationGrant};
use chio_test_support::prelude::*;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Corpus {
    positive: PositiveCase,
    negative: Vec<NegativeCase>,
}

#[derive(Deserialize)]
struct PositiveCase {
    signing_seed_hex: String,
    canonical_body_json: String,
    grant: Value,
}

#[derive(Deserialize)]
struct NegativeCase {
    id: String,
    operations: Vec<Mutation>,
    expected_schema_valid: bool,
    expected_signature_valid: bool,
}

#[derive(Deserialize)]
struct Mutation {
    op: String,
    path: String,
    value: Option<Value>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .test_expect("repo root")
}

fn load_json(path: PathBuf) -> Value {
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn corpus() -> Corpus {
    let path = repo_root().join("tests/bindings/vectors/declassification/v1.json");
    serde_json::from_value(load_json(path)).test_expect("declassification corpus")
}

struct Validator {
    path: PathBuf,
    schema: Value,
}

impl Validator {
    fn is_valid(&self, value: &Value) -> bool {
        chio_spec_validate::validate_value(
            &self.path,
            &self.schema,
            Path::new("<declassification-vector>"),
            value,
        )
        .is_ok()
    }
}

fn validator() -> Validator {
    let path =
        repo_root().join("spec/schemas/chio-wire/v1/security/declassification-grant.schema.json");
    Validator {
        schema: load_json(path.clone()),
        path,
    }
}

fn mutate(value: &mut Value, mutation: &Mutation) {
    match mutation.op.as_str() {
        "remove" => {
            let (parent, leaf) = mutation
                .path
                .rsplit_once('/')
                .unwrap_or_else(|| panic!("invalid remove pointer {}", mutation.path));
            let parent = value
                .pointer_mut(parent)
                .unwrap_or_else(|| panic!("missing remove parent {parent}"));
            let object = parent
                .as_object_mut()
                .unwrap_or_else(|| panic!("remove parent is not an object"));
            assert!(object.remove(leaf).is_some(), "missing remove leaf {leaf}");
        }
        "set" => {
            let replacement = mutation
                .value
                .clone()
                .unwrap_or_else(|| panic!("set mutation lacks value: {}", mutation.path));
            if let Some(slot) = value.pointer_mut(&mutation.path) {
                *slot = replacement;
                return;
            }
            let (parent, leaf) = mutation
                .path
                .rsplit_once('/')
                .unwrap_or_else(|| panic!("invalid set pointer {}", mutation.path));
            value
                .pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .unwrap_or_else(|| panic!("missing set parent {parent}"))
                .insert(leaf.to_string(), replacement);
        }
        other => panic!("unsupported mutation {other}"),
    }
}

#[test]
fn shared_positive_vector_matches_schema_rust_wire_and_signature() {
    let corpus = corpus();
    let validator = validator();
    assert!(validator.is_valid(&corpus.positive.grant));

    let grant: SignedDeclassificationGrant =
        serde_json::from_value(corpus.positive.grant).test_expect("grant decodes");
    assert!(grant.verify_signature().test_expect("signature verifies"));
    assert_eq!(
        String::from_utf8(canonical_json_bytes(grant.body()).test_expect("canonical body"))
            .test_expect("canonical body UTF-8"),
        corpus.positive.canonical_body_json
    );

    let seed = hex::decode(&corpus.positive.signing_seed_hex).test_expect("seed hex");
    let seed: [u8; 32] = seed.try_into().test_expect("32-byte seed");
    let resigned =
        SignedDeclassificationGrant::sign(grant.body().clone(), &Keypair::from_seed(&seed))
            .test_expect("grant resigns");
    assert_eq!(resigned, grant);
}

#[test]
fn shared_negative_vectors_fail_at_the_declared_boundary() {
    let corpus = corpus();
    let validator = validator();
    for case in corpus.negative {
        let mut candidate = corpus.positive.grant.clone();
        for operation in &case.operations {
            mutate(&mut candidate, operation);
        }
        assert_eq!(
            validator.is_valid(&candidate),
            case.expected_schema_valid,
            "schema verdict for {}",
            case.id
        );
        let signature_valid = serde_json::from_value::<SignedDeclassificationGrant>(candidate)
            .ok()
            .and_then(|grant| grant.verify_signature().ok())
            .unwrap_or(false);
        assert_eq!(
            signature_valid, case.expected_signature_valid,
            "signature verdict for {}",
            case.id
        );
    }
}
