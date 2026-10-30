//! Actual native fixture bytes shared with the Python and TypeScript bindings.
use chio_core_types::recovery::*;
use chio_core_types::{canonical_json_bytes, Keypair};
use chio_security_types::recovery::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const CORPUS: &str =
    include_str!("../../../../spec/vectors/recovery/v1/explanation-contracts.json");
/// Seed of the advisory authority that signs every signed vector.
const ADVISORY_AUTHORITY_SEED: [u8; 32] = [52; 32];
#[derive(Deserialize, Serialize)]
struct Corpus {
    format_version: u8,
    vectors: Vec<Vector>,
}
#[derive(Deserialize, Serialize)]
struct Vector {
    name: String,
    contract: String,
    valid: bool,
    schema_valid: bool,
    wire: String,
}
fn typed<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> bool {
    decode_contract::<T>(bytes).is_ok()
}
fn accepts(kind: &str, bytes: &[u8]) -> bool {
    match kind {
        "snapshot" => typed::<RecoverySnapshotV1>(bytes),
        "registry" => typed::<RecoveryRemedyRegistryV1>(bytes),
        "evaluation" => typed::<RecoveryExplanationEvaluationV1>(bytes),
        "report" => typed::<RecoveryExplanationReportV1>(bytes),
        "view" => typed::<RecoveryExplanationViewV1>(bytes),
        "signed_report" => decode_contract::<SignedRecoveryExplanationReportV1>(bytes)
            .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|valid| valid)),
        "signed_view" => decode_contract::<SignedRecoveryExplanationViewV1>(bytes)
            .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|valid| valid)),
        _ => false,
    }
}
fn schema_name(kind: &str) -> &str {
    match kind {
        "snapshot" => "explanation-snapshot",
        "registry" => "remedy-registry",
        "evaluation" => "explanation-evaluation",
        "report" => "explanation-report",
        "view" => "explanation-view",
        "signed_report" => "signed-explanation-report",
        "signed_view" => "signed-explanation-view",
        _ => "unknown",
    }
}

#[test]
fn recovery_shared_closed_wire_and_signature_corpus() -> Result {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1");
    let mut registry = jsonschema::Registry::new();
    let mut schemas = std::collections::BTreeMap::new();
    for group in std::fs::read_dir(&root)? {
        let group = group?;
        if !group.file_type()?.is_dir() {
            continue;
        }
        for path in std::fs::read_dir(group.path())? {
            let path = path?.path();
            if !path.to_string_lossy().ends_with(".schema.json") {
                continue;
            }
            let value: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            let Some(id) = value["$id"].as_str().map(str::to_owned) else {
                continue;
            };
            registry = registry.add(&id, value.clone())?;
            let file_id = format!(
                "https://chio.world/schemas/chio-wire/v1/{}",
                path.strip_prefix(&root)?.to_string_lossy()
            );
            if id != file_id {
                registry = registry.add(&file_id, value.clone())?;
            }
            schemas.insert(
                path.file_name()
                    .ok_or("schema filename")?
                    .to_string_lossy()
                    .into_owned(),
                value,
            );
        }
    }
    let registry = registry.prepare()?;
    let corpus: Corpus = serde_json::from_str(CORPUS)?;
    assert_eq!(corpus.format_version, 1);
    for vector in corpus.vectors {
        let schema = &schemas[&format!(
            "{}.schema.json",
            schema_name(&vector.contract).replace('_', "-")
        )];
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(schema)?;
        let shape = validator.is_valid(&serde_json::from_str::<Value>(&vector.wire)?);
        assert_eq!(shape, vector.schema_valid, "shape: {}", vector.name);
        assert_eq!(
            shape && accepts(&vector.contract, vector.wire.as_bytes()),
            vector.valid,
            "typed/crypto: {}",
            vector.name
        );
    }
    Ok(())
}

fn wire_of(value: &Value) -> Result<String> {
    Ok(String::from_utf8(canonical_json_bytes(value)?)?)
}

fn signed_wire<T, S>(
    corpus: &Corpus,
    unsigned: &str,
    sign: impl Fn(T, &Keypair) -> chio_core_types::Result<S>,
) -> Result<Value>
where
    T: serde::de::DeserializeOwned + Serialize,
    S: Serialize,
{
    let positive = corpus
        .vectors
        .iter()
        .find(|vector| vector.name == format!("{unsigned}-positive"))
        .ok_or("unsigned positive vector")?;
    let body = decode_contract::<T>(positive.wire.as_bytes())?;
    let key = Keypair::from_seed(&ADVISORY_AUTHORITY_SEED);
    Ok(serde_json::to_value(sign(body, &key)?)?)
}

/// The signed vectors are derived from the unsigned positive and
/// unknown-version vectors of the same contract; every other vector is input.
fn shared_vectors() -> Result<Corpus> {
    let mut corpus: Corpus = serde_json::from_str(CORPUS)?;
    let report = signed_wire(&corpus, "report", SignedRecoveryExplanationReportV1::sign)?;
    let view = signed_wire(&corpus, "view", SignedRecoveryExplanationViewV1::sign)?;
    let unknown_version_body = |unsigned: &str| -> Result<Value> {
        let vector = corpus
            .vectors
            .iter()
            .find(|vector| vector.name == format!("{unsigned}-unknown-version"))
            .ok_or("unsigned unknown-version vector")?;
        Ok(serde_json::from_str(&vector.wire)?)
    };
    let report_unknown_version = unknown_version_body("report")?;
    let view_unknown_version = unknown_version_body("view")?;
    for vector in &mut corpus.vectors {
        let (positive, unknown_version) = match vector.contract.as_str() {
            "signed_report" => (&report, &report_unknown_version),
            "signed_view" => (&view, &view_unknown_version),
            _ => continue,
        };
        let mut wire = positive.clone();
        let mutation = vector
            .name
            .strip_prefix(&format!("{}-", vector.contract))
            .ok_or("signed vector name")?;
        match mutation {
            "positive" => {}
            "unknown-field" => wire["unknown"] = Value::String("private-canary".to_string()),
            "unknown-version" => wire["body"] = unknown_version.clone(),
            "wrong-signature" => wire["signature"] = Value::String("0".repeat(128)),
            _ => return Err(format!("unknown signed vector {}", vector.name).into()),
        }
        vector.wire = wire_of(&wire)?;
    }
    Ok(corpus)
}

fn corpus_bytes(corpus: &Corpus) -> Result<String> {
    Ok(serde_json::to_string_pretty(corpus)? + "\n")
}

#[test]
fn signed_vectors_match_the_generator_output() -> Result {
    assert_eq!(corpus_bytes(&shared_vectors()?)?, CORPUS);
    Ok(())
}

#[test]
#[ignore = "explicit regeneration of the shared native explanation contract corpus"]
fn write_shared_vectors() -> Result {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_EXPLANATION_VECTOR_OUT").ok_or("explicit vector output required")?,
    );
    std::fs::write(path, corpus_bytes(&shared_vectors()?)?)?;
    Ok(())
}
