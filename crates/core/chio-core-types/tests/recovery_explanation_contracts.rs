//! Actual native fixture bytes shared with the Python and TypeScript bindings.
use chio_core_types::recovery::*;
use chio_security_types::recovery::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const CORPUS: &str =
    include_str!("../../../../spec/vectors/recovery/v1/explanation-contracts.json");
#[derive(Deserialize)]
struct Corpus {
    format_version: u8,
    vectors: Vec<Vector>,
}
#[derive(Deserialize)]
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
            .is_ok_and(|p| p.verify_signature().is_ok_and(|valid| valid)),
        "signed_view" => decode_contract::<SignedRecoveryExplanationViewV1>(bytes)
            .is_ok_and(|p| p.verify_signature().is_ok_and(|valid| valid)),
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
            for domain in ["chio.computer", "chio.world"] {
                let file_id = format!(
                    "https://{domain}/schemas/chio-wire/v1/{}",
                    path.strip_prefix(&root)?.to_string_lossy()
                );
                if id != file_id {
                    registry = registry.add(&file_id, value.clone())?;
                }
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
