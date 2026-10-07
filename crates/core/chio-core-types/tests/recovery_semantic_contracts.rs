//! Finite local schema and native typed/cryptographic semantic wire conformance.
use chio_core_types::recovery::*;
use chio_security_types::{recovery::*, semantic::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize)]
struct Corpus {
    format_version: u8,
    vectors: Vec<Vector>,
}
#[derive(Deserialize)]
struct Vector {
    name: String,
    schema: String,
    wire: String,
    valid: bool,
    schema_valid: bool,
}
fn typed<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> bool {
    decode_contract::<T>(bytes).is_ok()
}
fn accepts(schema: &str, bytes: &[u8]) -> bool {
    match schema {
        "semantic-package.schema.json" => typed::<SemanticPackageV1>(bytes),
        "semantic-deployment.schema.json" => typed::<SemanticDeploymentV1>(bytes),
        "semantic-action.schema.json" => typed::<SemanticActionV1>(bytes),
        "semantic-payload.schema.json" => typed::<SemanticPayloadV1>(bytes),
        "semantic-plan.schema.json" => typed::<SemanticPlanV1>(bytes),
        "semantic-audience.schema.json" => typed::<SemanticAudienceObservationV1>(bytes),
        "scoped-endorsement.schema.json" => typed::<ScopedEndorsementV1>(bytes),
        "semantic-annotation.schema.json" => typed::<SemanticAnnotationV1>(bytes),
        "semantic-transformation.schema.json" => typed::<SemanticTransformationV1>(bytes),
        "semantic-prerequisite.schema.json" => typed::<SemanticPrerequisiteV1>(bytes),
        "semantic-invocation.schema.json" => typed::<SemanticInvocationV1>(bytes),
        "semantic-provider-request.schema.json" => typed::<SemanticProviderRequestV1>(bytes),
        "semantic-provider-response.schema.json" => typed::<SemanticProviderResponseV1>(bytes),
        "signed-semantic-package.schema.json" => decode_contract::<SignedSemanticPackageV1>(bytes)
            .is_ok_and(|p| p.verify_signature().is_ok_and(|v| v)),
        "signed-semantic-deployment.schema.json" => {
            decode_contract::<SignedSemanticDeploymentV1>(bytes)
                .is_ok_and(|p| p.verify_signature().is_ok_and(|v| v))
        }
        "signed-semantic-audience.schema.json" => {
            decode_contract::<SignedSemanticAudienceV1>(bytes)
                .is_ok_and(|p| p.verify_signature().is_ok_and(|v| v))
        }
        "signed-scoped-endorsement.schema.json" => {
            decode_contract::<SignedScopedEndorsementV1>(bytes)
                .is_ok_and(|p| p.verify_signature().is_ok_and(|v| v))
        }
        "signed-semantic-annotation.schema.json" => {
            decode_contract::<SignedSemanticAnnotationV1>(bytes)
                .is_ok_and(|p| p.verify_signature().is_ok_and(|v| v))
        }
        "signed-semantic-transformation.schema.json" => {
            decode_contract::<SignedSemanticTransformationV1>(bytes)
                .is_ok_and(|p| p.verify_signature().is_ok_and(|v| v))
        }
        "signed-semantic-prerequisite.schema.json" => {
            decode_contract::<SignedSemanticPrerequisiteV1>(bytes)
                .is_ok_and(|p| p.verify_signature().is_ok_and(|v| v))
        }
        _ => false,
    }
}
#[test]
fn shared_closed_wire_and_role_signature_corpus() -> Result {
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
            for domain in ["chio.computer", "chio.world", "chio-protocol.dev"] {
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
                    .ok_or("filename")?
                    .to_string_lossy()
                    .into_owned(),
                value,
            );
        }
    }
    let registry = registry.prepare()?;
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/semantic-contracts.json"
    ))?;
    assert_eq!(corpus.format_version, 1);
    for vector in corpus.vectors {
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&schemas[&vector.schema])?;
        assert_eq!(
            validator.is_valid(&serde_json::from_str::<Value>(&vector.wire)?),
            vector.schema_valid,
            "schema: {}",
            vector.name
        );
        assert_eq!(
            accepts(&vector.schema, vector.wire.as_bytes()),
            vector.valid,
            "typed/crypto: {}",
            vector.name
        );
    }
    Ok(())
}
#[test]
fn ingress_bounds_and_private_diagnostics() -> Result {
    let oversized = vec![b' '; MAX_RECOVERY_WIRE_BYTES + 1];
    assert!(decode_contract::<SemanticInvocationV1>(&oversized).is_err());
    let depth = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    assert!(decode_contract::<SemanticInvocationV1>(depth.as_bytes()).is_err());
    let payload = SemanticPayloadV1 {
        fields: NonEmptyBoundedList::new(vec![SemanticFieldV1 {
            field: SemanticFieldId::new("body")?,
            value: SemanticValueV1::Text {
                value: ProtectedText::new("private-debug-canary")?,
            },
        }])?,
    };
    assert!(!format!("{payload:?}").contains("private-debug-canary"));
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/semantic-contracts.json"
    ))?;
    let value = corpus["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .find(|case| case["schema"] == "signed-scoped-endorsement.schema.json")
        .ok_or("endorsement")?;
    let signed: SignedScopedEndorsementV1 = serde_json::from_value(value["value"].clone())?;
    let mut wrong = RECOVERY_GRANT_SIGNATURE_DOMAIN.as_bytes().to_vec();
    wrong.push(0);
    wrong.extend(chio_core_types::canonical_json_bytes(signed.body())?);
    assert!(signed.verify_signature()?);
    assert!(!signed.authority_key().verify(&wrong, signed.signature()));
    Ok(())
}
