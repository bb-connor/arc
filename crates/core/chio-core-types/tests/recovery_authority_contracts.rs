//! Actual native fixture bytes shared with the Python and TypeScript bindings.
use chio_core_types::{canonical_json_bytes, recovery::*};
use chio_security_types::recovery::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[path = "../../../tooling/chio-spec-validate/src/utf8_bytes.rs"]
mod utf8_bytes;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const POSITIVE: &str = include_str!("../../../../spec/vectors/recovery/v1/authority-positive.json");
const CORPUS: &str = include_str!("../../../../spec/vectors/recovery/v1/authority-contracts.json");
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
        "action" => typed::<ActionIntentV1>(bytes),
        "requirements" => typed::<AuthorizationRequirementsV1>(bytes),
        "grant_binding" => typed::<RecoveryGrantBindingV1>(bytes),
        "approval_intent" => typed::<ApprovalIntentV1>(bytes),
        "command" => typed::<RecoveryCommandV1>(bytes),
        "support_issue_input" => typed::<RecoverySupportIssueInputV1>(bytes),
        "provider_body" => typed::<RecoveryProviderFinalityV1>(bytes),
        "grant" => decode_contract::<SignedRecoveryGrantV2>(bytes)
            .is_ok_and(|grant| grant.verify_signature().is_ok_and(|valid| valid)),
        "coverage" => decode_contract::<SignedAuthorityCoverageAttestationV1>(bytes)
            .is_ok_and(|proof| proof.verify_signature().is_ok_and(|valid| valid)),
        "provider_finality" => decode_contract::<SignedRecoveryProviderFinalityV1>(bytes)
            .is_ok_and(|proof| proof.verify_signature().is_ok_and(|valid| valid)),
        _ => typed::<Value>(bytes),
    }
}
fn schema_name(kind: &str) -> &str {
    match kind {
        "action" => "action-intent",
        "requirements" => "authorization-requirements",
        "grant_binding" => "grant-binding",
        "approval_intent" => "approval-intent",
        "grant" => "signed-grant-v2",
        "coverage" => "signed-authority-coverage",
        "provider_finality" => "signed-provider-finality",
        "provider_body" => "provider-finality",
        name => name,
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
            .with_keyword("x-maxUtf8Bytes", utf8_bytes::keyword)
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
#[test]
fn recovery_version_selection_preserves_legacy_bytes_and_refuses_downgrade() -> Result {
    let positive: Value = serde_json::from_str(POSITIVE)?;
    let action: ActionIntentV1 = serde_json::from_value(positive["action"].clone())?;
    assert!(action.origin.is_some());
    let preview: Vec<Value> = serde_json::from_str(
        positive["review_document"]["canonical_preview"]
            .as_str()
            .ok_or("native review preview")?,
    )?;
    assert_eq!(
        preview.first().ok_or("native review action")?["origin"],
        serde_json::to_value(&action.origin)?
    );
    let signed: SignedRecoveryGrantV2 = serde_json::from_value(positive["grant"].clone())?;
    assert!(signed.verify_signature()?);
    let key = chio_core_types::Keypair::from_seed(&[143; 32]);
    let legacy =
        chio_core_types::SignedDeclassificationGrant::sign(signed.body().claims.clone(), &key)?;
    let bytes = canonical_json_bytes(&legacy)?;
    let selected: SignedDisclosureGrant = decode_contract(&bytes)?;
    assert!(selected.legacy_v1().is_some());
    assert!(selected.recovery_v2().is_none());
    assert_eq!(bytes, canonical_json_bytes(&selected)?);
    let v2: SignedDisclosureGrant = signed.clone().into();
    assert_eq!(
        decode_contract::<SignedDisclosureGrant>(&canonical_json_bytes(&v2)?)?,
        v2
    );
    assert!(
        serde_json::from_value::<chio_core_types::SignedDeclassificationGrant>(
            serde_json::to_value(&v2)?
        )
        .is_err()
    );
    for value in [
        serde_json::json!({"kind":null,"grant":signed}),
        serde_json::json!({"grant":signed}),
        serde_json::json!({"kind":"recovery_v2","grant":null}),
        serde_json::json!({"kind":"unknown","grant":signed}),
    ] {
        assert!(decode_contract::<SignedDisclosureGrant>(&canonical_json_bytes(&value)?).is_err());
    }
    let mut swapped = serde_json::to_value(&signed)?;
    swapped["signature"] = serde_json::to_value(legacy.signature())?;
    let swapped: SignedRecoveryGrantV2 = serde_json::from_value(swapped)?;
    assert!(!swapped.verify_signature()?);
    let proof: SignedAuthorityCoverageAttestationV1 =
        serde_json::from_value(positive["coverage"][0].clone())?;
    assert!(proof.verify_signature()?);
    assert!(signed
        .signing_bytes()?
        .starts_with(b"chio:declassification-grant:v2\0"));
    assert!(proof
        .signing_bytes()?
        .starts_with(b"chio:recovery-authority-coverage:v1\0"));
    assert!(!format!("{signed:?}").contains("private-canary"));
    Ok(())
}

#[test]
fn recovery_original_claim_preserves_legacy_action_bytes_and_closed_shape() -> Result {
    // A retained old action is independent of current native-vector exports.
    const LEGACY: &[u8] =
        include_bytes!("../../../../spec/vectors/recovery/v1/legacy-action-intent.json");
    assert_eq!(
        chio_core_types::sha256_hex(LEGACY),
        "d081b668d7da2bf01de9e53e4eed6d7782e3e91532eb47575bb24adad2dff3ee"
    );
    let mut action: ActionIntentV1 = decode_contract(LEGACY)?;
    assert!(action.origin.is_none());
    assert_eq!(canonical_json_bytes(&action)?, LEGACY);
    action.origin = Some(RecoveryOriginV1 {
        operation: OperationRef::new(
            OperationId::new("original-native-operation")?,
            NativeAdmissionDigest::from_bytes([41; 32]),
            SafeInteger::new(1)?,
        )?,
        request_id: RequestId::new("original-process-request")?,
        closure: EvidenceRef::new("closure:original-native-operation")?,
    });
    let wire = canonical_json_bytes(&action)?;
    assert_eq!(decode_contract::<ActionIntentV1>(&wire)?, action);
    for mutation in 0..4 {
        let mut value = serde_json::to_value(&action)?;
        match mutation {
            0 => value["origin"]["operation"]["operation_version"] = 0.into(),
            1 => value["origin"]["request_id"] = "foreign whitespace".into(),
            2 => value["origin"]["claimed_authority"] = true.into(),
            _ => value["origin"] = Value::Null,
        }
        assert!(decode_contract::<ActionIntentV1>(&canonical_json_bytes(&value)?).is_err());
    }
    Ok(())
}
