//! Recovery authority vectors shared with the Python and TypeScript bindings.
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
        "grant" => decode_contract::<SignedRecoveryGrant>(bytes)
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
        "grant" => "signed-recovery-grant",
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
fn disclosure_grants_select_their_shape_by_kind() -> Result {
    let positive: Value = serde_json::from_str(POSITIVE)?;
    let action: ActionIntentV1 = serde_json::from_value(positive["action"].clone())?;
    let preview: Vec<Value> = serde_json::from_str(
        positive["review_document"]["canonical_preview"]
            .as_str()
            .ok_or("native review preview")?,
    )?;
    assert_eq!(
        preview.first().ok_or("native review action")?["origin"],
        serde_json::to_value(&action.origin)?
    );
    let signed: SignedRecoveryGrant = serde_json::from_value(positive["grant"].clone())?;
    assert!(signed.verify_signature()?);
    let key = chio_core_types::Keypair::from_seed(&[143; 32]);
    let declassification =
        chio_core_types::SignedDeclassificationGrant::sign(signed.body().claims.clone(), &key)?;
    let bytes = canonical_json_bytes(&declassification)?;
    let selected: SignedDisclosureGrant = decode_contract(&bytes)?;
    assert!(selected.declassification().is_some());
    assert!(selected.recovery().is_none());
    assert_eq!(bytes, canonical_json_bytes(&selected)?);
    let recovery: SignedDisclosureGrant = signed.clone().into();
    assert_eq!(
        decode_contract::<SignedDisclosureGrant>(&canonical_json_bytes(&recovery)?)?,
        recovery
    );
    assert_eq!(
        positive["request"]["declassification_grant"],
        serde_json::to_value(&recovery)?
    );
    assert!(
        serde_json::from_value::<chio_core_types::SignedDeclassificationGrant>(
            serde_json::to_value(&recovery)?
        )
        .is_err()
    );
    for value in [
        serde_json::json!({"kind":null,"grant":signed}),
        serde_json::json!({"grant":signed}),
        serde_json::json!({"kind":"recovery","grant":null}),
        serde_json::json!({"kind":"unknown","grant":signed}),
    ] {
        assert!(decode_contract::<SignedDisclosureGrant>(&canonical_json_bytes(&value)?).is_err());
    }
    let mut swapped = serde_json::to_value(&signed)?;
    swapped["signature"] = serde_json::to_value(declassification.signature())?;
    let swapped: SignedRecoveryGrant = serde_json::from_value(swapped)?;
    assert!(!swapped.verify_signature()?);
    let proof: SignedAuthorityCoverageAttestationV1 =
        serde_json::from_value(positive["coverage"][0].clone())?;
    assert!(proof.verify_signature()?);
    assert!(matches!(
        chio_core_types::crypto::verify_wrapped(
            proof.authority_key(),
            chio_core_types::recovery::CHIO_RECOVERY_GRANT_SCHEMA,
            proof.body(),
            proof.signature(),
        ),
        Err(chio_core_types::Error::SignatureRejected)
    ));
    assert!(!format!("{signed:?}").contains("private-canary"));
    Ok(())
}

#[test]
fn recovery_grant_refuses_the_declassification_grant_shape() -> Result {
    let positive: Value = serde_json::from_str(POSITIVE)?;
    let signed: SignedRecoveryGrant = serde_json::from_value(positive["grant"].clone())?;
    let key = chio_core_types::Keypair::from_seed(&[143; 32]);
    let declassification =
        chio_core_types::SignedDeclassificationGrant::sign(signed.body().claims.clone(), &key)?;
    let refused = decode_contract::<SignedRecoveryGrant>(&canonical_json_bytes(&declassification)?);
    assert_eq!(refused.err(), Some(ContractError::Malformed));
    Ok(())
}

#[test]
fn action_intents_require_a_closed_native_origin() -> Result {
    let positive: Value = serde_json::from_str(POSITIVE)?;
    let action: ActionIntentV1 = serde_json::from_value(positive["action"].clone())?;
    let wire = canonical_json_bytes(&action)?;
    assert_eq!(decode_contract::<ActionIntentV1>(&wire)?, action);
    for mutation in 0..5 {
        let mut value = serde_json::to_value(&action)?;
        match mutation {
            0 => value["origin"]["operation"]["operation_version"] = 0.into(),
            1 => value["origin"]["request_id"] = "foreign whitespace".into(),
            2 => value["origin"]["claimed_authority"] = true.into(),
            3 => value["origin"] = Value::Null,
            _ => {
                value
                    .as_object_mut()
                    .ok_or("action object")?
                    .remove("origin");
            }
        }
        assert_eq!(
            decode_contract::<ActionIntentV1>(&canonical_json_bytes(&value)?).err(),
            Some(ContractError::Malformed)
        );
    }
    Ok(())
}
