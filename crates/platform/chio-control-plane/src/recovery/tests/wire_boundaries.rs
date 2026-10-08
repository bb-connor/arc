//! Shared structural bytes pass through the actual bounded contract readers.
//! These transformed signed fields establish no signature or effect authority.
use chio_core_types::recovery::decode_contract;
use chio_kernel::recovery::{
    RecoveryApprovalSubmissionV1, RecoveryEffectContractV1, RecoveryRetainedApprovalV1,
};
use chio_security_types::recovery::{
    ActionIntentV1, ApprovalIntentV1, AuthorizationRequirementsV1, RecoveryCommandV1,
    RecoveryGrantBindingV1, RecoveryProviderFinalityV1, RecoverySupportIssueInputV1,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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
    contract: String,
    wire: String,
    schema_valid: bool,
    wire_profile_valid: bool,
    rust_typed_valid: bool,
    rust_retained_valid: Option<bool>,
    nested_approval_valid: Option<bool>,
}

fn typed<T: DeserializeOwned + Serialize>(wire: &[u8]) -> bool {
    decode_contract::<T>(wire).is_ok()
}

fn accepts(contract: &str, wire: &[u8]) -> Result<bool> {
    Ok(match contract {
        "approval_submission" => typed::<RecoveryApprovalSubmissionV1>(wire),
        "approval_intent" => typed::<ApprovalIntentV1>(wire),
        "command" => typed::<RecoveryCommandV1>(wire),
        "grant_binding" => typed::<RecoveryGrantBindingV1>(wire),
        "action" => typed::<ActionIntentV1>(wire),
        "requirements" => typed::<AuthorizationRequirementsV1>(wire),
        "provider_body" => typed::<RecoveryProviderFinalityV1>(wire),
        "support_issue_input" => typed::<RecoverySupportIssueInputV1>(wire),
        "support_issue_effect" => typed::<RecoveryEffectContractV1>(wire),
        _ => return Err(format!("unknown boundary contract: {contract}").into()),
    })
}

#[derive(Deserialize)]
struct Utf8Corpus {
    format_version: u8,
    vectors: Vec<Utf8Vector>,
}
#[derive(Deserialize)]
struct Utf8Vector {
    name: String,
    contract: String,
    wire: String,
    valid: bool,
}

#[test]
fn recovery_shared_approval_and_epoch_boundaries_use_the_owning_readers() -> Result {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/vectors/recovery/v1/byte-boundaries.json");
    let corpus: Corpus = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(corpus.format_version, 1);
    assert!(!corpus.vectors.is_empty());
    let mut names = std::collections::BTreeSet::new();
    let mut contracts = std::collections::BTreeSet::new();
    for vector in corpus.vectors {
        assert!(names.insert(vector.name.clone()), "duplicate boundary name");
        contracts.insert(vector.contract.clone());
        assert_eq!(
            typed::<Value>(vector.wire.as_bytes()),
            vector.wire_profile_valid,
            "actual foundation reader: {}",
            vector.name
        );
        assert_eq!(
            accepts(&vector.contract, vector.wire.as_bytes())?,
            vector.rust_typed_valid,
            "actual typed reader: {}",
            vector.name
        );
        assert_eq!(
            vector.schema_valid && vector.wire_profile_valid,
            vector.rust_typed_valid,
            "shared structural and resource boundaries: {}",
            vector.name
        );
        if let Some(expected) = vector.rust_retained_valid {
            assert_eq!(vector.contract, "approval_submission");
            assert_eq!(
                typed::<RecoveryRetainedApprovalV1>(vector.wire.as_bytes()),
                expected,
                "retained data reader: {}",
                vector.name
            );
        }
        if let Some(expected) = vector.nested_approval_valid {
            assert_eq!(vector.contract, "command");
            let command: Value = serde_json::from_str(&vector.wire)?;
            let approval = command["command"]["approval"]
                .as_str()
                .ok_or("approval text")?;
            assert_eq!(
                typed::<RecoveryApprovalSubmissionV1>(approval.as_bytes()),
                expected,
                "independent embedded approval reader: {}",
                vector.name
            );
        }
    }
    assert_eq!(
        contracts,
        [
            "action",
            "approval_intent",
            "approval_submission",
            "command",
            "grant_binding"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>()
    );
    // These are the same immutable UTF-8 bytes used by the owning SDK readers.
    // Every role reaches its concrete contract, including the native effect
    // contract. A generic JSON parser cannot stand in for a bounded resource.
    let utf8: Utf8Corpus = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/vectors/recovery/v1/authority-contracts.json"
    )))?;
    assert_eq!(utf8.format_version, 1);
    let mut utf8_names = std::collections::BTreeSet::new();
    let mut utf8_contracts = std::collections::BTreeSet::new();
    for vector in utf8
        .vectors
        .into_iter()
        .filter(|vector| vector.name.starts_with("utf8-bound/"))
    {
        assert!(
            utf8_names.insert(vector.name.clone()),
            "duplicate UTF-8 role"
        );
        utf8_contracts.insert(vector.contract.clone());
        assert_eq!(
            accepts(&vector.contract, vector.wire.as_bytes())?,
            vector.valid,
            "actual bounded UTF-8 role reader: {}",
            vector.name
        );
    }
    assert_eq!(utf8_names.len(), 22);
    assert_eq!(
        utf8_contracts,
        [
            "support_issue_input",
            "support_issue_effect",
            "provider_body",
            "action",
            "requirements"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>()
    );
    Ok(())
}
