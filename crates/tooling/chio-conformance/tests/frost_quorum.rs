use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chio_core::{is_supported_signed_artifact_schema, Keypair};
use chio_federation::frost::{
    FrostArtifactAuthorityRole, FrostArtifactTrustRoot, FrostArtifactTrustStore, FrostRosterV1,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn load_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn frost_registered_signed_artifacts_are_runtime_supported() {
    let registry = load_json(&repo_root().join("spec/schemas/registry.json"));
    let rows: BTreeMap<&str, (&str, &str)> = registry["artifacts"]
        .as_array()
        .unwrap_or_else(|| panic!("registry must carry an artifacts array"))
        .iter()
        .filter_map(|row| {
            let schema = row["schema"].as_str()?;
            schema.starts_with("chio.frost.").then(|| {
                (
                    schema,
                    (
                        row["artifactKind"]
                            .as_str()
                            .unwrap_or_else(|| panic!("FROST row must carry artifactKind")),
                        row["schemaFile"]
                            .as_str()
                            .unwrap_or_else(|| panic!("FROST row must carry schemaFile")),
                    ),
                )
            })
        })
        .collect();
    let expected = BTreeMap::from([
        (
            "chio.frost.authorization-slot-checkpoint.v1",
            (
                "frost_authorization_slot_checkpoint",
                "spec/schemas/chio-frost/v1/authorization-slot-checkpoint.schema.json",
            ),
        ),
        (
            "chio.frost.authorization.v1",
            (
                "frost_authorization",
                "spec/schemas/chio-frost/v1/authorization.schema.json",
            ),
        ),
        (
            "chio.frost.epoch-checkpoint.v1",
            (
                "frost_epoch_checkpoint",
                "spec/schemas/chio-frost/v1/epoch-checkpoint.schema.json",
            ),
        ),
        (
            "chio.frost.roster.v1",
            (
                "frost_roster",
                "spec/schemas/chio-frost/v1/roster.schema.json",
            ),
        ),
    ]);
    assert_eq!(rows, expected);
    for schema in rows.keys() {
        assert!(is_supported_signed_artifact_schema(schema));
    }
}

#[test]
fn frost_roster_schema_and_pinned_signature_are_separate_gates() {
    let family = repo_root().join("spec/schemas/chio-frost/v1");
    let schema = load_json(&family.join("roster.schema.json"));
    let positive = load_json(&family.join("fixtures/roster.positive.json"));
    let tampered = load_json(&family.join("fixtures/roster.tampered-signature.json"));
    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|error| panic!("compile FROST roster schema: {error}"));
    assert!(validator.is_valid(&positive));
    assert!(validator.is_valid(&tampered));

    let trust = FrostArtifactTrustStore::new([FrostArtifactTrustRoot {
        role: FrostArtifactAuthorityRole::Roster,
        key_id: "authority.treaty.v1".to_string(),
        public_key: Keypair::from_seed(&[0x42; 32]).public_key(),
    }])
    .unwrap_or_else(|error| panic!("build pinned FROST trust store: {error}"));
    let positive: FrostRosterV1 = serde_json::from_value(positive)
        .unwrap_or_else(|error| panic!("decode positive roster: {error}"));
    let tampered: FrostRosterV1 = serde_json::from_value(tampered)
        .unwrap_or_else(|error| panic!("decode tampered roster: {error}"));
    trust
        .verify_roster(&positive)
        .unwrap_or_else(|error| panic!("verify pinned roster: {error}"));
    assert!(trust.verify_roster(&tampered).is_err());
}
