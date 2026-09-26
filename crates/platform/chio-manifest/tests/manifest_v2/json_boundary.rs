use super::{unique_manifest_path, v2_manifest};
use chio_core::crypto::Keypair;
use chio_manifest::{
    load_existing_verified_manifest_registry, sign_manifest, RuntimeToolTopology,
    VerifiedManifestLoadError,
};

fn reject_alias(
    schema: serde_json::Value,
    original: &str,
    replacement: &str,
    expected_reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::from_seed(&[43; 32]);
    let mut manifest = v2_manifest(keypair.public_key().to_hex());
    manifest.tools[0].input_schema = schema;
    let signed = sign_manifest(&manifest, &keypair)?;
    let original_json = serde_json::to_string(&signed)?;
    assert_eq!(original_json.matches(original).count(), 1);
    let path = unique_manifest_path("strict-json");
    std::fs::write(&path, &original_json)?;
    let load = || {
        load_existing_verified_manifest_registry(
            &path,
            &keypair.public_key().to_hex(),
            "srv-v2",
            RuntimeToolTopology::remote(),
        )
    };
    let valid = load();
    if let Err(error) = valid {
        std::fs::remove_file(&path)?;
        return Err(error.into());
    }
    std::fs::write(&path, original_json.replacen(original, replacement, 1))?;
    let aliased = load();
    std::fs::remove_file(path)?;
    match aliased {
        Err(VerifiedManifestLoadError::CanonicalInput { source, .. }) => assert!(
            source.to_string().contains(expected_reason),
            "wrong refusal for aliased signed input: {source}"
        ),
        Err(error) => panic!("wrong error class for ambiguous JSON: {error}"),
        Ok(_) => panic!("signed manifest admitted an ambiguous JSON alias"),
    }
    Ok(())
}

#[test]
fn signed_file_rejects_shadowed_nested_schema_keywords() -> Result<(), Box<dyn std::error::Error>> {
    reject_alias(
        serde_json::json!({"type": "object"}),
        r#""type":"object""#,
        r#""type":"string","type":"object""#,
        "duplicate object key",
    )
}

#[test]
fn signed_file_rejects_fractional_precision_aliases() -> Result<(), Box<dyn std::error::Error>> {
    reject_alias(
        serde_json::json!({"type": "number", "minimum": 0.12345678901234568}),
        "0.12345678901234568",
        "0.123456789012345678901",
        "loses precision or changes representation",
    )
}

#[test]
fn signed_file_preserves_existing_numeric_schema_contract() -> Result<(), Box<dyn std::error::Error>>
{
    let keypair = Keypair::from_seed(&[44; 32]);
    let mut manifest = v2_manifest(keypair.public_key().to_hex());
    manifest.tools[0].input_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "whole": {"type": "number", "minimum": 1.0},
            "zero": {"type": "number", "minimum": -0.0},
            "large": {"type": "integer", "maximum": u64::MAX},
        },
    });
    let signed = sign_manifest(&manifest, &keypair)?;
    for bytes in [
        serde_json::to_vec(&signed)?,
        serde_json::to_vec_pretty(&signed)?,
        chio_core::canonical::canonical_json_bytes(&signed)?,
    ] {
        let path = unique_manifest_path("numeric-compatibility");
        std::fs::write(&path, bytes)?;
        let loaded = load_existing_verified_manifest_registry(
            &path,
            &keypair.public_key().to_hex(),
            "srv-v2",
            RuntimeToolTopology::remote(),
        );
        std::fs::remove_file(&path)?;
        loaded?;
    }
    Ok(())
}
