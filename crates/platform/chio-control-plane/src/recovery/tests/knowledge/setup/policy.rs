//! Trusted setup selection is an explicit, closed deployment requirement.
use super::*;

#[test]
fn setup_deployment_policy_codec_preserves_legacy_bytes_and_accepts_a_pinned_root() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let profile = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    let legacy = chio_core_types::canonical_json_bytes(&profile)?;
    let decoded: RecoveryDeploymentV1 = chio_core_types::recovery::decode_contract(&legacy)?;
    assert_eq!(chio_core_types::canonical_json_bytes(&decoded)?, legacy);
    let mut required = serde_json::to_value(profile)?;
    let policy = serde_json::json!({
        "operator_root": Keypair::from_seed(&[211; 32]).public_key(),
    });
    required
        .as_object_mut()
        .ok_or("deployment object")?
        .insert("setup_policy".into(), policy.clone());
    let wire = chio_core_types::canonical_json_bytes(&required)?;
    let selected: RecoveryDeploymentV1 = chio_core_types::recovery::decode_contract(&wire)?;
    assert_eq!(serde_json::to_value(&selected)?["setup_policy"], policy);
    assert_eq!(chio_core_types::canonical_json_bytes(&selected)?, wire);
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}

#[test]
fn setup_deployment_policy_codec_refuses_caller_readiness_and_missing_roots() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let profile = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    for policy in [
        serde_json::Value::Null,
        serde_json::json!({}),
        serde_json::json!({"operator_root": null}),
        serde_json::json!({
            "operator_root": Keypair::from_seed(&[211; 32]).public_key(),
            "ready": true,
        }),
    ] {
        let mut required = serde_json::to_value(&profile)?;
        required
            .as_object_mut()
            .ok_or("deployment object")?
            .insert("setup_policy".into(), policy);
        let wire = chio_core_types::canonical_json_bytes(&required)?;
        assert!(chio_core_types::recovery::decode_contract::<RecoveryDeploymentV1>(&wire).is_err());
    }
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}
