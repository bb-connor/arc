use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationHead, EnterpriseMigrationKey,
    EnterpriseMigrationScopeKind, EnterpriseMigrationTransitionBody,
    EnterpriseMigrationTransitionValidationError,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn key(
    control: EnterpriseMigrationControl,
    scope_kind: EnterpriseMigrationScopeKind,
) -> Result<EnterpriseMigrationKey, Box<dyn std::error::Error>> {
    Ok(EnterpriseMigrationKey {
        deployment_id: RecordId::new("production.test")?,
        scope_kind,
        scope_id: RecordId::new("scope.test")?,
        control,
    })
}

fn body() -> Result<EnterpriseMigrationTransitionBody, Box<dyn std::error::Error>> {
    Ok(EnterpriseMigrationTransitionBody::enforced(
        key(
            EnterpriseMigrationControl::CageEnforcement,
            EnterpriseMigrationScopeKind::ToolServer,
        )?,
        Digest32::new([1; 32]),
        Digest32::new([2; 32]),
        Digest32::new([3; 32]),
        Digest32::new([4; 32]),
        1,
        "signer".to_string(),
    )?)
}

fn unknown_field(error: &serde_json::Error, field: &str) -> bool {
    error
        .to_string()
        .starts_with(&format!("unknown field `{field}`"))
}

#[test]
fn enforced_registration_round_trips() -> TestResult {
    let body = body()?;
    let decoded: EnterpriseMigrationTransitionBody =
        serde_json::from_value(serde_json::to_value(&body)?)?;
    assert_eq!(decoded, body);
    Ok(())
}

#[test]
fn staged_registration_shapes_are_refused() -> TestResult {
    let current = serde_json::to_value(body()?)?;
    for (field, value) in [
        ("generation", json!(0)),
        ("from_stage", Value::Null),
        ("to_stage", json!("disabled")),
        ("prior_head_digest", Value::Null),
    ] {
        let mut staged = current.clone();
        staged[field] = value;
        let error = serde_json::from_value::<EnterpriseMigrationTransitionBody>(staged)
            .err()
            .ok_or("staged registration accepted")?;
        assert!(unknown_field(&error, field), "{field}: {error}");
    }
    Ok(())
}

#[test]
fn generation_bounded_heads_are_refused() -> TestResult {
    let head = json!({
        "key": serde_json::to_value(key(
            EnterpriseMigrationControl::CageEnforcement,
            EnterpriseMigrationScopeKind::ToolServer,
        )?)?,
        "minimum_generation": 2,
        "transition_digest": serde_json::to_value(Digest32::new([7; 32]))?,
    });
    let error = serde_json::from_value::<EnterpriseMigrationHead>(head)
        .err()
        .ok_or("generation-bounded head accepted")?;
    assert!(unknown_field(&error, "minimum_generation"), "{error}");
    Ok(())
}

#[test]
fn removed_legacy_configuration_control_is_refused() -> TestResult {
    let error = serde_json::from_value::<EnterpriseMigrationControl>(json!("legacy_configuration"))
        .err()
        .ok_or("legacy configuration control accepted")?;
    assert!(
        error
            .to_string()
            .starts_with("unknown variant `legacy_configuration`"),
        "{error}"
    );
    Ok(())
}

#[test]
fn registration_shape_refusals_are_exact() -> TestResult {
    let mut wrong_scope = body()?;
    wrong_scope.key = key(
        EnterpriseMigrationControl::CageEnforcement,
        EnterpriseMigrationScopeKind::Provider,
    )?;
    assert_eq!(
        wrong_scope.validate_shape(),
        Err(EnterpriseMigrationTransitionValidationError::ControlScope)
    );
    let mut zero = body()?;
    zero.posture_digest = Digest32::new([0; 32]);
    assert_eq!(
        zero.validate_shape(),
        Err(EnterpriseMigrationTransitionValidationError::ZeroDigest)
    );
    let mut untrusted = body()?;
    untrusted.trusted_at_unix_ms = 0;
    assert_eq!(
        untrusted.validate_shape(),
        Err(EnterpriseMigrationTransitionValidationError::UntrustedTime)
    );
    Ok(())
}
