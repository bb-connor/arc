use super::*;

fn evaluated() -> PostReturnEvaluationRecordV1 {
    let operation = committed_operation("terminal-snapshot");
    let outcome = returned(&operation, json!({"allowed": true}));
    record_external(&record_pure(&prepared_evaluation(&operation, &outcome)))
}

fn seal(snapshot: Option<Value>) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeError> {
    evaluated()
        .resolve_with_signing_preimage_and_snapshot(
            canonical_json_bytes(&json!({"allowed": true})).unwrap(),
            admission_digest("guard-decision"),
            admission_digest("pricing-verdict"),
            SettlementDispositionV1::NotApplicable,
            snapshot,
        )
        .map(|(evaluation, _)| evaluation)
}

#[test]
fn terminal_snapshot_legacy_none_preserves_original_canonical_lifecycle() {
    let evaluation = evaluated();
    let resolution = PostReturnResolutionV1::from_output(
        &evaluation,
        &json!({"allowed": true}),
        admission_digest("guard-decision"),
        admission_digest("pricing-verdict"),
        SettlementDispositionV1::NotApplicable,
    )
    .unwrap();
    let legacy = evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::Resolve(resolution),
        )
        .unwrap();
    let modern = seal(None).unwrap();
    assert_eq!(legacy, modern);
    assert_eq!(
        canonical_json_bytes(&legacy.to_persisted()).unwrap(),
        canonical_json_bytes(&modern.to_persisted()).unwrap()
    );
    assert!(
        serde_json::to_value(modern.to_persisted()).unwrap()["state"]["resolution"]
            .get("terminal_snapshot")
            .is_none()
    );
}

#[test]
fn terminal_snapshot_roundtrips_as_bounded_canonical_resolution() {
    let snapshot = json!({"schema": "test-terminal-facts.v1", "original_units": 5});
    let original = seal(Some(snapshot.clone())).unwrap();
    let bytes = canonical_json_bytes(&original.to_persisted()).unwrap();
    let persisted: PersistedPostReturnEvaluationRecordV1 =
        chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 65_536)
            .and_then(|input| input.decode_canonical())
            .unwrap();
    let restored = PostReturnEvaluationRecordV1::from_persisted(persisted).unwrap();
    assert_eq!(restored, original);
    assert_eq!(restored.retained_terminal_snapshot(), Some(&snapshot));
}

#[test]
fn terminal_snapshot_rejects_oversize_before_resolution() {
    let error = seal(Some(json!({"padding": "x".repeat(8_192)}))).unwrap_err();
    assert!(matches!(
        error,
        ToolOutcomeError::TooLarge {
            field: "resolution.terminal_snapshot",
            maximum: 8_192,
            ..
        }
    ));
}

#[test]
fn terminal_snapshot_rejects_nonobject_facts() {
    assert!(matches!(
        seal(Some(json!([1, 2, 3]))),
        Err(ToolOutcomeError::Invalid("resolution.terminal_snapshot"))
    ));
}

#[test]
fn terminal_snapshot_substitution_cannot_preserve_lifecycle_identity() {
    let original = seal(Some(json!({"original_units": 5}))).unwrap();
    let mut substituted = original.to_persisted();
    if let PostReturnEvaluationStateV1::Resolved { resolution } = &mut substituted.state {
        resolution.terminal_snapshot = Some(json!({"original_units": 9}));
    } else {
        panic!("test sealed resolution");
    }
    assert!(matches!(
        PostReturnEvaluationRecordV1::from_persisted(substituted),
        Err(ToolOutcomeError::Binding("evaluation.lifecycle_digest"))
    ));
}

#[test]
fn terminal_snapshot_wire_requires_canonical_json() {
    let original = seal(Some(json!({"original_units": 5}))).unwrap();
    let mut bytes = vec![b' '];
    bytes.extend(canonical_json_bytes(&original.to_persisted()).unwrap());
    assert!(
        chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 65_536)
            .and_then(|input| input.decode_canonical::<PersistedPostReturnEvaluationRecordV1>())
            .is_err()
    );
}
