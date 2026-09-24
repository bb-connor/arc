use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn binding() -> Result<RuntimeReplaySourceBinding, ChioRuntimeError> {
    RuntimeReplaySourceBinding::new("source", "runtime-authority", "destination-authority")
}

fn seal(markers: Vec<RuntimeReplayMarker>) -> Result<RuntimeReplaySourceSeal, ChioRuntimeError> {
    RuntimeReplaySourceSeal::from_inventory(
        binding()?,
        SqliteFileIdentity {
            device: u64::MAX,
            inode: u64::MAX - 1,
            link_count: 1,
        },
        "a".repeat(64),
        markers,
    )
}

#[test]
fn source_evidence_round_trips_exact_identity_without_exposing_marker_debug() -> TestResult {
    let original = seal(vec![RuntimeReplayMarker::new(
        RuntimeReplayMarkerKind::DestructiveLease,
        "private-resource-marker",
        "historical-admission",
    )?])?;
    let encoded = original.canonical_bytes()?;
    let decoded = RuntimeReplaySourceSeal::from_canonical_bytes(&encoded)?;
    assert_eq!(decoded, original);
    assert_eq!(decoded.file_identity().device, u64::MAX);
    assert_eq!(decoded.file_identity().inode, u64::MAX - 1);
    assert!(!format!("{decoded:?}").contains("private-resource-marker"));
    Ok(())
}

#[test]
fn source_evidence_rejects_tampering_and_noncanonical_encodings() -> TestResult {
    let original = seal(Vec::new())?;
    let canonical = original.canonical_bytes()?;
    let value: serde_json::Value = serde_json::from_slice(&canonical)?;
    for field in ["sourceId", "runtimeAuthorityId", "destinationAuthorityId"] {
        let mut changed = value.clone();
        changed["body"]["binding"][field] = serde_json::json!("substitution");
        let encoded = canonical_json_bytes(&changed)?;
        assert!(RuntimeReplaySourceSeal::from_canonical_bytes(&encoded).is_err());
    }
    for (field, replacement) in [
        ("schema", serde_json::json!("unsupported")),
        ("device", serde_json::json!("1")),
        ("inode", serde_json::json!("1")),
        ("linkCount", serde_json::json!(2)),
        ("markerCounts", serde_json::json!([1, 0, 0])),
        ("barrierSha256", serde_json::json!("b".repeat(64))),
    ] {
        let mut changed = value.clone();
        changed["body"][field] = replacement;
        assert!(
            RuntimeReplaySourceSeal::from_canonical_bytes(&canonical_json_bytes(&changed)?)
                .is_err()
        );
    }
    assert!(
        RuntimeReplaySourceSeal::from_canonical_bytes(&serde_json::to_vec_pretty(&value)?).is_err()
    );
    let mut unknown = value;
    unknown["unexpected"] = serde_json::json!(true);
    assert!(
        RuntimeReplaySourceSeal::from_canonical_bytes(&canonical_json_bytes(&unknown)?).is_err()
    );
    Ok(())
}

#[test]
fn marker_identity_is_kind_and_resource_not_historical_admission() -> TestResult {
    let marker = |kind, resource, admission| RuntimeReplayMarker::new(kind, resource, admission);
    assert!(seal(vec![
        marker(RuntimeReplayMarkerKind::DestructiveLease, "same", "first")?,
        marker(RuntimeReplayMarkerKind::DestructiveLease, "same", "second")?,
    ])
    .is_err());
    assert!(seal(vec![
        marker(RuntimeReplayMarkerKind::SwarmContinuation, "same", "first")?,
        marker(RuntimeReplayMarkerKind::DestructiveLease, "same", "first")?,
    ])
    .is_err());
    let valid = seal(vec![
        marker(RuntimeReplayMarkerKind::DestructiveLease, "same", "first")?,
        marker(RuntimeReplayMarkerKind::TreatyContinuation, "same", "first")?,
        marker(RuntimeReplayMarkerKind::SwarmContinuation, "same", "first")?,
    ])?;
    assert_eq!(valid.markers().len(), 3);
    Ok(())
}

#[test]
fn source_bounds_reject_complete_input_without_truncation() -> TestResult {
    for invalid in [
        "".to_owned(),
        " padded".to_owned(),
        "a\0b".to_owned(),
        "a".repeat(513),
    ] {
        assert!(
            RuntimeReplaySourceBinding::new(invalid.clone(), "runtime", "destination").is_err()
        );
        assert!(RuntimeReplayMarker::new(
            RuntimeReplayMarkerKind::DestructiveLease,
            invalid,
            "admission"
        )
        .is_err());
    }
    let marker = RuntimeReplayMarker::new(
        RuntimeReplayMarkerKind::DestructiveLease,
        "lease",
        "admission",
    )?;
    let Err(error) = seal(vec![marker; MAX_RUNTIME_REPLAY_SOURCE_MARKERS + 1]) else {
        return Err("oversized marker inventory accepted".into());
    };
    assert_eq!(error.code(), "runtime_replay_source_inventory_limit");
    let Err(error) = RuntimeReplaySourceSeal::from_canonical_bytes(&vec![
        b' ';
        MAX_RUNTIME_REPLAY_SOURCE_BYTES
            + 1
    ]) else {
        return Err("oversized encoded inventory accepted".into());
    };
    assert_eq!(error.code(), "runtime_replay_source_inventory_limit");
    Ok(())
}
