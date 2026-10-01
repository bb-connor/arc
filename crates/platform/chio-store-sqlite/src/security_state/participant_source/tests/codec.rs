use super::*;

#[test]
fn fingerprint_decoder_rejects_noncanonical_unbounded_and_unknown_shapes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let _store = seed(&path)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    let bytes = expected.canonical_bytes()?;
    assert_eq!(expected.digest()?.len(), 64);
    let mut whitespace = bytes.clone();
    whitespace.push(b'\n');
    for invalid in [Vec::new(), vec![b' '; 65_537], whitespace] {
        assert!(SecurityParticipantSourceSnapshot::from_canonical_bytes(&invalid).is_err());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    // Independently computed from the v1 length-framed canonical row stream.
    // Roundtrips alone would accept incompatible encoder/decoder drift.
    let sequence = value["tables"]
        .as_array()
        .ok_or("missing table fingerprints")?
        .iter()
        .find(|entry| entry["table"] == "security_flow_sequences")
        .ok_or("missing sequence fingerprint")?;
    assert_eq!(sequence["row_count"], 1);
    assert_eq!(sequence["encoded_bytes"], 65);
    assert_eq!(
        sequence["digest"],
        "bc1d5d9ae16c7db43c1f1ce21c9ccad9a013792116d73dd5e5a3611be1baa621"
    );
    for (field, invalid) in [
        ("schema", serde_json::json!("future")),
        ("link_count", serde_json::json!(2)),
        ("device", serde_json::json!("01")),
        ("inode", serde_json::json!("18446744073709551616")),
        ("catalog_digest", serde_json::json!("A".repeat(64))),
        ("tables", serde_json::json!([])),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut changed = value.clone();
        changed[field] = invalid;
        assert!(
            SecurityParticipantSourceSnapshot::from_canonical_bytes(
                &chio_core::canonical_json_bytes(&changed)?
            )
            .is_err(),
            "{field}"
        );
    }
    for (field, invalid) in [
        ("row_count", serde_json::json!(16_385)),
        ("encoded_bytes", serde_json::json!(67_108_865)),
        ("table", serde_json::json!("security_flow_sequences")),
        ("digest", serde_json::json!("invalid")),
        ("extra", serde_json::json!(1)),
    ] {
        let mut changed = value.clone();
        changed["tables"][0][field] = invalid;
        assert!(
            SecurityParticipantSourceSnapshot::from_canonical_bytes(
                &chio_core::canonical_json_bytes(&changed)?
            )
            .is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn destination_labels_are_pinned_but_are_not_activation_authority() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let _store = seed(&path)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    let other = source.preview(&SecurityParticipantSourceBinding::new(
        "private-source",
        "security-authority",
        "different-destination",
    )?)?;
    assert_ne!(other.digest()?, expected.digest()?);
    source.seal_exact(&expected)?;
    assert!(source.verify_seal(&other).is_err());
    assert!(source.seal_exact(&other).is_err());
    source.verify_seal(&expected)?;
    Ok(())
}
