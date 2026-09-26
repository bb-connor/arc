use super::*;

#[test]
fn matching_fingerprints_cannot_substitute_for_retained_row_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.db");
    drop(crate::security_state::seeded_security_history(&path)?);
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let snapshot = source.preview(&SecurityParticipantSourceBinding::new(
        "source",
        "authority",
        "destination",
    )?)?;
    source.seal_exact(&snapshot)?;
    let mut retained = source.read_sealed_rows(&snapshot)?;
    let (_, fences) = retained
        .tables
        .iter_mut()
        .find(|(name, _)| *name == "security_egress_fences")
        .ok_or("fence rows absent")?;
    let row = fences.first_mut().ok_or("fence absent")?;
    let mut value: serde_json::Value = serde_json::from_slice(row)?;
    value[11] = serde_json::json!({"type":"integer", "value":"1000"});
    *row = canonical_json_bytes(&value)?;

    // Exercise the row-storage boundary independently of physical source
    // verification. Even self-consistent fingerprints cannot admit malformed
    // decoded history. This synthetic pin is not a verified source seal.
    let fingerprints = retained
        .tables
        .iter()
        .map(|(table, rows)| {
            let mut hasher = TableHasher::new(table);
            for row in rows {
                hasher.push(row)?;
            }
            Ok(hasher.finish())
        })
        .collect::<Result<Vec<_>, crate::security_state::SecurityParticipantSourceError>>()?;
    let mut pinned: serde_json::Value = serde_json::from_slice(&snapshot.canonical_bytes()?)?;
    pinned["tables"] = serde_json::to_value(fingerprints)?;
    let snapshot =
        SecurityParticipantSourceSnapshot::from_canonical_bytes(&canonical_json_bytes(&pinned)?)?;
    let record = records::new_expectation(snapshot)?;
    let mut destination = Connection::open_in_memory()?;
    destination.execute_batch(SECURITY_PARTICIPANT_MIGRATION_SCHEMA)?;
    let tx = destination.transaction_with_behavior(TransactionBehavior::Immediate)?;
    records::insert_expectation(&tx, &record)?;
    assert!(insert_rows(&tx, &record, retained).is_err());
    drop(tx);
    assert_eq!(
        destination.query_row(
            "SELECT COUNT(*) FROM security_participant_migration_rows",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    Ok(())
}
