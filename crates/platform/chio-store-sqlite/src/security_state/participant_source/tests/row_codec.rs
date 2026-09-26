use super::super::{decode_retained_security_row, inventory};
use super::*;
use rusqlite::{params_from_iter, types::Value};

#[test]
fn all_retained_tables_decode_into_a_disposable_projection_without_changing_fingerprints(
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.db");
    let _store = seeded_security_history(&path)?;
    let source = Connection::open(&path)?;
    let destination = Connection::open_in_memory()?;
    super::super::super::migrate(&destination)?;
    destination.execute_batch(
        "BEGIN IMMEDIATE; PRAGMA defer_foreign_keys = ON;
         DELETE FROM security_declassification_lifecycle;",
    )?;
    let mut retained = std::collections::BTreeMap::<&str, Vec<Vec<Value>>>::new();
    let expected = inventory::visit(&source, |table, row| {
        retained
            .entry(table)
            .or_default()
            .push(decode_retained_security_row(table, row)?);
        Ok(())
    })?;
    fn insert(destination: &Connection, table: &str, values: &[Value]) -> TestResult {
        let parameters = (1..=values.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(",");
        // Callers select only compiled table names or inventory-provided names.
        destination.execute(
            &format!("INSERT INTO {table} VALUES ({parameters})"),
            params_from_iter(values),
        )?;
        Ok(())
    }
    for (table, rows) in &retained {
        if *table == "security_declassification_uses"
            || *table == "security_declassification_receipt_outbox"
        {
            continue;
        }
        for values in rows {
            insert(&destination, table, values)?;
        }
    }
    // A final terminal use cannot precede its historical consumption insert:
    // the live trigger requires matching use/outbox state at each transition.
    // Stage only inside this fresh, disposable transaction. No committed source
    // state is rewound, and no observer receives the intermediate projection.
    let uses = retained
        .get("security_declassification_uses")
        .ok_or("uses absent")?;
    let outbox = retained
        .get("security_declassification_receipt_outbox")
        .ok_or("outbox absent")?;
    for values in uses {
        let mut pending = values.clone();
        pending[3] = Value::Text("consumed_pending_dispatch".into());
        pending[8] = Value::Null;
        pending[9] = Value::Null;
        insert(&destination, "security_declassification_uses", &pending)?;
    }
    for values in outbox {
        if values[2] == Value::Text("consumption".into()) {
            insert(
                &destination,
                "security_declassification_receipt_outbox",
                values,
            )?;
        }
    }
    for values in uses {
        if values[3] == Value::Text("consumed_pending_dispatch".into()) {
            continue;
        }
        destination.execute(
            "UPDATE security_declassification_uses SET state = ?3,
             outcome_binding = ?4, transition_id = ?5 WHERE tenant_id = ?1 AND grant_id = ?2",
            rusqlite::params![values[1], values[0], values[3], values[8], values[9]],
        )?;
    }
    for values in outbox {
        if values[2] == Value::Text("outcome".into()) {
            insert(
                &destination,
                "security_declassification_receipt_outbox",
                values,
            )?;
        }
    }
    destination.execute_batch("COMMIT")?;
    assert_eq!(inventory::read(&destination)?, expected);
    inventory::validate_domain(&destination)?;
    assert_eq!(
        destination.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, i64>(0)
        })?,
        0
    );
    Ok(())
}

#[test]
fn row_codec_preserves_sqlite_integer_extremes_and_binary_values() -> TestResult {
    for number in [i64::MIN, 0, 9_007_199_254_740_993, i64::MAX] {
        let bytes = chio_core::canonical_json_bytes(&serde_json::json!([
            {"type":"text", "value":"tenant"},
            {"type":"integer", "value":number.to_string()}
        ]))?;
        assert_eq!(
            decode_retained_security_row("security_flow_sequences", &bytes)?,
            vec![Value::Text("tenant".into()), Value::Integer(number)]
        );
    }
    let bytes = chio_core::canonical_json_bytes(&serde_json::json!([
        {"type":"text", "value":"tenant"},
        {"type":"text", "value":"principal"},
        {"type":"text", "value":"epoch"},
        {"type":"blob", "value":"00ff01"},
        {"type":"blob", "value":"ab".repeat(32)},
        {"type":"integer", "value":"1"}
    ]))?;
    let values = decode_retained_security_row("security_principal_flow_state", &bytes)?;
    assert_eq!(values[3], Value::Blob(vec![0, 255, 1]));
    assert_eq!(values[4], Value::Blob(vec![0xab; 32]));
    for invalid in ["AB", "a", "gg"] {
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
        changed[3]["value"] = invalid.into();
        assert!(
            decode_retained_security_row(
                "security_principal_flow_state",
                &chio_core::canonical_json_bytes(&changed)?
            )
            .is_err(),
            "{invalid}"
        );
    }
    Ok(())
}

#[test]
fn row_codec_rejects_noncanonical_cells_shapes_and_declared_type_changes() -> TestResult {
    let valid = serde_json::json!([
        {"type":"text", "value":"tenant"},
        {"type":"integer", "value":"1"}
    ]);
    for invalid in [
        serde_json::json!(null),
        serde_json::json!([]),
        serde_json::Value::Array(vec![serde_json::json!({"type":"null"}); 65]),
        serde_json::json!([{"type":"null"}, {"type":"integer","value":"1"}]),
        serde_json::json!([{"type":"text","value":"tenant"}, {"type":"text","value":"1"}]),
        serde_json::json!([{"type":"text","value":"tenant","extra":true}, {"type":"integer","value":"1"}]),
    ] {
        assert!(decode_retained_security_row(
            "security_flow_sequences",
            &chio_core::canonical_json_bytes(&invalid)?
        )
        .is_err());
    }
    for invalid in [
        "01",
        "+1",
        "-0",
        "1.0",
        "1e0",
        "9223372036854775808",
        "-9223372036854775809",
    ] {
        let mut changed = valid.clone();
        changed[1]["value"] = invalid.into();
        assert!(
            decode_retained_security_row(
                "security_flow_sequences",
                &chio_core::canonical_json_bytes(&changed)?
            )
            .is_err(),
            "{invalid}"
        );
    }
    let mut bytes = chio_core::canonical_json_bytes(&valid)?;
    assert!(decode_retained_security_row("unknown_table", &bytes).is_err());
    bytes.push(b'\n');
    assert!(decode_retained_security_row("security_flow_sequences", &bytes).is_err());
    assert!(decode_retained_security_row(
        "security_flow_sequences",
        br#"[{"type":"text","value":"tenant"},{"type":"integer","value":"1","value":"1"}]"#
    )
    .is_err());
    Ok(())
}

#[test]
fn row_codec_enforces_encoded_cell_and_decoded_row_bounds() -> TestResult {
    assert!(decode_retained_security_row(
        "security_flow_sequences",
        &vec![b' '; 16 * 1024 * 1024 + 1]
    )
    .is_err());
    let oversized = chio_core::canonical_json_bytes(&serde_json::json!([
        {"type":"text", "value":"x".repeat(1024 * 1024 + 1)},
        {"type":"integer", "value":"1"}
    ]))?;
    assert!(decode_retained_security_row("security_flow_sequences", &oversized).is_err());
    let excessive_row = chio_core::canonical_json_bytes(&serde_json::json!([
        {"type":"text", "value":"x".repeat(1024 * 1024)},
        {"type":"text", "value":"x".repeat(1024 * 1024)},
        {"type":"text", "value":"x".repeat(1024 * 1024)},
        {"type":"text", "value":"epoch"},
        {"type":"null"}, {"type":"blob", "value":"00".repeat(32)},
        {"type":"null"}, {"type":"null"},
        {"type":"text", "value":"transition"}, {"type":"integer", "value":"0"}
    ]))?;
    assert!(decode_retained_security_row("security_isolation_epochs", &excessive_row).is_err());
    Ok(())
}
