// CLI handlers for `chio cert` commands.

use std::collections::BTreeSet;
use std::path::Path;

use chio_acp_proxy::{
    generate_compliance_certificate, verify_compliance_certificate, ComplianceCertificate,
    ComplianceConfig, ComplianceReceiptEntry, VerificationMode,
};

use crate::CliError;

/// `chio cert generate` -- walk the receipt store for a session and produce
/// a signed compliance certificate.
pub fn cmd_cert_generate(
    session_id: &str,
    receipt_db: &Path,
    budget_limit: u64,
    output: Option<&Path>,
    authority_seed_file: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let default_seed_path = std::path::PathBuf::from(".chio-authority-seed");
    let seed_path = authority_seed_file.unwrap_or(&default_seed_path);
    let keypair = crate::load_existing_authority_keypair(seed_path)?;

    let db_path = receipt_db.to_string_lossy();
    let conn = rusqlite::Connection::open_with_flags(
        receipt_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| CliError::cli_other_error(format!("failed to open receipt db {db_path}: {e}")))?;

    let receipts = load_session_receipts(&conn, session_id)?;

    let config = ComplianceConfig {
        budget_limit,
        required_guards: Vec::new(),
        authorized_scopes: Vec::new(),
        expected_tenant_id: None,
        trusted_kernel_keys: BTreeSet::from([keypair.public_key().to_hex()]),
    };

    let cert = generate_compliance_certificate(
        session_id,
        &receipts,
        &config,
        &keypair,
        &chio_acp_proxy::AcpClock::default(),
    )
    .map_err(|error| {
        CliError::with_source(
            &chio_errors::_generated::error_codes::ATTEST_RECEIPT_SIGNING_FAILED,
            error,
        )
    })?;

    let cert_json = serde_json::to_string_pretty(&cert)
        .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &cert_json)
            .map_err(|e| CliError::cli_other_error(format!("failed to write output: {e}")))?;
        if !json_output {
            eprintln!(
                "compliance certificate for session {} written to {}",
                session_id,
                out_path.display()
            );
        }
    }

    if json_output || output.is_none() {
        println!("{cert_json}");
    }

    Ok(())
}

/// `chio cert verify` -- verify a compliance certificate.
pub fn cmd_cert_verify(
    certificate_path: &Path,
    full: bool,
    receipt_db: Option<&Path>,
    trusted_kernel_pubkey: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let cert_text = crate::input::read_text(certificate_path)
        .map_err(|e| CliError::cli_other_error(format!("failed to read certificate: {e}")))?;

    let cert: ComplianceCertificate = crate::input::text(&cert_text).map_err(CliError::from)?;

    let mode = if full {
        VerificationMode::FullBundle
    } else {
        VerificationMode::Lightweight
    };

    let receipts = if full {
        if let Some(db_path) = receipt_db {
            let conn = rusqlite::Connection::open_with_flags(
                db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|e| CliError::cli_other_error(format!("failed to open receipt db: {e}")))?;
            let entries = load_session_receipts(&conn, &cert.body.session_id)?;
            Some(entries)
        } else {
            return Err(CliError::cli_other_error(
                "full-bundle verification requires --receipt-db".to_string(),
            ));
        }
    } else {
        None
    };

    let trusted_kernel_key =
        crate::load_trusted_kernel_pubkey(trusted_kernel_pubkey).map_err(|e| {
            CliError::cli_other_error(format!("failed to load trusted kernel pubkey: {e}"))
        })?;
    let config = ComplianceConfig {
        budget_limit: 0,
        required_guards: Vec::new(),
        authorized_scopes: Vec::new(),
        expected_tenant_id: None,
        trusted_kernel_keys: BTreeSet::from([trusted_kernel_key.to_hex()]),
    };

    let result = verify_compliance_certificate(&cert, mode, receipts.as_deref(), &config);

    if json_output {
        let result_json = serde_json::to_string_pretty(&result)
            .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?;
        println!("{result_json}");
    } else if result.passed {
        println!("PASS: {}", result.summary);
    } else {
        println!("FAIL: {}", result.summary);
    }

    if !result.passed {
        std::process::exit(1);
    }

    Ok(())
}

/// `chio cert inspect` -- display certificate contents.
pub fn cmd_cert_inspect(certificate_path: &Path, json_output: bool) -> Result<(), CliError> {
    let cert_text = crate::input::read_text(certificate_path)
        .map_err(|e| CliError::cli_other_error(format!("failed to read certificate: {e}")))?;

    let cert: ComplianceCertificate = crate::input::text(&cert_text).map_err(CliError::from)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&cert.body)
                .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?
        );
    } else {
        println!("Session ID:     {}", cert.body.session_id);
        println!("Schema:         {}", cert.body.schema);
        println!("Issued at:      {}", cert.body.issued_at);
        println!("Receipt count:  {}", cert.body.receipt_count);
        println!("First receipt:  {}", cert.body.first_receipt_at);
        println!("Last receipt:   {}", cert.body.last_receipt_at);
        println!(
            "Signatures:     {}",
            if cert.body.all_signatures_valid {
                "valid"
            } else {
                "INVALID"
            }
        );
        println!(
            "Chain:          {}",
            if cert.body.chain_continuous {
                "continuous"
            } else {
                "BROKEN"
            }
        );
        println!(
            "Scope:          {}",
            if cert.body.scope_compliant {
                "compliant"
            } else {
                "VIOLATED"
            }
        );
        println!(
            "Budget:         {}",
            if cert.body.budget_compliant {
                "compliant"
            } else {
                "EXCEEDED"
            }
        );
        println!(
            "Guards:         {}",
            if cert.body.guards_compliant {
                "compliant"
            } else {
                "BYPASSED"
            }
        );
        if !cert.body.anomalies.is_empty() {
            println!("Anomalies:");
            for a in &cert.body.anomalies {
                println!("  - {a}");
            }
        }
        println!("Signer key:     {}", cert.signer_key.to_hex());
        println!("Kernel key:     {}", cert.body.kernel_key.to_hex());
    }

    Ok(())
}

/// Load Chio receipts for a given session from the SQLite receipt store.
///
/// This queries the `chio_receipts` table for receipts whose
/// signed metadata names the exact session, independent of capability ID.
fn load_session_receipts(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Vec<ComplianceReceiptEntry>, CliError> {
    let table_exists: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chio_receipts'")
        .and_then(|mut statement| statement.exists([]))
        .map_err(|source| {
            CliError::with_source(&chio_errors::_generated::error_codes::CLI_IO, source)
        })?;
    if !table_exists {
        return Err(CliError::cli_other_error(
            "receipt store has no chio_receipts table",
        ));
    }
    let mut statement = conn.prepare(
        "SELECT rowid, CASE WHEN typeof(json_data) = 'text' AND length(CAST(json_data AS BLOB)) <= ?2 THEN json_data ELSE NULL END FROM chio_receipts WHERE CASE WHEN typeof(json_data) = 'text' AND length(CAST(json_data AS BLOB)) <= ?2 AND json_valid(json_data) THEN COALESCE(CASE WHEN json_type(json_data, '$.metadata.acp.sessionId') = 'text' THEN json_extract(json_data, '$.metadata.acp.sessionId') END, CASE WHEN json_type(json_data, '$.metadata.receipt_context.session_id') = 'text' THEN json_extract(json_data, '$.metadata.receipt_context.session_id') END) = ?1 ELSE 1 END ORDER BY rowid LIMIT ?3"
    ).map_err(|source| CliError::with_source(&chio_errors::_generated::error_codes::CLI_IO, source))?;
    let rows = statement
        .query_map(
            rusqlite::params![
                session_id,
                1024 * 1024,
                crate::input::collection::MAX_ENTRIES as i64 + 1
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|source| {
            CliError::with_source(&chio_errors::_generated::error_codes::CLI_IO, source)
        })?;
    let mut budget = crate::input::collection::Budget::default();
    let mut entries = Vec::new();
    for row in rows {
        let (seq, json_data) = row.map_err(|source| {
            CliError::with_source(&chio_errors::_generated::error_codes::CLI_IO, source)
        })?;
        budget.enter(0)?;
        budget.charge(json_data.len())?;
        let seq = u64::try_from(seq).map_err(|source| {
            CliError::with_source(&chio_errors::_generated::error_codes::CLI_IO, source)
        })?;
        let receipt = crate::input::json(json_data.as_bytes())?;
        entries.push(ComplianceReceiptEntry { receipt, seq });
    }
    Ok(entries)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn session_selection_is_exact_and_row_decoding_fails_closed() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute(
            "CREATE TABLE chio_receipts (capability_id TEXT, json_data TEXT)",
            [],
        )
        .unwrap();
        for session in ["target-extra", "targetX", "target_", "target%"] {
            db.execute(
                "INSERT INTO chio_receipts VALUES (?1, ?2)",
                rusqlite::params![
                    format!("acp-session:{session}"),
                    serde_json::json!({"metadata":{"acp":{"sessionId":session}}}).to_string()
                ],
            )
            .unwrap();
        }
        assert!(load_session_receipts(&db, "target").unwrap().is_empty());
        for exact in ["target-extra", "targetX", "target_", "target%"] {
            let error = load_session_receipts(&db, exact).unwrap_err();
            assert!(std::error::Error::source(&error).is_some());
        }
        db.execute(
            "INSERT INTO chio_receipts VALUES ('acp-session:large', ?1)",
            ["x".repeat(1024 * 1024 + 1)],
        )
        .unwrap();
        let error = load_session_receipts(&db, "large").unwrap_err();
        assert!(std::error::Error::source(&error).is_some());
        assert!(!error.to_string().contains("xxxxx"));
    }
    #[test]
    fn session_query_includes_signed_enforced_receipts_with_real_capability_ids() {
        use chio_core::receipt::kinds::*;
        use chio_core::receipt::{
            body::{ChioReceipt, ChioReceiptBody},
            decision::ToolCallAction,
        };
        let signer = chio_core::Keypair::from_seed(&[42; 32]);
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: String::new(),
                timestamp: 1,
                capability_id: "real-enforced-capability".into(),
                tool_server: "acp-proxy".into(),
                tool_name: "read".into(),
                action: ToolCallAction::from_parameters(serde_json::json!({"path":"/example"}))
                    .unwrap(),
                decision: None,
                receipt_kind: ReceiptKind::TraceObservation,
                boundary_class: BoundaryClass::DetectOnly,
                observation_outcome: Some(ObservationOutcome::Observed),
                tool_origin: ToolOrigin::CallerExecuted,
                redaction_mode: RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: "content".into(),
                policy_hash: "policy".into(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({"acp":{"sessionId":"target_%"}})),
                trust_level: TrustLevel::Verified,
                kernel_key: signer.public_key(),
                bbs_projection_version: None,
                tenant_id: None,
            },
            &signer,
        )
        .unwrap();
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute(
            "CREATE TABLE chio_receipts (capability_id TEXT, json_data TEXT)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO chio_receipts VALUES (?1, ?2)",
            rusqlite::params![
                receipt.capability_id,
                serde_json::to_string(&receipt).unwrap()
            ],
        )
        .unwrap();
        let loaded = load_session_receipts(&db, "target_%").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].receipt.id, receipt.id);
        assert!(loaded[0].receipt.verify_signature().unwrap());
        assert!(load_session_receipts(&db, "target").unwrap().is_empty());
    }

    #[test]
    fn missing_receipt_table_is_not_an_empty_success() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        assert!(load_session_receipts(&db, "target")
            .unwrap_err()
            .to_string()
            .contains("no chio_receipts"));
    }
}
