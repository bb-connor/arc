#[path = "../../../security/chio-quarantine/tests/response_support/simulation.rs"]
mod support;

use chio_core::{receipt::body::ChioReceipt, Ed25519Backend, Keypair, SigningBackend};
use chio_kernel::response_simulation_report::{
    verify_response_simulation_receipt, ResponseSimulationReport,
};
use chio_quarantine::simulation::evaluate_response_simulation;
use chio_security_types::{ports::*, response_simulation::*};
use chio_store_sqlite::{security_state::SqliteSecurityStateStore, SqliteReceiptStore};
use support::{fixture, TestResult};

fn signed_report() -> TestResult<(ResponseSimulationReport, ChioReceipt, chio_core::PublicKey)> {
    let (plan, snapshot) = fixture(Some(4000))?;
    assert_eq!(RESPONSE_SIMULATION_SCHEMA, "chio.response-simulation.v1");
    let report = ResponseSimulationReport {
        schema: RESPONSE_SIMULATION_SCHEMA.to_owned(),
        configuration_digest: Digest32::new([11; 32]),
        authorization_capability_hash: hex::encode(
            plan.operator_capability.capability_digest.as_bytes(),
        ),
        governed_intent_hash: "22".repeat(32),
        policy_decision_hash: "33".repeat(32),
        approval_set_hash: None,
        authorized_at_unix_ms: 1000,
        evaluation: evaluate_response_simulation(&plan, &snapshot)?,
        plan,
        snapshot,
    };
    let signer = Ed25519Backend::new(Keypair::from_seed(&[71; 32]));
    let receipt =
        ChioReceipt::sign_with_backend(report.receipt_body(signer.public_key())?, &signer)?;
    Ok((report, receipt, signer.public_key()))
}

#[test]
fn response_dry_run_signed_report_round_trips_real_receipt_store_and_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipts.sqlite");
    let (report, receipt, signer) = signed_report()?;
    let evidence_id = report.evidence_id()?;
    let store = SqliteReceiptStore::open(&path)?;
    store.append_indexed_security_evidence(&evidence_id, &receipt)?;
    drop(store);
    let store = SqliteReceiptStore::open(&path)?;
    let retained = store
        .load_indexed_security_evidence(&evidence_id)?
        .ok_or("report missing after restart")?;
    let verified = verify_response_simulation_receipt(
        &retained,
        &evidence_id,
        &signer,
        report.configuration_digest,
    )?;
    assert_eq!(verified, report);
    assert_eq!(retained.id, receipt.id);
    assert_eq!(verified.evaluation.apply.len(), 6);
    assert_eq!(verified.evaluation.expiry.len(), 10);
    Ok(())
}

#[test]
fn response_dry_run_verification_refuses_tampering_wrong_trust_and_configuration() -> TestResult {
    let (report, mut receipt, signer) = signed_report()?;
    let id = report.evidence_id()?;
    let backend = Ed25519Backend::new(Keypair::from_seed(&[71; 32]));
    for substitution in ["receipt_kind", "model_result", "execution_mode"] {
        let mut body = receipt.body();
        // Re-sign with a freshly derived id, without adding a signing nonce
        // that would exercise closed-metadata rejection before this mutation.
        body.id.clear();
        match substitution {
            "receipt_kind" => body.tool_name = "response_completion".to_owned(),
            "model_result" => {
                body.metadata.as_mut().ok_or("missing metadata")?["response_simulation_report"]
                    ["evaluation"]["apply"][0]["outcome"] =
                    serde_json::json!("would_deliver_alert");
            }
            "execution_mode" => {
                body.metadata.as_mut().ok_or("missing metadata")?["response_simulation_report"]
                    ["plan"]["execution"]["mode"] = serde_json::json!("live");
            }
            _ => unreachable!(),
        }
        let rebound = ChioReceipt::sign_with_backend(body, &backend)?;
        assert!(rebound.verify_signature()?);
        let error =
            verify_response_simulation_receipt(&rebound, &id, &signer, report.configuration_digest)
                .err()
                .ok_or("valid signature hid a changed report contract")?;
        assert_eq!(
            error.kind(),
            PortErrorKind::IntegrityFailure,
            "{substitution}"
        );
    }
    let wrong_signer = Keypair::from_seed(&[72; 32]).public_key();
    for (key, config) in [
        (&wrong_signer, report.configuration_digest),
        (&signer, Digest32::new([12; 32])),
    ] {
        let error = verify_response_simulation_receipt(&receipt, &id, key, config)
            .err()
            .ok_or("untrusted report accepted")?;
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
    receipt.tool_name = "response_completion".to_owned();
    let error =
        verify_response_simulation_receipt(&receipt, &id, &signer, report.configuration_digest)
            .err()
            .ok_or("live evidence substitution accepted")?;
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    Ok(())
}

#[test]
fn response_dry_run_sqlite_capture_reads_all_five_stateful_targets_without_creating_work(
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.sqlite");
    let store = SqliteSecurityStateStore::open(&path)?;
    let (plan, expected) = fixture(None)?;
    let captured = store.capture_response_simulation(&plan)?;
    assert_eq!(captured.states.len(), expected.states.len());
    for effect in plan.effects.as_slice() {
        if effect.kind == chio_security_types::ResponseEffectKind::EscalateAlert {
            continue;
        }
        let observed = captured
            .states
            .as_slice()
            .iter()
            .find(|state| state.matches(&plan, effect) == Ok(true))
            .ok_or("snapshot target missing")?;
        let original = expected
            .states
            .as_slice()
            .iter()
            .find(|state| state.matches(&plan, effect) == Ok(true))
            .ok_or("fixture target missing")?;
        assert_eq!(observed, original);
    }
    assert_eq!(captured.plan_hash, plan.plan_hash);
    let connection = rusqlite::Connection::open(&path)?;
    for table in [
        "security_response_dispatches",
        "security_session_throttle_effects",
        "security_egress_restriction_effects",
        "security_effect_contributions",
        "security_capability_set_suspension_effects",
        "security_issuance_freeze_effects",
    ] {
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 0, "capture mutated {table}");
    }
    Ok(())
}
