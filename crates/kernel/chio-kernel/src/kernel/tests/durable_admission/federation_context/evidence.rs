use super::*;
use crate::kernel::verified_treaty::TreatyVerificationEvidence;

fn retained(fixture: &Fixture) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let state = fixture.store.state.lock().map_err(|_| "test lock")?;
    Ok(serde_json::from_str(
        state
            .raw_outcome
            .as_ref()
            .ok_or("raw")?
            .federation_context_json()
            .ok_or("context")?,
    )?)
}

#[test]
fn retained_treaty_evidence_reverification_checks_original_signatures_and_keys() -> TestResult {
    let fixture = completed_fixture("retained-federation-signatures")?;
    let value = retained(&fixture)?;
    let evidence: TreatyVerificationEvidence =
        serde_json::from_value(value["treaty_evidence"].clone())?;
    let now = value["admitted_at_unix_ms"]
        .as_u64()
        .ok_or("admitted time")?;
    let origin = fixture.origin_keypair.public_key();
    let local = fixture.kernel.config.keypair.public_key();
    let material = evidence.reverify(
        &fixture.request,
        ["kernel.org-a", "kernel.org-b"],
        [&origin, &local],
        now,
    )?;
    assert_eq!(
        material.receipt_metadata()["chio_runtime"]["federation_treaty_dsse"]["treaty_binding_ref"]
            ["admission_report_sha256"],
        "3".repeat(64)
    );
    let other = Keypair::generate().public_key();
    assert!(evidence
        .reverify(
            &fixture.request,
            ["kernel.org-a", "kernel.org-b"],
            [&other, &local],
            now
        )
        .is_err());
    let mut changed = value["treaty_evidence"].clone();
    changed["envelope"]["signatures"][0]["sig"] = serde_json::json!("A".repeat(88));
    let forged: TreatyVerificationEvidence = serde_json::from_value(changed)?;
    assert!(forged
        .reverify(
            &fixture.request,
            ["kernel.org-a", "kernel.org-b"],
            [&origin, &local],
            now
        )
        .is_err());
    let mut substituted = fixture.request.clone();
    substituted.arguments = serde_json::json!({"different": true});
    assert!(evidence
        .reverify(
            &substituted,
            ["kernel.org-a", "kernel.org-b"],
            [&origin, &local],
            now
        )
        .is_err());
    // Historical verification does not extend live execution permission.
    assert!(evidence
        .reverify(
            &fixture.request,
            ["kernel.org-a", "kernel.org-b"],
            [&origin, &local],
            4_102_444_800_000
        )
        .is_err());
    Ok(())
}

#[test]
fn retained_federation_context_recovery_uses_original_pin_time() -> TestResult {
    let fixture = completed_fixture("retained-federation-expiry")?;
    let expiry = retained(&fixture)?["peer"]["rotationDue"]
        .as_u64()
        .ok_or("pin expiry")?;
    let (kernel, admissions) = recovered_kernel(&fixture)?;
    let _clock = crate::scope_fixed_runtime_for_current_thread(
        expiry.checked_add(1).ok_or("expiry overflow")?,
        [],
    );
    let response = recover(&kernel, &fixture.request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn retained_federation_context_rejects_a_changed_local_identity() -> TestResult {
    let fixture = completed_fixture("retained-federation-local-key")?;
    let (mut kernel, admissions) = recovered_kernel(&fixture)?;
    kernel.config.keypair = Keypair::generate();
    let result = recover(&kernel, &fixture.request);
    assert!(result.as_ref().is_err_and(|error| error
        .to_string()
        .contains("retained federation context does not match")));
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn retained_treaty_evidence_rejects_unknown_fields() -> TestResult {
    let fixture = completed_fixture("retained-federation-fields")?;
    let value = retained(&fixture)?;
    for field in ["root", "admission", "envelope"] {
        let mut changed = value["treaty_evidence"].clone();
        let object = if field == "root" {
            &mut changed
        } else {
            &mut changed[field]
        };
        object["ignored_authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TreatyVerificationEvidence>(changed).is_err());
    }
    Ok(())
}
