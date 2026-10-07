use super::common::*;
use chio_core_types::{canonical_json_bytes, recovery::*};
use chio_security_types::recovery::*;

#[test]
fn recomputation_refuses_validly_resigned_semantic_substitutions() -> Result {
    let f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    let signed = SignedRecoveryExplanationReportV1::sign(body.clone(), &f.key)?;
    f.verify(&signed, &view, 1001)?;
    let foreign = chio_core_types::Keypair::from_seed(&[28; 32]);
    assert!(f
        .verify(
            &SignedRecoveryExplanationReportV1::sign(body.clone(), &foreign)?,
            &view,
            1001
        )
        .is_err());
    for field in [
        "deployment_digest",
        "policy_digest",
        "contract_digest",
        "snapshot_digest",
        "registry_digest",
        "intent_digest",
        "evaluation_digest",
        "projection_digest",
    ] {
        let mut value = serde_json::to_value(&body)?;
        value[field][0] = serde_json::json!(99);
        let changed: RecoveryExplanationReportV1 = serde_json::from_value(value)?;
        let resigned = SignedRecoveryExplanationReportV1::sign(changed, &f.key)?;
        assert!(resigned.verify_signature()?);
        assert!(f.verify(&resigned, &view, 1001).is_err(), "binding {field}");
    }
    for (field, value) in [
        ("trust_domain", "foreign-domain"),
        ("issuer", "foreign-issuer"),
        ("recipient", "foreign-viewer"),
        ("protected_graph_ref", "foreign-reference"),
    ] {
        let mut data = serde_json::to_value(&body)?;
        data[field] = serde_json::json!(value);
        let signed =
            SignedRecoveryExplanationReportV1::sign(serde_json::from_value(data)?, &f.key)?;
        assert!(signed.verify_signature()?);
        assert!(f.verify(&signed, &view, 1001).is_err());
    }
    let mut changed = body.clone();
    changed.scope.process_id = ProcessId::new("foreign-process")?;
    assert!(f
        .verify(
            &SignedRecoveryExplanationReportV1::sign(changed, &f.key)?,
            &view,
            1001
        )
        .is_err());
    let mut changed = body.clone();
    changed.limits.work = SafeInteger::new(2000)?;
    assert!(f
        .verify(
            &SignedRecoveryExplanationReportV1::sign(changed, &f.key)?,
            &view,
            1001
        )
        .is_err());
    let mut changed = body.clone();
    changed.expires_at_unix_ms = SafeInteger::new(19000)?;
    assert!(f
        .verify(
            &SignedRecoveryExplanationReportV1::sign(changed, &f.key)?,
            &view,
            1001
        )
        .is_err());
    assert!(f.verify(&signed, &view, 999).is_err());
    assert!(f.verify(&signed, &view, 20000).is_err());
    Ok(())
}
#[test]
fn original_basis_is_required_even_when_changes_leave_the_advice_identical() -> Result {
    let mut f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    let signed = SignedRecoveryExplanationReportV1::sign(body, &f.key)?;
    let changed_version = SafeInteger::new(99)?;
    f.mutate_fact(0, |fact| {
        if let ExplanationFactStateV1::Known { version, .. } = &mut fact.state {
            *version = changed_version;
        }
    })?;
    assert!(f.verify(&signed, &view, 1001).is_err());
    let mut f = Fixture::new()?;
    f.snapshot.influence = ExplanationInfluenceV1::Observed {
        basis: SourceDigest::from_bytes([8; 32]),
        integrity: ExplanationIntegrity::NativeOwned,
    };
    assert!(f.verify(&signed, &view, 1001).is_err());
    let mut f = Fixture::new()?;
    f.mutate_template(|t| t.cost.budget_units = SafeInteger::ZERO)?;
    assert_eq!(f.payloads()?.0, view);
    assert!(f.verify(&signed, &view, 1001).is_err());
    Ok(())
}
#[test]
fn projection_provenance_requires_expected_key_recipient_and_domain() -> Result {
    let f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    let signed = SignedRecoveryExplanationViewV1::sign(view.clone(), &f.key)?;
    chio_recovery::verify_explanation_view(
        &signed,
        &f.key.public_key(),
        &f.domain,
        &f.issuer,
        &f.recipient,
        SafeInteger::new(1001)?,
    )?;
    let foreign = chio_core_types::Keypair::from_seed(&[28; 32]);
    assert!(chio_recovery::verify_explanation_view(
        &signed,
        &foreign.public_key(),
        &f.domain,
        &f.issuer,
        &f.recipient,
        SafeInteger::new(1001)?
    )
    .is_err());
    assert!(chio_recovery::verify_explanation_view(
        &signed,
        &f.key.public_key(),
        &f.domain,
        &f.issuer,
        &ActorId::new("other-viewer")?,
        SafeInteger::new(1001)?
    )
    .is_err());
    let report = SignedRecoveryExplanationReportV1::sign(body, &f.key)?;
    let mut swapped = serde_json::to_value(&signed)?;
    swapped["signature"] = serde_json::to_value(report.signature())?;
    let swapped: SignedRecoveryExplanationViewV1 = serde_json::from_value(swapped)?;
    assert!(!swapped.verify_signature()?);
    let mut changed = view.clone();
    changed.projection.candidates = BoundedList::new(vec![])?;
    changed.projection.summary = ExplanationViewSummaryV1::NoDisclosableAdvice;
    let mut inputs = chio_recovery::ExplanationReportInputs {
        snapshot: &f.snapshot,
        registry: &f.registry,
        view: &changed,
        audience: f.audience()?,
    };
    assert!(chio_recovery::explanation_report_payload(&inputs, f.limits).is_err());
    inputs.view = &view;
    assert!(chio_recovery::explanation_report_payload(&inputs, f.limits).is_ok());
    Ok(())
}
#[test]
fn advisory_bytes_are_rejected_as_every_live_authority_contract() -> Result {
    let f = Fixture::new()?;
    let (view, report) = f.payloads()?;
    let values = [
        serde_json::to_value(SignedRecoveryExplanationViewV1::sign(view, &f.key)?)?,
        serde_json::to_value(SignedRecoveryExplanationReportV1::sign(report, &f.key)?)?,
    ];
    for value in values {
        let bytes = canonical_json_bytes(&value)?;
        assert!(decode_contract::<SignedRecoveryGrantV2>(&bytes).is_err());
        assert!(decode_contract::<SignedDisclosureGrant>(&bytes).is_err());
        assert!(decode_contract::<RecoveryCommandV1>(&bytes).is_err());
        assert!(decode_contract::<ApprovalIntentV1>(&bytes).is_err());
    }
    Ok(())
}
#[test]
#[ignore = "explicit regeneration of synthetic explanation cross-language signature fixtures"]
fn export_positive() -> Result {
    let f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    let output = serde_json::json!({"format_version":1,"provenance":"synthetic pure explanation inputs, advisory signer seed 29, never execution authority",
        "snapshot":f.snapshot,"registry":f.registry,
        "evaluation":chio_recovery::evaluate_explanation(&f.snapshot,&f.registry,f.limits)?,
        "report":SignedRecoveryExplanationReportV1::sign(body,&f.key)?,"view":SignedRecoveryExplanationViewV1::sign(view,&f.key)?});
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../spec/vectors/recovery/v1/explanation-positive.json"),
        serde_json::to_string_pretty(&output)? + "\n",
    )?;
    Ok(())
}
