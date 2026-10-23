use super::common::*;
use chio_core_types::canonical_json_bytes;
use chio_core_types::recovery::{
    decode_contract, SignedDisclosureGrant, SignedRecoveryExplanationReportV1,
    SignedRecoveryExplanationViewV1, SignedRecoveryGrant,
};
use chio_core_types::Keypair;
use chio_recovery::{
    explanation_report_payload, verify_explanation_view, ExplanationExpectedTrust,
    ExplanationReportInputs,
};
use chio_security_types::recovery::{
    ActorId, ApprovalIntentV1, AuthorityDomainId, BoundedList, ContractDigest, ContractError,
    DeploymentDigest, ExplanationFactStateV1, ExplanationInfluenceV1, ExplanationIntegrity,
    ExplanationViewSummaryV1, IntentDigest, IssuerId, PolicyDigest, ProcessId, RecoveryCommandV1,
    RecoveryExplanationReportV1, RecoveryScopeV1, SafeInteger, SourceDigest,
};

const NOW: u64 = OBSERVED_AT + 1;

#[test]
fn recomputation_refuses_validly_resigned_semantic_substitutions() -> Result {
    let f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    let signed = SignedRecoveryExplanationReportV1::sign(body.clone(), &f.key)?;
    f.verify(&signed, &view, NOW)?;
    let foreign = Keypair::from_seed(&[28; 32]);
    assert_eq!(
        f.verify(
            &SignedRecoveryExplanationReportV1::sign(body.clone(), &foreign)?,
            &view,
            NOW
        )
        .err(),
        Some(ContractError::BindingMismatch)
    );
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
        assert_eq!(
            f.verify(&resigned, &view, NOW).err(),
            Some(ContractError::BindingMismatch),
            "binding {field}"
        );
    }
    for (field, value) in [
        ("trust_domain", "foreign-domain"),
        ("issuer", "foreign-issuer"),
        ("recipient", "foreign-viewer"),
        ("protected_graph_ref", "foreign-reference"),
    ] {
        let mut data = serde_json::to_value(&body)?;
        data[field] = serde_json::json!(value);
        let resigned =
            SignedRecoveryExplanationReportV1::sign(serde_json::from_value(data)?, &f.key)?;
        assert!(resigned.verify_signature()?);
        assert_eq!(
            f.verify(&resigned, &view, NOW).err(),
            Some(ContractError::BindingMismatch),
            "binding {field}"
        );
    }
    let mut changed = body.clone();
    changed.scope.process_id = ProcessId::new("foreign-process")?;
    let mut limited = body.clone();
    limited.limits.work = SafeInteger::new(2000)?;
    let mut shortened = body.clone();
    shortened.expires_at_unix_ms = SafeInteger::new(EXPIRES_AT - 1000)?;
    for (name, changed) in [
        ("scope", changed),
        ("limits", limited),
        ("expiry", shortened),
    ] {
        assert_eq!(
            f.verify(
                &SignedRecoveryExplanationReportV1::sign(changed, &f.key)?,
                &view,
                NOW
            )
            .err(),
            Some(ContractError::BindingMismatch),
            "binding {name}"
        );
    }
    Ok(())
}

#[test]
fn report_validity_is_the_half_open_interval_from_issue_to_expiry() -> Result {
    let f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    assert_eq!(body.issued_at_unix_ms.get(), OBSERVED_AT);
    assert_eq!(body.expires_at_unix_ms.get(), EXPIRES_AT);
    let signed = SignedRecoveryExplanationReportV1::sign(body, &f.key)?;
    f.verify(&signed, &view, OBSERVED_AT)?;
    f.verify(&signed, &view, EXPIRES_AT - 1)?;
    for now in [OBSERVED_AT - 1, EXPIRES_AT, EXPIRES_AT + 1] {
        assert_eq!(
            f.verify(&signed, &view, now).err(),
            Some(ContractError::BindingMismatch),
            "instant {now}"
        );
    }
    Ok(())
}

#[test]
fn every_expected_trust_binding_is_required() -> Result {
    let f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    let signed = SignedRecoveryExplanationReportV1::sign(body, &f.key)?;
    let key = f.key.public_key();
    f.verify_with(&signed, &view, &f.expected(&key), NOW)?;
    let foreign_key = Keypair::from_seed(&[28; 32]).public_key();
    let foreign_domain = AuthorityDomainId::new("foreign-domain")?;
    let foreign_issuer = IssuerId::new("foreign-issuer")?;
    let foreign_scope = RecoveryScopeV1 {
        process_id: ProcessId::new("foreign-process")?,
        ..f.snapshot.scope.clone()
    };
    let mut foreign_limits = f.limits;
    foreign_limits.work = SafeInteger::new(2048)?;
    let cases: Vec<(&str, ExplanationExpectedTrust<'_>)> = vec![
        (
            "key",
            ExplanationExpectedTrust {
                key: &foreign_key,
                ..f.expected(&key)
            },
        ),
        (
            "trust_domain",
            ExplanationExpectedTrust {
                trust_domain: &foreign_domain,
                ..f.expected(&key)
            },
        ),
        (
            "issuer",
            ExplanationExpectedTrust {
                issuer: &foreign_issuer,
                ..f.expected(&key)
            },
        ),
        (
            "scope",
            ExplanationExpectedTrust {
                scope: &foreign_scope,
                ..f.expected(&key)
            },
        ),
        (
            "deployment_digest",
            ExplanationExpectedTrust {
                deployment_digest: DeploymentDigest::from_bytes([9; 32]),
                ..f.expected(&key)
            },
        ),
        (
            "policy_digest",
            ExplanationExpectedTrust {
                policy_digest: PolicyDigest::from_bytes([9; 32]),
                ..f.expected(&key)
            },
        ),
        (
            "contract_digest",
            ExplanationExpectedTrust {
                contract_digest: ContractDigest::from_bytes([9; 32]),
                ..f.expected(&key)
            },
        ),
        (
            "intent_digest",
            ExplanationExpectedTrust {
                intent_digest: IntentDigest::from_bytes([9; 32]),
                ..f.expected(&key)
            },
        ),
        (
            "limits",
            ExplanationExpectedTrust {
                limits: foreign_limits,
                ..f.expected(&key)
            },
        ),
    ];
    for (name, expected) in cases {
        assert_eq!(
            f.verify_with(&signed, &view, &expected, NOW).err(),
            Some(ContractError::BindingMismatch),
            "expected {name}"
        );
    }
    Ok(())
}

#[test]
fn original_basis_is_required_even_when_changes_leave_the_advice_identical() -> Result {
    let f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    let signed = SignedRecoveryExplanationReportV1::sign(body, &f.key)?;
    let mut version = Fixture::new()?;
    let changed_version = SafeInteger::new(99)?;
    version.mutate_fact(0, |fact| {
        if let ExplanationFactStateV1::Known { version, .. } = &mut fact.state {
            *version = changed_version;
        }
    })?;
    assert_eq!(version.payloads()?.0, view);
    assert_eq!(
        version.verify(&signed, &view, NOW).err(),
        Some(ContractError::BindingMismatch)
    );
    let mut influence = Fixture::new()?;
    influence.snapshot.influence = ExplanationInfluenceV1::Observed {
        basis: SourceDigest::from_bytes([8; 32]),
        integrity: ExplanationIntegrity::NativeOwned,
    };
    assert_eq!(influence.payloads()?.0, view);
    assert_eq!(
        influence.verify(&signed, &view, NOW).err(),
        Some(ContractError::BindingMismatch)
    );
    let mut cost = Fixture::new()?;
    cost.mutate_template(|t| t.cost.budget_units = SafeInteger::ZERO)?;
    assert_eq!(cost.payloads()?.0, view);
    assert_eq!(
        cost.verify(&signed, &view, NOW).err(),
        Some(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn projection_provenance_requires_expected_key_recipient_domain_issuer_and_time() -> Result {
    let f = Fixture::new()?;
    let (view, body) = f.payloads()?;
    let signed = SignedRecoveryExplanationViewV1::sign(view.clone(), &f.key)?;
    let key = f.key.public_key();
    let at = |now: u64| SafeInteger::new(now);
    verify_explanation_view(&signed, &key, &f.domain, &f.issuer, &f.recipient, at(NOW)?)?;
    let foreign = Keypair::from_seed(&[28; 32]).public_key();
    let foreign_domain = AuthorityDomainId::new("foreign-domain")?;
    let foreign_issuer = IssuerId::new("foreign-issuer")?;
    let other_viewer = ActorId::new("other-viewer")?;
    for (name, result) in [
        (
            "key",
            verify_explanation_view(
                &signed,
                &foreign,
                &f.domain,
                &f.issuer,
                &f.recipient,
                at(NOW)?,
            ),
        ),
        (
            "trust_domain",
            verify_explanation_view(
                &signed,
                &key,
                &foreign_domain,
                &f.issuer,
                &f.recipient,
                at(NOW)?,
            ),
        ),
        (
            "issuer",
            verify_explanation_view(
                &signed,
                &key,
                &f.domain,
                &foreign_issuer,
                &f.recipient,
                at(NOW)?,
            ),
        ),
        (
            "recipient",
            verify_explanation_view(&signed, &key, &f.domain, &f.issuer, &other_viewer, at(NOW)?),
        ),
        (
            "before issue",
            verify_explanation_view(
                &signed,
                &key,
                &f.domain,
                &f.issuer,
                &f.recipient,
                at(OBSERVED_AT - 1)?,
            ),
        ),
        (
            "at expiry",
            verify_explanation_view(
                &signed,
                &key,
                &f.domain,
                &f.issuer,
                &f.recipient,
                at(view.expires_at_unix_ms.get())?,
            ),
        ),
    ] {
        assert_eq!(
            result.err(),
            Some(ContractError::BindingMismatch),
            "view {name}"
        );
    }
    let report = SignedRecoveryExplanationReportV1::sign(body, &f.key)?;
    let mut swapped = serde_json::to_value(&signed)?;
    swapped["signature"] = serde_json::to_value(report.signature())?;
    let swapped: SignedRecoveryExplanationViewV1 = serde_json::from_value(swapped)?;
    assert!(!swapped.verify_signature()?);
    assert_eq!(
        verify_explanation_view(&swapped, &key, &f.domain, &f.issuer, &f.recipient, at(NOW)?).err(),
        Some(ContractError::BindingMismatch)
    );
    let mut changed = view.clone();
    changed.projection.candidates = BoundedList::new(vec![])?;
    changed.projection.summary = ExplanationViewSummaryV1::NoDisclosableAdvice;
    let mut inputs = ExplanationReportInputs {
        snapshot: &f.snapshot,
        registry: &f.registry,
        view: &changed,
        audience: f.audience()?,
    };
    assert_eq!(
        explanation_report_payload(&inputs, f.limits).err(),
        Some(ContractError::BindingMismatch)
    );
    inputs.view = &view;
    explanation_report_payload(&inputs, f.limits)?;
    Ok(())
}

#[test]
fn advisory_bytes_are_refused_as_every_live_authority_contract() -> Result {
    let f = Fixture::new()?;
    let (view, report) = f.payloads()?;
    let view = SignedRecoveryExplanationViewV1::sign(view, &f.key)?;
    let report = SignedRecoveryExplanationReportV1::sign(report, &f.key)?;
    let encoded = [canonical_json_bytes(&view)?, canonical_json_bytes(&report)?];
    assert!(decode_contract::<SignedRecoveryExplanationViewV1>(&encoded[0]).is_ok());
    assert!(decode_contract::<SignedRecoveryExplanationReportV1>(&encoded[1]).is_ok());
    for bytes in encoded {
        assert_eq!(
            decode_contract::<SignedRecoveryGrant>(&bytes).err(),
            Some(ContractError::Malformed)
        );
        assert_eq!(
            decode_contract::<SignedDisclosureGrant>(&bytes).err(),
            Some(ContractError::Malformed)
        );
        assert_eq!(
            decode_contract::<RecoveryCommandV1>(&bytes).err(),
            Some(ContractError::Malformed)
        );
        assert_eq!(
            decode_contract::<ApprovalIntentV1>(&bytes).err(),
            Some(ContractError::Malformed)
        );
    }
    Ok(())
}
