use super::*;
use chio_core_types::canonical_json_bytes;
use serde_json::Value;

#[test]
fn original_agreement_commits_finding_context_and_required_facets() -> Result<()> {
    let fixture = super::native::fixture()?;
    let agreement = serde_json::to_value(&fixture.agreement)?;
    let policy = serde_json::to_value(&fixture.native.policy)?;
    assert!(
        policy["findingContext"].is_object(),
        "missing original verifier context"
    );
    assert_eq!(
        agreement["body"]["findingContextSha256"],
        crate::common::digest(&policy["findingContext"])?
    );
    assert_eq!(
        agreement["body"]["requiredFindingFacets"],
        policy["requiredFindingFacets"]
    );
    assert_eq!(
        agreement["body"]["schema"],
        "chio.experimental.native-funded-w0-agreement.v2"
    );
    let raw = canonical_json_bytes(&fixture.agreement)?;
    let decoded: super::super::agreement::SignedAgreement = super::super::evidence::decode(&raw)?;
    decoded.validate(&fixture.native.policy, &fixture.request)?;
    Ok(())
}

#[test]
fn canonical_signed_artifact_decoding_rejects_raw_ambiguity() -> Result<()> {
    let fixture = super::native::fixture()?;
    let raw = canonical_json_bytes(&fixture.agreement)?;
    let value: Value = serde_json::from_slice(&raw)?;
    let mut alternatives = vec![serde_json::to_vec_pretty(&value)?];
    let mut with_null = value.clone();
    with_null["body"]["captureWaiverTerms"] = Value::Null;
    alternatives.push(canonical_json_bytes(&with_null)?);
    let mut unknown = value.clone();
    unknown["body"]["unsignedOverride"] = Value::Bool(true);
    alternatives.push(canonical_json_bytes(&unknown)?);
    let text = String::from_utf8(raw)?;
    alternatives.push(
        text.replacen("\"body\":", "\"body\":{},\"body\":", 1)
            .into_bytes(),
    );
    for raw in alternatives {
        assert!(
            super::super::evidence::decode::<super::super::agreement::SignedAgreement>(&raw)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn signed_requirement_or_context_substitution_cannot_admit_work() -> Result<()> {
    let f = super::native::fixture()?;
    let provider = crate::common::key(f.directory.path())?;
    for mutation in 0..4 {
        let mut body = f.agreement.body.clone();
        match mutation {
            0 => body.finding_context_sha256 = "f".repeat(64),
            1 => {
                body.required_finding_facets.pop();
            }
            2 => body
                .required_finding_facets
                .insert(1, chio_finding::FindingFacetKind::ReceiptAuthenticity),
            _ => body.schema = "chio.experimental.native-funded-w0-agreement.v1".into(),
        }
        let signed = body.sign(&f.buyer, &provider)?;
        assert!(
            f.native.execute(&signed, &f.request).is_err(),
            "mutation {mutation}"
        );
        assert!(f
            .native
            .journal
            .by_request(&f.request.request_id)?
            .is_none());
        assert!(f.native.operation(&f.request)?.is_none());
    }
    Ok(())
}

struct LocalChecker(Value);
impl super::super::verification::Checker for LocalChecker {
    fn check(&self, _: &str) -> Result<Value> {
        Ok(self.0.clone())
    }
}

fn candidate(
    f: &super::native::Fixture,
) -> Result<(
    super::super::evidence::Evidence,
    super::super::evidence::Submission,
    super::super::settlement_observer::Verified,
)> {
    use crate::{
        common::digest,
        funded_work::{evidence, settlement, settlement_observer},
    };
    f.native.execute(&f.agreement, &f.request)?;
    let original = f.native.evidence(&f.request)?;
    let submission = evidence::submit(
        &original,
        &original.output,
        &crate::common::key(f.directory.path())?,
        &f.native.journal,
    )?;
    f.native
        .journal
        .retain(&original.binding.allocation_id, "submission", &submission)?;
    // Unit boundary input. Actual inclusion is separately exercised by the
    // owned-chain lifecycle tests; this value is not published as rail proof.
    let claim = settlement_observer::Verified {
        allocation_id: original.binding.allocation_id.clone(),
        commitment: Some(format!("0x{}", digest(&submission)?)),
        state: 2,
        action: settlement::Action::Submit,
        transaction_hash: format!("0x{}", "a".repeat(64)),
        observation_sha256: "b".repeat(64),
        block_hash: format!("0x{}", "c".repeat(64)),
        block_number: 10,
        chain_time: f.agreement.body.work.challenge_until + 1,
    };
    Ok((original, submission, claim))
}

#[test]
fn unavailable_or_unsupported_finding_facets_cannot_mint_financial_decisions() -> Result<()> {
    use crate::funded_work::verification::{decide, Verifier};
    use chio_finding::FindingFacetKind::*;
    for missing in [
        ReceiptAuthenticity,
        BondBacking,
        IssuerLineage,
        IntentBinding,
    ] {
        let f = super::native::fixture_with_requirements(vec![
            ArtifactIntegrity,
            missing,
            GuaranteeConsistency,
        ])?;
        let (original, submission, claim) = candidate(&f)?;
        let key = crate::common::key(&f.directory.path().join("verifier"))?;
        let checker = LocalChecker(original.output.clone());
        let error = decide(
            &original,
            &submission,
            &claim,
            &Verifier {
                policy: &f.native.policy,
                custody: &f.native.journal,
                key: &key,
                checker: &checker,
            },
        )
        .err()
        .ok_or("required missing facet authorized a decision")?;
        let expected = if matches!(missing, IssuerLineage | IntentBinding) {
            "Unsupported"
        } else {
            "Unavailable"
        };
        assert!(error.to_string().contains(expected), "{missing:?}: {error}");
        assert!(f
            .native
            .journal
            .retained::<Value>(&original.binding.allocation_id, "decision")?
            .is_none());
        let report = f.native.report(&f.request)?;
        assert_eq!(report["executions"], 1);
        assert_eq!(report["nativePaymentState"], "Settling");
    }
    Ok(())
}

#[test]
fn signed_decision_cannot_override_missing_or_changed_finding_authority() -> Result<()> {
    use crate::funded_work::{
        evidence,
        finding_acceptance::Outcome,
        verification::{self, Verifier},
    };
    let f = super::native::fixture()?;
    let (original, submission, claim) = candidate(&f)?;
    let key = crate::common::key(&f.directory.path().join("verifier"))?;
    let checker = LocalChecker(original.output.clone());
    let decision = verification::decide(
        &original,
        &submission,
        &claim,
        &Verifier {
            policy: &f.native.policy,
            custody: &f.native.journal,
            key: &key,
            checker: &checker,
        },
    )?;
    verification::verify_decision(&decision, &submission, &f.native.policy)?;
    for mutation in 0..7 {
        let mut body = decision.body.clone();
        match mutation {
            0 => body.finding_assessment.context_sha256 = "f".repeat(64),
            1 => {
                body.finding_assessment.required_facets.pop();
            }
            2 => {
                body.finding_assessment.facets[0].outcome =
                    chio_finding::FindingFacetOutcome::Unavailable
            }
            3 => body.finding_assessment.outcome = Outcome::Unavailable,
            4 => {
                body.finding_assessment.evaluated_at =
                    f.native.policy.finding_context.profile.body.expires_at
            }
            5 => body.schema = "chio.experimental.native-funded-decision.v1".into(),
            _ => {
                body.finding_assessment.facets[1].outcome =
                    chio_finding::FindingFacetOutcome::Failed
            }
        }
        let signed = evidence::sign(body, &key)?;
        assert!(
            verification::verify_decision(&signed, &submission, &f.native.policy).is_err(),
            "mutation {mutation}"
        );
    }
    let mut changed = f.native.policy.clone();
    changed
        .required_finding_facets
        .insert(1, chio_finding::FindingFacetKind::ReceiptAuthenticity);
    assert!(verification::verify_decision(&decision, &submission, &changed).is_err());
    Ok(())
}

#[test]
fn registered_artifact_vectors_cover_current_signed_shapes() -> Result<()> {
    use crate::{
        common::digest,
        funded_work::{
            child::Dependency,
            evidence,
            verification::{self, Verifier},
            wire,
        },
    };
    let f = super::native::fixture()?;
    let child = super::native::fixture()?;
    let (original, submission, claim) = candidate(&f)?;
    let key = crate::common::key(&f.directory.path().join("verifier"))?;
    let checker = LocalChecker(original.output.clone());
    let decision = verification::decide(
        &original,
        &submission,
        &claim,
        &Verifier {
            policy: &f.native.policy,
            custody: &f.native.journal,
            key: &key,
            checker: &checker,
        },
    )?;
    let dependency = evidence::sign(
        Dependency {
            schema: chio_core_types::CHIO_EXPERIMENTAL_NATIVE_FUNDED_DEPENDENCY_V1_SCHEMA.into(),
            parent_agreement: digest(&f.agreement)?,
            child_agreement: digest(&child.agreement)?,
            parent_request: digest(&f.request)?,
            child_request: digest(&child.request)?,
            parent_authority: f.native.policy.authority_uuid.clone(),
            child_authority: child.native.policy.authority_uuid.clone(),
            input_sha256: chio_core_types::sha256_hex(original.input.as_bytes()),
        },
        &crate::common::key(f.directory.path())?,
    )?;
    let values = [
        ("agreement", canonical_json_bytes(&f.agreement)?),
        ("submission", canonical_json_bytes(&submission)?),
        ("dependency", canonical_json_bytes(&dependency)?),
        ("decision", canonical_json_bytes(&decision)?),
    ];
    for (name, raw) in values {
        assert_eq!(wire::parse(&raw)?["authorityVerified"], false);
        if let Some(path) = std::env::var_os("CHIO_WORK_VECTOR_OUTPUT") {
            std::fs::create_dir_all(&path)?;
            std::fs::write(
                std::path::PathBuf::from(path).join(format!("{name}.json")),
                raw,
            )?;
        }
    }
    Ok(())
}

#[test]
fn shared_malformed_vectors_match_the_registered_rust_parser() -> Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/registered-work");
    let manifest: Value = serde_json::from_slice(&std::fs::read(root.join("manifest.json"))?)?;
    let cases = manifest["cases"].as_array().ok_or("vector cases missing")?;
    assert!(cases.len() >= 57);
    for case in cases {
        let path = root.join(case["file"].as_str().ok_or("vector file missing")?);
        let accepted = case["accepted"]
            .as_bool()
            .ok_or("vector expectation missing")?;
        let result = crate::funded_work::wire::parse(&std::fs::read(path)?);
        assert_eq!(
            result.is_ok(),
            accepted,
            "{}: {:?}",
            case["name"],
            result.err().map(|e| e.to_string())
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires the owned Node chain and pinned Python checker; selected by registered-work qualification"]
fn required_facet_failure_times_out_without_a_chain_decision_or_payment() -> Result<()> {
    use crate::funded_work::{finding_acceptance, lifecycle, local_chain::LocalChain, smoke};
    use chio_finding::FindingFacetKind::*;
    use serde_json::json;
    use std::sync::Arc;
    for (name, required, expected) in [
        (
            "required-receipt-unavailable",
            ReceiptAuthenticity,
            "Unavailable",
        ),
        ("required-lineage-unsupported", IssuerLineage, "Unsupported"),
    ] {
        let state = tempfile::tempdir()?;
        let chain = Arc::new(LocalChain::start()?);
        let setup = chain.request(json!({"method":"initialize"}))?;
        let scenario = smoke::setup_with_requirements(
            state.path(),
            chain.clone(),
            &setup,
            &chio_core_types::Keypair::generate(),
            "funded-facet-denial",
            vec![ArtifactIntegrity, required, GuaranteeConsistency],
        )?;
        let native = &scenario.native;
        chain
            .request(json!({"method":"pin-verifier","key":native.policy.verifier_key.to_hex()}))?;
        let first = native.execute(&scenario.agreement, &scenario.request)?;
        let checkpoint: crate::funded_work::Checkpoint = Arc::new(|_| Ok(()));
        let advance = |phase: &str| -> Result<()> {
            chain.request(json!({"method":"advance","allocation":scenario.funding["allocationId"],"phase":phase}))?;
            Ok(())
        };
        let error = lifecycle::progress(
            state.path(),
            native,
            &scenario.request,
            "pay",
            &checkpoint,
            &advance,
        )
        .err()
        .ok_or("missing facet authorized settlement")?;
        assert!(error.to_string().contains(expected), "{error}");
        let allocation = scenario.funding["allocationId"]
            .as_str()
            .ok_or("allocation missing")?;
        assert!(native
            .journal
            .retained::<Value>(allocation, "decision")?
            .is_none());
        let submission: crate::funded_work::evidence::Submission = native
            .journal
            .retained(allocation, "submission")?
            .ok_or("submission missing")?;
        let assessment = finding_acceptance::evaluate_finding(
            &submission.body.finding,
            &native.policy.finding_context,
            &scenario.agreement.body.finding_context_sha256,
            &scenario.agreement.body.required_finding_facets,
            crate::common::now()?,
        )?;
        assert_ne!(assessment.outcome, finding_acceptance::Outcome::Accepted);
        advance("refund")?;
        let refund = lifecycle::progress(
            state.path(),
            native,
            &scenario.request,
            "pay",
            &checkpoint,
            &advance,
        )?;
        assert_eq!(refund["financial"], "refund");
        let summary = chain.request(json!({"method":"summary","allocation":allocation}))?;
        assert_eq!(summary["events"]["ClaimSubmitted"], 1);
        assert_eq!(summary["events"]["DecisionRecorded"], 0);
        assert_eq!(summary["events"]["Paid"], 0);
        assert_eq!(summary["refunded"], "100");
        assert_eq!(summary["payerBalance"], "1000");
        assert_eq!(native.report(&scenario.request)?["executions"], 1);
        if let Some(path) = std::env::var_os("CHIO_FUNDED_EVIDENCE_DIR") {
            let report = json!({"first":first,"requirements":scenario.agreement.body.required_finding_facets,
                "assessment":assessment,"denial":error.to_string(),"refund":refund,"chain":summary});
            std::fs::write(
                std::path::PathBuf::from(path).join(format!("{name}.json")),
                serde_json::to_vec_pretty(&report)?,
            )?;
        }
    }
    Ok(())
}
