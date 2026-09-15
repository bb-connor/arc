use super::*;
use crate::funded_work::{evidence, smoke};
use chio_finding::FindingFacetKind;
use serde_json::json;

#[test]
#[ignore = "requires the owned private chain; selected by execution-evidence qualification"]
fn native_execution_receipt_is_available_before_claim_or_payment() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let f = smoke::setup(directory.path())?;
    let first = f.native.execute(&f.agreement, &f.request)?;
    assert_eq!(first["executions"], 1);
    assert_eq!(first["paymentState"], "pending");
    let original = f.native.evidence(&f.request)?;
    let submission = evidence::submit(
        &original,
        &original.output,
        &crate::common::key(directory.path())?,
        &f.native.journal,
    )?;
    assert_eq!(submission.body.finding.evidence_receipt_ids.len(), 1);
    assert_ne!(
        submission.body.finding.evidence_checkpoint_ref,
        "unavailable:pre-settlement"
    );
    assert_eq!(
        f.agreement.body.required_finding_facets,
        [
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::GuaranteeConsistency,
        ]
    );
    let chain = f.chain.request(json!({
        "method": "summary", "allocation": f.funding["allocationId"]
    }))?;
    assert_eq!(chain["state"], "Funded");
    assert_eq!(chain["events"]["ClaimSubmitted"], 0);
    assert_eq!(chain["events"]["DecisionRecorded"], 0);
    assert_eq!(chain["paid"], "0");
    let allocation = original.binding.allocation_id.as_str();
    let bundle: crate::funded_work::execution_evidence::Bundle = f
        .native
        .journal
        .retained(allocation, "execution-evidence")?
        .ok_or("execution bundle missing")?;
    let repeated = f
        .native
        .kernel
        .export_durable_execution_evidence(&f.request)?;
    assert_eq!(
        crate::common::digest(&repeated)?,
        crate::common::digest(&bundle.receipt)?
    );
    for (field, replacement) in [
        ("operation_id", "foreign-operation".to_owned()),
        ("hold_id", "foreign-hold".to_owned()),
        ("authorization_id", "foreign-authorization".to_owned()),
        ("outcome_id", "12".repeat(32)),
        ("raw_outcome_sha256", "12".repeat(32)),
        ("request_sha256", "12".repeat(32)),
    ] {
        let mut changed = bundle.clone();
        let mut body = changed.receipt.body();
        body.metadata.as_mut().ok_or("metadata missing")?["execution_evidence"][field] =
            json!(replacement);
        changed.receipt = chio_core_types::receipt::body::ChioReceipt::sign(
            body,
            &crate::common::key(directory.path())?,
        )?;
        chio_core_types::receipt::execution_evidence::verify_pre_settlement_execution_receipt(
            &changed.receipt,
            std::slice::from_ref(&f.native.policy.provider_key),
        )?;
        let error = crate::funded_work::execution_evidence::validate(
            &changed,
            &f.native.policy,
            &original.binding,
            &f.request,
        )
        .err()
        .ok_or("signed foreign source accepted")?;
        assert!(
            error.to_string().contains("original native source"),
            "{field}: {error}"
        );
        assert!(f
            .native
            .journal
            .retain(allocation, "execution-evidence", &changed)
            .is_err());
    }
    let mut unknown = serde_json::to_value(&bundle)?;
    unknown["financialBacking"] = json!(true);
    assert!(
        evidence::decode::<crate::funded_work::execution_evidence::Bundle>(
            &chio_core_types::canonical_json_bytes(&unknown)?
        )
        .is_err()
    );
    let assessment = crate::funded_work::finding_acceptance::evaluate_with_evidence(
        &chio_core_types::canonical_json_bytes(&submission.body.finding)?,
        &f.native.policy.finding_context,
        &f.agreement.body.finding_context_sha256,
        &f.agreement.body.required_finding_facets,
        crate::common::now()?,
        Some(&bundle),
    )?;
    assert_eq!(
        assessment.outcome,
        crate::funded_work::finding_acceptance::Outcome::Accepted
    );
    for facet in [
        FindingFacetKind::MeteredExposureBacking,
        FindingFacetKind::SettledSpendBacking,
    ] {
        assert_eq!(
            assessment
                .facets
                .iter()
                .find(|f| f.facet == facet)
                .ok_or("facet missing")?
                .outcome,
            chio_finding::FindingFacetOutcome::Unavailable
        );
    }
    if let Some(path) = std::env::var_os("CHIO_FUNDED_EVIDENCE_DIR") {
        let path = std::path::PathBuf::from(path);
        std::fs::write(
            path.join("execution-witness.json"),
            chio_core_types::canonical_json_bytes(&json!({
                "agreement":f.agreement,"submission":submission,"context":f.native.policy.finding_context,
                "bundle":bundle,"output":original.output
            }))?,
        )?;
        std::fs::write(
            path.join("execution-pins.json"),
            chio_core_types::canonical_json_bytes(&json!({
                "buyer":f.native.policy.buyer_key,"provider":f.native.policy.provider_key,
                "verifier":f.native.policy.verifier_key,"authorityUuid":f.native.policy.authority_uuid,
                "allocationId":f.funding["allocationId"]
            }))?,
        )?;
        std::fs::write(
            path.join("execution-assessment.json"),
            chio_core_types::canonical_json_bytes(&assessment)?,
        )?;
    }
    Ok(())
}
