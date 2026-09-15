use crate::{
    common::{digest, Result},
    funded_work::{evidence, finding_acceptance, settlement, verification},
};
use chio_core_types::{canonical_json_bytes, receipt::lineage::SignedExportEnvelope, Keypair};
use chio_finding::FindingFacetKind;

fn required() -> Vec<FindingFacetKind> {
    vec![
        FindingFacetKind::ArtifactIntegrity,
        FindingFacetKind::ReceiptAuthenticity,
        FindingFacetKind::CheckpointMembership,
        FindingFacetKind::GuaranteeConsistency,
    ]
}

struct Checker(serde_json::Value);
impl verification::Checker for Checker {
    fn check(&self, _: &str) -> Result<serde_json::Value> {
        Ok(self.0.clone())
    }
}

#[test]
fn invalid_execution_standing_cannot_mint_either_financial_decision() -> Result<()> {
    let f = super::native::fixture_profile(required(), true)?;
    let (mut original, submission, claim) = super::wire::candidate(&f)?;
    let original_bundle = original.execution.clone().ok_or("execution missing")?;
    let verifier = crate::common::key(&f.directory.path().join("verifier"))?;
    let status = crate::common::key(&f.directory.path().join("status"))?;
    let checker = Checker(original.output.clone());
    let foreign = Keypair::generate();
    for role in 0..2 {
        for revoked in [false, true] {
            let mut bundle = original_bundle.clone();
            let mut body = bundle.signer_statuses[role].body.clone();
            if revoked {
                body.revoked_from = Some(body.observed_at);
            }
            bundle.signer_statuses[role] =
                SignedExportEnvelope::sign(body, if revoked { &status } else { &foreign })?;
            f.native.journal.connection()?.execute(
                "UPDATE records SET payload=?1 WHERE allocation=?2 AND kind='execution-evidence'",
                rusqlite::params![
                    canonical_json_bytes(&bundle)?,
                    original.binding.allocation_id
                ],
            )?;
            original.execution = Some(bundle.clone());
            let assessment = finding_acceptance::evaluate_with_evidence(
                &canonical_json_bytes(&submission.body.finding)?,
                &f.native.policy.finding_context,
                &f.agreement.body.finding_context_sha256,
                &required(),
                crate::common::now()?,
                Some(&bundle),
            )?;
            assert_eq!(assessment.outcome, finding_acceptance::Outcome::Rejected);
            assert!(verification::decide(
                &original,
                &submission,
                &claim,
                &verification::Verifier {
                    policy: &f.native.policy,
                    custody: &f.native.journal,
                    key: &verifier,
                    checker: &checker,
                }
            )
            .is_err());
            assert!(f
                .native
                .journal
                .retained::<verification::Decision>(&original.binding.allocation_id, "decision")?
                .is_none());
            for accepted in [false, true] {
                let forged = evidence::sign(
                    verification::DecisionBody {
                        schema: "chio.experimental.native-funded-decision.v2".into(),
                        binding: original.binding.clone(),
                        commitment: format!("0x{}", digest(&submission)?),
                        finding_id: submission.body.finding.finding_id.clone(),
                        checker_sha256: verification::checker_digest(),
                        claim_transaction_hash: claim.transaction_hash.clone(),
                        claim_block_hash: claim.block_hash.clone(),
                        accepted,
                        finding_assessment: assessment.clone(),
                    },
                    &verifier,
                )?;
                assert!(verification::verify_decision(
                    &forged,
                    &submission,
                    &f.native.policy,
                    &f.native.journal
                )
                .is_err());
            }
            let entry = f
                .native
                .journal
                .by_operation(&original.binding.operation_id)?
                .ok_or("entry missing")?;
            assert!(settlement::request(
                &entry,
                settlement::Action::Submit,
                &f.native.policy,
                &f.native.journal
            )
            .is_err());
        }
    }
    f.native.journal.connection()?.execute(
        "UPDATE records SET payload=?1 WHERE allocation=?2 AND kind='execution-evidence'",
        rusqlite::params![
            canonical_json_bytes(&original_bundle)?,
            original.binding.allocation_id
        ],
    )?;
    original.execution = Some(original_bundle);
    assert!(
        verification::decide(
            &original,
            &submission,
            &claim,
            &verification::Verifier {
                policy: &f.native.policy,
                custody: &f.native.journal,
                key: &verifier,
                checker: &checker,
            }
        )?
        .body
        .accepted
    );
    Ok(())
}

#[test]
fn accepted_execution_decision_replays_after_finding_expiry() -> Result<()> {
    let mut f = super::native::fixture_profile(required(), true)?;
    // A short, real validity window exercises present-time expiry without
    // injecting a different historical evaluation clock into the verifier.
    let now = crate::common::now()?;
    f.agreement.body.work.submit_by = now + 15;
    f.agreement.body.work.challenge_until = now + 16;
    f.agreement.body.work.resolve_by = now + 17;
    f.agreement.body.work.refund_after = now + 18;
    f.request = f.native.request(
        &f.request.request_id,
        include_str!("../../../fixtures/openapi.json"),
        now + 15,
    )?;
    f.agreement.body.request_sha256 = digest(&f.request)?;
    f.agreement = f
        .agreement
        .body
        .sign(&f.buyer, &crate::common::key(f.directory.path())?)?;
    super::native::bind_observation(&f.source, &f.agreement)?;
    let (original, submission, claim) = super::wire::candidate(&f)?;
    let key = crate::common::key(&f.directory.path().join("verifier"))?;
    let checker = Checker(original.output.clone());
    let decision = verification::decide(
        &original,
        &submission,
        &claim,
        &verification::Verifier {
            policy: &f.native.policy,
            custody: &f.native.journal,
            key: &key,
            checker: &checker,
        },
    )?;
    assert!(decision.body.accepted);
    let remaining = submission
        .body
        .finding
        .expires_at
        .saturating_sub(crate::common::now()?);
    std::thread::sleep(std::time::Duration::from_secs(remaining));
    assert!(crate::common::now()? >= submission.body.finding.expires_at);
    assert!(evidence::verify(
        &canonical_json_bytes(&submission)?,
        &original,
        &f.native.policy,
        &f.native.journal
    )
    .is_err());
    verification::verify_decision(&decision, &submission, &f.native.policy, &f.native.journal)?;
    let entry = f
        .native
        .journal
        .by_operation(&original.binding.operation_id)?
        .ok_or("entry missing")?;
    // Submit replay and payout preparation consume the original accepted
    // decision even when a fresh claim could no longer be issued.
    for action in [settlement::Action::Submit, settlement::Action::Pay] {
        settlement::request(&entry, action, &f.native.policy, &f.native.journal)?;
    }
    let replay = f.native.evidence(&f.request)?;
    assert_eq!(digest(&replay.execution)?, digest(&original.execution)?);
    assert_eq!(f.native.journal.execution_count()?, 1);
    Ok(())
}
