use crate::{
    common::{digest, Result},
    funded_work::{checkpoint_handoff as handoff, checkpoint_operator as operator, evidence},
};
use chio_core_types::{canonical_json_bytes, Keypair};
use chio_finding::FindingFacetKind;

fn fixture() -> Result<(super::native::Fixture, tempfile::TempDir)> {
    let f = super::native::fixture_profile(
        vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::GuaranteeConsistency,
        ],
        true,
    )?;
    let separate = tempfile::tempdir()?;
    for role in ["checkpoint", "status"] {
        std::fs::rename(f.directory.path().join(role), separate.path().join(role))?;
    }
    operator::initialize(
        separate.path(),
        &operator::Enrollment {
            schema: operator::ENROLLMENT_SCHEMA.into(),
            authority_uuid: f.native.policy.authority_uuid.clone(),
            context: f.native.policy.finding_context.clone(),
        },
    )?;
    f.native.execute(&f.agreement, &f.request)?;
    Ok((f, separate))
}

#[test]
fn external_checkpoint_completes_evidence_without_provider_key_custody() -> Result<()> {
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    assert!(f.native.evidence(&f.request).is_err());
    assert_eq!(request.receipt.tool_name, "review");
    let bundle = operator::sign(separate.path(), &request)?;
    handoff::import(&f.native, &f.request, &bundle)?;
    let original = f.native.evidence(&f.request)?;
    let submission = evidence::submit(
        &original,
        &original.output,
        &crate::common::key(f.directory.path())?,
        &f.native.journal,
    )?;
    let assessment = crate::funded_work::finding_acceptance::evaluate_with_evidence(
        &canonical_json_bytes(&submission.body.finding)?,
        &f.native.policy.finding_context,
        &f.agreement.body.finding_context_sha256,
        &f.agreement.body.required_finding_facets,
        crate::common::now()?,
        original.execution.as_ref(),
    )?;
    assert_eq!(
        assessment.outcome,
        crate::funded_work::finding_acceptance::Outcome::Accepted
    );
    assert_eq!(super::native::native_counts(&f)?, (1, 1));
    assert_eq!(f.native.journal.execution_count()?, 1);
    assert_eq!(
        digest(&handoff::export(&f.native, &f.request)?)?,
        digest(&request)?
    );
    handoff::import(&f.native, &f.request, &bundle)?;
    assert!(!f.directory.path().join("checkpoint").exists());
    assert!(!f.directory.path().join("status").exists());
    Ok(())
}

#[test]
fn operator_replays_first_response_without_signers_and_rejects_other_receipts() -> Result<()> {
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    let first = operator::sign(separate.path(), &request)?;
    for role in ["checkpoint", "status"] {
        std::fs::remove_file(separate.path().join(role).join("key.seed"))?;
    }
    assert_eq!(
        canonical_json_bytes(&operator::sign(separate.path(), &request)?)?,
        canonical_json_bytes(&first)?
    );
    let mut changed = request.clone();
    let mut body = changed.receipt.body();
    body.content_hash = "12".repeat(32);
    changed.receipt = chio_core_types::receipt::body::ChioReceipt::sign(
        body,
        &crate::common::key(f.directory.path())?,
    )?;
    assert!(operator::sign(separate.path(), &changed).is_err());
    std::fs::remove_file(separate.path().join(operator::DATABASE))?;
    assert!(operator::sign(separate.path(), &request).is_err());
    assert!(!separate.path().join(operator::DATABASE).exists());
    Ok(())
}

#[test]
fn rotated_operator_key_cannot_sign_pending_original_work() -> Result<()> {
    for role in ["checkpoint", "status"] {
        let (f, separate) = fixture()?;
        let request = handoff::export(&f.native, &f.request)?;
        std::fs::write(
            separate.path().join(role).join("key.seed"),
            Keypair::generate().seed_hex(),
        )?;
        assert!(operator::sign(separate.path(), &request).is_err());
        assert!(f.native.evidence(&f.request).is_err());
    }
    Ok(())
}

#[test]
fn signed_foreign_authority_and_changed_context_cannot_consume_operator_slot() -> Result<()> {
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    let mut changed = request.clone();
    changed.context_sha256 = "ab".repeat(32);
    assert!(operator::sign(separate.path(), &changed).is_err());
    changed = request.clone();
    let mut body = changed.receipt.body();
    body.metadata.as_mut().ok_or("metadata missing")?["execution_evidence"]["authority_uuid"] =
        serde_json::json!("foreign-authority");
    changed.receipt = chio_core_types::receipt::body::ChioReceipt::sign(
        body,
        &crate::common::key(f.directory.path())?,
    )?;
    assert!(operator::sign(separate.path(), &changed).is_err());
    handoff::import(
        &f.native,
        &f.request,
        &operator::sign(separate.path(), &request)?,
    )?;
    Ok(())
}

#[test]
fn import_rejects_signed_revocation_foreign_signers_and_checkpoint_substitution() -> Result<()> {
    use chio_core_types::receipt::lineage::SignedExportEnvelope;
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    let bundle = operator::sign(separate.path(), &request)?;
    let status_key = crate::common::key(&separate.path().join("status"))?;
    let foreign = Keypair::generate();
    let allocation = f
        .native
        .original_evidence(&f.request)?
        .binding
        .allocation_id;
    for role in 0..2 {
        for revoked in [false, true] {
            let mut changed = bundle.clone();
            let mut body = changed.signer_statuses[role].body.clone();
            if revoked {
                body.revoked_from = Some(body.observed_at);
            }
            changed.signer_statuses[role] =
                SignedExportEnvelope::sign(body, if revoked { &status_key } else { &foreign })?;
            assert!(handoff::import(&f.native, &f.request, &changed).is_err());
            assert!(f
                .native
                .journal
                .retained::<serde_json::Value>(&allocation, "execution-checkpoint")?
                .is_none());
        }
    }
    let mut changed = bundle.clone();
    changed.checkpoints[0] = chio_kernel::checkpoint::build_checkpoint(
        1,
        1,
        1,
        &[canonical_json_bytes(&bundle.receipt)?],
        &Keypair::generate(),
    )?;
    changed.transparency =
        chio_kernel::checkpoint::validate_checkpoint_transparency(&changed.checkpoints)?;
    assert!(handoff::import(&f.native, &f.request, &changed).is_err());
    handoff::import(&f.native, &f.request, &bundle)?;
    Ok(())
}

#[test]
fn external_custody_loss_after_finding_cannot_be_repaired_by_resigning() -> Result<()> {
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    let bundle = operator::sign(separate.path(), &request)?;
    handoff::import(&f.native, &f.request, &bundle)?;
    let original = f.native.evidence(&f.request)?;
    let allocation = &original.binding.allocation_id;
    // A partial first import can complete with the original checkpoint intact.
    f.native
        .journal
        .connection()?
        .execute("DELETE FROM records WHERE kind='execution-evidence'", [])?;
    handoff::import(&f.native, &f.request, &bundle)?;
    let submission = evidence::submit(
        &original,
        &original.output,
        &crate::common::key(f.directory.path())?,
        &f.native.journal,
    )?;
    f.native
        .journal
        .retain(allocation, "submission", &submission)?;
    f.native
        .journal
        .connection()?
        .execute("DELETE FROM records WHERE kind='execution-evidence'", [])?;
    assert!(handoff::import(&f.native, &f.request, &bundle).is_err());
    assert!(f.native.evidence(&f.request).is_err());
    Ok(())
}

#[test]
fn local_and_external_checkpoint_writers_cannot_both_claim_first_custody() -> Result<()> {
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    let bundle = operator::sign(separate.path(), &request)?;
    let allocation = f
        .native
        .original_evidence(&f.request)?
        .binding
        .allocation_id;
    assert!(f
        .native
        .journal
        .retain_before(
            &allocation,
            "execution-checkpoint",
            &bundle.checkpoints[0],
            &["execution-request"]
        )
        .is_err());
    assert!(f
        .native
        .journal
        .retained::<serde_json::Value>(&allocation, "execution-checkpoint")?
        .is_none());
    handoff::import(&f.native, &f.request, &bundle)?;
    Ok(())
}

#[test]
fn operator_custody_corruption_cannot_publish_a_replacement_response() -> Result<()> {
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    let bundle = operator::sign(separate.path(), &request)?;
    let database = rusqlite::Connection::open(separate.path().join(operator::DATABASE))?;
    assert!(database.execute("DELETE FROM custody", []).is_err());
    assert!(database
        .execute("UPDATE custody SET request=NULL,response=NULL", [])
        .is_err());
    database.execute_batch("DROP TRIGGER custody_no_replace;")?;
    let mut changed = bundle.clone();
    changed.receipt.content_hash = "ab".repeat(32);
    database.execute(
        "UPDATE custody SET response=?1",
        [canonical_json_bytes(&changed)?],
    )?;
    assert!(operator::sign(separate.path(), &request).is_err());
    database.execute_batch("DROP TRIGGER custody_no_delete; DELETE FROM custody;")?;
    assert!(operator::sign(separate.path(), &request).is_err());
    Ok(())
}

#[test]
fn concurrent_operator_connections_retain_one_identical_response() -> Result<()> {
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    let responses = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| operator::sign(separate.path(), &request)))
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "operator worker panicked")?)
            .collect::<Result<Vec<_>>>()
    })?;
    for response in &responses[1..] {
        assert_eq!(
            canonical_json_bytes(response)?,
            canonical_json_bytes(&responses[0])?
        );
    }
    handoff::import(&f.native, &f.request, &responses[0])?;
    assert_eq!(f.native.journal.execution_count()?, 1);
    Ok(())
}

#[test]
fn failed_response_publication_replays_committed_bytes_without_keys() -> Result<()> {
    let (f, separate) = fixture()?;
    let request = handoff::export(&f.native, &f.request)?;
    let path = separate.path().join("request.json");
    std::fs::write(&path, canonical_json_bytes(&request)?)?;
    let occupied = separate.path().join("occupied.json");
    std::fs::write(&occupied, b"preserve existing bytes")?;
    assert!(operator::sign_file(separate.path(), &path, &occupied).is_err());
    assert_eq!(std::fs::read(&occupied)?, b"preserve existing bytes");
    for role in ["checkpoint", "status"] {
        std::fs::remove_file(separate.path().join(role).join("key.seed"))?;
    }
    let output = separate.path().join("recovered.json");
    operator::sign_file(separate.path(), &path, &output)?;
    let bundle = evidence::read(&output)?;
    handoff::import(&f.native, &f.request, &bundle)?;
    Ok(())
}
