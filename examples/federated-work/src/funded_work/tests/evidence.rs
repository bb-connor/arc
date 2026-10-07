use super::native::fixture;
use crate::{common::Result, funded_work::evidence};

#[test]
fn custody_capacity_preserves_exact_retrieval_and_retries() -> Result<()> {
    let f = fixture()?;
    let first = f.native.journal.put_blob(b"original")?;
    for n in 1..crate::funded_work::journal::CAPACITY * 8 {
        f.native
            .journal
            .put_blob(format!("object-{n}").as_bytes())?;
    }
    assert!(f.native.journal.put_blob(b"overflow").is_err());
    assert_eq!(f.native.journal.put_blob(b"original")?, first);
    assert_eq!(f.native.journal.blob(&first)?, b"original");
    Ok(())
}

#[test]
fn finding_requires_the_original_retained_native_outcome() -> Result<()> {
    let f = fixture()?;
    assert!(f.native.evidence(&f.request).is_err());
    let first = f.native.execute(&f.agreement, &f.request)?;
    let original = f.native.evidence(&f.request)?;
    assert_eq!(original.binding.operation_id, first["operationId"]);
    assert_eq!(original.binding.hold_id, first["holdId"]);
    let key = crate::common::key(f.directory.path())?;
    let submission = evidence::submit(&original, &original.output, &key, &f.native.journal)?;
    let raw = chio_core_types::canonical_json_bytes(&submission)?;
    assert!(evidence::verify(
        &raw,
        &original,
        &f.native.policy,
        &f.native.journal
    )?);
    let mut changed = original;
    changed.binding.hold_id.push_str("-replacement");
    assert!(evidence::verify(&raw, &changed, &f.native.policy, &f.native.journal).is_err());
    assert!(evidence::verify(b"{}", &changed, &f.native.policy, &f.native.journal).is_err());
    Ok(())
}

#[test]
fn authenticated_wrong_result_is_rejected_without_replacing_execution() -> Result<()> {
    let f = fixture()?;
    f.native.execute(&f.agreement, &f.request)?;
    let original = f.native.evidence(&f.request)?;
    let key = crate::common::key(f.directory.path())?;
    let submission = evidence::submit(&original, &serde_json::json!([]), &key, &f.native.journal)?;
    let raw = chio_core_types::canonical_json_bytes(&submission)?;
    assert!(!evidence::verify(
        &raw,
        &original,
        &f.native.policy,
        &f.native.journal
    )?);
    assert_eq!(f.native.report(&f.request)?["executions"], 1);
    Ok(())
}

#[test]
fn custody_loss_and_noncanonical_or_forged_finding_cannot_decide() -> Result<()> {
    let f = fixture()?;
    f.native.execute(&f.agreement, &f.request)?;
    let original = f.native.evidence(&f.request)?;
    let key = crate::common::key(f.directory.path())?;
    let submission = evidence::submit(&original, &original.output, &key, &f.native.journal)?;
    let raw = chio_core_types::canonical_json_bytes(&submission)?;
    let mut spaced = vec![b' '];
    spaced.extend_from_slice(&raw);
    assert!(evidence::verify(&spaced, &original, &f.native.policy, &f.native.journal).is_err());
    let mut forged = submission.clone();
    forged.body.finding.signature = "00".repeat(64);
    forged = evidence::sign(forged.body, &key)?;
    assert!(evidence::verify(
        &chio_core_types::canonical_json_bytes(&forged)?,
        &original,
        &f.native.policy,
        &f.native.journal
    )
    .is_err());
    let fresh = fixture()?;
    assert!(evidence::verify(&raw, &original, &f.native.policy, &fresh.native.journal).is_err());
    f.native
        .journal
        .retain(&original.binding.allocation_id, "submission", &submission)?;
    f.native
        .journal
        .retain(&original.binding.allocation_id, "submission", &submission)?;
    assert!(f
        .native
        .journal
        .retain(&original.binding.allocation_id, "submission", &forged)
        .is_err());
    Ok(())
}

#[test]
#[ignore = "requires the local Node chain and CHIO_FUNDED_PYTHON; exercised by lifecycle qualification"]
fn private_chain_pays_the_original_native_operation() -> Result<()> {
    let state = tempfile::tempdir()?;
    let report = crate::funded_work::lifecycle::run(state.path(), "pay")?;
    assert_eq!(report["replay"]["nativeState"], "Completed");
    assert_eq!(report["replay"]["paymentState"], "paid");
    assert_eq!(report["replay"]["executions"], 1);
    assert_eq!(report["chain"]["beneficiaryBalance"], "100");
    Ok(())
}
