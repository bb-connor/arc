use super::*;

#[test]
fn checkpoint_equivocation_fails_before_membership() -> TestResult {
    let fx = fixture()?;
    let mut fork = fx.checkpoint.clone();
    fork.body.issued_at = fork.body.issued_at.saturating_add(1);
    fork.signature = keypair(23).sign(&canonical_json_bytes(&fork.body)?);
    let checkpoints = vec![fx.checkpoint.clone(), fork];
    let transparency = build_checkpoint_transparency(&checkpoints)?;

    assert_eq!(
        verify_checkpoint_membership(
            &fx.receipts,
            &checkpoints,
            &transparency,
            &fx.profile.body,
            &serde_json::from_str::<Finding>(&fx.raw_finding)?.evidence_checkpoint_ref,
        ),
        Err(CheckpointMembershipError::TransparencyInvalid)
    );
    Ok(())
}

#[test]
fn checkpoint_transparency_records_must_match_the_signed_set() -> TestResult {
    let fx = fixture()?;
    let mut transparency = fx.checkpoint_transparency.clone();
    transparency.publications.clear();

    assert_eq!(
        verify_checkpoint_membership(
            &fx.receipts,
            std::slice::from_ref(&fx.checkpoint),
            &transparency,
            &fx.profile.body,
            &serde_json::from_str::<Finding>(&fx.raw_finding)?.evidence_checkpoint_ref,
        ),
        Err(CheckpointMembershipError::TransparencyInvalid)
    );
    Ok(())
}
