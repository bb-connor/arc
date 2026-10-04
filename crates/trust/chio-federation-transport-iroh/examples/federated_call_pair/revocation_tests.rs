use super::*;
use chio_federation_transport_iroh::lanes::revocation::RevocationRootSink;

#[test]
fn rejected_or_inexact_acknowledgments_are_not_delivered_epochs() {
    use chio_federation_transport_iroh::lanes::revocation::RevocationLaneResponse;
    assert!(!revocation::accepted_epoch(
        &RevocationLaneResponse::Rejected {
            code: "sink-rejected".into(),
            message: "missing materialization".into(),
        },
        7
    ));
    for merged_epochs in [vec![], vec![6], vec![8], vec![7, 7], vec![6, 7]] {
        assert!(!revocation::accepted_epoch(
            &RevocationLaneResponse::PushAccepted { merged_epochs },
            7
        ));
    }
    assert!(revocation::accepted_epoch(
        &RevocationLaneResponse::PushAccepted {
            merged_epochs: vec![7]
        },
        7
    ));
}

#[test]
fn unannounced_root_cannot_refresh_revocation_snapshot() -> Result<(), BoxError> {
    let view = Arc::new(RevocationView::new());
    let subjects = Arc::new(OriginPublishedSubjects::default());
    let sink = OriginRevocationSink::new(view.clone(), subjects);
    let mut oracle = InMemoryRevocationOracle::new();
    let root = oracle.insert(
        RevocationKey::new("revoked-capability", EpochNonce::new(0)),
        1_000,
    )?;
    let signer = Ed25519RootSigner::new("origin", Keypair::from_seed(&[71; 32]));
    let signed = SignedEpochRoot::sign(root, &signer)?;
    // Root delivery can succeed while the separate subjects lane is unavailable,
    // or after a receiver restart erased its materialized subjects.
    assert!(sink.merge_batch(&[signed]).is_err());
    assert_eq!(view.current_epoch(), 0);
    assert_eq!(view.load().issued_at_unix_ms, 0);
    Ok(())
}

fn signed(root: EpochRoot) -> Result<SignedEpochRoot, BoxError> {
    Ok(SignedEpochRoot::sign(
        root,
        &Ed25519RootSigner::new("origin", Keypair::from_seed(&[71; 32])),
    )?)
}

#[test]
fn complete_snapshots_revoke_and_reset_only_under_their_exact_root() -> Result<(), BoxError> {
    let view = Arc::new(RevocationView::new());
    let subjects = Arc::new(OriginPublishedSubjects::default());
    let sink = OriginRevocationSink::new(view.clone(), subjects.clone());
    let names = vec!["cap-a".into(), "cap-b".into()];
    let root = materialized_root(1, 1_000, &names)?;
    subjects.install(&root, &names)?;
    sink.merge_root(&signed(root.clone())?)?;
    assert!(view.load().is_revoked(&RevocationViewSubject::new("cap-a")));
    assert_eq!(view.load().revoked.len(), 2);
    // An identical announcement/root retry is harmless and does not lose leaves.
    subjects.install(&root, &names)?;
    sink.merge_root(&signed(root)?)?;
    // Trial reset requires a newly announced empty root, not just a newer epoch
    // stamped onto the previous commitment.
    let reset = materialized_root(2, 2_000, &[])?;
    assert!(sink.merge_root(&signed(reset.clone())?).is_err());
    assert_eq!(view.current_epoch(), 1);
    assert_eq!(view.load().revoked.len(), 2);
    subjects.install(&reset, &[])?;
    sink.merge_root(&signed(reset)?)?;
    assert!(view.load().revoked.is_empty());
    assert_eq!(view.current_epoch(), 2);
    Ok(())
}

#[test]
fn root_substitution_and_mixed_batches_never_advance_freshness() -> Result<(), BoxError> {
    let names = vec!["cap-a".into()];
    let root = materialized_root(4, 4_000, &names)?;
    for field in ["hash", "count", "epoch", "time"] {
        let view = Arc::new(RevocationView::new());
        let subjects = Arc::new(OriginPublishedSubjects::default());
        let sink = OriginRevocationSink::new(view.clone(), subjects.clone());
        subjects.install(&root, &names)?;
        let mut changed = root.clone();
        match field {
            "hash" => changed.root_hash[0] ^= 1,
            "count" => changed.leaf_count += 1,
            "epoch" => changed.epoch += 1,
            _ => changed.issued_at_unix_ms += 1,
        }
        for batch in [
            vec![signed(root.clone())?, signed(changed.clone())?],
            vec![signed(changed)?, signed(root.clone())?],
        ] {
            assert!(sink.merge_batch(&batch).is_err(), "{field}");
            assert_eq!(view.current_epoch(), 0, "{field}");
            assert_eq!(view.load().issued_at_unix_ms, 0, "{field}");
        }
    }
    Ok(())
}

#[test]
fn missing_duplicate_or_reordered_subjects_cannot_satisfy_a_root() -> Result<(), BoxError> {
    let names = vec!["cap-a".into(), "cap-b".into()];
    let root = materialized_root(1, 1_000, &names)?;
    let subjects = OriginPublishedSubjects::default();
    for invalid in [
        vec![],
        vec!["cap-a".into()],
        vec!["cap-b".into(), "cap-a".into()],
        vec!["cap-a".into(), "cap-a".into()],
    ] {
        assert!(subjects.install(&root, &invalid).is_err());
    }
    subjects.install(&root, &names)?;
    let conflict = materialized_root(1, 1_000, &[])?;
    assert!(subjects.install(&conflict, &[]).is_err());
    assert!(subjects
        .install(&materialized_root(2, 999, &names)?, &names)
        .is_err());
    subjects.install(&materialized_root(2, 2_000, &names)?, &names)?;
    assert!(subjects.install(&root, &names).is_err());
    Ok(())
}

#[test]
fn receiver_restart_requires_rematerialization_before_heartbeat() -> Result<(), BoxError> {
    let view = Arc::new(RevocationView::new());
    let subjects = Arc::new(OriginPublishedSubjects::default());
    let sink = OriginRevocationSink::new(view.clone(), subjects.clone());
    let names = vec!["cap-a".into()];
    let root = materialized_root(2, 2_000, &names)?;
    subjects.install(&root, &names)?;
    sink.merge_root(&signed(root)?)?;
    let after_restart = Arc::new(OriginPublishedSubjects::default());
    let restarted = OriginRevocationSink::new(view.clone(), after_restart.clone());
    let heartbeat = materialized_root(3, 3_000, &names)?;
    assert!(restarted.merge_root(&signed(heartbeat.clone())?).is_err());
    assert_eq!(view.current_epoch(), 2);
    assert_eq!(view.load().issued_at_unix_ms, 2_000);
    after_restart.install(&heartbeat, &names)?;
    restarted.merge_root(&signed(heartbeat)?)?;
    assert_eq!(view.current_epoch(), 3);
    assert!(view.load().is_revoked(&RevocationViewSubject::new("cap-a")));
    Ok(())
}
