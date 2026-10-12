//! Production snapshot freshness and sequential revocation installation harnesses.

use alloc::collections::BTreeSet;
use alloc::sync::Arc;

use crate::{
    RevocationSnapshot, RevocationSnapshotFreshnessError, RevocationView, RevocationViewError,
    RevocationViewSubject,
};

/// Production freshness arithmetic over the full three-u64 input domain.
/// Returns a joint witness from additional concrete production boundary calls.
pub(super) fn verify_revocation_snapshot_timestamp_freshness() -> bool {
    let issued_at_unix_ms = kani::any::<u64>();
    let now_unix_ms = kani::any::<u64>();
    let max_staleness_ms = kani::any::<u64>();
    let snapshot = RevocationSnapshot {
        epoch: kani::any::<u64>(),
        root_hash: kani::any::<[u8; 32]>(),
        issued_at_unix_ms,
        revoked: BTreeSet::new(),
    };
    let actual = snapshot.verify_freshness(now_unix_ms, max_staleness_ms);
    let issued = u128::from(issued_at_unix_ms);
    let now = u128::from(now_unix_ms);
    let maximum_age = u128::from(max_staleness_ms);
    let expected = if issued > now {
        Err(RevocationSnapshotFreshnessError::Future)
    } else if now - issued > maximum_age {
        Err(RevocationSnapshotFreshnessError::Stale)
    } else {
        Ok(())
    };
    assert_eq!(actual, expected);

    // Evaluate every boundary call before joining their results. This witness
    // supplements the unrestricted assertion above; it does not bound inputs.
    let mut boundary = RevocationSnapshot::empty();
    let zero = boundary.verify_freshness(0, 0);
    let maximum_age = boundary.verify_freshness(u64::MAX, u64::MAX);
    let maximum_age_stale = boundary.verify_freshness(u64::MAX, u64::MAX - 1);
    boundary.issued_at_unix_ms = 10;
    let fresh = boundary.verify_freshness(12, 5);
    let threshold = boundary.verify_freshness(12, 2);
    let stale = boundary.verify_freshness(13, 2);
    let future = boundary.verify_freshness(9, 0);
    boundary.issued_at_unix_ms = u64::MAX;
    let maximum_timestamp = boundary.verify_freshness(u64::MAX, 0);
    let future_with_maximum_age = boundary.verify_freshness(u64::MAX - 1, u64::MAX);

    zero.is_ok()
        && maximum_age.is_ok()
        && maximum_age_stale == Err(RevocationSnapshotFreshnessError::Stale)
        && fresh.is_ok()
        && threshold.is_ok()
        && stale == Err(RevocationSnapshotFreshnessError::Stale)
        && future == Err(RevocationSnapshotFreshnessError::Future)
        && maximum_timestamp.is_ok()
        && future_with_maximum_age == Err(RevocationSnapshotFreshnessError::Future)
}

fn symbolic_revocation_snapshot(epoch: u64) -> RevocationSnapshot {
    // The subject fixture is every subset of these two fixed identifiers.
    // Epoch, issue time, and every root-hash byte retain their full domains.
    let mut revoked = BTreeSet::new();
    if kani::any::<bool>() {
        revoked.insert(RevocationViewSubject::from("a"));
    }
    if kani::any::<bool>() {
        revoked.insert(RevocationViewSubject::from("b"));
    }
    RevocationSnapshot {
        epoch,
        root_hash: kani::any::<[u8; 32]>(),
        issued_at_unix_ms: kani::any::<u64>(),
        revoked,
    }
}

fn assert_revocation_snapshot_payload(
    actual: &RevocationSnapshot,
    expected: &RevocationSnapshot,
    root_byte_index: usize,
) {
    assert_eq!(actual.epoch, expected.epoch);
    assert_eq!(actual.issued_at_unix_ms, expected.issued_at_unix_ms);
    // A symbolic index over all 32 positions checks every root byte without
    // introducing a fixture loop or restricting the root-hash input.
    assert_eq!(
        actual.root_hash[root_byte_index],
        expected.root_hash[root_byte_index]
    );
    assert_eq!(actual.revoked.len(), expected.revoked.len());
    let first_subject = RevocationViewSubject::from("a");
    let second_subject = RevocationViewSubject::from("b");
    assert_eq!(
        actual.is_revoked(&first_subject),
        expected.is_revoked(&first_subject)
    );
    assert_eq!(
        actual.is_revoked(&second_subject),
        expected.is_revoked(&second_subject)
    );
}

fn assert_sequential_revocation_install(
    view: &RevocationView,
    candidate: RevocationSnapshot,
    root_byte_index: usize,
) -> bool {
    let before = view.load();
    let candidate_epoch = candidate.epoch;
    let result = view.install_if_newer(candidate.clone());
    let installed = view.load();
    let advanced = match result {
        Ok(previous) => {
            assert!(candidate_epoch > before.epoch);
            assert!(Arc::ptr_eq(&previous, &before));
            assert_revocation_snapshot_payload(&installed, &candidate, root_byte_index);
            true
        }
        Err(error) => {
            assert!(candidate_epoch <= before.epoch);
            assert_eq!(
                error,
                RevocationViewError::NonMonotoneEpoch {
                    candidate: candidate_epoch,
                    installed: before.epoch,
                }
            );
            assert!(Arc::ptr_eq(&installed, &before));
            false
        }
    };

    match view.install_if_newer(candidate) {
        Err(error) => assert_eq!(
            error,
            RevocationViewError::NonMonotoneEpoch {
                candidate: candidate_epoch,
                installed: installed.epoch,
            }
        ),
        Ok(_) => panic!("repeating the candidate must not replace the installed snapshot"),
    }
    assert!(Arc::ptr_eq(&view.load(), &installed));
    advanced
}

/// Sequential calls to the production ArcSwap store, with unrestricted epochs.
///
/// The finite subject fixture is all subsets of {"a", "b"}. This harness does
/// not establish racing-writer linearizability, failed-CAS retry behavior,
/// concurrent memory reclamation, or progress under contention.
#[kani::proof]
pub fn verify_revocation_view_epoch_install_sequential() {
    let initial_epoch = kani::any::<u64>();
    let first_epoch = kani::any::<u64>();
    let second_epoch = kani::any::<u64>();
    let root_byte_index = usize::from(kani::any::<u8>());
    kani::assume(root_byte_index < 32);
    let view = RevocationView::new();
    let sentinel = view.load();
    assert_revocation_snapshot_payload(&sentinel, &RevocationSnapshot::empty(), root_byte_index);
    if initial_epoch > 0 {
        let initial = symbolic_revocation_snapshot(initial_epoch);
        match view.install_if_newer(initial.clone()) {
            Ok(previous) => assert!(Arc::ptr_eq(&previous, &sentinel)),
            Err(_) => panic!("a positive initial epoch must replace the sentinel"),
        }
        assert_revocation_snapshot_payload(&view.load(), &initial, root_byte_index);
    }

    let retained = view.load();
    let retained_payload = (*retained).clone();
    assert_eq!(retained.epoch, initial_epoch);
    let first_advanced = assert_sequential_revocation_install(
        &view,
        symbolic_revocation_snapshot(first_epoch),
        root_byte_index,
    );
    assert_revocation_snapshot_payload(&retained, &retained_payload, root_byte_index);
    let after_first_epoch = view.current_epoch();
    let second_advanced = assert_sequential_revocation_install(
        &view,
        symbolic_revocation_snapshot(second_epoch),
        root_byte_index,
    );
    assert_revocation_snapshot_payload(&retained, &retained_payload, root_byte_index);

    kani::cover!(
        initial_epoch == 0,
        "empty sentinel used as initial snapshot"
    );
    kani::cover!(initial_epoch == u64::MAX, "maximum initial epoch retained");
    kani::cover!(first_epoch == 0, "zero candidate refused");
    kani::cover!(first_epoch == initial_epoch, "equal first epoch refused");
    kani::cover!(first_epoch < initial_epoch, "older first epoch refused");
    kani::cover!(first_advanced, "newer first epoch installed");
    kani::cover!(
        first_epoch == u64::MAX && first_advanced,
        "maximum first epoch installed"
    );
    kani::cover!(
        second_epoch == after_first_epoch,
        "equal second epoch refused"
    );
    kani::cover!(
        second_epoch < after_first_epoch,
        "older second epoch refused"
    );
    kani::cover!(second_advanced, "newer second epoch installed");
    kani::cover!(
        second_epoch == u64::MAX && second_advanced,
        "maximum second epoch installed"
    );
}
