//! Complete revocation snapshots for this experiment's two delivery lanes.
use super::*;
use chio_federation_transport_iroh::lanes::revocation::{
    RevocationLaneError, RevocationLaneResponse, RevocationRootSink,
};
use chio_kernel_core::RevocationSnapshot;

pub(super) fn accepted_epoch(response: &RevocationLaneResponse, epoch: u64) -> bool {
    matches!(response, RevocationLaneResponse::PushAccepted { merged_epochs } if merged_epochs.as_slice() == [epoch])
}

/// Reconstruct the complete, canonically ordered leaf set. The experiment's
/// control file can reset its revocations between trials; each reset produces a
/// different root. This is not an append-only production revocation authority.
pub(super) fn materialized_root(
    epoch: u64,
    issued_at_unix_ms: u64,
    subjects: &[String],
) -> Result<EpochRoot, BoxError> {
    if epoch == 0 || subjects.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("revocation subjects require a positive epoch and sorted unique IDs".into());
    }
    let mut oracle = InMemoryRevocationOracle::new();
    for subject in subjects {
        oracle.insert(
            RevocationKey::new(subject.clone(), EpochNonce::new(0)),
            issued_at_unix_ms,
        )?;
    }
    let materialized = oracle.epoch_root();
    Ok(EpochRoot {
        epoch,
        issued_at_unix_ms,
        ..materialized
    })
}

#[derive(Debug)]
struct AnnouncedRoot {
    root: EpochRoot,
    subjects: BTreeSet<RevocationViewSubject>,
}

#[derive(Debug, Default)]
pub(super) struct OriginPublishedSubjects {
    inner: Mutex<Option<AnnouncedRoot>>,
}

impl OriginPublishedSubjects {
    /// Called only after the announcement's pinned origin signature is checked.
    pub(super) fn install(&self, root: &EpochRoot, subjects: &[String]) -> Result<(), BoxError> {
        if materialized_root(root.epoch, root.issued_at_unix_ms, subjects)? != *root {
            return Err(
                "announced subjects do not reconstruct the complete revocation root".into(),
            );
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "revocation subjects lock poisoned")?;
        if let Some(previous) = guard.as_ref() {
            if root.epoch < previous.root.epoch
                || (root.epoch == previous.root.epoch && *root != previous.root)
                || root.issued_at_unix_ms < previous.root.issued_at_unix_ms
            {
                return Err("revocation announcement regressed or conflicts with its epoch".into());
            }
        }
        *guard = Some(AnnouncedRoot {
            root: root.clone(),
            subjects: subjects
                .iter()
                .cloned()
                .map(RevocationViewSubject::new)
                .collect(),
        });
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct OriginRevocationSink {
    view: Arc<RevocationView>,
    subjects: Arc<OriginPublishedSubjects>,
}

impl OriginRevocationSink {
    pub(super) fn new(view: Arc<RevocationView>, subjects: Arc<OriginPublishedSubjects>) -> Self {
        Self { view, subjects }
    }
}

impl RevocationRootSink for OriginRevocationSink {
    fn merge_root(&self, signed: &SignedEpochRoot) -> Result<(), RevocationLaneError> {
        self.merge_batch(std::slice::from_ref(signed))
    }

    fn merge_batch(&self, roots: &[SignedEpochRoot]) -> Result<(), RevocationLaneError> {
        if roots.is_empty() {
            return Ok(());
        }
        let reject = |reason: &str| RevocationLaneError::SinkRejected(reason.into());
        let guard = self
            .subjects
            .inner
            .lock()
            .map_err(|_| reject("revocation subjects lock poisoned"))?;
        let announced = guard
            .as_ref()
            .ok_or_else(|| reject("revocation root has no materialized subjects"))?;
        // Validate the entire batch before advancing freshness. Retain the lock
        // through installation so an announcement cannot replace this binding.
        if roots.iter().any(|signed| signed.root != announced.root) {
            return Err(reject(
                "revocation root differs from the materialized announcement",
            ));
        }
        let snapshot = RevocationSnapshot {
            epoch: announced.root.epoch,
            root_hash: announced.root.root_hash,
            issued_at_unix_ms: announced.root.issued_at_unix_ms,
            revoked: announced.subjects.clone(),
        };
        match self.view.install_if_newer(snapshot) {
            Ok(_) | Err(chio_kernel_core::RevocationViewError::NonMonotoneEpoch { .. }) => Ok(()),
        }
    }
}
