//! A test thread can open stores as the prior-44 binary did, without the
//! handle migration, and retain handle rows through the prior generic writer
//! bytes. Production startup and issuance are unchanged.
#[cfg(feature = "admission-test-support")]
use super::*;
use std::cell::Cell;

thread_local! {
    static PRIOR_FORMAT_STARTUP: Cell<bool> = const { Cell::new(false) };
}

/// While held, stores opened on this thread skip the handle migration exactly
/// as a prior-44 binary did.
pub struct PriorFormatHandleStartupGuard(());

impl PriorFormatHandleStartupGuard {
    pub fn arm() -> Self {
        PRIOR_FORMAT_STARTUP.with(|prior| prior.set(true));
        Self(())
    }
}

impl Drop for PriorFormatHandleStartupGuard {
    fn drop(&mut self) {
        PRIOR_FORMAT_STARTUP.with(|prior| prior.set(false));
    }
}

pub(super) fn prior_format_startup() -> bool {
    PRIOR_FORMAT_STARTUP.with(Cell::get)
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Retain the handle of each listed profile generation exactly as the
    /// prior-44 generic writer did: the same canonical record with one event
    /// and one global commit per row, and no index entry.
    pub fn retain_prior_format_handles_fixture(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        recipient: &ArtifactRecipientId,
        generations: std::ops::RangeInclusive<u64>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Vec<ArtifactHandleV1>, AdmissionOperationStoreError> {
        let span = generations.end().checked_sub(*generations.start());
        if span
            .and_then(|span| usize::try_from(span).ok())
            .is_none_or(|span| span > MAX_HANDLE_INDEX_ENTRIES)
        {
            return Err(refused("prior handle fixture bound"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let mut handles = Vec::new();
            for generation in generations {
                let mut prior = profile.clone();
                prior.generation = SafeInteger::new(generation).map_err(refused)?;
                let (record, _) =
                    super::super::release::derive_handle(&tx, actor, &prior, reference, recipient)?;
                let key = handle_key(actor.scope(), &record.handle.handle)?;
                if load::<HandleRecord>(&tx, &key)?.is_none() {
                    protected::retain_prior_format_handle_fixture(
                        &tx,
                        &self.serving_owner,
                        &key,
                        &scope_key(actor.scope())?,
                        &protected::encode(&record)?,
                    )?;
                }
                handles.push(record.handle);
            }
            Ok((tx, handles))
        })
    }
}
