use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use super::*;

type MutationSequencers = HashMap<String, Weak<SequencerState>>;

#[derive(Default)]
struct SequencerState {
    mutations: Mutex<()>,
    live_operations: Mutex<HashSet<AdmissionOperationId>>,
}

#[derive(Clone)]
pub struct AdmissionMutationSequencer {
    inner: Arc<SequencerState>,
}

/// Process-local exclusion, not a durable lease or dispatch authority. Shared
/// by every coordinator with this serving fence and released on cancellation.
pub(crate) struct AdmissionLiveOperation {
    inner: Arc<SequencerState>,
    operation_id: AdmissionOperationId,
}

impl Drop for AdmissionLiveOperation {
    fn drop(&mut self) {
        // A poisoned registry stays closed. Cleanup must not panic during unwind.
        if let Ok(mut live) = self.inner.live_operations.lock() {
            live.remove(&self.operation_id);
        }
    }
}

pub struct AdmissionMutationGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl AdmissionMutationSequencer {
    pub fn for_fence(fence: &StoreMutationFence) -> Result<Self, AdmissionOperationError> {
        validate_store_fence(fence)?;
        static SEQUENCERS: OnceLock<Mutex<MutationSequencers>> = OnceLock::new();

        let key = format!(
            "{}\0{}\0{}",
            fence.store_uuid, fence.lease_id, fence.owner_epoch
        );
        let registry = SEQUENCERS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut sequencers = registry
            .lock()
            .map_err(|_| AdmissionOperationError::MutationSequencerPoisoned)?;
        sequencers.retain(|_, sequencer| sequencer.strong_count() > 0);
        let inner = if let Some(sequencer) = sequencers.get(&key).and_then(Weak::upgrade) {
            sequencer
        } else {
            let sequencer = Arc::new(SequencerState::default());
            sequencers.insert(key, Arc::downgrade(&sequencer));
            sequencer
        };
        Ok(Self { inner })
    }

    pub fn lock(&self) -> Result<AdmissionMutationGuard<'_>, AdmissionOperationError> {
        self.inner
            .mutations
            .lock()
            .map(|guard| AdmissionMutationGuard { _guard: guard })
            .map_err(|_| AdmissionOperationError::MutationSequencerPoisoned)
    }

    /// Never wait across a callback or await. A duplicate must not attach to a
    /// live operation and then compensate another evaluation's reservations.
    pub(crate) fn try_own_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionLiveOperation>, AdmissionOperationError> {
        let mut live = self
            .inner
            .live_operations
            .lock()
            .map_err(|_| AdmissionOperationError::MutationSequencerPoisoned)?;
        if !live.insert(operation_id.clone()) {
            return Ok(None);
        }
        Ok(Some(AdmissionLiveOperation {
            inner: self.inner.clone(),
            operation_id: operation_id.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn sequencer(name: &str) -> TestResult<AdmissionMutationSequencer> {
        Ok(AdmissionMutationSequencer::for_fence(
            &StoreMutationFence {
                store_uuid: name.into(),
                lease_id: "live-operation-test".into(),
                owner_epoch: 1,
            },
        )?)
    }

    #[test]
    fn identical_fences_exclude_duplicate_live_operations_until_drop() -> TestResult {
        let first = sequencer("shared-live-operation")?;
        let second = sequencer("shared-live-operation")?;
        let id = AdmissionOperationId::from_persisted("a".repeat(64))?;
        let owner = first.try_own_operation(&id)?.ok_or("first owner")?;
        assert!(second.try_own_operation(&id)?.is_none());
        drop(owner);
        assert!(second.try_own_operation(&id)?.is_some());
        Ok(())
    }

    #[test]
    fn unrelated_live_operations_do_not_hold_the_mutation_lock() -> TestResult {
        let sequencer = sequencer("independent-live-operations")?;
        let first = AdmissionOperationId::from_persisted("a".repeat(64))?;
        let second = AdmissionOperationId::from_persisted("b".repeat(64))?;
        let _first = sequencer.try_own_operation(&first)?.ok_or("first owner")?;
        let _second = sequencer
            .try_own_operation(&second)?
            .ok_or("second owner")?;
        let _mutation = sequencer.lock()?;
        Ok(())
    }

    #[test]
    fn unwinding_releases_live_ownership_without_poisoning_the_registry() -> TestResult {
        let sequencer = sequencer("cancelled-live-operation")?;
        let id = AdmissionOperationId::from_persisted("a".repeat(64))?;
        let owner = sequencer.try_own_operation(&id)?.ok_or("first owner")?;
        assert!(std::panic::catch_unwind(|| {
            let _owner = owner;
            panic!("cancel the live invocation");
        })
        .is_err());
        assert!(sequencer.try_own_operation(&id)?.is_some());
        Ok(())
    }

    #[test]
    fn poisoned_live_registry_denies_acquisition_and_drop_does_not_panic() -> TestResult {
        let sequencer = sequencer("poisoned-live-operation")?;
        let id = AdmissionOperationId::from_persisted("a".repeat(64))?;
        let owner = sequencer.try_own_operation(&id)?.ok_or("first owner")?;
        assert!(std::panic::catch_unwind(|| {
            let _guard = sequencer
                .inner
                .live_operations
                .lock()
                .unwrap_or_else(|_| panic!("already poisoned"));
            panic!("poison the ownership registry");
        })
        .is_err());
        drop(owner);
        assert!(matches!(
            sequencer.try_own_operation(&id),
            Err(AdmissionOperationError::MutationSequencerPoisoned)
        ));
        Ok(())
    }

    #[test]
    fn identical_store_fences_share_one_mutation_sequence() {
        let fence = StoreMutationFence {
            store_uuid: "store-1".to_owned(),
            lease_id: "lease-1".to_owned(),
            owner_epoch: 1,
        };
        let first = AdmissionMutationSequencer::for_fence(&fence).expect("first sequencer");
        let second = AdmissionMutationSequencer::for_fence(&fence).expect("second sequencer");
        let held = first.lock().expect("first lock");
        let (sender, receiver) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            sender.send("waiting").expect("send waiting");
            let _guard = second.lock().expect("second lock");
            sender.send("acquired").expect("send acquired");
        });

        assert_eq!(receiver.recv().expect("receive waiting"), "waiting");
        assert!(receiver.recv_timeout(Duration::from_millis(25)).is_err());
        drop(held);
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("receive acquired"),
            "acquired"
        );
        waiter.join().expect("join waiter");
    }
}
