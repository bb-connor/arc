//! Observations live for the entire delegated xSync, including real filesystem I/O.
//! Stack capture happens on the syncing thread; symbolization happens only on a
//! watchdog snapshot, outside the observation lock. No ptrace access is needed.

use super::SyncRecord;
use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Observation {
    record: SyncRecord,
    stack: Arc<Backtrace>,
}

#[derive(Default)]
pub(super) struct ActiveSyncs(Mutex<BTreeMap<usize, Observation>>);

pub(super) struct SyncObservation<'a> {
    owner: &'a ActiveSyncs,
    handle: usize,
}

impl ActiveSyncs {
    pub(super) fn enter(&self, handle: usize, record: SyncRecord) -> SyncObservation<'_> {
        let observation = Observation {
            record,
            stack: Arc::new(Backtrace::force_capture()),
        };
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(handle, observation);
        SyncObservation {
            owner: self,
            handle,
        }
    }

    pub(super) fn snapshot(&self, prefix: &str) -> String {
        let active: Vec<_> = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .filter(|entry| entry.record.path.starts_with(prefix))
            .cloned()
            .collect();
        let mut output = String::from("active syncs:\n");
        if active.is_empty() {
            output.push_str("  (none)\n");
        }
        for entry in active {
            output.push_str(&format!(
                "  active owner: {}\n  {}, elapsed {:?}, WAL write={}, checkpoint={}\n  entry stack:\n{}\n",
                entry.record.thread,
                entry.record,
                entry.record.started.elapsed(),
                entry.record.wal_write_lock,
                entry.record.wal_checkpoint_lock,
                entry.stack,
            ));
        }
        output
    }
}

impl Drop for SyncObservation<'_> {
    fn drop(&mut self) {
        self.owner
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.handle);
    }
}
