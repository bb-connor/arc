use chio_security_types::ports::{
    AdvisorySecurityEvent, BoundedVec, CorrelationCasRequest, CorrelationDeleteRequest,
    CorrelationEventIndexRequest, CorrelationPartial, CorrelationPartitionKey, CorrelationScan,
    EventAppend, EventPartitionScan, PortError, PortResult, SecurityEventStore,
    VerifiedSecurityEvent,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

type PartitionKey = (String, String, [u8; 32]);
type EventKey = (String, String);
type EventOwnerKey = (String, String, String);

#[derive(Default)]
struct State {
    events: BTreeMap<EventKey, VerifiedSecurityEvent>,
    event_owners: BTreeMap<EventOwnerKey, [u8; 32]>,
    indexes: BTreeMap<PartitionKey, BTreeSet<String>>,
    partition_generations: BTreeMap<PartitionKey, u64>,
    partials: BTreeMap<PartitionKey, CorrelationPartial>,
}

#[derive(Default)]
pub struct TestStore {
    state: Mutex<State>,
    fail: AtomicBool,
}

impl TestStore {
    pub fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }

    fn lock(&self) -> PortResult<MutexGuard<'_, State>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        self.state.lock().map_err(|_| PortError::unavailable())
    }
}

fn partition_key(key: &CorrelationPartitionKey) -> PartitionKey {
    (
        key.tenant_id.as_str().to_owned(),
        key.rule_id.as_str().to_owned(),
        *key.partition_hash.as_bytes(),
    )
}

impl SecurityEventStore for TestStore {
    fn append_verified(&self, event: &VerifiedSecurityEvent) -> PortResult<EventAppend> {
        let mut state = self.lock()?;
        let key = (
            event.tenant_id.as_str().to_owned(),
            event.event_id.as_str().to_owned(),
        );
        if let Some(existing) = state.events.get(&key) {
            return if existing == event {
                Ok(EventAppend::Duplicate)
            } else {
                Err(PortError::conflict())
            };
        }
        state.events.insert(key, event.clone());
        Ok(EventAppend::Inserted)
    }

    fn append_advisory(&self, _event: &AdvisorySecurityEvent) -> PortResult<EventAppend> {
        if self.fail.load(Ordering::SeqCst) {
            Err(PortError::unavailable())
        } else {
            Ok(EventAppend::Inserted)
        }
    }

    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()> {
        let mut state = self.lock()?;
        let owner_key = (
            request.key.tenant_id.as_str().to_owned(),
            request.key.rule_id.as_str().to_owned(),
            request.event_id.as_str().to_owned(),
        );
        if let Some(owner) = state.event_owners.get(&owner_key) {
            return if owner == request.key.partition_hash.as_bytes() {
                Ok(())
            } else {
                Err(PortError::conflict())
            };
        }
        let event_key = (
            request.key.tenant_id.as_str().to_owned(),
            request.event_id.as_str().to_owned(),
        );
        let event = state
            .events
            .get(&event_key)
            .ok_or_else(PortError::invalid_data)?;
        let key = partition_key(&request.key);
        if state
            .partials
            .get(&key)
            .is_some_and(|partial| event.event_time_unix_ms <= partial.watermark_unix_ms)
        {
            return Err(PortError::conflict());
        }
        state
            .event_owners
            .insert(owner_key, *request.key.partition_hash.as_bytes());
        state
            .indexes
            .entry(key.clone())
            .or_default()
            .insert(request.event_id.as_str().to_owned());
        let generation = state.partition_generations.entry(key).or_default();
        *generation = generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        Ok(())
    }

    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan> {
        if scan.max_results == 0 || scan.max_results > 4_096 {
            return Err(PortError::invalid_data());
        }
        let state = self.lock()?;
        let key = (
            scan.tenant_id.as_str().to_owned(),
            scan.rule_id.as_str().to_owned(),
            *scan.partition_hash.as_bytes(),
        );
        let mut events = Vec::new();
        if let Some(ids) = state.indexes.get(&key) {
            for id in ids {
                let event_key = (scan.tenant_id.as_str().to_owned(), id.clone());
                let event = state
                    .events
                    .get(&event_key)
                    .ok_or_else(PortError::integrity_failure)?;
                let after = match (scan.after_event_time_unix_ms, scan.after_event_id.as_ref()) {
                    (None, _) => true,
                    (Some(time), None) => event.event_time_unix_ms > time,
                    (Some(time), Some(event_id)) => {
                        event.event_time_unix_ms > time
                            || event.event_time_unix_ms == time && event.event_id > *event_id
                    }
                };
                if after && event.event_time_unix_ms <= scan.through_event_time_unix_ms {
                    events.push(event.clone());
                }
            }
        }
        events.sort_by(|left, right| {
            left.event_time_unix_ms
                .cmp(&right.event_time_unix_ms)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        let truncated = events.len() > scan.max_results as usize;
        events.truncate(scan.max_results as usize);
        Ok(CorrelationScan {
            events: BoundedVec::new(events).map_err(|_| PortError::integrity_failure())?,
            partition_generation: state.partition_generations.get(&key).copied().unwrap_or(0),
            truncated,
        })
    }

    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>> {
        Ok(self.lock()?.partials.get(&partition_key(key)).cloned())
    }

    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial> {
        let mut state = self.lock()?;
        let key = partition_key(&request.partial.key);
        let partition_generation = state.partition_generations.get(&key).copied().unwrap_or(0);
        if partition_generation != request.observed_partition_generation {
            return Err(PortError::conflict());
        }
        let current = state.partials.get(&key);
        match (current, request.expected_generation) {
            (None, None) if request.partial.generation == 0 => {}
            (Some(current), Some(expected))
                if current.generation == expected
                    && request.partial.generation == expected.saturating_add(1)
                    && request.partial.watermark_unix_ms >= current.watermark_unix_ms => {}
            _ => return Err(PortError::conflict()),
        }
        state.partials.insert(key, request.partial.clone());
        Ok(request.partial.clone())
    }

    fn delete_correlation(&self, request: &CorrelationDeleteRequest) -> PortResult<()> {
        let mut state = self.lock()?;
        let key = partition_key(&request.key);
        if state
            .partials
            .get(&key)
            .is_none_or(|partial| partial.generation != request.expected_generation)
        {
            return Err(PortError::conflict());
        }
        state.partials.remove(&key);
        Ok(())
    }
}
