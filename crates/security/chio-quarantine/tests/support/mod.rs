use chio_security_types::ports::{
    AdvisorySecurityEvent, BoundedVec, CorrelationCasRequest, CorrelationDeleteRequest,
    CorrelationEventAdmission, CorrelationEventAdmissionRequest, CorrelationEventIndexRequest,
    CorrelationOutcomeCommitRequest, CorrelationOutcomeKey, CorrelationOutcomePublication,
    CorrelationOutcomeStatus, CorrelationPartial, CorrelationPartitionKey, CorrelationScan,
    CreateOutcome, EventAppend, EventPartitionScan, PortError, PortResult, SecurityEventStore,
    VerifiedSecurityEvent,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

type PartitionKey = (String, String, [u8; 32]);
type EventKey = (String, String);
type EventOwnerKey = (String, String, String);
type OutcomeKey = (String, String, String);

#[derive(Clone, Default)]
struct State {
    events: BTreeMap<EventKey, VerifiedSecurityEvent>,
    event_owners: BTreeMap<EventOwnerKey, [u8; 32]>,
    indexes: BTreeMap<PartitionKey, BTreeSet<String>>,
    partition_generations: BTreeMap<PartitionKey, u64>,
    partials: BTreeMap<PartitionKey, CorrelationPartial>,
    outcomes: BTreeMap<OutcomeKey, CorrelationOutcomePublication>,
    outcome_correlations: BTreeMap<OutcomeKey, CorrelationCasRequest>,
}

#[derive(Default)]
pub struct TestStore {
    state: Mutex<State>,
    fail: AtomicBool,
    fail_next_index: AtomicBool,
    lose_next_outcome_commit_ack: AtomicBool,
}

impl TestStore {
    pub fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }

    pub fn fail_next_partition_index(&self) {
        self.fail_next_index.store(true, Ordering::SeqCst);
    }

    pub fn lose_next_outcome_commit_ack(&self) {
        self.lose_next_outcome_commit_ack
            .store(true, Ordering::SeqCst);
    }

    pub fn durable_correlation_counts(&self) -> PortResult<(usize, usize, usize)> {
        let state = self.lock()?;
        Ok((
            state.events.len(),
            state.indexes.len(),
            state.partials.len(),
        ))
    }

    pub fn durable_outcome_count(&self) -> PortResult<usize> {
        Ok(self.lock()?.outcomes.len())
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

fn outcome_key(key: &CorrelationOutcomeKey) -> OutcomeKey {
    (
        key.tenant_id.as_str().to_owned(),
        key.rule_id.as_str().to_owned(),
        key.event_id.as_str().to_owned(),
    )
}

fn append_verified_state(
    state: &mut State,
    event: &VerifiedSecurityEvent,
) -> PortResult<EventAppend> {
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

fn index_partition_event_state(
    state: &mut State,
    request: &CorrelationEventIndexRequest,
) -> PortResult<()> {
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

fn compare_and_swap_correlation_state(
    state: &mut State,
    request: &CorrelationCasRequest,
) -> PortResult<CorrelationPartial> {
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

fn validate_outcome_binding(
    state: &State,
    outcome: &CorrelationOutcomePublication,
) -> PortResult<bool> {
    if outcome
        .partition_hash
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || outcome.status == CorrelationOutcomeStatus::Deferred
    {
        return Err(PortError::invalid_data());
    }
    let event = state
        .events
        .get(&(
            outcome.key.tenant_id.as_str().to_owned(),
            outcome.key.event_id.as_str().to_owned(),
        ))
        .ok_or_else(PortError::integrity_failure)?;
    if event.body_hash != outcome.event_body_hash
        || event.evidence_hash != outcome.event_evidence_hash
    {
        return Err(PortError::integrity_failure());
    }
    let owner = state.event_owners.get(&(
        outcome.key.tenant_id.as_str().to_owned(),
        outcome.key.rule_id.as_str().to_owned(),
        outcome.key.event_id.as_str().to_owned(),
    ));
    if owner.is_some_and(|owner| owner == outcome.partition_hash.as_bytes()) {
        return Ok(true);
    }
    if owner.is_some()
        || !matches!(
            outcome.status,
            CorrelationOutcomeStatus::Duplicate | CorrelationOutcomeStatus::TooLate
        )
    {
        return Err(PortError::conflict());
    }
    let partition = state
        .partials
        .get(&(
            outcome.key.tenant_id.as_str().to_owned(),
            outcome.key.rule_id.as_str().to_owned(),
            *outcome.partition_hash.as_bytes(),
        ))
        .ok_or_else(PortError::conflict)?;
    if event.event_time_unix_ms > outcome.watermark_unix_ms
        || outcome.watermark_unix_ms > partition.watermark_unix_ms
    {
        return Err(PortError::conflict());
    }
    Ok(false)
}

impl SecurityEventStore for TestStore {
    fn admit_verified_correlation_event(
        &self,
        request: &CorrelationEventAdmissionRequest,
    ) -> PortResult<CorrelationEventAdmission> {
        let mut state = self.lock()?;
        let mut staged = state.clone();
        let append = append_verified_state(&mut staged, &request.event)?;
        let capacity = request
            .capacity
            .as_ref()
            .map(|capacity| compare_and_swap_correlation_state(&mut staged, capacity))
            .transpose()?;
        if self.fail_next_index.swap(false, Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        index_partition_event_state(&mut staged, &request.index)?;
        *state = staged;
        Ok(CorrelationEventAdmission { append, capacity })
    }

    fn append_verified(&self, event: &VerifiedSecurityEvent) -> PortResult<EventAppend> {
        let mut state = self.lock()?;
        append_verified_state(&mut state, event)
    }

    fn append_advisory(&self, _event: &AdvisorySecurityEvent) -> PortResult<EventAppend> {
        if self.fail.load(Ordering::SeqCst) {
            Err(PortError::unavailable())
        } else {
            Ok(EventAppend::Inserted)
        }
    }

    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()> {
        if self.fail_next_index.swap(false, Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        let mut state = self.lock()?;
        index_partition_event_state(&mut state, request)
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

    fn load_correlation_max_seen_event_time(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<u64>> {
        let state = self.lock()?;
        let Some(event_ids) = state.indexes.get(&partition_key(key)) else {
            return Ok(None);
        };
        event_ids
            .iter()
            .map(|event_id| {
                state
                    .events
                    .get(&(key.tenant_id.as_str().to_owned(), event_id.clone()))
                    .map(|event| event.event_time_unix_ms)
                    .ok_or_else(PortError::integrity_failure)
            })
            .collect::<PortResult<Vec<_>>>()
            .map(|event_times| event_times.into_iter().max())
    }

    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial> {
        let mut state = self.lock()?;
        compare_and_swap_correlation_state(&mut state, request)
    }

    fn commit_correlation_outcome(
        &self,
        request: &CorrelationOutcomeCommitRequest,
    ) -> PortResult<CorrelationPartial> {
        let mut state = self.lock()?;
        let mut staged = state.clone();
        let key = outcome_key(&request.outcome.key);
        if let Some(existing) = staged.outcomes.get(&key) {
            return if existing == &request.outcome
                && staged.outcome_correlations.get(&key) == Some(&request.correlation)
            {
                Ok(request.correlation.partial.clone())
            } else {
                Err(PortError::conflict())
            };
        }
        if request.outcome.partition_hash != request.correlation.partial.key.partition_hash
            || !validate_outcome_binding(&staged, &request.outcome)?
        {
            return Err(PortError::integrity_failure());
        }
        let partial = compare_and_swap_correlation_state(&mut staged, &request.correlation)?;
        staged.outcomes.insert(key, request.outcome.clone());
        staged.outcome_correlations.insert(
            outcome_key(&request.outcome.key),
            request.correlation.clone(),
        );
        *state = staged;
        if self
            .lose_next_outcome_commit_ack
            .swap(false, Ordering::SeqCst)
        {
            Err(PortError::unavailable())
        } else {
            Ok(partial)
        }
    }

    fn commit_correlation_outcome_only(
        &self,
        outcome: &CorrelationOutcomePublication,
    ) -> PortResult<CreateOutcome> {
        let mut state = self.lock()?;
        let key = outcome_key(&outcome.key);
        if let Some(existing) = state.outcomes.get(&key) {
            return if existing == outcome {
                Ok(CreateOutcome::Existing)
            } else {
                Err(PortError::conflict())
            };
        }
        validate_outcome_binding(&state, outcome)?;
        state.outcomes.insert(key, outcome.clone());
        Ok(CreateOutcome::Created)
    }

    fn load_correlation_outcome(
        &self,
        key: &CorrelationOutcomeKey,
    ) -> PortResult<Option<CorrelationOutcomePublication>> {
        Ok(self.lock()?.outcomes.get(&outcome_key(key)).cloned())
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
