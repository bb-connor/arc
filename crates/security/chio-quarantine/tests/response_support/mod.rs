use chio_security_types::ports::{
    CreateOutcome, RecordId, ResponseCasRequest, ResponseEffectCasRequest, ResponseEffectKey,
    ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord, ResponseReceiptCursor,
    ResponseReceiptCursorCasRequest, ResponseStore, ScheduledWork, SchedulerClaimRequest,
};
use chio_security_types::ports::{PortError, PortResult};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

#[derive(Default)]
struct State {
    plan: Option<ResponsePlanRecord>,
    transitions: BTreeMap<String, ResponseCasRequest>,
    effects: BTreeMap<String, ResponseEffectRecord>,
    effect_transitions: BTreeMap<String, ResponseEffectCasRequest>,
    receipt_cursor: Option<ResponseReceiptCursor>,
    receipt_cursor_transitions: BTreeMap<String, ResponseReceiptCursorCasRequest>,
}

#[derive(Default)]
pub struct TestResponseStore {
    state: Mutex<State>,
}

impl TestResponseStore {
    fn state(&self) -> PortResult<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| PortError::unavailable())
    }
}

impl ResponseStore for TestResponseStore {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        let state = self.state()?;
        Ok(state
            .plan
            .as_ref()
            .filter(|plan| plan.tenant_id == key.tenant_id && plan.action_id == key.action_id)
            .cloned())
    }

    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome> {
        let mut state = self.state()?;
        match state.plan.as_ref() {
            Some(existing) if existing == record => Ok(CreateOutcome::Existing),
            Some(_) => Err(PortError::conflict()),
            None => {
                state.plan = Some(record.clone());
                Ok(CreateOutcome::Created)
            }
        }
    }

    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord> {
        let mut state = self.state()?;
        if let Some(existing) = state.transitions.get(request.transition_id.as_str()) {
            if existing != request {
                return Err(PortError::conflict());
            }
            return state.plan.clone().ok_or_else(PortError::integrity_failure);
        }
        let current = state.plan.as_ref().ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.record.tenant_id
            || current.action_id != request.record.action_id
            || current.generation != request.expected_generation
            || request.record.generation != request.expected_generation.saturating_add(1)
        {
            return Err(PortError::conflict());
        }
        state
            .transitions
            .insert(request.transition_id.as_str().to_owned(), request.clone());
        state.plan = Some(request.record.clone());
        Ok(request.record.clone())
    }

    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        let state = self.state()?;
        Ok(state
            .effects
            .get(key.effect_id.as_str())
            .filter(|effect| effect.tenant_id == key.tenant_id)
            .cloned())
    }

    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome> {
        if record.generation != 0 {
            return Err(PortError::invalid_data());
        }
        let mut state = self.state()?;
        match state.effects.get(record.effect_id.as_str()) {
            Some(existing) if existing == record => Ok(CreateOutcome::Existing),
            Some(_) => Err(PortError::conflict()),
            None => {
                state
                    .effects
                    .insert(record.effect_id.as_str().to_owned(), record.clone());
                Ok(CreateOutcome::Created)
            }
        }
    }

    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord> {
        let mut state = self.state()?;
        if let Some(existing) = state.effect_transitions.get(request.transition_id.as_str()) {
            if existing != request {
                return Err(PortError::conflict());
            }
            return state
                .effects
                .get(request.record.effect_id.as_str())
                .cloned()
                .ok_or_else(PortError::integrity_failure);
        }
        let current = state
            .effects
            .get(request.record.effect_id.as_str())
            .ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.record.tenant_id
            || current.action_id != request.record.action_id
            || current.generation != request.expected_generation
            || request.record.generation
                != request
                    .expected_generation
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::conflict());
        }
        state
            .effect_transitions
            .insert(request.transition_id.as_str().to_owned(), request.clone());
        state.effects.insert(
            request.record.effect_id.as_str().to_owned(),
            request.record.clone(),
        );
        Ok(request.record.clone())
    }

    fn load_receipt_cursor(
        &self,
        key: &ResponsePlanKey,
    ) -> PortResult<Option<ResponseReceiptCursor>> {
        let state = self.state()?;
        Ok(state
            .receipt_cursor
            .as_ref()
            .filter(|cursor| cursor.tenant_id == key.tenant_id && cursor.action_id == key.action_id)
            .cloned())
    }

    fn initialize_receipt_cursor(
        &self,
        cursor: &ResponseReceiptCursor,
    ) -> PortResult<CreateOutcome> {
        if cursor.generation != 0 {
            return Err(PortError::invalid_data());
        }
        let mut state = self.state()?;
        match state.receipt_cursor.as_ref() {
            Some(existing) if existing == cursor => Ok(CreateOutcome::Existing),
            Some(_) => Err(PortError::conflict()),
            None => {
                state.receipt_cursor = Some(cursor.clone());
                Ok(CreateOutcome::Created)
            }
        }
    }

    fn compare_and_swap_receipt_cursor(
        &self,
        request: &ResponseReceiptCursorCasRequest,
    ) -> PortResult<ResponseReceiptCursor> {
        let mut state = self.state()?;
        if let Some(existing) = state
            .receipt_cursor_transitions
            .get(request.transition_id.as_str())
        {
            if existing != request {
                return Err(PortError::conflict());
            }
            return state
                .receipt_cursor
                .clone()
                .ok_or_else(PortError::integrity_failure);
        }
        let current = state
            .receipt_cursor
            .as_ref()
            .ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.cursor.tenant_id
            || current.action_id != request.cursor.action_id
            || current.plan_hash != request.cursor.plan_hash
            || current.generation != request.expected_generation
            || current.current_evidence_id != request.expected_evidence_id
            || request.cursor.generation
                != request
                    .expected_generation
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::conflict());
        }
        state
            .receipt_cursor_transitions
            .insert(request.transition_id.as_str().to_owned(), request.clone());
        state.receipt_cursor = Some(request.cursor.clone());
        Ok(request.cursor.clone())
    }

    fn claim_due(&self, _request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>> {
        Ok(Vec::new())
    }
}

#[allow(dead_code)]
pub fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
}
