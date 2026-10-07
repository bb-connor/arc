//! Legacy-family recovery inventory bodies with bounded page ownership.
use super::*;

impl InMemoryAdmissionOperationStore {
    pub(super) fn recovery_candidates_legacy(
        &self,
        kind: AdmissionOperationKind,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut operations = state
            .operations
            .values()
            .filter(|operation| operation.kind() == kind)
            .filter(|operation| {
                !matches!(
                    operation.state(),
                    AdmissionOperationState::Completed
                        | AdmissionOperationState::CompensatedBeforeDispatch
                        | AdmissionOperationState::OutcomeUnknownAfterDispatch
                )
            })
            .map(|operation| {
                let priority = if operation.state() != AdmissionOperationState::CallerReserved {
                    0u8
                } else if state.cleanup_actions.values().any(|action| {
                    action.operation_id() == operation.operation_id()
                        && action.kind() == AdmissionCleanupActionKind::CallerReservationHandoff
                        && action.state() != AdmissionCleanupActionState::Completed
                }) {
                    1
                } else {
                    2
                };
                (priority, operation.clone())
            })
            .collect::<Vec<_>>();
        operations.sort_unstable_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.operation_id().cmp(right.1.operation_id()))
        });
        operations.truncate(limit);
        Ok(operations
            .into_iter()
            .map(|(_, operation)| operation)
            .collect())
    }

    pub(super) fn recovery_candidates_page(
        &self,
        kind: AdmissionOperationKind,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut page = std::collections::BTreeMap::new();
        for operation in state.operations.values().filter(|operation| {
            operation.kind() == kind
                && after_operation_id.is_none_or(|cursor| operation.operation_id() > cursor)
                && !matches!(
                    operation.state(),
                    AdmissionOperationState::Completed
                        | AdmissionOperationState::CompensatedBeforeDispatch
                        | AdmissionOperationState::OutcomeUnknownAfterDispatch
                )
        }) {
            page.insert(operation.operation_id(), operation);
            if page.len() > limit {
                page.pop_last();
            }
        }
        Ok(page.into_values().cloned().collect())
    }

    pub(super) fn compensation_cleanup_page(
        &self,
        kind: Option<AdmissionOperationKind>,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut page = std::collections::BTreeSet::new();
        for operation in state.operations.values().filter(|operation| {
            kind.is_none_or(|kind| operation.kind() == kind)
                && after_operation_id.is_none_or(|cursor| operation.operation_id() > cursor)
                && matches!(
                    operation.state(),
                    AdmissionOperationState::CompensationPending
                        | AdmissionOperationState::CompensatedBeforeDispatch
                )
                && state.cleanup_actions.values().any(|action| {
                    action.operation_id() == operation.operation_id()
                        && !matches!(
                            action.kind(),
                            AdmissionCleanupActionKind::CallerReservationHandoffIntent
                                | AdmissionCleanupActionKind::CallerReservationHandoff
                        )
                        && action.state() != AdmissionCleanupActionState::Completed
                })
        }) {
            page.insert(operation.operation_id());
            if page.len() > limit {
                page.pop_last();
            }
        }
        Ok(page.into_iter().map(str::to_owned).collect())
    }
    pub(super) fn compensation_cleanup_legacy(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut operation_ids = state
            .operations
            .values()
            .filter(|operation| {
                matches!(
                    operation.state(),
                    AdmissionOperationState::CompensationPending
                        | AdmissionOperationState::CompensatedBeforeDispatch
                ) && kind.is_none_or(|kind| operation.kind() == kind)
                    && state.cleanup_actions.values().any(|action| {
                        action.operation_id() == operation.operation_id()
                            && !matches!(
                                action.kind(),
                                AdmissionCleanupActionKind::CallerReservationHandoffIntent
                                    | AdmissionCleanupActionKind::CallerReservationHandoff
                            )
                            && action.state() != AdmissionCleanupActionState::Completed
                    })
            })
            .map(|operation| operation.operation_id().to_string())
            .collect::<Vec<_>>();
        operation_ids.sort_unstable();
        operation_ids.truncate(limit);
        Ok(operation_ids)
    }

    pub(super) fn pending_cleanup_action_page(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut page = std::collections::BTreeSet::new();
        for action in state.cleanup_actions.values().filter(|action| {
            action.kind() == action_kind
                && action.state() != AdmissionCleanupActionState::Completed
                && after_operation_id.is_none_or(|cursor| action.operation_id() > cursor)
        }) {
            let Some(operation) = state.operations.get(action.operation_id()) else {
                continue;
            };
            if operation.kind() != operation_kind
                || (action_kind == AdmissionCleanupActionKind::TerminalReceipt
                    && operation.state() == AdmissionOperationState::CompensationPending)
            {
                continue;
            }
            page.insert(operation.operation_id());
            if page.len() > limit {
                page.pop_last();
            }
        }
        Ok(page.into_iter().map(str::to_owned).collect())
    }
}
