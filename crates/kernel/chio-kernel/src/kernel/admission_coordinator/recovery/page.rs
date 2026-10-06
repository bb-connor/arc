//! One physical page bounds a host tick; known failures retain fenced deferrals.
use super::*;
use crate::admission_operation::{
    AdmissionOperationId, AdmissionOperationStoreError, AdmissionRecoveryPageQuery,
};

impl ChioKernel {
    pub(super) fn reconcile_admission_recovery_page(
        &self,
        now: u64,
        candidate_limit: usize,
        cursor: Option<&AdmissionOperationId>,
    ) -> Result<(usize, Option<AdmissionOperationId>), KernelError> {
        let runtime = self.durable_runtime()?;
        let mut reconciled = 0_usize;
        let page = runtime
            .store
            .recovery_page(AdmissionRecoveryPageQuery {
                not_after_unix_ms: now,
                candidate_limit,
                after_operation_id: cursor,
                fence: &runtime.fence,
            })
            .map_err(failure::port_error)?;
        if page.scanned_candidates > candidate_limit
            || page.next_cursor.is_some() != (page.scanned_candidates == candidate_limit)
            || page.operations.len() > page.scanned_candidates
            || page
                .next_cursor
                .as_ref()
                .is_some_and(|next| cursor.is_some_and(|previous| next <= previous))
            || page.operations.iter().any(|operation| {
                cursor.is_some_and(|previous| operation.binding().operation_id() <= previous)
                    || page
                        .next_cursor
                        .as_ref()
                        .is_some_and(|next| operation.binding().operation_id() > next)
            })
            || page.operations.windows(2).any(|pair| match pair {
                [left, right] => left.binding().operation_id() >= right.binding().operation_id(),
                _ => true,
            })
        {
            return Err(durable_store_error(
                AdmissionOperationStoreError::Invariant(
                    "recovery cursor page violated its candidate or ordering bound".into(),
                ),
            ));
        }
        for operation in page.operations {
            let Some(_live_owner) = runtime
                .mutation_sequencer
                .try_own_operation(operation.binding().operation_id())
                .map_err(failure::operation_error)?
            else {
                continue;
            };
            let previous = runtime
                .store
                .load_recovery_status(operation.binding().operation_id(), &runtime.fence, now)
                .map_err(failure::port_error)?;
            if previous.as_ref().is_some_and(|previous| {
                previous.quarantined && previous.deferral.retry_not_before_unix_ms > now
            }) {
                continue;
            }
            match self.recover_one_admission(&operation, now) {
                Ok(changed) => {
                    if let Some(previous) = previous.as_ref() {
                        let current = runtime
                            .store
                            .load_by_operation_id(operation.binding().operation_id())
                            .map_err(durable_store_error)?
                            .ok_or_else(|| {
                                durable_store_error(AdmissionOperationStoreError::NotFound)
                            })?;
                        self.clear_admission_recovery_deferral(&current, previous, now)?;
                    }
                    if changed {
                        reconciled = reconciled.checked_add(1).ok_or_else(|| {
                            durable_store_error(AdmissionOperationStoreError::Invariant(
                                "admission recovery count overflow".into(),
                            ))
                        })?;
                    }
                }
                Err(error) if failure::classify(&error).is_some() => {
                    self.defer_admission_recovery(&operation, previous.as_ref(), &error, now)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok((reconciled, page.next_cursor))
    }
}
