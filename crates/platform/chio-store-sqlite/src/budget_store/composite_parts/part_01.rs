use super::store::{
    BudgetAdmissionOperationParts, BudgetHoldCreateInput, BudgetMutationEventInput,
};
use super::*;

#[derive(Debug, Clone)]
struct StoredCompositeAuthorization {
    admission_operation: StoredAdmissionOperation,
    hold_id: String,
    event_id: String,
    capability_id: String,
    grant_index: usize,
    requested_exposure_units: u64,
    max_cost_per_invocation: Option<u64>,
    max_total_cost_units: Option<u64>,
    authority: Option<BudgetEventAuthority>,
    allowed: bool,
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    revocation_set: CanonicalRevocationSet,
    committed_cost_units_after: u64,
    invocation_count_after: u32,
    event_seq: u64,
    invocation_counts_after: Vec<BudgetInvocationQuotaUsage>,
    aggregate_root_capability_id: Option<String>,
    aggregate_root_binding_digest: Option<String>,
    authorization_artifact_digests: Vec<String>,
}

#[derive(Debug)]
struct StagedQuota {
    quota: BudgetInvocationQuota,
    reserved: u32,
    captured: u32,
    exists: bool,
}

#[derive(Debug)]
struct StoredCompositeHold {
    admission_operation: StoredAdmissionOperation,
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    revocation_set: CanonicalRevocationSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredAdmissionOperation {
    operation_id: String,
    request_binding_hash: String,
}

impl StoredAdmissionOperation {
    fn from_columns(
        operation_id: Option<String>,
        request_binding_hash: Option<String>,
        subject: &str,
    ) -> Result<Self, BudgetStoreError> {
        let operation_id = operation_id.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("persisted {subject} omits admission operation_id"))
        })?;
        let request_binding_hash = request_binding_hash.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "persisted {subject} omits admission request_binding_hash"
            ))
        })?;
        BudgetAdmissionOperationBinding::new(operation_id.clone(), request_binding_hash.clone())?;
        Ok(Self {
            operation_id,
            request_binding_hash,
        })
    }

    fn validate_binding(
        &self,
        requested: &BudgetAdmissionOperationBinding,
        subject: &str,
    ) -> Result<(), BudgetStoreError> {
        self.validate_parts(
            requested.operation_id(),
            requested.request_binding_hash(),
            subject,
        )
    }

    fn validate_parts(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        subject: &str,
    ) -> Result<(), BudgetStoreError> {
        if self.operation_id != operation_id {
            return Err(BudgetStoreError::Conflict(format!(
                "{subject} belongs to a different admission operation_id"
            )));
        }
        if self.request_binding_hash != request_binding_hash {
            return Err(BudgetStoreError::Conflict(format!(
                "{subject} belongs to a different admission request_binding_hash"
            )));
        }
        Ok(())
    }
}

fn required_admission_operation<'a>(
    admission_operation: Option<&'a BudgetAdmissionOperationBinding>,
    subject: &str,
) -> Result<&'a BudgetAdmissionOperationBinding, BudgetStoreError> {
    admission_operation.ok_or_else(|| {
        BudgetStoreError::Invariant(format!("{subject} requires an admission operation binding"))
    })
}

fn validate_base_hold_admission_operation(
    hold: &SqliteBudgetHold,
    requested: &BudgetAdmissionOperationBinding,
) -> Result<(), BudgetStoreError> {
    StoredAdmissionOperation::from_columns(
        hold.operation_id.clone(),
        hold.request_binding_hash.clone(),
        "composite base hold",
    )?
    .validate_binding(requested, "composite base hold")
}

impl StoredCompositeAuthorization {
    fn authorization_input(&self) -> Result<SqliteStoredCompositeAuthorizeInput, BudgetStoreError> {
        Ok(SqliteStoredCompositeAuthorizeInput {
            authorization: SqliteCompositeAuthorizeInput {
                operation_id: self.admission_operation.operation_id.clone(),
                request_binding_hash: self.admission_operation.request_binding_hash.clone(),
                capability_id: self.capability_id.clone(),
                grant_index: self.grant_index,
                requested_exposure_units: self.requested_exposure_units,
                max_cost_per_invocation: self.max_cost_per_invocation,
                max_total_cost_units: self.max_total_cost_units,
                hold_id: self.hold_id.clone(),
                event_id: self.event_id.clone(),
                authority: self.authority.clone(),
                invocation_quotas: self
                    .invocation_counts_after
                    .iter()
                    .map(|usage| usage.quota.clone())
                    .collect(),
                revocation_set: self.revocation_set.clone(),
                authorization_artifact_digests: self.authorization_artifact_digests.clone(),
            },
            aggregate_family_evidence: match (
                self.aggregate_root_capability_id.as_ref(),
                self.aggregate_root_binding_digest.as_ref(),
            ) {
                (Some(root_capability_id), Some(root_binding_digest)) => {
                    Some(SqliteAggregateFamilyEvidence {
                        root_capability_id: root_capability_id.clone(),
                        root_binding_digest: root_binding_digest.clone(),
                    })
                }
                (None, None) => None,
                _ => {
                    return Err(BudgetStoreError::Invariant(
                        "persisted aggregate-family authorization has incomplete root evidence"
                            .to_string(),
                    ));
                }
            },
        })
    }

    fn matches(
        &self,
        request: &SqliteCompositeAuthorizeInput,
        aggregate_family_evidence: Option<&SqliteAggregateFamilyEvidence>,
    ) -> bool {
        self.hold_id == request.hold_id
            && self.event_id == request.event_id
            && self.capability_id == request.capability_id
            && self.grant_index == request.grant_index
            && self.requested_exposure_units == request.requested_exposure_units
            && self.max_cost_per_invocation == request.max_cost_per_invocation
            && self.max_total_cost_units == request.max_total_cost_units
            && self.authority == request.authority
            && self.revocation_set == request.revocation_set
            && self.aggregate_root_capability_id.as_deref()
                == aggregate_family_evidence.map(|evidence| evidence.root_capability_id.as_str())
            && self.aggregate_root_binding_digest.as_deref()
                == aggregate_family_evidence.map(|evidence| evidence.root_binding_digest.as_str())
            && self.authorization_artifact_digests == request.authorization_artifact_digests
            && self
                .invocation_counts_after
                .iter()
                .map(|usage| &usage.quota)
                .eq(request.invocation_quotas.iter())
    }

    fn into_decision(self) -> BudgetAuthorizeHoldDecision {
        let metadata = composite_metadata(
            self.authority,
            self.allowed.then_some(self.event_seq),
            self.event_id,
        );
        if self.allowed {
            BudgetAuthorizeHoldDecision::Authorized(AuthorizedBudgetHold {
                hold_id: Some(self.hold_id),
                authorized_exposure_units: self.requested_exposure_units,
                committed_cost_units_after: self.committed_cost_units_after,
                invocation_count_after: self.invocation_count_after,
                invocation_counts_after: self.invocation_counts_after,
                invocation_state: self.invocation_state,
                monetary_state: self.monetary_state,
                revocation_set: Some(self.revocation_set),
                metadata,
            })
        } else {
            BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: Some(self.hold_id),
                attempted_exposure_units: self.requested_exposure_units,
                committed_cost_units_after: self.committed_cost_units_after,
                invocation_count_after: self.invocation_count_after,
                invocation_counts_after: self.invocation_counts_after,
                invocation_state: self.invocation_state,
                monetary_state: self.monetary_state,
                revocation_set: Some(self.revocation_set),
                metadata,
            })
        }
    }
}

fn with_composite_savepoint<T>(
    transaction: &rusqlite::Transaction<'_>,
    name: &str,
    apply: impl FnOnce() -> Result<T, BudgetStoreError>,
) -> Result<T, BudgetStoreError> {
    transaction.execute_batch(&format!("SAVEPOINT {name}"))?;
    match apply() {
        Ok(value) => {
            transaction.execute_batch(&format!("RELEASE {name}"))?;
            Ok(value)
        }
        Err(error) => {
            if let Err(rollback_error) =
                transaction.execute_batch(&format!("ROLLBACK TO {name}; RELEASE {name}"))
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget savepoint rollback failed after `{error}`: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

impl SqliteBudgetStore {
    pub fn mutation_event_for_event_id_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    event_id,
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    recorded_at,
                    event_seq,
                    usage_seq,
                    exposure_units,
                    realized_spend_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    invocation_count_after,
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                    authority_id,
                    lease_id,
                    lease_epoch,
                    operation_id,
                    request_binding_hash
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                mutation_record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Read one persisted composite authorization by its exact event ID.
    ///
    /// This method never creates or retries an authorization mutation. It is
    /// the crash-recovery point query used by the broker composition adapter.
    pub fn query_composite_authorization(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetAuthorizeHoldDecision>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let Some(record) = Self::load_mutation_event(&transaction, event_id)? else {
            transaction.rollback()?;
            return Ok(None);
        };
        if record.kind != BudgetMutationKind::ReserveInvocations {
            return Err(BudgetStoreError::Conflict(format!(
                "budget event_id `{event_id}` is not a composite authorization"
            )));
        }
        let hold_id = record.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite authorization event `{event_id}` omits hold_id"
            ))
        })?;
        let authorization =
            load_composite_authorization(&transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "composite authorization event `{event_id}` omits its frozen decision"
                ))
            })?;
        let admission_operation = record.admission_operation.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite authorization event `{event_id}` omits admission ownership"
            ))
        })?;
        authorization
            .admission_operation
            .validate_binding(admission_operation, "composite authorization")?;
        load_composite_mutation_state(&transaction, event_id)?
            .admission_operation
            .validate_binding(admission_operation, "composite authorization snapshot")?;
        if authorization.event_id != event_id {
            return Err(BudgetStoreError::Conflict(format!(
                "composite hold `{hold_id}` belongs to a different authorization event"
            )));
        }
        let decision = authorization.into_decision();
        transaction.rollback()?;
        Ok(Some(decision))
    }

    /// Reconstruct the immutable input bound to one persisted composite
    /// authorization event. This is a read-only crash-recovery query and never
    /// creates, retries, or mutates an authorization.
    pub fn query_composite_authorization_input(
        &self,
        event_id: &str,
    ) -> Result<Option<SqliteStoredCompositeAuthorizeInput>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let Some(record) = Self::load_mutation_event(&transaction, event_id)? else {
            transaction.rollback()?;
            return Ok(None);
        };
        if record.kind != BudgetMutationKind::ReserveInvocations {
            return Err(BudgetStoreError::Conflict(format!(
                "budget event_id `{event_id}` is not a composite authorization"
            )));
        }
        let hold_id = record.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite authorization event `{event_id}` omits hold_id"
            ))
        })?;
        let authorization =
            load_composite_authorization(&transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "composite authorization event `{event_id}` omits its frozen decision"
                ))
            })?;
        let admission_operation = record.admission_operation.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite authorization event `{event_id}` omits admission ownership"
            ))
        })?;
        authorization
            .admission_operation
            .validate_binding(admission_operation, "composite authorization")?;
        load_composite_mutation_state(&transaction, event_id)?
            .admission_operation
            .validate_binding(admission_operation, "composite authorization snapshot")?;
        if authorization.event_id != event_id {
            return Err(BudgetStoreError::Conflict(format!(
                "composite hold `{hold_id}` belongs to a different authorization event"
            )));
        }
        let input = authorization.authorization_input()?;
        transaction.rollback()?;
        Ok(Some(input))
    }

    /// Read one persisted composite reverse or capture mutation by event ID.
    pub fn query_composite_hold_mutation(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let Some(record) = Self::load_mutation_event(&transaction, event_id)? else {
            transaction.rollback()?;
            return Ok(None);
        };
        let hold_id = record.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite mutation event `{event_id}` omits hold_id"
            ))
        })?;
        let admission_operation = load_mutation_admission_operation(&transaction, event_id)?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "composite mutation event `{event_id}` omits admission ownership"
                ))
            })?;
        let admission_binding = BudgetAdmissionOperationBinding::new(
            admission_operation.operation_id.clone(),
            admission_operation.request_binding_hash.clone(),
        )?;
        let decision = match record.kind {
            BudgetMutationKind::CaptureInvocations => {
                let request = BudgetCaptureInvocationRequest {
                    capability_id: record.capability_id.clone(),
                    grant_index: record.grant_index as usize,
                    hold_id: Some(hold_id.to_string()),
                    event_id: Some(event_id.to_string()),
                    authority: record.authority.clone(),
                    admission_operation: Some(admission_binding.clone()),
                };
                load_composite_capture_decision(&transaction, event_id, &request)?
            }
            BudgetMutationKind::ReverseInvocations => load_composite_transition_decision(
                &transaction,
                event_id,
                BudgetMutationKind::ReverseInvocations,
                &record.capability_id,
                record.grant_index as usize,
                hold_id,
                record.authority.as_ref(),
                record.exposure_units,
                record.realized_spend_units,
                &admission_binding,
            )?,
            _ => {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget event_id `{event_id}` is not a composite reverse or capture"
                )))
            }
        }
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite mutation event `{event_id}` omits its frozen decision"
            ))
        })?;
        transaction.rollback()?;
        Ok(Some(decision))
    }

    pub(super) fn capture_composite_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision =
            Self::capture_invocation_reservations_in_transaction(&transaction, &request)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub(super) fn query_composite_invocation_capture(
        &self,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture query requires event_id".to_string())
        })?;
        if event_id.is_empty() {
            return Err(BudgetStoreError::Invariant(
                "invocation capture query requires non-empty event_id".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let decision = load_composite_capture_decision(&transaction, event_id, request)?;
        transaction.rollback()?;
        Ok(decision)
    }

    pub fn capture_invocation_reservations_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_capture_invocations", || {
            let hold_id = request.hold_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant("invocation capture requires hold_id".to_string())
            })?;
            let artifact_count = transaction.query_row(
                "SELECT COUNT(*) FROM budget_composite_authorization_artifacts WHERE hold_id = ?1",
                params![hold_id],
                |row| budget_u64_from_row(row, 0, "authorization artifact count"),
            )?;
            if artifact_count > 0 {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget hold `{hold_id}` requires the combined admission capture authority"
                )));
            }
            Self::capture_composite_invocation_reservations_in_transaction_unchecked(
                transaction,
                request,
            )
        })
    }

    pub(crate) fn capture_composite_invocation_reservations_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture requires event_id".to_string())
        })?;
        if hold_id.is_empty() || event_id.is_empty() {
            return Err(BudgetStoreError::Invariant(
                "invocation capture requires non-empty hold_id and event_id".to_string(),
            ));
        }
        let admission_operation = required_admission_operation(
            request.admission_operation.as_ref(),
            "composite invocation capture",
        )?;

        if let Some(decision) = load_composite_capture_decision(transaction, event_id, request)? {
            return Ok(decision);
        }

        let authorization =
            load_composite_authorization(transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "missing composite budget authorization for hold `{hold_id}`"
                ))
            })?;
        if !authorization.allowed {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` was not authorized"
            )));
        }
        if authorization.capability_id != request.capability_id
            || authorization.grant_index != request.grant_index
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        if authorization.authority.as_ref() != request.authority.as_ref() {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` authority does not match invocation capture"
            )));
        }
        authorization
            .admission_operation
            .validate_binding(admission_operation, "composite authorization")?;
        let base_hold = SqliteBudgetStore::ensure_open_hold(
            transaction,
            hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            hold_id,
            base_hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        validate_base_hold_admission_operation(&base_hold, admission_operation)?;
        let current_hold = load_composite_hold(transaction, hold_id)?;
        current_hold
            .admission_operation
            .validate_binding(admission_operation, "composite hold")?;
        if current_hold.invocation_state != BudgetInvocationReservationState::Authorized {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` invocation reservation is not authorized"
            )));
        }
        let completed_monetary_disposition = match current_hold.monetary_state {
            BudgetMonetaryHoldState::Reconciled => Some(HoldDisposition::Reconciled),
            BudgetMonetaryHoldState::Released => Some(HoldDisposition::Released),
            BudgetMonetaryHoldState::Captured => Some(HoldDisposition::Captured),
            BudgetMonetaryHoldState::None if base_hold.reserved_until.is_some() => None,
            BudgetMonetaryHoldState::None => Some(HoldDisposition::Captured),
            BudgetMonetaryHoldState::Exposed => None,
            BudgetMonetaryHoldState::Reversed => {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` has an authorized invocation reservation after reversal"
                )));
            }
        };
        if current_hold.revocation_set != authorization.revocation_set {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` revocation evidence diverged from authorization"
            )));
        }

        let mut staged = Vec::with_capacity(authorization.invocation_counts_after.len());
        for snapshot in &authorization.invocation_counts_after {
            let quota = &snapshot.quota;
            let (profile, owner_id, grant_index_key) = quota_storage_key(quota.key())?;
            let (maximum, reserved, captured) = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![profile, owner_id, grant_index_key],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key().owner_id()
                    ))
                })?;
            if maximum != quota.max_invocations() || reserved == 0 {
                return Err(BudgetStoreError::Conflict(format!(
                    "invocation quota `{}` does not contain the reserved hold unit",
                    quota.key().owner_id()
                )));
            }
            staged.push(StagedQuota {
                quota: quota.clone(),
                reserved: reserved - 1,
                captured: captured.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "captured invocation count overflowed u32".to_string(),
                    )
                })?,
                exists: true,
            });
        }
        let invocation_counts_after = staged
            .iter()
            .map(|entry| BudgetInvocationQuotaUsage {
                quota: entry.quota.clone(),
                reserved_invocations_after: entry.reserved,
                captured_invocations_after: entry.captured,
            })
            .collect::<Vec<_>>();
        for usage in &invocation_counts_after {
            usage.validate()?;
        }
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let legacy_usage = load_legacy_usage_for_identity(
            transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        if legacy_usage.0 != primary_count_after {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }

        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        persist_quota_rows(transaction, &staged, event_seq, now)?;
        let updated_projection = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3, seq = ?4
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                now,
                sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            ],
        )?;
        if updated_projection != 1 {
            return Err(BudgetStoreError::Invariant(
                "missing composite budget usage row".to_string(),
            ));
        }
        let updated_hold = transaction.execute(
            r#"
            UPDATE budget_composite_holds
            SET invocation_state = ?2, updated_at = ?3
            WHERE hold_id = ?1 AND invocation_state = ?4
            "#,
            params![
                hold_id,
                BudgetInvocationReservationState::Captured.as_str(),
                now,
                BudgetInvocationReservationState::Authorized.as_str(),
            ],
        )?;
        if updated_hold != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state changed during capture"
            )));
        }
        if let Some(disposition) = completed_monetary_disposition {
            SqliteBudgetStore::update_hold(
                transaction,
                hold_id,
                base_hold.remaining_exposure_units,
                disposition,
                request.authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event_with_admission_operation(
            transaction,
            BudgetMutationEventInput {
                event_id: Some(event_id),
                hold_id: Some(hold_id),
                authority: request.authority.as_ref(),
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                kind: BudgetMutationKind::CaptureInvocations,
                allowed: None,
                event_seq,
                usage_seq: Some(event_seq),
                exposure_units: 0,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: primary_count_after,
                total_cost_exposed_after: legacy_usage.1,
                total_cost_realized_spend_after: legacy_usage.2,
                admission_operation: Some(BudgetAdmissionOperationParts::new(
                    admission_operation.operation_id(),
                    admission_operation.request_binding_hash(),
                )),
            },
        )?;
        persist_composite_mutation_snapshot(
            transaction,
            event_id,
            BudgetInvocationReservationState::Captured,
            current_hold.monetary_state,
            &current_hold.revocation_set,
            &invocation_counts_after,
            admission_operation,
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: 0,
            realized_spend_units: 0,
            committed_cost_units_after: checked_committed_cost_units(
                legacy_usage.1,
                legacy_usage.2,
            )?,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: BudgetInvocationReservationState::Captured,
            monetary_state: current_hold.monetary_state,
            revocation_set: Some(current_hold.revocation_set),
            metadata: composite_metadata(
                request.authority.clone(),
                Some(event_seq),
                event_id.to_string(),
            ),
        })
    }

    pub(super) fn reverse_composite_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision = Self::reverse_composite_budget_hold_in_transaction(&transaction, request)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn reverse_composite_budget_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_reverse_composite_hold", || {
            Self::reverse_composite_budget_hold_in_transaction_unchecked(transaction, request)
        })
    }

    fn reverse_composite_budget_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reverse requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reverse requires event_id".to_string())
        })?;
        let admission_operation = required_admission_operation(
            request.admission_operation.as_ref(),
            "composite reverse",
        )?;
        if let Some(decision) = load_composite_transition_decision(
            transaction,
            event_id,
            BudgetMutationKind::ReverseInvocations,
            &request.capability_id,
            request.grant_index,
            hold_id,
            request.authority.as_ref(),
            request.reversed_exposure_units,
            0,
            admission_operation,
        )? {
            return Ok(decision);
        }

        let authorization =
            load_composite_authorization(transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "missing composite budget authorization for hold `{hold_id}`"
                ))
            })?;
        if !authorization.allowed
            || authorization.capability_id != request.capability_id
            || authorization.grant_index != request.grant_index
            || authorization.authority.as_ref() != request.authority.as_ref()
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match the composite reverse"
            )));
        }
        authorization
            .admission_operation
            .validate_binding(admission_operation, "composite authorization")?;
        let base_hold = SqliteBudgetStore::ensure_open_hold(
            transaction,
            hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            hold_id,
            base_hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        validate_base_hold_admission_operation(&base_hold, admission_operation)?;
        let current_hold = load_composite_hold(transaction, hold_id)?;
        current_hold
            .admission_operation
            .validate_binding(admission_operation, "composite hold")?;
        if current_hold.invocation_state != BudgetInvocationReservationState::Authorized {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` invocation reservation cannot be reversed"
            )));
        }
        let monetary_state = match current_hold.monetary_state {
            BudgetMonetaryHoldState::Exposed => {
                if base_hold.remaining_exposure_units != request.reversed_exposure_units {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` reverse amount does not match exposure"
                    )));
                }
                BudgetMonetaryHoldState::Reversed
            }
            BudgetMonetaryHoldState::None
            | BudgetMonetaryHoldState::Released
            | BudgetMonetaryHoldState::Reversed => {
                if request.reversed_exposure_units != 0 {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` has no reversible monetary exposure"
                    )));
                }
                current_hold.monetary_state
            }
            BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget hold `{hold_id}` monetary state cannot be reversed"
                )));
            }
        };

        let mut staged = Vec::with_capacity(authorization.invocation_counts_after.len());
        for snapshot in &authorization.invocation_counts_after {
            let quota = &snapshot.quota;
            let (profile, owner_id, grant_index_key) = quota_storage_key(quota.key())?;
            let (maximum, reserved, captured) = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![profile, owner_id, grant_index_key],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key().owner_id()
                    ))
                })?;
            if maximum != quota.max_invocations() || reserved == 0 {
                return Err(BudgetStoreError::Conflict(format!(
                    "invocation quota `{}` does not contain the reserved hold unit",
                    quota.key().owner_id()
                )));
            }
            staged.push(StagedQuota {
                quota: quota.clone(),
                reserved: reserved - 1,
                captured,
                exists: true,
            });
        }
        let invocation_counts_after = staged
            .iter()
            .map(|entry| BudgetInvocationQuotaUsage {
                quota: entry.quota.clone(),
                reserved_invocations_after: entry.reserved,
                captured_invocations_after: entry.captured,
            })
            .collect::<Vec<_>>();
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let legacy_usage = load_legacy_usage_for_identity(
            transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        if legacy_usage.0
            != primary_count_after.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("primary invocation count overflowed u32".to_string())
            })?
        {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }
        let exposed_after = legacy_usage
            .1
            .checked_sub(request.reversed_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot reverse more than total exposed cost".to_string(),
                )
            })?;
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        persist_quota_rows(transaction, &staged, event_seq, now)?;
        let updated_projection = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET invocation_count = ?3, total_cost_exposed = ?4,
                updated_at = ?5, seq = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                i64::from(primary_count_after),
                sqlite_integer_from_u64(exposed_after, "composite exposed total")?,
                now,
                sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            ],
        )?;
        if updated_projection != 1 {
            return Err(BudgetStoreError::Invariant(
                "missing composite budget usage row".to_string(),
            ));
        }
        let updated_hold = transaction.execute(
            r#"
            UPDATE budget_composite_holds
            SET invocation_state = ?2, monetary_state = ?3,
                remaining_exposure_units = 0, updated_at = ?4
            WHERE hold_id = ?1 AND invocation_state = ?5
            "#,
            params![
                hold_id,
                BudgetInvocationReservationState::Reversed.as_str(),
                monetary_state.as_str(),
                now,
                BudgetInvocationReservationState::Authorized.as_str(),
            ],
        )?;
        if updated_hold != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state changed during reverse"
            )));
        }
        SqliteBudgetStore::update_hold(
            transaction,
            hold_id,
            0,
            HoldDisposition::Reversed,
            request.authority.as_ref(),
        )?;
        SqliteBudgetStore::append_mutation_event_with_admission_operation(
            transaction,
            BudgetMutationEventInput {
                event_id: Some(event_id),
                hold_id: Some(hold_id),
                authority: request.authority.as_ref(),
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                kind: BudgetMutationKind::ReverseInvocations,
                allowed: None,
                event_seq,
                usage_seq: Some(event_seq),
                exposure_units: request.reversed_exposure_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: primary_count_after,
                total_cost_exposed_after: exposed_after,
                total_cost_realized_spend_after: legacy_usage.2,
                admission_operation: Some(BudgetAdmissionOperationParts::new(
                    admission_operation.operation_id(),
                    admission_operation.request_binding_hash(),
                )),
            },
        )?;
        persist_composite_mutation_snapshot(
            transaction,
            event_id,
            BudgetInvocationReservationState::Reversed,
            monetary_state,
            &current_hold.revocation_set,
            &invocation_counts_after,
            admission_operation,
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: checked_committed_cost_units(
                exposed_after,
                legacy_usage.2,
            )?,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: BudgetInvocationReservationState::Reversed,
            monetary_state,
            revocation_set: Some(current_hold.revocation_set),
            metadata: composite_metadata(request.authority, Some(event_seq), event_id.to_string()),
        })
    }

    pub(super) fn settle_composite_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
        capture: bool,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision =
            Self::settle_composite_budget_hold_in_transaction(&transaction, request, capture)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn settle_composite_budget_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReconcileHoldRequest,
        capture: bool,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_settle_composite_hold", || {
            Self::settle_composite_budget_hold_in_transaction_unchecked(
                transaction,
                request,
                capture,
            )
        })
    }

    fn settle_composite_budget_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReconcileHoldRequest,
        capture: bool,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite settlement requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite settlement requires event_id".to_string())
        })?;
        let admission_operation = required_admission_operation(
            request.admission_operation.as_ref(),
            "composite settlement",
        )?;
        if request.realized_spend_units > request.exposed_cost_units {
            return Err(BudgetStoreError::Conflict(
                "realized spend exceeds exposed cost".to_string(),
            ));
        }
        let kind = if capture {
            BudgetMutationKind::CaptureExposure
        } else {
            BudgetMutationKind::ReconcileSpend
        };
        let next_monetary_state = if capture {
            BudgetMonetaryHoldState::Captured
        } else {
            BudgetMonetaryHoldState::Reconciled
        };
        let terminal_disposition = if capture {
            HoldDisposition::Captured
        } else {
            HoldDisposition::Reconciled
        };

        if let Some(decision) = load_composite_transition_decision(
            transaction,
            event_id,
            kind,
            &request.capability_id,
            request.grant_index,
            hold_id,
            request.authority.as_ref(),
            request.exposed_cost_units,
            request.realized_spend_units,
            admission_operation,
        )? {
            return Ok(decision);
        }

        let authorization =
            load_composite_authorization(transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "missing composite budget authorization for hold `{hold_id}`"
                ))
            })?;
        if !authorization.allowed
            || authorization.capability_id != request.capability_id
            || authorization.grant_index != request.grant_index
            || authorization.authority.as_ref() != request.authority.as_ref()
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match the composite settlement"
            )));
        }
        authorization
            .admission_operation
            .validate_binding(admission_operation, "composite authorization")?;
        let base_hold = SqliteBudgetStore::ensure_open_hold(
            transaction,
            hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            hold_id,
            base_hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        validate_base_hold_admission_operation(&base_hold, admission_operation)?;
        let current_hold = load_composite_hold(transaction, hold_id)?;
        current_hold
            .admission_operation
            .validate_binding(admission_operation, "composite hold")?;
        if current_hold.monetary_state != BudgetMonetaryHoldState::Exposed
            || base_hold.remaining_exposure_units != request.exposed_cost_units
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not contain the settled exposure"
            )));
        }
        if matches!(
            current_hold.invocation_state,
            BudgetInvocationReservationState::Reversed
                | BudgetInvocationReservationState::Denied
                | BudgetInvocationReservationState::Absent
        ) {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` invocation state cannot settle monetary exposure"
            )));
        }
        let next_disposition =
            if current_hold.invocation_state == BudgetInvocationReservationState::Authorized {
                HoldDisposition::Open
            } else {
                terminal_disposition
            };

        let invocation_counts_after =
            load_live_quota_usages(transaction, &authorization.invocation_counts_after)?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let legacy_usage = load_legacy_usage_for_identity(
            transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        if legacy_usage.0 != primary_count_after {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }
        let exposed_after = legacy_usage
            .1
            .checked_sub(request.exposed_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot settle more than total exposed cost".to_string(),
                )
            })?;
        let realized_after = legacy_usage
            .2
            .checked_add(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow("realized spend overflowed u64".to_string())
            })?;
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        let updated_projection = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET total_cost_exposed = ?3, total_cost_realized_spend = ?4,
                updated_at = ?5, seq = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                sqlite_integer_from_u64(exposed_after, "composite exposed total")?,
                sqlite_integer_from_u64(realized_after, "composite realized-spend total")?,
                now,
                sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            ],
        )?;
        if updated_projection != 1 {
            return Err(BudgetStoreError::Invariant(
                "missing composite budget usage row".to_string(),
            ));
        }
        let updated_hold = transaction.execute(
            r#"
            UPDATE budget_composite_holds
            SET monetary_state = ?2, remaining_exposure_units = 0, updated_at = ?3
            WHERE hold_id = ?1 AND monetary_state = ?4
            "#,
            params![
                hold_id,
                next_monetary_state.as_str(),
                now,
                BudgetMonetaryHoldState::Exposed.as_str(),
            ],
        )?;
        if updated_hold != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary state changed during settlement"
            )));
        }
        SqliteBudgetStore::update_hold(
            transaction,
            hold_id,
            0,
            next_disposition,
            request.authority.as_ref(),
        )?;
        SqliteBudgetStore::append_mutation_event_with_admission_operation(
            transaction,
            BudgetMutationEventInput {
                event_id: Some(event_id),
                hold_id: Some(hold_id),
                authority: request.authority.as_ref(),
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                kind,
                allowed: None,
                event_seq,
                usage_seq: Some(event_seq),
                exposure_units: request.exposed_cost_units,
                realized_spend_units: request.realized_spend_units,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: primary_count_after,
                total_cost_exposed_after: exposed_after,
                total_cost_realized_spend_after: realized_after,
                admission_operation: Some(BudgetAdmissionOperationParts::new(
                    admission_operation.operation_id(),
                    admission_operation.request_binding_hash(),
                )),
            },
        )?;
        persist_composite_mutation_snapshot(
            transaction,
            event_id,
            current_hold.invocation_state,
            next_monetary_state,
            &current_hold.revocation_set,
            &invocation_counts_after,
            admission_operation,
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after: checked_committed_cost_units(
                exposed_after,
                realized_after,
            )?,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: current_hold.invocation_state,
            monetary_state: next_monetary_state,
            revocation_set: Some(current_hold.revocation_set),
            metadata: composite_metadata(request.authority, Some(event_seq), event_id.to_string()),
        })
    }

    pub(super) fn release_composite_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision = Self::release_composite_budget_hold_in_transaction(&transaction, request)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn release_composite_budget_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_release_composite_hold", || {
            Self::release_composite_budget_hold_in_transaction_unchecked(transaction, request)
        })
    }

    fn release_composite_budget_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires event_id".to_string())
        })?;
        let admission_operation = required_admission_operation(
            request.admission_operation.as_ref(),
            "composite release",
        )?;
        if let Some(decision) = load_composite_transition_decision(
            transaction,
            event_id,
            BudgetMutationKind::ReleaseExposure,
            &request.capability_id,
            request.grant_index,
            hold_id,
            request.authority.as_ref(),
            request.released_exposure_units,
            0,
            admission_operation,
        )? {
            return Ok(decision);
        }

        let authorization =
            load_composite_authorization(transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "missing composite budget authorization for hold `{hold_id}`"
                ))
            })?;
        if !authorization.allowed
            || authorization.capability_id != request.capability_id
            || authorization.grant_index != request.grant_index
            || authorization.authority.as_ref() != request.authority.as_ref()
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match the composite release"
            )));
        }
        authorization
            .admission_operation
            .validate_binding(admission_operation, "composite authorization")?;
        let base_hold = SqliteBudgetStore::ensure_open_hold(
            transaction,
            hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            hold_id,
            base_hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        validate_base_hold_admission_operation(&base_hold, admission_operation)?;
        let current_hold = load_composite_hold(transaction, hold_id)?;
        current_hold
            .admission_operation
            .validate_binding(admission_operation, "composite hold")?;
        if current_hold.monetary_state != BudgetMonetaryHoldState::Exposed
            || request.released_exposure_units > base_hold.remaining_exposure_units
            || matches!(
                current_hold.invocation_state,
                BudgetInvocationReservationState::Reversed
                    | BudgetInvocationReservationState::Denied
                    | BudgetInvocationReservationState::Absent
            )
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` cannot release the requested exposure"
            )));
        }

        let invocation_counts_after =
            load_live_quota_usages(transaction, &authorization.invocation_counts_after)?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let legacy_usage = load_legacy_usage_for_identity(
            transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        if legacy_usage.0 != primary_count_after {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }
        let exposed_after = legacy_usage
            .1
            .checked_sub(request.released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot release more than total exposed cost".to_string(),
                )
            })?;
        let remaining_exposure = base_hold
            .remaining_exposure_units
            .checked_sub(request.released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("cannot release more than hold exposure".to_string())
            })?;
        let next_monetary_state = if remaining_exposure == 0 {
            BudgetMonetaryHoldState::Released
        } else {
            BudgetMonetaryHoldState::Exposed
        };
        let next_disposition = if remaining_exposure == 0
            && current_hold.invocation_state == BudgetInvocationReservationState::Captured
        {
            HoldDisposition::Released
        } else {
            HoldDisposition::Open
        };
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        let updated_projection = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET total_cost_exposed = ?3, updated_at = ?4, seq = ?5
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                sqlite_integer_from_u64(exposed_after, "composite exposed total")?,
                now,
                sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            ],
        )?;
        if updated_projection != 1 {
            return Err(BudgetStoreError::Invariant(
                "missing composite budget usage row".to_string(),
            ));
        }
        let updated_hold = transaction.execute(
            r#"
            UPDATE budget_composite_holds
            SET monetary_state = ?2, remaining_exposure_units = ?3, updated_at = ?4
            WHERE hold_id = ?1 AND monetary_state = ?5
            "#,
            params![
                hold_id,
                next_monetary_state.as_str(),
                sqlite_integer_from_u64(remaining_exposure, "composite remaining exposure")?,
                now,
                BudgetMonetaryHoldState::Exposed.as_str(),
            ],
        )?;
        if updated_hold != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary state changed during release"
            )));
        }
        SqliteBudgetStore::update_hold(
            transaction,
            hold_id,
            remaining_exposure,
            next_disposition,
            request.authority.as_ref(),
        )?;
        SqliteBudgetStore::append_mutation_event_with_admission_operation(
            transaction,
            BudgetMutationEventInput {
                event_id: Some(event_id),
                hold_id: Some(hold_id),
                authority: request.authority.as_ref(),
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                kind: BudgetMutationKind::ReleaseExposure,
                allowed: None,
                event_seq,
                usage_seq: Some(event_seq),
                exposure_units: request.released_exposure_units,
                realized_spend_units: 0,
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost_units: None,
                invocation_count_after: primary_count_after,
                total_cost_exposed_after: exposed_after,
                total_cost_realized_spend_after: legacy_usage.2,
                admission_operation: Some(BudgetAdmissionOperationParts::new(
                    admission_operation.operation_id(),
                    admission_operation.request_binding_hash(),
                )),
            },
        )?;
        persist_composite_mutation_snapshot(
            transaction,
            event_id,
            current_hold.invocation_state,
            next_monetary_state,
            &current_hold.revocation_set,
            &invocation_counts_after,
            admission_operation,
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: checked_committed_cost_units(
                exposed_after,
                legacy_usage.2,
            )?,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: current_hold.invocation_state,
            monetary_state: next_monetary_state,
            revocation_set: Some(current_hold.revocation_set),
            metadata: composite_metadata(request.authority, Some(event_seq), event_id.to_string()),
        })
    }
}
