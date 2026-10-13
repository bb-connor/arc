use super::client::build_client;
use super::errors::into_budget_store_error;
use super::*;

#[path = "budget/lifecycle.rs"]
mod lifecycle;
#[path = "budget/recovery.rs"]
mod recovery;
#[path = "budget/structured.rs"]
mod structured;

#[derive(Clone, Copy)]
enum StructuredUsageSequenceRelation {
    None,
    ExistingProjection,
    AdvancesAtCommit,
}

pub fn build_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn BudgetStore>, CliError> {
    Ok(Box::new(remote_budget_store(control_url, control_token)?))
}

pub(crate) fn build_shared_remote_budget_store(
    control_url: &str,
    control_token: &str,
    recovery_fence: chio_kernel::admission_operation::StoreMutationFence,
) -> Result<Arc<RemoteBudgetStore>, CliError> {
    let mut store = remote_budget_store(control_url, control_token)?;
    store.recovery_fence = Some(recovery_fence);
    Ok(Arc::new(store))
}

fn remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<RemoteBudgetStore, CliError> {
    Ok(RemoteBudgetStore {
        client: build_client(control_url, control_token)?,
        recovery_fence: None,
        cached_usage: Mutex::new(HashMap::new()),
    })
}

fn remote_budget_grant_index(grant_index: usize) -> Result<u32, BudgetStoreError> {
    u32::try_from(grant_index)
        .map_err(|_| BudgetStoreError::Invariant("grant_index exceeds u32 range".to_string()))
}

fn validate_remote_budget_identity(
    capability_id: &str,
    grant_index: usize,
    response_capability_id: &str,
    response_grant_index: usize,
    transition: &str,
) -> Result<(), BudgetStoreError> {
    if response_capability_id != capability_id || response_grant_index != grant_index {
        return Err(BudgetStoreError::Invariant(format!(
            "remote budget {transition} response changed the request identity"
        )));
    }
    Ok(())
}

fn structured_budget_error(error: impl Into<String>) -> BudgetStoreError {
    BudgetStoreError::Invariant(error.into())
}

fn reject_unsupported_remote_hard_authority(
    request: &BudgetAuthorizeHoldRequest,
) -> Result<(), BudgetStoreError> {
    if request
        .invocation_quotas
        .iter()
        .any(|quota| quota.key.profile == BudgetQuotaProfile::AggregateFamilyInvocation)
    {
        return Err(structured_budget_error(
            "advisory remote budget authority cannot enforce aggregate family invocation limits without a modeled partition escrow profile",
        ));
    }
    if request.cumulative_approval.is_some() {
        return Err(structured_budget_error(
            "advisory remote budget authority cannot reserve cumulative family approval without a modeled partition escrow profile",
        ));
    }
    Ok(())
}

impl BudgetStore for RemoteBudgetStore {
    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<chio_kernel::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        self.load_retained_budget_hold(hold_id)
    }

    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        BudgetGuaranteeLevel::AdvisoryPosthoc
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        remote_budget_grant_index(request.grant_index)?;
        request.validate()?;
        reject_unsupported_remote_hard_authority(&request)?;
        if !request.invocation_quotas.is_empty()
            || request.cumulative_approval.is_some()
            || request.admission_binding.is_some()
        {
            return self.authorize_structured_budget_hold(request);
        }
        let response = self
            .client
            .authorize_budget_exposure(&TryChargeCostRequest {
                capability_id: request.capability_id.clone(),
                grant_index: request.grant_index,
                max_invocations: request.max_invocations,
                cost_units: request.requested_exposure_units,
                max_cost_per_invocation: request.max_cost_per_invocation,
                max_total_cost_units: request.max_total_cost_units,
                hold_id: request.hold_id.clone(),
                event_id: request.event_id.clone(),
            })
            .map_err(into_budget_store_error)?;
        validate_remote_budget_identity(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            "authorization",
        )?;
        if response.hold_id != request.hold_id {
            return Err(BudgetStoreError::Invariant(
                "remote budget authorization response changed or omitted the request hold identity"
                    .to_string(),
            ));
        }
        let event_id_matches = match response.decision {
            BudgetAuthorizeExposureDecision::AlreadyCaptured => !response.event_id.is_empty(),
            BudgetAuthorizeExposureDecision::Authorized
            | BudgetAuthorizeExposureDecision::Denied => response.event_id == request.event_id,
        };
        if !event_id_matches {
            return Err(BudgetStoreError::Invariant(
                "remote budget authorization response changed or omitted the request event identity"
                    .to_string(),
            ));
        }
        let event_id = response.event_id.clone();
        let mutation_invocation_count_after =
            response.mutation_invocation_count_after.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "remote budget authorization response omitted event-time invocation count"
                        .to_string(),
                )
            })?;
        let mutation_committed_cost_units_after = response
            .mutation_committed_cost_units_after
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "remote budget authorization response omitted event-time committed cost"
                        .to_string(),
                )
            })?;
        let captured_state = if matches!(
            response.decision,
            BudgetAuthorizeExposureDecision::AlreadyCaptured
        ) {
            Some((
                response.exposure_units.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted original exposure"
                            .to_string(),
                    )
                })?,
                response.realized_spend_units.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted original realized spend"
                            .to_string(),
                    )
                })?,
            ))
        } else {
            None
        };
        match response.decision {
            BudgetAuthorizeExposureDecision::Authorized
                if response.exposure_units == Some(request.requested_exposure_units)
                    && response.realized_spend_units == Some(0) => {}
            BudgetAuthorizeExposureDecision::Denied
                if response.exposure_units.is_none() && response.realized_spend_units.is_none() => {
            }
            BudgetAuthorizeExposureDecision::AlreadyCaptured => {}
            _ => {
                return Err(BudgetStoreError::Invariant(
                    "remote budget authorization response changed the event-time exposure state"
                        .to_string(),
                ))
            }
        }
        let required_committed_cost = match response.decision {
            BudgetAuthorizeExposureDecision::Authorized => Some(request.requested_exposure_units),
            BudgetAuthorizeExposureDecision::AlreadyCaptured => {
                let (exposure_units, realized_spend_units) = captured_state.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted original mutation state"
                            .to_string(),
                    )
                })?;
                Some(
                    exposure_units
                        .checked_add(realized_spend_units)
                        .ok_or_else(|| {
                            BudgetStoreError::Overflow(
                                "captured remote authorization replay overflowed committed cost"
                                    .to_string(),
                            )
                        })?,
                )
            }
            BudgetAuthorizeExposureDecision::Denied => None,
        };
        if required_committed_cost.is_some_and(|required| {
            mutation_invocation_count_after == 0 || mutation_committed_cost_units_after < required
        }) {
            return Err(BudgetStoreError::Invariant(
                "remote budget authorization response returned impossible event-time state"
                    .to_string(),
            ));
        }
        let metadata = self.remote_budget_commit_metadata(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
            Some(event_id),
        );
        let decision = match response.decision {
            BudgetAuthorizeExposureDecision::Authorized => {
                BudgetAuthorizeHoldDecision::Authorized(BudgetHoldAuthorizationRecord {
                    cleanup_custody: response.cleanup_custody,
                    hold_id: Some(request.hold_id),
                    admission_binding: None,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after: mutation_committed_cost_units_after,
                    invocation_count_after: mutation_invocation_count_after,
                    invocation_quota_usages: Vec::new(),
                    cumulative_approval: None,
                    invocation_state: BudgetInvocationState::Authorized,
                    monetary_state: if request.requested_exposure_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Exposed
                    },
                    metadata,
                })
            }
            BudgetAuthorizeExposureDecision::Denied => {
                BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                    hold_id: Some(request.hold_id),
                    admission_binding: None,
                    attempted_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after: mutation_committed_cost_units_after,
                    invocation_count_after: mutation_invocation_count_after,
                    invocation_quota_usages: Vec::new(),
                    cumulative_approval: None,
                    invocation_state: BudgetInvocationState::Denied,
                    monetary_state: BudgetMonetaryState::None,
                    metadata,
                })
            }
            BudgetAuthorizeExposureDecision::AlreadyCaptured => {
                let (exposure_units, realized_spend_units) = captured_state.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured remote authorization replay omitted original mutation state"
                            .to_string(),
                    )
                })?;
                BudgetAuthorizeHoldDecision::AlreadyCaptured(BudgetHoldMutationDecision {
                    hold_id: Some(request.hold_id),
                    admission_binding: None,
                    exposure_units,
                    realized_spend_units,
                    committed_cost_units_after: mutation_committed_cost_units_after,
                    invocation_count_after: mutation_invocation_count_after,
                    invocation_quota_usages: Vec::new(),
                    cumulative_approval: None,
                    invocation_state: BudgetInvocationState::Captured,
                    monetary_state: if exposure_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Exposed
                    },
                    metadata,
                })
            }
        };
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response.usage_seq,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        Ok(decision)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        self.capture_invocation_reservations_remote(request)
    }

    fn authorize_cumulative_approval(
        &self,
        request: BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<BudgetCumulativeApprovalAuthorizationDecision, BudgetStoreError> {
        self.authorize_cumulative_approval_remote(request)
    }

    fn cancel_captured_before_dispatch(
        &self,
        request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        self.cancel_captured_before_dispatch_remote(request)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.reverse_budget_hold_remote(request)
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.release_budget_hold_remote(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.reconcile_budget_hold_remote(request)
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.capture_budget_hold_remote(request)
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let response = self
            .client
            .list_budgets(&BudgetQuery {
                capability_id: capability_id.map(ToOwned::to_owned),
                limit: Some(limit),
            })
            .map_err(into_budget_store_error)?;
        let usages: Vec<_> = response
            .usages
            .into_iter()
            .map(|usage| BudgetUsageRecord {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                updated_at: usage.updated_at,
                seq: usage.seq.unwrap_or(0),
                total_cost_exposed: usage.total_cost_exposed,
                total_cost_realized_spend: usage.total_cost_realized_spend,
            })
            .collect();
        self.merge_cached_usages(capability_id, &usages)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        let grant_index_u32 = remote_budget_grant_index(grant_index)?;
        if let Some(cached) = self.cached_entry(capability_id, grant_index) {
            if cached.observed.is_complete() {
                cached.record.committed_cost_units()?;
                return Ok(Some(cached.record));
            }
        }
        self.list_usages(MAX_LIST_LIMIT, Some(capability_id))
            .map(|usages| {
                usages
                    .into_iter()
                    .find(|usage| usage.grant_index == grant_index_u32)
            })
    }

    fn get_cumulative_approval_operation_usage(
        &self,
        operation_id: &str,
    ) -> Result<Option<BudgetCumulativeApprovalUsage>, BudgetStoreError> {
        self.get_cumulative_approval_operation_usage_remote(operation_id)
    }

    fn get_invocation_quota_usage(
        &self,
        _key: &BudgetQuotaKey,
    ) -> Result<Option<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        Err(structured_budget_error(
            "remote budget authority does not expose invocation quota usage",
        ))
    }

    fn get_cumulative_approval_account_usage(
        &self,
        _key: &BudgetCumulativeApprovalAccountKey,
    ) -> Result<Option<chio_kernel::budget_store::BudgetCumulativeApprovalAccountUsage>, BudgetStoreError> {
        Err(structured_budget_error(
            "remote budget authority does not expose cumulative approval account usage",
        ))
    }

    fn list_mutation_events(
        &self,
        _limit: usize,
        _capability_id: Option<&str>,
        _grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        Err(structured_budget_error(
            "remote budget authority does not expose mutation events",
        ))
    }

    /// The remote authority reaps its own holds; this client owns none.
    fn reap_orphaned_holds(
        &self,
        _realized_by_hold: &HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        Ok((0, 0))
    }

    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        Ok(0)
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        Ok(None)
    }

    fn request_id_has_reserved_hold(
        &self,
        _request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        Ok(None)
    }

    fn mark_hold_reserved(
        &self,
        _hold_id: &str,
        _reserved_until_unix_secs: i64,
        _currency: &str,
        _payment_reference: Option<&str>,
        _envelope: &chio_kernel::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        Err(structured_budget_error(
            "remote budget authority does not support durable hold reservation",
        ))
    }

    fn reap_expired_reserved_holds(&self, _now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        Ok(0)
    }
}

impl RemoteBudgetStore {
    pub(super) fn cache_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
        seq: Option<u64>,
        invocation_count: Option<u32>,
        total_cost_exposed: Option<u64>,
        total_cost_realized_spend: Option<u64>,
    ) -> Result<BudgetUsageRecord, BudgetStoreError> {
        let grant_index_u32 = remote_budget_grant_index(grant_index)?;
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let key = (capability_id.to_string(), grant_index);
        if let Some(existing) = cached_usage.get(&key).map(|entry| &entry.record) {
            if seq.is_some_and(|seq| seq < existing.seq) || seq.is_none() && existing.seq > 0 {
                existing.committed_cost_units()?;
                return Ok(existing.clone());
            }
        }

        if invocation_count.is_none()
            && total_cost_exposed.is_none()
            && total_cost_realized_spend.is_none()
            && seq.is_none()
        {
            return Ok(cached_usage
                .get(&key)
                .map(|entry| entry.record.clone())
                .unwrap_or(BudgetUsageRecord {
                    capability_id: capability_id.to_string(),
                    grant_index: grant_index_u32,
                    invocation_count: 0,
                    updated_at: 0,
                    seq: 0,
                    total_cost_exposed: 0,
                    total_cost_realized_spend: 0,
                }));
        }

        let prior = cached_usage.get(&key);
        let same_sequence = prior.filter(|entry| seq == Some(entry.record.seq));
        let (mut projected, mut observed) = match same_sequence {
            Some(entry) => (entry.record.clone(), entry.observed),
            None => (
                BudgetUsageRecord {
                    capability_id: capability_id.to_string(),
                    grant_index: grant_index_u32,
                    invocation_count: 0,
                    updated_at: 0,
                    seq: seq.unwrap_or(0),
                    total_cost_exposed: 0,
                    total_cost_realized_spend: 0,
                },
                BudgetUsageProvenance::default(),
            ),
        };
        if let Some(invocation_count) = invocation_count {
            projected.invocation_count = invocation_count;
            observed.invocation_count = true;
        }
        if let Some(total_cost_exposed) = total_cost_exposed {
            projected.total_cost_exposed = total_cost_exposed;
            observed.total_cost_exposed = true;
        }
        if let Some(total_cost_realized_spend) = total_cost_realized_spend {
            projected.total_cost_realized_spend = total_cost_realized_spend;
            observed.total_cost_realized_spend = true;
        }
        if same_sequence.is_some_and(|entry| !entry.observed.agrees_with(&entry.record, &projected))
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget cache replay changed state at the same sequence".to_string(),
            ));
        }
        projected.committed_cost_units()?;
        cached_usage.insert(
            key,
            CachedBudgetUsage {
                record: projected.clone(),
                observed,
            },
        );
        Ok(projected)
    }

    #[cfg(test)]
    pub(super) fn cached_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Option<BudgetUsageRecord> {
        self.cached_entry(capability_id, grant_index)
            .map(|entry| entry.record)
    }

    fn cached_entry(&self, capability_id: &str, grant_index: usize) -> Option<CachedBudgetUsage> {
        match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
        .get(&(capability_id.to_string(), grant_index))
        .cloned()
    }

    fn merge_cached_usages(
        &self,
        capability_id: Option<&str>,
        usages: &[BudgetUsageRecord],
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let keyed_usages = usages
            .iter()
            .map(|usage| {
                if capability_id.is_some_and(|expected| usage.capability_id != expected) {
                    return Err(BudgetStoreError::Invariant(
                        "remote budget list response changed the requested capability identity"
                            .to_string(),
                    ));
                }
                usage.committed_cost_units()?;
                let grant_index = usize::try_from(usage.grant_index).map_err(|_| {
                    BudgetStoreError::Invariant("grant_index exceeds usize range".to_string())
                })?;
                Ok(((usage.capability_id.clone(), grant_index), usage.clone()))
            })
            .collect::<Result<Vec<_>, BudgetStoreError>>()?;
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut merged = cached_usage.clone();
        for (key, usage) in &keyed_usages {
            if let Some(existing) = merged.get(key) {
                if usage.seq < existing.record.seq {
                    continue;
                }
                if usage.seq == existing.record.seq {
                    if existing.observed.is_complete() && existing.record != *usage
                        || !existing.observed.agrees_with(&existing.record, usage)
                    {
                        return Err(BudgetStoreError::Invariant(
                            "remote budget cache replay changed state at the same sequence"
                                .to_string(),
                        ));
                    }
                    if existing.observed.is_complete() {
                        continue;
                    }
                }
            }
            // List responses carry the full durable usage projection.
            merged.insert(
                key.clone(),
                CachedBudgetUsage {
                    record: usage.clone(),
                    observed: BudgetUsageProvenance::complete(),
                },
            );
        }
        if merged.iter().any(|(key, entry)| {
            capability_id.is_none_or(|expected| key.0 == expected) && !entry.observed.is_complete()
        }) {
            return Err(BudgetStoreError::Invariant(
                "remote budget list could not complete a known usage projection".to_string(),
            ));
        }
        let merged_usages = keyed_usages
            .iter()
            .map(|(key, _)| {
                merged
                    .get(key)
                    .map(|entry| entry.record.clone())
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "remote budget list merge omitted a validated usage".to_string(),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        *cached_usage = merged;
        Ok(merged_usages)
    }

    fn remote_budget_commit_metadata(
        &self,
        authority: Option<&BudgetAuthorityMetadataView>,
        commit: Option<&BudgetWriteCommitView>,
        fallback_authority: Option<&BudgetEventAuthority>,
        event_id: Option<String>,
    ) -> BudgetCommitMetadata {
        BudgetCommitMetadata {
            authority: remote_budget_event_authority(authority, commit)
                .or_else(|| fallback_authority.cloned()),
            guarantee_level: remote_budget_guarantee_level(authority, commit),
            budget_profile: self.budget_authority_profile(),
            metering_profile: self.budget_metering_profile(),
            budget_commit_index: response_budget_commit_index(authority, commit),
            event_id,
            recorded_at_unix_seconds: None,
        }
    }
}

fn response_budget_commit_index(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> Option<u64> {
    commit
        .map(|commit| commit.commit_index)
        .or_else(|| authority.and_then(|authority| authority.budget_commit_index))
}

fn remote_budget_event_authority(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> Option<BudgetEventAuthority> {
    commit
        .filter(|commit| commit.quorum_committed)
        .map(|commit| BudgetEventAuthority {
            authority_id: commit.authority_id.clone(),
            lease_id: commit.lease_id.clone(),
            lease_epoch: commit.lease_epoch,
        })
        .or_else(|| {
            authority.map(|authority| BudgetEventAuthority {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            })
        })
}

fn remote_budget_guarantee_level(
    _authority: Option<&BudgetAuthorityMetadataView>,
    _commit: Option<&BudgetWriteCommitView>,
) -> BudgetGuaranteeLevel {
    BudgetGuaranteeLevel::AdvisoryPosthoc
}
