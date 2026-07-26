pub trait BudgetStore: Send + Sync {
    fn authority_profile(&self) -> BudgetStoreProfile {
        BudgetStoreProfile::EphemeralLocal
    }

    /// Whether this backend durably co-commits an authorization hold and its
    /// `HoldPlaced` payment-journal row, then supports durable compare-and-set
    /// journal advances, exact readback, incomplete-row listing, and closure.
    ///
    /// Operation-owned payment admission relies on all of those properties as
    /// one recovery contract. Backends must not return `true` merely because
    /// they implement one or more journal methods. The default is fail-closed.
    fn supports_durable_atomic_payment_journal(&self) -> bool {
        false
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError>;

    /// Atomically check monetary budget limits and record provisional exposure if within bounds.
    ///
    /// Checks:
    /// 1. `invocation_count < max_invocations` (if set)
    /// 2. `cost_units <= max_cost_per_invocation` (if set)
    /// 3. `(total_cost_exposed + total_cost_realized_spend + cost_units)
    ///    <= max_total_cost_units` (if set)
    ///
    /// On pass: increments `invocation_count` by 1 and `total_cost_exposed` by
    /// `cost_units`, allocates a new replication seq, returns `Ok(true)`.
    /// On any limit exceeded: rolls back, returns `Ok(false)`.
    ///
    // SAFETY: HA overrun bound = max_cost_per_invocation x node_count
    // In a split-brain scenario, each HA node may independently approve up to
    // one invocation at the full per-invocation cap before the LWW merge
    // propagates the updated total. The maximum possible overrun is therefore
    // bounded by max_cost_per_invocation multiplied by the number of active
    // nodes in the HA cluster.
    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        let _ = authority;
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
        )
    }

    /// Reverse a previously applied provisional exposure for a pre-execution denial path.
    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
    }

    /// Release a previously exposed monetary amount without changing invocation count.
    ///
    /// This is used when the kernel needs to release provisional exposure without
    /// realizing any spend in the budget store itself.
    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
    }

    /// Atomically release provisional exposure and record realized spend.
    ///
    /// This removes `exposed_cost_units` from `total_cost_exposed` and adds
    /// `realized_cost_units` to `total_cost_realized_spend` without changing
    /// invocation count. `realized_cost_units` must not exceed
    /// `exposed_cost_units`.
    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        let _ = hold_id;
        let _ = event_id;
        self.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let _ = authority;
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError>;

    fn list_mutation_events(
        &self,
        _limit: usize,
        _capability_id: Option<&str>,
        _grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget mutation events unavailable for this backend".to_string(),
        ))
    }

    /// Return the exact durable mutation event for an explicit id.
    /// Hard-guarantee stores using the default authorization method must override this.
    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        let _ = event_id;
        Err(BudgetStoreError::Invariant(
            "exact budget mutation event lookup is unavailable for this backend".to_string(),
        ))
    }

    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        BudgetGuaranteeLevel::SingleNodeAtomic
    }

    fn budget_authority_profile(&self) -> BudgetAuthorityProfile {
        BudgetAuthorityProfile::AuthoritativeHoldEvent
    }

    fn budget_metering_profile(&self) -> BudgetMeteringProfile {
        BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual
    }

    /// Exact durable counter identity used by partition-escrow configuration.
    /// A store must return `Some` only when it enforces the named namespace
    /// under the supplied fencing token across restart and failover.
    fn partition_escrow_store_binding(
        &self,
    ) -> Result<Option<PartitionEscrowStoreBinding>, BudgetStoreError> {
        Ok(None)
    }

    /// Open holds created at or before `older_than_unix_ms`, oldest first.
    /// Default: empty (stores without hold rows have nothing to sweep).
    fn list_open_holds_older_than(
        &self,
        _older_than_unix_ms: u64,
        _limit: usize,
    ) -> Result<Vec<OpenHoldSummary>, BudgetStoreError> {
        Ok(Vec::new())
    }

    /// Release the remaining exposure of an open hold, mark it expired, and
    /// append an expire event. Idempotent: a non-open hold returns
    /// `Ok(false)`. Default: unsupported.
    fn expire_open_hold(&self, _hold_id: &str) -> Result<bool, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "open-hold sweep is not supported by this budget store".to_string(),
        ))
    }

    /// Reverse legacy no-payment caller-reservation holds whose atomic
    /// authorization committed but whose nonce TTL stamp did not.
    /// Implementations must select only holds carrying the explicit no-payment
    /// authorization marker, still open, unstamped, and not owned by an
    /// admission operation. A rail-moving path must never enter this recovery
    /// lane. The recovery is a startup operation and must make each recovered
    /// request id retryable.
    fn recover_unstamped_caller_reservations(&self) -> Result<usize, BudgetStoreError> {
        Ok(0)
    }

    /// Count of holds currently open, for the open-holds gauge. Default: 0.
    fn open_hold_count(&self) -> Result<u64, BudgetStoreError> {
        Ok(0)
    }

    /// Insert a fresh payment-journal row in `HoldPlaced`. Fails closed on
    /// a reused request id. Default: unsupported.
    fn record_payment_journal(
        &self,
        _entry: &crate::payment::PaymentJournalRecord,
    ) -> Result<(), BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "payment journal is not supported by this budget store".to_string(),
        ))
    }

    /// Compare-and-set state advance. `expected` must match the current row
    /// state or the call fails closed. When advancing to `Settling` the
    /// caller MUST pass `settle` so the store stamps the committed action
    /// and amount atomically with the state change; `settle` is invalid on
    /// every other transition. Default: unsupported.
    fn advance_payment_journal(
        &self,
        _request_id: &str,
        _expected: crate::payment::PaymentJournalState,
        _next: crate::payment::PaymentJournalState,
        _authorization_id: Option<&str>,
        _transaction_id: Option<&str>,
        _settle: Option<crate::payment::PaymentSettleIntent>,
    ) -> Result<(), BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "payment journal is not supported by this budget store".to_string(),
        ))
    }

    /// Move the row to `Closed`. Idempotent: an already-closed or absent
    /// row returns `Ok(false)`. Default: unsupported.
    fn close_payment_journal(&self, _request_id: &str) -> Result<bool, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "payment journal is not supported by this budget store".to_string(),
        ))
    }

    /// Rows in a non-terminal state created at or before
    /// `older_than_unix_ms`, oldest first, for boot reconciliation.
    /// Default: empty (stores without the journal have no orphans).
    fn list_incomplete_payment_journal(
        &self,
        _older_than_unix_ms: u64,
    ) -> Result<Vec<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        Ok(Vec::new())
    }

    /// Look up one incomplete payment-journal row by request id. Scoped
    /// identically to [`Self::list_incomplete_payment_journal`]: a closed,
    /// reconcile-failed, or absent row returns `Ok(None)`, never a stale
    /// terminal record. Default: a linear scan over
    /// `list_incomplete_payment_journal`, correct for any store but O(n) in
    /// the number of open rows; a store expecting many concurrent monetary
    /// orphans should override this with a keyed lookup.
    fn get_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        Ok(self
            .list_incomplete_payment_journal(u64::MAX)?
            .into_iter()
            .find(|row| row.request_id == request_id))
    }

    /// Rail recorded on `request_id`'s payment-journal row, if (and only if)
    /// that row is currently `ReconcileFailed`: a durable operator incident
    /// the money-path pass already gave up on. Distinct from
    /// [`Self::get_payment_journal`], which never surfaces a reconcile-
    /// failed row (see its doc) -- the monetary dispatch-intent reconciler
    /// uses this targeted lookup so such a row is promoted into a
    /// dead-letter instead of being reported as a clean resolution, keeping
    /// the incident visible to RFC-0003's health-flipping dead-letter
    /// surface. Default: `Ok(None)`, for stores without the journal or
    /// without this targeted lookup (they report no incidents, matching
    /// `list_incomplete_payment_journal`'s empty default).
    fn payment_journal_reconcile_failed_rail(
        &self,
        _request_id: &str,
    ) -> Result<Option<String>, BudgetStoreError> {
        Ok(None)
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request.requires_existing_authorization_replay() {
            return Err(BudgetStoreError::Invariant(
                "snapshot-derived authorization requires the committed replay operation"
                    .to_string(),
            ));
        }
        if !request.invocation_quotas().is_empty() || request.revocation_set().is_some() {
            return Err(BudgetStoreError::Invariant(
                "composite budget holds are unavailable for this backend".to_string(),
            ));
        }
        let requires_durable_decision = !matches!(
            self.budget_guarantee_level(),
            BudgetGuaranteeLevel::AdvisoryPosthoc
        );
        let durable_event_preexisted = if requires_durable_decision {
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "durable budget authorization requires an event_id".to_string(),
                )
            })?;
            let existing = self.get_mutation_event_by_id(event_id)?;
            if let Some(record) = existing.as_ref() {
                let frozen_allowed = record.allowed.ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "durable budget authorization event omitted its outcome".to_string(),
                    )
                })?;
                validate_default_authorization_event(&request, frozen_allowed, record)?;
            }
            Some(existing.is_some())
        } else {
            None
        };
        let monetary_state = if request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some()
        {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        let allowed = self.try_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.max_invocations,
            request.requested_exposure_units,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let durable_decision_event = if requires_durable_decision {
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "durable budget authorization requires an event_id".to_string(),
                )
            })?;
            let exact_event = self
                .get_mutation_event_by_id(event_id)
                .and_then(|record| {
                    record.ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "durable budget authorization event `{event_id}` is unavailable"
                        ))
                    })
                })
                .and_then(|record| {
                    let committed_cost_units_after =
                        validate_default_authorization_event(&request, allowed, &record)?;
                    Ok((record, committed_cost_units_after))
                });
            match exact_event {
                Ok(record) => Some(record),
                Err(error) => {
                    if allowed && durable_event_preexisted == Some(false) {
                        let rollback_event_id =
                            format!("{event_id}:missing-decision-event-rollback");
                        if let Err(rollback_error) = self
                            .reverse_charge_cost_with_ids_and_authority(
                                &request.capability_id,
                                request.grant_index,
                                request.requested_exposure_units,
                                request.hold_id.as_deref(),
                                Some(&rollback_event_id),
                                request.authority.as_ref(),
                            )
                        {
                            tracing::warn!(
                                capability_id = %request.capability_id,
                                grant_index = request.grant_index,
                                reason = %redacted!(&rollback_error.to_string()),
                                "budget hold rollback failed after durable decision lookup failure"
                            );
                        }
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        // The recoverable money record exists only for a granted hold: a
        // budget-denied request never touches the rail, so journaling it
        // would leave an incomplete HoldPlaced row for reconciliation to
        // raise as a false monetary incident. Stores that cannot co-commit
        // the two writes persist the journal immediately after the grant; a
        // store that cannot persist it revokes the hold it just granted and
        // fails closed, so the money path never runs without its crash
        // record. A crash between the grant and the journal write leaves an
        // orphaned hold the sweeper expires, returning both its exposure
        // and its invocation slot.
        if allowed {
            if let Some(journal) = request.payment_journal.as_ref() {
                if let Err(error) = self.record_payment_journal(journal) {
                    let rollback_event_id = request
                        .event_id
                        .as_deref()
                        .map(|event_id| format!("{event_id}:journal-rollback"));
                    if let Err(rollback_error) = self.reverse_charge_cost_with_ids_and_authority(
                        &request.capability_id,
                        request.grant_index,
                        request.requested_exposure_units,
                        request.hold_id.as_deref(),
                        rollback_event_id.as_deref(),
                        request.authority.as_ref(),
                    ) {
                        // The hold leaks until the sweeper expires it;
                        // capacity is fail-closed under-spend meanwhile.
                        tracing::warn!(
                            capability_id = %request.capability_id,
                            grant_index = request.grant_index,
                            reason = %redacted!(&rollback_error.to_string()),
                            "budget hold rollback failed after a journal write failure; the \
                             hold sweeper will expire the orphaned hold"
                        );
                    }
                    return Err(error);
                }
            }
        }
        let (committed_cost_units_after, invocation_count_after, metadata) =
            match durable_decision_event {
                Some((record, committed_cost_units_after)) => (
                    committed_cost_units_after,
                    record.invocation_count_after,
                    budget_commit_metadata(
                        self,
                        record.authority,
                        Some(record.event_seq),
                        Some(record.event_id),
                    ),
                ),
                None => {
                    let usage = self.get_usage(&request.capability_id, request.grant_index)?;
                    let committed_cost_units_after = usage
                        .as_ref()
                        .map(BudgetUsageRecord::committed_cost_units)
                        .transpose()?
                        .unwrap_or(0);
                    let invocation_count_after =
                        usage.as_ref().map_or(0, |usage| usage.invocation_count);
                    let metadata = budget_commit_metadata(
                        self,
                        request.authority,
                        allowed
                            .then(|| usage.as_ref().map(|usage| usage.seq))
                            .flatten(),
                        request.event_id,
                    );
                    (
                        committed_cost_units_after,
                        invocation_count_after,
                        metadata,
                    )
                }
            };

        if allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after,
                    invocation_counts_after: Vec::new(),
                    invocation_state: BudgetInvocationReservationState::Absent,
                    monetary_state,
                    revocation_set: None,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after,
                invocation_counts_after: Vec::new(),
                invocation_state: BudgetInvocationReservationState::Denied,
                monetary_state: BudgetMonetaryHoldState::None,
                revocation_set: None,
                metadata,
            }))
        }
    }

    /// Return the exact frozen decision for a previously committed composite
    /// authorization without creating or retrying the mutation.
    ///
    /// Cleanup snapshots can outlive the capability, revocation, supplemental,
    /// or escrow evidence that originally authorized a hold. A recovery path
    /// must therefore use this read-only operation instead of treating the
    /// snapshot as fresh admission authority. Implementations that can prove
    /// absence return [`BudgetStoreError::MissingCommittedReplay`]. The default
    /// is unsupported rather than assuming absence.
    fn replay_budget_authorization(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if !request.requires_existing_authorization_replay() {
            return Err(BudgetStoreError::Invariant(
                "committed replay requires a snapshot-derived authorization request".to_string(),
            ));
        }
        Err(BudgetStoreError::Invariant(
            "exact committed budget authorization replay is unavailable for this backend"
                .to_string(),
        ))
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Reversed,
            revocation_set: None,
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Released,
            revocation_set: None,
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after: usage
                .as_ref()
                .map(BudgetUsageRecord::committed_cost_units)
                .transpose()?
                .unwrap_or(0),
            invocation_count_after: usage.as_ref().map_or(0, |usage| usage.invocation_count),
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Reconciled,
            revocation_set: None,
            metadata: budget_commit_metadata(
                self,
                request.authority,
                usage.as_ref().map(|usage| usage.seq),
                request.event_id,
            ),
        })
    }

    fn capture_budget_hold(
        &self,
        _request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "monetary hold capture unavailable for this backend".to_string(),
        ))
    }

    fn capture_invocation_reservations(
        &self,
        _request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "invocation reservation capture unavailable for this backend".to_string(),
        ))
    }

    /// Return the exact prior capture for an idempotency key without creating
    /// a new mutation. A mismatched request for an existing event is an error.
    fn query_invocation_capture(
        &self,
        _request: &BudgetCaptureInvocationRequest,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "invocation reservation capture query unavailable for this backend".to_string(),
        ))
    }

    /// Reverse any hold that is still `open` after a process restart, arbitrated
    /// by the provided realized-spend map. Holds present in `realized_by_hold`
    /// are reconciled to their recorded amount; holds absent from it (orphans)
    /// are reversed. Stores that do not persist hold state return `Ok((0, 0))`
    /// (the default). Returns `(reconciled, reversed)` counts.
    ///
    /// Callers must supply a realized-spend map built from the durable receipt
    /// log (ADR-0013). Passing an empty map reverses all open holds, which
    /// enables double-spend: a hold left open by a crash after the spend but
    /// before reconcile represents real spent budget. Use `count_open_holds`
    /// to log the hold count and leave holds reserved (fail-closed) when the
    /// durable receipt log is not available at startup.
    fn reap_orphaned_holds(
        &self,
        realized_by_hold: &std::collections::HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        let _ = realized_by_hold;
        Ok((0, 0))
    }

    /// Return the number of holds still in the `open` state. Stores that do
    /// not persist hold state return `Ok(0)` (the default). Use at startup to
    /// log the number of holds that will remain reserved under the fail-closed
    /// policy when the durable receipt log arbitration map is unavailable.
    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        Ok(0)
    }

    /// Ids of holds that are still `open` and were stamped as a delegated
    /// reserve-for-caller reservation: marked reserved (via
    /// [`Self::mark_hold_reserved`], [`Self::mark_invocation_hold_reserved`], or
    /// [`Self::reserve_invocation_hold`]) with a delegation depth of at least
    /// one. Such a hold keeps its delegated child's sibling-sum share admitted
    /// against the parent for as long as it stays open. A freshly built mediation
    /// kernel consults this after a restart: the
    /// in-memory sibling-sum reservations were lost, and the durable hold record
    /// carries neither the immediate parent capability id nor the child and
    /// parent shares needed to rebuild them, so mediation denies delegated
    /// admission fail-closed while any such hold from a prior process is still
    /// open.
    ///
    /// `Ok(Some(ids))` enumerates those holds precisely. `Ok(None)` marks a store
    /// that cannot enumerate them; the caller then falls back to
    /// [`Self::count_open_holds`] and gates on the presence of any open hold. The
    /// default is `Ok(None)` so a store that does not persist hold state is
    /// treated as unable to enumerate rather than as having none.
    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        Ok(None)
    }

    /// Whether any authorization hold id begins with the durable
    /// `budget-hold:{request_id}:` prefix, regardless of the capability id and
    /// grant index encoded after it.
    ///
    /// The mediated pre-execution gate derives each hold id from
    /// (request_id, capability id, grant index), so a caller that replays one
    /// request_id under a DIFFERENT capability token would slip past a
    /// per-capability exact-id probe (its `budget-hold:{request_id}:{other_cap}:..`
    /// row never matches) and win a second reservation after a restart cleared
    /// the in-memory reuse window. Matching the prefix rejects the replay no
    /// matter which capability presented it.
    ///
    /// `Ok(Some(true))` = at least one hold id begins with the prefix;
    /// `Ok(Some(false))` = none does; `Ok(None)` marks a store that cannot
    /// enumerate holds by prefix, so the caller falls back to the per-capability
    /// exact probe. The default is `Ok(None)` so a store that does not persist
    /// hold state is treated as unable to enumerate rather than as having none.
    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        let _ = request_id;
        Ok(None)
    }

    /// Project a single hold by id, or `None` when it is unknown. Stores that
    /// do not persist hold state return `Ok(None)` (the default). Used by the
    /// reconcile-by-nonce entry point to resolve the exact reserved hold a
    /// signed execution nonce names.
    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        let _ = hold_id;
        Ok(None)
    }

    /// Stamp an open hold with the wall-clock unix second after which the TTL
    /// reaper may settle it if it is still unreconciled, and record the currency
    /// the grant was authorized in. Only the pre-execution
    /// authorization-reserving path calls this, so a normal in-flight hold
    /// (reconciled or reversed within one evaluation) is never marked and never
    /// touched by the TTL reaper. The recorded currency lets reconcile-by-nonce
    /// reject a caller-supplied realized currency that differs from the grant's.
    /// `payment_reference` records the rail transaction id of a prepaid MustPrepay
    /// reservation (`None` for a reserve with no prepayment) so reconcile-by-nonce
    /// can stamp it onto the authoritative receipt. `envelope` records the grant
    /// ceiling and delegation lineage so reconcile-by-nonce reports the grant's
    /// budget total/remaining and true lineage instead of the reservation's own
    /// exposure. Stores that do not persist hold state treat this as a no-op (the
    /// default).
    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _ = (
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        );
        Ok(())
    }

    /// Stamp an existing atomic invocation-only authorization hold for
    /// caller-mediated execution. The hold must already be open, must belong to
    /// the exact capability and grant, must carry an invocation debit, and must
    /// have zero authorized and remaining monetary exposure. This method never
    /// creates a hold and never records a currency, payment reference, or budget
    /// total. `envelope.budget_total` must therefore be `None`.
    fn mark_invocation_hold_reserved(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _ = (
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        );
        Err(BudgetStoreError::Invariant(
            "invocation hold reservation stamping is unavailable for this backend".to_string(),
        ))
    }

    /// Stamp an existing operation-owned composite hold for caller-mediated
    /// execution. The store must match both immutable admission identifiers and
    /// must never create or fall back to a legacy hold. `currency` is required
    /// for non-zero monetary exposure and must be `None` for zero exposure.
    fn mark_admission_operation_hold_reserved(
        &self,
        hold_id: &str,
        admission_operation: &BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _ = (
            hold_id,
            admission_operation,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        );
        Err(BudgetStoreError::Invariant(
            "operation-owned hold reservation stamping is unavailable for this backend"
                .to_string(),
        ))
    }

    /// Adopt an already-debited invocation into a durable reserved hold that
    /// carries zero monetary exposure, so a `max_invocations`-only reservation is
    /// reversible and reapable by hold id exactly like a monetary reserve. The
    /// invocation was already counted by [`Self::try_increment`]; this records the
    /// hold WITHOUT touching the invocation count, marks it reserved with the TTL
    /// deadline, and records no currency (there is no monetary envelope to
    /// validate on reconcile). Reversing the hold returns the invocation;
    /// reconciling or reaping it keeps the invocation consumed. `envelope` records
    /// the delegation lineage so reconcile-by-nonce stamps the true depth/root
    /// (its `budget_total` is `None`: an invocation reserve carries no monetary
    /// ceiling). Stores that do not persist hold state treat this as a no-op (the
    /// default).
    fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let _ = (
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        );
        Ok(())
    }

    /// Settle every reserved hold that is still `open` and whose `reserved_until`
    /// is at or before `now_unix_secs` at its reserved worst-case, forfeiting the
    /// reserved amount to realized spend. In the two-phase reserve/reconcile flow
    /// the ONLY evidence a spend occurred is the caller's reconcile; an
    /// expired-and-unreconciled hold may correspond to a call that DID execute and
    /// spend. Releasing it (realized 0) would under-count real spend and fail open
    /// for a cumulative spend cap, so an abandoning caller instead FORFEITS the
    /// reserved worst-case (the grant's realized total advances by it) and must
    /// reconcile the real cost before expiry to reclaim the difference.
    /// Fail-closed and self-healing: it settles ONLY holds that were explicitly
    /// marked reserved (via [`Self::mark_hold_reserved`],
    /// [`Self::mark_invocation_hold_reserved`], or
    /// [`Self::mark_admission_operation_hold_reserved`]) and are past their
    /// expiry; a not-yet-expired reserved hold and a reconciled/reversed/released
    /// hold are never touched. A reaped snapshot reports `Expired` after the
    /// worst-case amount is committed. Idempotent (an expired hold is no longer
    /// open). Returns the number of holds settled. Stores that do not persist
    /// hold state return `Ok(0)` (the default).
    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        let _ = now_unix_secs;
        Ok(0)
    }
}

fn validate_default_authorization_event(
    request: &BudgetAuthorizeHoldRequest,
    allowed: bool,
    record: &BudgetMutationRecord,
) -> Result<u64, BudgetStoreError> {
    let grant_index = u32::try_from(request.grant_index)
        .map_err(|_| BudgetStoreError::Invariant("budget grant index exceeds u32".to_string()))?;
    if request.event_id.as_deref() != Some(record.event_id.as_str())
        || record.hold_id != request.hold_id
        || record.capability_id != request.capability_id
        || record.grant_index != grant_index
        || record.exposure_units != request.requested_exposure_units
        || record.max_invocations != request.max_invocations
        || record.max_cost_per_invocation != request.max_cost_per_invocation
        || record.max_total_cost_units != request.max_total_cost_units
        || record.authority != request.authority
        || record.admission_operation != request.admission_operation
    {
        return Err(BudgetStoreError::Conflict(
            "budget authorization event was reused for a different request".to_string(),
        ));
    }
    if record.event_seq == 0
        || record.kind != BudgetMutationKind::AuthorizeExposure
        || record.allowed != Some(allowed)
        || record.usage_seq != allowed.then_some(record.event_seq)
    {
        return Err(BudgetStoreError::Invariant(
            "durable budget authorization event has an invalid decision shape".to_string(),
        ));
    }
    checked_committed_cost_units(
        record.total_cost_exposed_after,
        record.total_cost_realized_spend_after,
    )
}

fn checked_committed_cost_units(
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> Result<u64, BudgetStoreError> {
    total_cost_exposed
        .checked_add(total_cost_realized_spend)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "total_cost_exposed + total_cost_realized_spend overflowed u64".to_string(),
            )
        })
}

pub use in_memory::InMemoryBudgetStore;

#[cfg(test)]
mod tests {
    include!("budget_store/tests.inc");
    include!("budget_store/tests.part2.inc");
}
