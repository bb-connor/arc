pub struct DurableAttestedFindingBatchPlanner {
    batch_store: Arc<dyn AttestedFindingBatchStore>,
    outbox_store: Arc<dyn AttestedFindingResponseOutboxStore>,
    finding_authority: Arc<dyn ActiveResponseFindingAuthority>,
    policy: Arc<dyn AttestedFindingResponsePolicyPlanner>,
    coordinator: Arc<dyn AttestedFindingResponseCoordinator>,
    clock: Arc<dyn SecurityClock>,
}

const MAX_ATTESTED_FINDING_STARTUP_RECOVERY_RECORDS: u64 = 1_000_000;
const MAX_ATTESTED_FINDING_STARTUP_RECOVERY_WALL_CLOCK_MS: u64 = 3_600_000;
const ATTESTED_FINDING_STARTUP_RECOVERY_POLL_MS: u64 = 10;

/// Hard operational bounds for synchronous startup reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestedFindingResponseRecoveryLimits {
    max_records_per_pass: u32,
    max_startup_records: u64,
    max_startup_wall_clock_ms: u64,
}

impl AttestedFindingResponseRecoveryLimits {
    pub fn new(
        max_records_per_pass: u32,
        max_startup_records: u64,
        max_startup_wall_clock_ms: u64,
    ) -> PortResult<Self> {
        if max_records_per_pass == 0
            || max_records_per_pass > MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN
            || max_startup_records < u64::from(max_records_per_pass)
            || max_startup_records > MAX_ATTESTED_FINDING_STARTUP_RECOVERY_RECORDS
            || max_startup_wall_clock_ms == 0
            || max_startup_wall_clock_ms
                > MAX_ATTESTED_FINDING_STARTUP_RECOVERY_WALL_CLOCK_MS
        {
            return Err(PortError::invalid_data());
        }
        Ok(Self {
            max_records_per_pass,
            max_startup_records,
            max_startup_wall_clock_ms,
        })
    }

    #[must_use]
    pub const fn max_records_per_pass(self) -> u32 {
        self.max_records_per_pass
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AttestedFindingResponseRecoveryReport {
    pub records_examined: u64,
    pub plans_published: u32,
    pub admissions_prepared: u32,
    pub completions_persisted: u32,
    pub retryable_failures: u32,
    pub terminal_failures: u32,
}

impl AttestedFindingResponseRecoveryReport {
    fn merge(&mut self, other: Self) {
        self.records_examined = self.records_examined.saturating_add(other.records_examined);
        self.plans_published = self.plans_published.saturating_add(other.plans_published);
        self.admissions_prepared = self
            .admissions_prepared
            .saturating_add(other.admissions_prepared);
        self.completions_persisted = self
            .completions_persisted
            .saturating_add(other.completions_persisted);
        self.retryable_failures = self
            .retryable_failures
            .saturating_add(other.retryable_failures);
        self.terminal_failures = self
            .terminal_failures
            .saturating_add(other.terminal_failures);
    }
}

impl DurableAttestedFindingBatchPlanner {
    pub(crate) fn new(
        batch_store: Arc<dyn AttestedFindingBatchStore>,
        outbox_store: Arc<dyn AttestedFindingResponseOutboxStore>,
        finding_authority: Arc<dyn ActiveResponseFindingAuthority>,
        policy: Arc<dyn AttestedFindingResponsePolicyPlanner>,
        coordinator: Arc<dyn AttestedFindingResponseCoordinator>,
        clock: Arc<dyn SecurityClock>,
    ) -> PortResult<Self> {
        batch_store.ensure_attested_finding_batches_ready()?;
        outbox_store.ensure_attested_finding_response_outbox_ready()?;
        finding_authority
            .ensure_ready()
            .map_err(map_finding_authority_error)?;
        policy.ensure_ready()?;
        coordinator.ensure_configured()?;
        Ok(Self {
            batch_store,
            outbox_store,
            finding_authority,
            policy,
            coordinator,
            clock,
        })
    }

    fn ensure_recovery_ready(&self) -> PortResult<()> {
        self.batch_store.ensure_attested_finding_batches_ready()?;
        self.outbox_store
            .ensure_attested_finding_response_outbox_ready()?;
        self.clock.now_unix_ms()?;
        self.coordinator.ensure_configured()
    }

    pub(crate) fn outbox_health(&self) -> PortResult<AttestedFindingResponseOutboxHealth> {
        self.outbox_store
            .attested_finding_response_outbox_health()
    }

    pub(crate) fn response_coordinator_is_ready(&self) -> bool {
        self.coordinator.ensure_ready().is_ok()
    }

    fn resume_published_batch(
        &self,
        publication: &AttestedFindingBatchPublication,
    ) -> PortResult<()> {
        self.ensure_recovery_ready()?;
        let now_unix_ms = self.clock.now_unix_ms()?;
        let mut report = AttestedFindingResponseRecoveryReport::default();
        let mut first_error = None;
        for (ordinal, binding) in publication.body.bindings.as_slice().iter().enumerate() {
            let ordinal = u32::try_from(ordinal).map_err(|_| PortError::integrity_failure())?;
            if let Err(error) = self.resume_published_response(
                publication,
                ordinal,
                binding,
                now_unix_ms,
                &mut report,
            ) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn resume_published_response(
        &self,
        publication: &AttestedFindingBatchPublication,
        ordinal: u32,
        binding: &AttestedFindingBatchBinding,
        now_unix_ms: u64,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        let mut current = self.load_exact_published_response(publication, ordinal, binding)?;
        if let Some(result) = published_response_terminal_result(&current) {
            return result;
        }
        if current.next_attempt_at_unix_ms > now_unix_ms {
            return Err(PortError::unavailable());
        }
        if current.planning_state == AttestedFindingResponsePlanningState::Pending {
            self.ensure_ready()?;
            let planning = self.plan_pending_response(current, now_unix_ms, report);
            current = self.load_exact_published_response(publication, ordinal, binding)?;
            planning?;
            if let Some(result) = published_response_terminal_result(&current) {
                return result;
            }
        }
        if current.planning_state != AttestedFindingResponsePlanningState::Planned
            || current.publication.is_none()
        {
            return Err(PortError::unavailable());
        }
        if current.next_attempt_at_unix_ms > now_unix_ms {
            return Err(PortError::unavailable());
        }
        let execution = self.execute_pending_response(current, now_unix_ms, report);
        let current = self.load_exact_published_response(publication, ordinal, binding)?;
        execution?;
        published_response_terminal_result(&current)
            .unwrap_or_else(|| Err(PortError::unavailable()))
    }

    fn load_exact_published_response(
        &self,
        publication: &AttestedFindingBatchPublication,
        ordinal: u32,
        binding: &AttestedFindingBatchBinding,
    ) -> PortResult<AttestedFindingResponseOutboxRecord> {
        if binding.tenant_id != publication.body.tenant_id {
            return Err(PortError::integrity_failure());
        }
        let current = self
            .outbox_store
            .load_attested_finding_response_outbox(&AttestedFindingResponseOutboxKey {
                tenant_id: binding.tenant_id.clone(),
                action_id: binding.action_id.clone(),
            })?
            .ok_or_else(PortError::integrity_failure)?;
        if current.batch_id != publication.body.batch_id
            || current.ordinal != ordinal
            || current.binding != *binding
        {
            return Err(PortError::integrity_failure());
        }
        Ok(current)
    }

    pub(crate) fn resume_incomplete_pass(
        &self,
        max_records: u32,
    ) -> PortResult<AttestedFindingResponseRecoveryReport> {
        let (report, first_error) =
            self.resume_incomplete_pass_collecting(max_records, None)?;
        match first_error {
            Some(error) => Err(error),
            None => Ok(report),
        }
    }

    fn resume_incomplete_pass_collecting(
        &self,
        max_records: u32,
        deadline: Option<Instant>,
    ) -> PortResult<(
        AttestedFindingResponseRecoveryReport,
        Option<PortError>,
    )> {
        if max_records == 0 || max_records > MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN {
            return Err(PortError::invalid_data());
        }
        self.ensure_recovery_ready()?;
        let now_unix_ms = self.clock.now_unix_ms()?;
        let mut report = AttestedFindingResponseRecoveryReport::default();
        let mut first_error = None;
        for pending in self.outbox_store.scan_incomplete_attested_finding_responses(
            now_unix_ms,
            max_records,
        )? {
            if deadline
                .as_ref()
                .is_some_and(|deadline| Instant::now() >= *deadline)
            {
                first_error = Some(PortError::unavailable());
                break;
            }
            report.records_examined = report.records_examined.saturating_add(1);
            if let Err(error) = self.execute_pending_response(pending, now_unix_ms, &mut report) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        let remaining = u64::from(max_records)
            .saturating_sub(report.records_examined)
            .min(u64::from(u32::MAX));
        if remaining != 0
            && deadline
                .as_ref()
                .is_none_or(|deadline| Instant::now() < *deadline)
        {
            match self.ensure_ready() {
                Ok(()) => {
                    let remaining =
                        u32::try_from(remaining).map_err(|_| PortError::invalid_data())?;
                    for pending in self.outbox_store.scan_unplanned_attested_finding_responses(
                        now_unix_ms,
                        remaining,
                    )? {
                        if deadline
                            .as_ref()
                            .is_some_and(|deadline| Instant::now() >= *deadline)
                        {
                            if first_error.is_none() {
                                first_error = Some(PortError::unavailable());
                            }
                            break;
                        }
                        report.records_examined = report.records_examined.saturating_add(1);
                        if let Err(error) =
                            self.plan_pending_response(pending, now_unix_ms, &mut report)
                        {
                            if first_error.is_none() {
                                first_error = Some(error);
                            }
                        }
                    }
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        Ok((report, first_error))
    }

    pub(crate) fn resume_incomplete_until_drained(
        &self,
        limits: AttestedFindingResponseRecoveryLimits,
    ) -> PortResult<AttestedFindingResponseRecoveryReport> {
        self.ensure_recovery_ready()?;
        let started = Instant::now();
        let wall_clock_budget = Duration::from_millis(limits.max_startup_wall_clock_ms);
        let deadline = started
            .checked_add(wall_clock_budget)
            .ok_or_else(PortError::invalid_data)?;
        let mut total = AttestedFindingResponseRecoveryReport::default();
        loop {
            let health = self.outbox_health()?;
            if response_recovery_backlog(&health) == 0 {
                return Ok(total);
            }
            if started.elapsed() >= wall_clock_budget
                || total.records_examined >= limits.max_startup_records
            {
                return Err(PortError::unavailable());
            }
            let remaining_records = limits
                .max_startup_records
                .saturating_sub(total.records_examined);
            let pass_limit = u64::from(limits.max_records_per_pass)
                .min(remaining_records)
                .min(u64::from(u32::MAX));
            let pass_limit = u32::try_from(pass_limit).map_err(|_| PortError::invalid_data())?;
            let (pass, _observed_error) =
                self.resume_incomplete_pass_collecting(pass_limit, Some(deadline))?;
            let examined = pass.records_examined;
            total.merge(pass);
            let remaining_health = self.outbox_health()?;
            if response_recovery_backlog(&remaining_health) == 0 {
                if started.elapsed() > wall_clock_budget {
                    return Err(PortError::unavailable());
                }
                return Ok(total);
            }
            if started.elapsed() >= wall_clock_budget
                || total.records_examined >= limits.max_startup_records
            {
                return Err(PortError::unavailable());
            }
            if examined == 0 {
                let remaining = wall_clock_budget.saturating_sub(started.elapsed());
                std::thread::sleep(
                    remaining.min(Duration::from_millis(
                        ATTESTED_FINDING_STARTUP_RECOVERY_POLL_MS,
                    )),
                );
            }
        }
    }

    fn begin_attempt(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        now_unix_ms: u64,
    ) -> PortResult<AttestedFindingResponseOutboxRecord> {
        let exponent = u32::try_from(current.attempts.min(12))
            .map_err(|_| PortError::integrity_failure())?;
        let delay = ATTESTED_FINDING_RESPONSE_INITIAL_RETRY_MS
            .checked_shl(exponent)
            .unwrap_or(ATTESTED_FINDING_RESPONSE_MAX_RETRY_MS)
            .min(ATTESTED_FINDING_RESPONSE_MAX_RETRY_MS);
        let next_attempt_at_unix_ms = now_unix_ms
            .checked_add(delay)
            .ok_or_else(PortError::invalid_data)?;
        self.outbox_store
            .transition_attested_finding_response_outbox(
                current,
                AttestedFindingResponseOutboxTransition::BeginAttempt {
                    next_attempt_at_unix_ms,
                },
            )
    }

    fn plan_pending_response(
        &self,
        current: AttestedFindingResponseOutboxRecord,
        now_unix_ms: u64,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        let claimed = match self.begin_attempt(&current, now_unix_ms) {
            Ok(claimed) => claimed,
            Err(error) if error.kind() == PortErrorKind::Conflict => return Ok(()),
            Err(error) => return Err(error),
        };
        let finding = match self
            .finding_authority
            .load_correlated_finding(&claimed.binding.evidence_id)
        {
            Ok(Some(finding)) => finding,
            Ok(None) => {
                return self.close_planning_failure(
                    &claimed,
                    PortError::integrity_failure(),
                    report,
                );
            }
            Err(error) => {
                return self.close_planning_failure(
                    &claimed,
                    map_finding_authority_error(error),
                    report,
                );
            }
        };
        let plan = match build_reserved_response_plan(
            &finding,
            &claimed.batch_id,
            claimed.ordinal,
            &claimed.binding,
            self.policy.as_ref(),
        ) {
            Ok(plan) => plan,
            Err(error) => return self.close_planning_failure(&claimed, error, report),
        };
        let publication = build_attested_finding_response_plan_publication(&plan)?;
        match self
            .outbox_store
            .publish_attested_finding_response_plan(&publication)
        {
            Ok(_) => {
                report.plans_published = report.plans_published.saturating_add(1);
                Ok(())
            }
            Err(error) => self.close_planning_failure(&claimed, error, report),
        }
    }

    fn close_planning_failure(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        error: PortError,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        if error.kind() == PortErrorKind::Unavailable {
            self.outbox_store
                .transition_attested_finding_response_outbox(
                    current,
                    AttestedFindingResponseOutboxTransition::RetryableFailure {
                        next_attempt_at_unix_ms: current.next_attempt_at_unix_ms,
                        error_code: error.code().clone(),
                        outcome_unknown_after_dispatch: false,
                    },
                )?;
            report.retryable_failures = report.retryable_failures.saturating_add(1);
        } else {
            self.outbox_store
                .transition_attested_finding_response_outbox(
                    current,
                    AttestedFindingResponseOutboxTransition::PlanningFailed {
                        error_code: error.code().clone(),
                    },
                )?;
            report.terminal_failures = report.terminal_failures.saturating_add(1);
        }
        Err(error)
    }

    fn execute_pending_response(
        &self,
        current: AttestedFindingResponseOutboxRecord,
        now_unix_ms: u64,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        let claimed = match self.begin_attempt(&current, now_unix_ms) {
            Ok(claimed) => claimed,
            Err(error) if error.kind() == PortErrorKind::Conflict => return Ok(()),
            Err(error) => return Err(error),
        };
        let publication = claimed
            .publication
            .as_ref()
            .ok_or_else(PortError::integrity_failure)?;
        if let Some(dispatch_id) = claimed.execution_dispatch_id.as_ref() {
            let binding = match claimed.prepared_dispatch_binding.as_ref() {
                Some(binding)
                    if claimed.admission_state
                        == AttestedFindingResponseAdmissionState::Prepared
                        && &binding.dispatch_id == dispatch_id =>
                {
                    binding
                }
                _ => {
                    return self.mark_outcome_unknown_after_dispatch(
                        &claimed,
                        PortError::integrity_failure(),
                        report,
                    );
                }
            };
            match self
                .coordinator
                .resume_dispatch_committed(&publication.body.response_plan, binding)
            {
                Ok(AttestedFindingDispatchCommittedResume::Completed(evidence)) => {
                    return self.persist_recovered_completion(
                        &claimed,
                        &evidence,
                        dispatch_id,
                        report,
                    );
                }
                Ok(AttestedFindingDispatchCommittedResume::NotDispatchCommitted) => {}
                Err(error) => {
                    return self.mark_outcome_unknown_after_dispatch(&claimed, error, report);
                }
            }
            match self
                .coordinator
                .recover_committed(&publication.body.response_plan, dispatch_id)
            {
                Ok(Some(evidence)) => {
                    return self.persist_recovered_completion(
                        &claimed,
                        &evidence,
                        dispatch_id,
                        report,
                    );
                }
                Ok(None)
                    if now_unix_ms >= publication.body.response_plan.expires_at_unix_ms =>
                {
                    return self.terminate_prepared_never_committed(
                        &claimed,
                        &publication.body.response_plan,
                        None,
                        report,
                    );
                }
                Ok(None) => {}
                Err(error) => {
                    return self.mark_outcome_unknown_after_dispatch(&claimed, error, report);
                }
            }
        }
        if let Err(error) = self.ensure_ready() {
            return self.close_admission_failure(&claimed, error, report);
        }
        if claimed.admission_state == AttestedFindingResponseAdmissionState::Pending
            && now_unix_ms >= publication.body.response_plan.expires_at_unix_ms
        {
            self.outbox_store
                .transition_attested_finding_response_outbox(
                    &claimed,
                    AttestedFindingResponseOutboxTransition::ExpiredBeforeAdmission,
                )?;
            report.terminal_failures = report.terminal_failures.saturating_add(1);
            return Err(PortError::new(
                PortErrorKind::InvalidData,
                error_code("active_response.plan_expired")?,
            ));
        }
        let finding = match self
            .finding_authority
            .load_correlated_finding(&claimed.binding.evidence_id)
        {
            Ok(Some(finding)) => finding,
            Ok(None) => {
                return self.close_admission_failure(
                    &claimed,
                    PortError::integrity_failure(),
                    report,
                );
            }
            Err(error) => {
                return self.close_admission_failure(
                    &claimed,
                    map_finding_authority_error(error),
                    report,
                );
            }
        };
        if let Err(error) = validate_authoritative_finding_binding(&finding, &claimed.binding) {
            return self.close_admission_failure(&claimed, error, report);
        }
        let plan = ReservedAttestedFindingResponsePlan {
            finding,
            batch_id: claimed.batch_id.clone(),
            ordinal: claimed.ordinal,
            binding: claimed.binding.clone(),
            response_plan: publication.body.response_plan.clone(),
            admission_artifact_ref: publication.body.admission_artifact_ref.clone(),
            admission_artifact_digest: claimed.admission_artifact_digest,
        };
        let artifacts = match self
            .policy
            .load_admission_artifacts(&plan, plan.admission_artifact_ref())
        {
            Ok(artifacts) => artifacts,
            Err(error) => return self.close_admission_failure(&claimed, error, report),
        };
        let trusted_artifact_authority = match self.policy.trusted_artifact_authority() {
            Ok(authority) => authority,
            Err(error) => return self.close_admission_failure(&claimed, error, report),
        };
        let artifact_digest = match artifacts.verify_authority_attestation(
            plan.admission_artifact_ref(),
            plan.response_plan(),
            &trusted_artifact_authority,
        ) {
            Ok(digest) => digest,
            Err(error) => return self.close_admission_failure(&claimed, error, report),
        };
        let artifact_bound = match claimed.admission_artifact_digest.as_ref() {
            Some(expected) if expected == &artifact_digest => claimed,
            Some(_) => {
                return self.close_admission_failure(
                    &claimed,
                    PortError::integrity_failure(),
                    report,
                );
            }
            None => match self
                .outbox_store
                .transition_attested_finding_response_outbox(
                    &claimed,
                    AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                        artifact_digest,
                    },
                ) {
                Ok(bound) => bound,
                Err(error) if error.kind() == PortErrorKind::Conflict => return Ok(()),
                Err(error) => return Err(error),
            },
        };
        let plan = ReservedAttestedFindingResponsePlan {
            admission_artifact_digest: Some(artifact_digest),
            ..plan
        };
        let termination_artifacts = artifacts.clone();
        let preparation = match artifact_bound.admission_state {
            AttestedFindingResponseAdmissionState::Pending => {
                self.coordinator.prepare_admission(&plan, artifacts)
            }
            AttestedFindingResponseAdmissionState::Prepared => {
                let binding = artifact_bound
                    .prepared_dispatch_binding
                    .as_ref()
                    .ok_or_else(PortError::integrity_failure)?;
                match self
                    .coordinator
                    .reconstruct_pre_dispatch(&plan, artifacts, binding)
                {
                    Ok(AttestedFindingPreDispatchReconstruction::Prepared(prepared)) => {
                        Ok(*prepared)
                    }
                    Ok(AttestedFindingPreDispatchReconstruction::NotPrepared) => {
                        return self.mark_outcome_unknown_after_dispatch(
                            &artifact_bound,
                            PortError::unavailable(),
                            report,
                        );
                    }
                    Err(error) => Err(error),
                }
            }
            AttestedFindingResponseAdmissionState::Rejected => {
                return Err(terminal_admission_error(&artifact_bound));
            }
            AttestedFindingResponseAdmissionState::Expired => {
                return Err(terminal_admission_error(&artifact_bound));
            }
        };
        let prepared = match preparation {
            Ok(prepared) => prepared,
            Err(error)
                if artifact_bound.admission_state
                    == AttestedFindingResponseAdmissionState::Prepared
                    && error.kind() == PortErrorKind::InvalidData =>
            {
                return self.terminate_prepared_never_committed(
                    &artifact_bound,
                    plan.response_plan(),
                    Some(&termination_artifacts),
                    report,
                );
            }
            Err(error) => return self.close_admission_failure(&artifact_bound, error, report),
        };
        let prepared_dispatch_binding =
            match prepared.durable_dispatch_binding(plan.response_plan()) {
                Ok(binding) => binding,
                Err(error) => {
                    self.coordinator.cancel_prepared(&plan, &prepared)?;
                    return self.close_admission_failure(&artifact_bound, error, report);
                }
            };
        let prepared_dispatch_id = prepared_dispatch_binding.dispatch_id.clone();
        let admitted = match artifact_bound.admission_state {
            AttestedFindingResponseAdmissionState::Pending => {
                match self.outbox_store.transition_attested_finding_response_outbox(
                    &artifact_bound,
                    AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                        prepared_dispatch_binding: Box::new(prepared_dispatch_binding.clone()),
                    },
                ) {
                    Ok(admitted) => {
                        report.admissions_prepared =
                            report.admissions_prepared.saturating_add(1);
                        admitted
                    }
                    Err(error) => {
                        let latest = self
                            .outbox_store
                            .load_attested_finding_response_outbox(&artifact_bound.key())?
                            .ok_or_else(PortError::integrity_failure)?;
                        if latest.admission_state
                            == AttestedFindingResponseAdmissionState::Prepared
                            && latest.execution_dispatch_id.as_ref()
                                == Some(&prepared_dispatch_id)
                            && latest.prepared_dispatch_binding.as_ref()
                                == Some(&prepared_dispatch_binding)
                        {
                            report.admissions_prepared =
                                report.admissions_prepared.saturating_add(1);
                            if latest.completion_state
                                == AttestedFindingResponseCompletionState::Completed
                            {
                                return Ok(());
                            }
                            latest
                        } else if latest == artifact_bound {
                            self.coordinator.cancel_prepared(&plan, &prepared)?;
                            return Err(error);
                        } else {
                            return Err(PortError::integrity_failure());
                        }
                    }
                }
            }
            AttestedFindingResponseAdmissionState::Prepared => {
                if artifact_bound.execution_dispatch_id.as_ref() != Some(&prepared_dispatch_id)
                    || artifact_bound.prepared_dispatch_binding.as_ref()
                        != Some(&prepared_dispatch_binding)
                {
                    return Err(PortError::integrity_failure());
                }
                artifact_bound
            }
            AttestedFindingResponseAdmissionState::Rejected => {
                return Err(terminal_admission_error(&artifact_bound));
            }
            AttestedFindingResponseAdmissionState::Expired => {
                return Err(terminal_admission_error(&artifact_bound));
            }
        };
        let evidence = match self.coordinator.execute_prepared(&plan, prepared) {
            Ok(evidence) => evidence,
            Err(error) if error.kind() == PortErrorKind::InvalidData => {
                return self.terminate_prepared_never_committed(
                    &admitted,
                    plan.response_plan(),
                    Some(&termination_artifacts),
                    report,
                );
            }
            Err(error) => {
                return self.mark_outcome_unknown_after_dispatch(&admitted, error, report);
            }
        };
        if evidence.dispatch_id() != &prepared_dispatch_id {
            return self.mark_outcome_unknown_after_dispatch(
                &admitted,
                PortError::integrity_failure(),
                report,
            );
        }
        self.persist_completion(&admitted, &evidence, &prepared_dispatch_id, report)
    }

    fn persist_recovered_completion(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        evidence: &AttestedFindingResponseCompletionProof,
        dispatch_id: &RecordId,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        if evidence.dispatch_id() != dispatch_id
            || evidence.evidence_body_hash().is_zero()
            || evidence
                .evidence_id()
                .as_str()
                .bytes()
                .all(|byte| byte == b'0')
        {
            return self.mark_outcome_unknown_after_dispatch(
                current,
                PortError::integrity_failure(),
                report,
            );
        }
        self.persist_completion(current, evidence, dispatch_id, report)
    }

    fn persist_completion(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        evidence: &AttestedFindingResponseCompletionProof,
        dispatch_id: &RecordId,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        match self.outbox_store.transition_attested_finding_response_outbox(
            current,
            AttestedFindingResponseOutboxTransition::Completed {
                execution_dispatch_id: dispatch_id.clone(),
                outcome: evidence.outcome(),
                evidence_id: evidence.evidence_id().clone(),
                evidence_body_hash: *evidence.evidence_body_hash(),
            },
        ) {
            Ok(_) => {
                report.completions_persisted = report.completions_persisted.saturating_add(1);
                Ok(())
            }
            Err(error) => {
                let latest = self
                    .outbox_store
                    .load_attested_finding_response_outbox(&current.key())?;
                if latest.as_ref().is_some_and(|record| {
                    response_completion_matches(record, evidence, dispatch_id)
                }) {
                    return Ok(());
                }
                match latest {
                    Some(record)
                        if record.admission_state
                            == AttestedFindingResponseAdmissionState::Prepared
                            && record.execution_dispatch_id.as_ref()
                                == Some(dispatch_id)
                            && record.completion_state
                                != AttestedFindingResponseCompletionState::Completed =>
                    {
                        self.mark_outcome_unknown_after_dispatch(&record, error, report)
                    }
                    _ => Err(error),
                }
            }
        }
    }

    fn mark_outcome_unknown_after_dispatch(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        error: PortError,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        self.outbox_store
            .transition_attested_finding_response_outbox(
                current,
                AttestedFindingResponseOutboxTransition::RetryableFailure {
                    next_attempt_at_unix_ms: current.next_attempt_at_unix_ms,
                    error_code: error.code().clone(),
                    outcome_unknown_after_dispatch: true,
                },
            )?;
        report.retryable_failures = report.retryable_failures.saturating_add(1);
        Err(error)
    }

    fn terminate_prepared_never_committed(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        response_plan: &ResponsePlan,
        current_artifacts: Option<&AttestedFindingAdmissionArtifacts>,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        let binding = current
            .prepared_dispatch_binding
            .as_ref()
            .ok_or_else(PortError::integrity_failure)?;
        if current.admission_state != AttestedFindingResponseAdmissionState::Prepared
            || current.execution_dispatch_id.as_ref() != Some(&binding.dispatch_id)
            || binding.validate_for_plan(response_plan).is_err()
        {
            return Err(PortError::integrity_failure());
        }
        match self.coordinator.terminate_never_committed(
            response_plan,
            binding,
            current_artifacts,
        ) {
            Ok(()) => self.close_prepared_never_committed(
                current,
                PortError::new(
                    PortErrorKind::InvalidData,
                    error_code("active_response.never_committed")?,
                ),
                report,
            ),
            Err(error) => {
                let retryable = PortError::new(
                    PortErrorKind::Unavailable,
                    error.code().clone(),
                );
                self.mark_outcome_unknown_after_dispatch(current, retryable, report)
            }
        }
    }

    fn close_prepared_never_committed(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        error: PortError,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        if current.admission_state != AttestedFindingResponseAdmissionState::Prepared
            || !is_definitively_never_committed(&error)
        {
            return Err(PortError::integrity_failure());
        }
        self.outbox_store
            .transition_attested_finding_response_outbox(
                current,
                AttestedFindingResponseOutboxTransition::ExpiredAfterPreparedNeverCommitted,
            )?;
        report.terminal_failures = report.terminal_failures.saturating_add(1);
        Err(error)
    }

    fn close_admission_failure(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        error: PortError,
        report: &mut AttestedFindingResponseRecoveryReport,
    ) -> PortResult<()> {
        if current.admission_state == AttestedFindingResponseAdmissionState::Prepared
            || error.kind() == PortErrorKind::Unavailable
        {
            self.outbox_store
                .transition_attested_finding_response_outbox(
                    current,
                    AttestedFindingResponseOutboxTransition::RetryableFailure {
                        next_attempt_at_unix_ms: current.next_attempt_at_unix_ms,
                        error_code: error.code().clone(),
                        outcome_unknown_after_dispatch: current.admission_state
                            == AttestedFindingResponseAdmissionState::Prepared,
                    },
                )?;
            report.retryable_failures = report.retryable_failures.saturating_add(1);
        } else {
            self.outbox_store
                .transition_attested_finding_response_outbox(
                    current,
                    AttestedFindingResponseOutboxTransition::AdmissionRejected {
                        error_code: error.code().clone(),
                    },
                )?;
            report.terminal_failures = report.terminal_failures.saturating_add(1);
        }
        Err(error)
    }
}

fn error_code(value: &str) -> PortResult<ErrorCode> {
    ErrorCode::new(value).map_err(|_| PortError::integrity_failure())
}

fn terminal_admission_error(current: &AttestedFindingResponseOutboxRecord) -> PortError {
    current.last_error_code.clone().map_or_else(
        PortError::integrity_failure,
        |error_code| PortError::new(PortErrorKind::InvalidData, error_code),
    )
}

fn published_response_terminal_result(
    current: &AttestedFindingResponseOutboxRecord,
) -> Option<PortResult<()>> {
    if current.completion_state == AttestedFindingResponseCompletionState::Completed {
        return Some(Ok(()));
    }
    if current.is_complete() {
        return Some(Err(terminal_admission_error(current)));
    }
    None
}

fn is_definitively_never_committed(error: &PortError) -> bool {
    error.kind() == PortErrorKind::InvalidData
        && error.code().as_str() == "active_response.never_committed"
}

fn response_recovery_backlog(health: &AttestedFindingResponseOutboxHealth) -> u64 {
    health
        .planning_pending
        .saturating_add(health.admission_pending)
        .saturating_add(health.completion_pending)
        .saturating_add(health.outcome_unknown_after_dispatch)
}

fn response_completion_matches(
    record: &AttestedFindingResponseOutboxRecord,
    evidence: &AttestedFindingResponseCompletionProof,
    dispatch_id: &RecordId,
) -> bool {
    record.admission_state == AttestedFindingResponseAdmissionState::Prepared
        && record.completion_state == AttestedFindingResponseCompletionState::Completed
        && record.execution_dispatch_id.as_ref() == Some(dispatch_id)
        && record.completion_outcome == Some(evidence.outcome())
        && record.completion_evidence_id.as_ref() == Some(evidence.evidence_id())
        && record.completion_evidence_body_hash.as_ref() == Some(evidence.evidence_body_hash())
}

fn map_finding_authority_error(error: ActiveResponseFindingAuthorityError) -> PortError {
    match error {
        ActiveResponseFindingAuthorityError::Unavailable(_) => PortError::unavailable(),
        ActiveResponseFindingAuthorityError::Integrity(_) => PortError::integrity_failure(),
    }
}

impl AttestedFindingBatchPlanner for DurableAttestedFindingBatchPlanner {
    fn ensure_bootstrap_ready(&self) -> PortResult<()> {
        self.batch_store.ensure_attested_finding_batches_ready()?;
        self.outbox_store
            .ensure_attested_finding_response_outbox_ready()?;
        self.finding_authority
            .ensure_ready()
            .map_err(map_finding_authority_error)?;
        self.clock.now_unix_ms()?;
        self.policy.ensure_ready()?;
        self.coordinator.ensure_configured()
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.batch_store.ensure_attested_finding_batches_ready()?;
        self.outbox_store
            .ensure_attested_finding_response_outbox_ready()?;
        self.finding_authority
            .ensure_ready()
            .map_err(map_finding_authority_error)?;
        self.clock.now_unix_ms()?;
        self.policy.ensure_ready()?;
        self.coordinator.ensure_ready()
    }

    fn publish_attested_batch(
        &self,
        findings: &[AuthoritativeCorrelatedFindingEvidence],
    ) -> PortResult<()> {
        let publication = build_attested_finding_batch_publication(findings)?;
        self.batch_store.publish_attested_finding_batch(&publication)?;
        let persisted = self
            .batch_store
            .load_attested_finding_batch(&AttestedFindingBatchKey {
                tenant_id: publication.body.tenant_id.clone(),
                batch_id: publication.body.batch_id.clone(),
            })?
            .ok_or_else(PortError::integrity_failure)?;
        if persisted != publication {
            return Err(PortError::integrity_failure());
        }
        self.resume_published_batch(&publication)
    }

    fn load_published_attested_batch(
        &self,
        key: &AttestedFindingBatchKey,
    ) -> PortResult<AttestedFindingBatchPublication> {
        self.batch_store
            .load_attested_finding_batch(key)?
            .ok_or_else(PortError::integrity_failure)
    }
}
