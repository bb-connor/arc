use super::*;

#[derive(Default)]
struct OutboxFaults {
    hidden: Option<AttestedFindingResponseOutboxKey>,
    refuse_admission_rejection_writes: bool,
    strip_refusal_codes: bool,
}

struct FaultingResponseOutboxStore {
    inner: Arc<SqliteSecurityStateStore>,
    faults: OutboxFaults,
}

impl AttestedFindingResponseOutboxStore for FaultingResponseOutboxStore {
    fn ensure_attested_finding_response_outbox_ready(&self) -> PortResult<()> {
        self.inner.ensure_attested_finding_response_outbox_ready()
    }

    fn publish_attested_finding_response_plan(
        &self,
        publication: &AttestedFindingResponsePlanPublication,
    ) -> PortResult<CreateOutcome> {
        self.inner
            .publish_attested_finding_response_plan(publication)
    }

    fn load_attested_finding_response_outbox(
        &self,
        key: &AttestedFindingResponseOutboxKey,
    ) -> PortResult<Option<AttestedFindingResponseOutboxRecord>> {
        if self.faults.hidden.as_ref() == Some(key) {
            return Ok(None);
        }
        let mut record = self.inner.load_attested_finding_response_outbox(key)?;
        if self.faults.strip_refusal_codes {
            if let Some(record) = record.as_mut() {
                if record.is_complete()
                    && !matches!(
                        record.completion_state,
                        AttestedFindingResponseCompletionState::Completed
                            | AttestedFindingResponseCompletionState::Simulated
                    )
                {
                    record.last_error_code = None;
                }
            }
        }
        Ok(record)
    }

    fn scan_unplanned_attested_finding_responses(
        &self,
        now_unix_ms: u64,
        limit: u32,
    ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
        self.inner
            .scan_unplanned_attested_finding_responses(now_unix_ms, limit)
    }

    fn scan_incomplete_attested_finding_responses(
        &self,
        now_unix_ms: u64,
        limit: u32,
    ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
        self.inner
            .scan_incomplete_attested_finding_responses(now_unix_ms, limit)
    }

    fn transition_attested_finding_response_outbox(
        &self,
        current: &AttestedFindingResponseOutboxRecord,
        transition: AttestedFindingResponseOutboxTransition,
    ) -> PortResult<AttestedFindingResponseOutboxRecord> {
        if self.faults.refuse_admission_rejection_writes
            && matches!(
                transition,
                AttestedFindingResponseOutboxTransition::AdmissionRejected { .. }
            )
        {
            return Err(PortError::integrity_failure());
        }
        self.inner
            .transition_attested_finding_response_outbox(current, transition)
    }

    fn attested_finding_response_outbox_health(
        &self,
    ) -> PortResult<AttestedFindingResponseOutboxHealth> {
        self.inner.attested_finding_response_outbox_health()
    }
}

fn faulting_planner(
    store: &Arc<SqliteSecurityStateStore>,
    faults: OutboxFaults,
    findings: &[AuthoritativeCorrelatedFindingEvidence],
    policy: Arc<dyn AttestedFindingResponsePolicyPlanner>,
    coordinator: &Arc<RecordingResponseCoordinator>,
) -> DurableAttestedFindingBatchPlanner {
    DurableAttestedFindingBatchPlanner::new(
        Arc::clone(store) as Arc<dyn AttestedFindingBatchStore>,
        Arc::new(FaultingResponseOutboxStore {
            inner: Arc::clone(store),
            faults,
        }),
        Arc::new(TestFindingAuthority::new(findings)),
        policy,
        Arc::clone(coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
        Arc::new(FixedClock(10_002)),
    )
    .unwrap_or_else(|error| panic!("faulting planner: {error}"))
}

fn open_store(directory: &tempfile::TempDir, name: &str) -> Arc<SqliteSecurityStateStore> {
    Arc::new(
        SqliteSecurityStateStore::open(directory.path().join(name))
            .unwrap_or_else(|error| panic!("open {name}: {error}")),
    )
}

fn load_response(
    store: &SqliteSecurityStateStore,
    publication: &AttestedFindingBatchPublication,
    ordinal: usize,
) -> AttestedFindingResponseOutboxRecord {
    store
        .load_attested_finding_response_outbox(&recovery_outbox_key(publication, ordinal))
        .unwrap_or_else(|error| panic!("load response {ordinal}: {error}"))
        .unwrap_or_else(|| panic!("response {ordinal} missing"))
}

fn execution_count(coordinator: &RecordingResponseCoordinator) -> usize {
    coordinator
        .executions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len()
}

#[test]
fn published_batch_with_an_unverifiable_response_row_is_not_acknowledged() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = open_store(&directory, "unverifiable-response-row.sqlite");
    let findings = vec![
        authoritative_finding_with_identity("finding-unverifiable-row", "rule-unverifiable", 96),
        authoritative_finding_with_identity("finding-verified-row", "rule-verified", 97),
    ];
    let publication = build_attested_finding_batch_publication(&findings)
        .unwrap_or_else(|error| panic!("publication: {error}"));
    let coordinator = Arc::new(RecordingResponseCoordinator::default());
    let planner = faulting_planner(
        &store,
        OutboxFaults {
            hidden: Some(recovery_outbox_key(&publication, 0)),
            ..OutboxFaults::default()
        },
        &findings,
        Arc::new(RecordingResponsePolicy),
        &coordinator,
    );

    let error = rejected(
        planner.publish_attested_batch(&findings),
        "a response row that cannot be read back must keep its event unacknowledged",
    );

    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(error.code(), PortError::integrity_failure().code());
    assert_eq!(
        load_response(&store, &publication, 1).completion_state,
        AttestedFindingResponseCompletionState::Completed
    );
    assert_eq!(execution_count(&coordinator), 1);
}

#[test]
fn published_batch_whose_refusal_could_not_be_recorded_is_not_acknowledged() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = open_store(&directory, "unrecorded-refusal.sqlite");
    let refused =
        authoritative_finding_with_identity("finding-unrecorded-refusal", "rule-unrecorded", 98);
    let completed =
        authoritative_finding_with_identity("finding-recorded-success", "rule-recorded", 99);
    let findings = vec![refused.clone(), completed];
    let publication = build_attested_finding_batch_publication(&findings)
        .unwrap_or_else(|error| panic!("publication: {error}"));
    let refusal_code = ErrorCode::new("active_response.unrecorded_refusal")
        .unwrap_or_else(|error| panic!("refusal code: {error}"));
    let coordinator = Arc::new(RecordingResponseCoordinator::default());
    let planner = faulting_planner(
        &store,
        OutboxFaults {
            refuse_admission_rejection_writes: true,
            ..OutboxFaults::default()
        },
        &findings,
        Arc::new(SelectiveArtifactResponsePolicy {
            rejected: BTreeMap::from([(refused.evidence_id().clone(), refusal_code)]),
        }),
        &coordinator,
    );

    let error = rejected(
        planner.publish_attested_batch(&findings),
        "a refusal that was never recorded must keep its event unacknowledged",
    );

    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(error.code(), PortError::integrity_failure().code());
    let unrecorded = load_response(&store, &publication, 0);
    assert_eq!(
        unrecorded.admission_state,
        AttestedFindingResponseAdmissionState::Pending
    );
    assert_eq!(unrecorded.last_error_code, None);
    assert_eq!(
        load_response(&store, &publication, 1).completion_state,
        AttestedFindingResponseCompletionState::Completed
    );
    assert_eq!(execution_count(&coordinator), 1);
}

#[test]
fn published_batch_with_a_terminal_row_missing_its_refusal_code_is_not_acknowledged() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = open_store(&directory, "uncoded-terminal-refusal.sqlite");
    let finding =
        authoritative_finding_with_identity("finding-uncoded-refusal", "rule-uncoded", 100);
    let publication = publish_recovery_batch(store.as_ref(), std::slice::from_ref(&finding));
    let pending = load_response(&store, &publication, 0);
    store
        .transition_attested_finding_response_outbox(
            &pending,
            AttestedFindingResponseOutboxTransition::PlanningFailed {
                error_code: ErrorCode::new("active_response.recorded_refusal")
                    .unwrap_or_else(|error| panic!("refusal code: {error}")),
            },
        )
        .unwrap_or_else(|error| panic!("record terminal refusal: {error}"));
    let coordinator = Arc::new(RecordingResponseCoordinator::default());
    let planner = faulting_planner(
        &store,
        OutboxFaults {
            strip_refusal_codes: true,
            ..OutboxFaults::default()
        },
        std::slice::from_ref(&finding),
        Arc::new(RecordingResponsePolicy),
        &coordinator,
    );

    let error = rejected(
        planner.publish_attested_batch(std::slice::from_ref(&finding)),
        "a terminal response row without its recorded refusal must keep its event unacknowledged",
    );

    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    assert_eq!(error.code(), PortError::integrity_failure().code());
    assert_eq!(execution_count(&coordinator), 0);
}
