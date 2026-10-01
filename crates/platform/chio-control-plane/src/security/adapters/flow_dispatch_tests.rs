use super::*;
use crate::security::adapters::{canonical_body, PreparedFlowDispatch};
use chio_flow::FlowDenial;
use chio_store_sqlite::security_state::SecurityStateClock;
use std::sync::atomic::AtomicU64;

mod evidence_callbacks {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/flow_dispatch_tests/evidence_callbacks.rs"
    ));
}

struct ControlledClock(AtomicU64);

impl SecurityClock for ControlledClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

impl SecurityStateClock for ControlledClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        SecurityClock::now_unix_ms(self)
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    resolver: PersistentFlowResolver,
    state: Arc<SqliteSecurityStateStore>,
    clock: Arc<ControlledClock>,
    classifier: Arc<CountingEmptyClassifier>,
    receipts: Arc<RecordingSecurityReceipts>,
    request: ToolCallRequest,
    context: SecurityInvocationContextV1,
}

impl Fixture {
    fn new(declassify: bool) -> Self {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let clock = Arc::new(ControlledClock(AtomicU64::new(150_000)));
        let state = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                directory.path().join("security.sqlite"),
                clock.clone(),
            )
            .unwrap_or_else(|error| panic!("state: {error:?}")),
        );
        let snapshot = state
            .join(&FlowJoinRequest {
                key: flow_key(),
                principal_join: InformationLabel::bottom(),
                lineage_join: InformationLabel::bottom(),
                session_join: InformationLabel::bottom(),
                transition_id: RecordId::new("initial-flow")
                    .unwrap_or_else(|error| panic!("transition: {error}")),
            })
            .unwrap_or_else(|error| panic!("initialize flow: {error:?}"));
        let authority = Keypair::from_seed(&[91; 32]);
        let purpose = DeclassificationPurpose::new("support")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        let receipts = Arc::new(RecordingSecurityReceipts::default());
        let (registry, config, request) = if declassify {
            (
                declassification_registry(&purpose),
                declassifying_evidence_flow_config(&authority, state.clone(), receipts.clone()),
                declassifying_flow_request(&authority, &purpose),
            )
        } else {
            (flow_registry(), flow_config(), flow_request())
        };
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = PersistentFlowResolver::new(
            registry,
            state.clone(),
            classifier.clone(),
            clock.clone(),
            config,
        );
        let key = flow_key();
        let context = SecurityInvocationContextV1::new(
            key.tenant_id,
            key.session_id,
            key.principal_id,
            key.isolation_epoch_id,
            key.lineage_id,
            7,
        )
        .with_flow_state_generation(snapshot.context_generation);
        Self {
            directory,
            resolver,
            state,
            clock,
            classifier,
            receipts,
            request,
            context,
        }
    }

    fn prepare(&self) -> PreparedFlowDispatch<'_> {
        self.resolver
            .prepare_dispatch(
                &FlowPreInvocationInput {
                    security_context: &self.context,
                    request: &self.request,
                },
                RecordId::new("prepared-dispatch")
                    .unwrap_or_else(|error| panic!("commitment: {error}")),
            )
            .unwrap_or_else(|error| panic!("prepare: {error}"))
    }

    fn snapshot(&self) -> FlowStateSnapshot {
        self.state
            .load(&flow_key())
            .unwrap_or_else(|error| panic!("load: {error:?}"))
            .unwrap_or_else(|| panic!("missing flow"))
    }

    fn inventory(&self) -> Vec<(String, i64)> {
        let connection = Connection::open(self.directory.path().join("security.sqlite"))
            .unwrap_or_else(|error| panic!("inspect: {error}"));
        [
            "security_transitions",
            "security_egress_fences",
            "security_declassification_uses",
            "security_declassification_receipt_outbox",
        ]
        .into_iter()
        .map(|table| {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            (table.to_owned(), count)
        })
        .collect()
    }

    fn assert_unused(&self, snapshot: &FlowStateSnapshot, inventory: &[(String, i64)]) {
        assert_eq!(&self.snapshot(), snapshot);
        assert_eq!(self.inventory(), inventory);
        assert!(self.receipts.bodies().is_empty());
    }
}

#[test]
fn preparing_and_dropping_either_profile_does_not_mutate_sqlite() {
    for declassify in [false, true] {
        let fixture = Fixture::new(declassify);
        let snapshot = fixture.snapshot();
        let inventory = fixture.inventory();
        let prepared = fixture.prepare();
        assert!(prepared.admission().declassification.is_none());
        fixture.assert_unused(&snapshot, &inventory);
        drop(prepared);
        fixture.assert_unused(&snapshot, &inventory);
        assert_eq!(fixture.classifier.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn prepared_dispatch_keeps_live_envelope_and_argument_hashes_distinct() {
    for declassify in [false, true] {
        let fixture = Fixture::new(declassify);
        let snapshot = fixture.snapshot();
        let inventory = fixture.inventory();
        let prepared = fixture.prepare();
        let envelope = chio_core::canonical_json_bytes(&fixture.request)
            .unwrap_or_else(|error| panic!("live request: {error}"));
        let payload = canonical_body(&fixture.request.arguments)
            .unwrap_or_else(|error| panic!("payload: {error}"));
        assert_eq!(
            prepared.live_request_digest(),
            Digest32::new(*chio_core::sha256(&envelope).as_bytes())
        );
        assert_eq!(
            prepared.admission().request_hash,
            canonical_request_hash(&payload)
                .unwrap_or_else(|error| panic!("payload hash: {error}"))
        );
        assert_ne!(
            prepared.live_request_digest(),
            prepared.admission().request_hash
        );
        assert!(prepared.validate_live_request(&fixture.request).is_ok());
        fixture.assert_unused(&snapshot, &inventory);
    }
}

#[test]
fn prepared_dispatch_rejects_envelope_substitution_with_equal_arguments() {
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    let snapshot = fixture.snapshot();
    let inventory = fixture.inventory();
    for field in ["request", "agent", "server", "tool", "origin", "capability"] {
        let mut changed = fixture.request.clone();
        match field {
            "request" => changed.request_id = "other-request".into(),
            "agent" => changed.agent_id = "other-agent".into(),
            "server" => changed.server_id = "other-server".into(),
            "tool" => changed.tool_name = "other-tool".into(),
            "origin" => changed.federated_origin_kernel_id = Some("other-kernel".into()),
            "capability" => changed.capability.id = "other-capability".into(),
            _ => unreachable!("closed test matrix"),
        }
        assert_eq!(changed.arguments, fixture.request.arguments);
        assert!(
            matches!(
                prepared.validate_live_request(&changed),
                Err(FlowDenial::DeclassificationBindingMismatch)
            ),
            "{field}"
        );
    }
    fixture.assert_unused(&snapshot, &inventory);
}

#[test]
fn prepared_dispatch_binds_transient_grant_without_changing_its_payload_commitment() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    let snapshot = fixture.snapshot();
    let inventory = fixture.inventory();
    let mut stripped = fixture.request.clone();
    stripped.declassification_grant = None;
    assert_eq!(stripped.arguments, fixture.request.arguments);
    assert!(matches!(
        prepared.validate_live_request(&stripped),
        Err(FlowDenial::DeclassificationBindingMismatch)
    ));
    fixture.assert_unused(&snapshot, &inventory);
    // The unchanged signed grant still verifies and commits with its existing
    // payload hash. A full-envelope grant hash would be self-referential.
    let mut outcome = prepared
        .commit()
        .unwrap_or_else(|error| panic!("commit: {error}"))
        .unwrap_or_else(|| panic!("outcome owner"));
    outcome
        .record(DeclassificationDispatchOutcome::Released)
        .unwrap_or_else(|error| panic!("outcome: {error}"));
}

#[test]
fn prepared_commit_uses_fresh_consumption_time_without_reclassification() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.clock.0.store(150_125, Ordering::SeqCst);
    let mut outcome = prepared
        .commit()
        .unwrap_or_else(|error| panic!("commit: {error}"))
        .unwrap_or_else(|| panic!("missing outcome owner"));
    assert_eq!(fixture.classifier.calls.load(Ordering::SeqCst), 1);
    let record = fixture
        .state
        .load_declassification_use(&DeclassificationUseQuery {
            tenant_id: flow_key().tenant_id,
            grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
        })
        .unwrap_or_else(|error| panic!("read consumption: {error:?}"))
        .unwrap_or_else(|| panic!("missing consumption"));
    assert_eq!(record.consumed_at_unix_ms, 150_125);
    assert_eq!(
        record.state,
        DeclassificationUseState::ConsumedPendingDispatch
    );
    outcome
        .record(DeclassificationDispatchOutcome::Released)
        .unwrap_or_else(|error| panic!("release: {error}"));
    assert_eq!(fixture.receipts.bodies().len(), 2);
}

#[test]
fn prepared_non_declassifying_commit_uses_the_physical_fence() {
    let fixture = Fixture::new(false);
    assert!(fixture
        .prepare()
        .commit()
        .unwrap_or_else(|error| panic!("commit: {error}"))
        .is_none());
    assert_eq!(fixture.classifier.calls.load(Ordering::SeqCst), 1);
    let connection = Connection::open(fixture.directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("inspect: {error}"));
    let commitment: String = connection
        .query_row(
            "SELECT dispatch_commitment_id FROM security_egress_fences",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("fence commitment: {error}"));
    assert_eq!(commitment, "prepared-dispatch");
}

#[test]
fn expired_prepared_grant_is_not_consumed() {
    let fixture = Fixture::new(true);
    let snapshot = fixture.snapshot();
    let inventory = fixture.inventory();
    let prepared = fixture.prepare();
    fixture.clock.0.store(200_000, Ordering::SeqCst);
    assert!(matches!(
        prepared.commit(),
        Err(chio_flow::FlowDenial::DeclassificationExpired)
    ));
    fixture.assert_unused(&snapshot, &inventory);
}

#[test]
fn expired_fence_plan_is_not_renewed_at_commit() {
    for declassify in [false, true] {
        let fixture = Fixture::new(declassify);
        let snapshot = fixture.snapshot();
        let inventory = fixture.inventory();
        let prepared = fixture.prepare();
        fixture.clock.0.store(160_000, Ordering::SeqCst);
        assert!(matches!(
            prepared.commit(),
            Err(chio_flow::FlowDenial::StateChanged)
        ));
        fixture.assert_unused(&snapshot, &inventory);
    }
}

#[test]
fn clock_rollback_cannot_consume_a_prepared_grant() {
    let fixture = Fixture::new(true);
    let snapshot = fixture.snapshot();
    let inventory = fixture.inventory();
    let prepared = fixture.prepare();
    fixture.clock.0.store(149_999, Ordering::SeqCst);
    assert!(matches!(
        prepared.commit(),
        Err(chio_flow::FlowDenial::StateChanged)
    ));
    fixture.assert_unused(&snapshot, &inventory);
}

#[test]
fn another_flow_transition_invalidates_preparation_without_consuming() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture
        .state
        .join(&FlowJoinRequest {
            key: flow_key(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: RecordId::new("competing-transition")
                .unwrap_or_else(|error| panic!("transition: {error}")),
        })
        .unwrap_or_else(|error| panic!("competing join: {error:?}"));
    let snapshot = fixture.snapshot();
    let inventory = fixture.inventory();
    assert!(matches!(
        prepared.commit(),
        Err(chio_flow::FlowDenial::StateChanged)
    ));
    fixture.assert_unused(&snapshot, &inventory);
}

#[test]
fn concurrent_preparations_do_not_establish_two_owners() {
    let fixture = Fixture::new(true);
    let first = fixture.prepare();
    let second = fixture.prepare();
    let mut outcome = first
        .commit()
        .unwrap_or_else(|error| panic!("first: {error}"))
        .unwrap_or_else(|| panic!("first owner"));
    let snapshot = fixture.snapshot();
    let inventory = fixture.inventory();
    assert!(matches!(
        second.commit(),
        Err(chio_flow::FlowDenial::StateChanged)
    ));
    assert_eq!(fixture.snapshot(), snapshot);
    assert_eq!(fixture.inventory(), inventory);
    outcome
        .record(DeclassificationDispatchOutcome::Released)
        .unwrap_or_else(|error| panic!("release: {error}"));
}

#[test]
fn racing_prepared_commits_consume_the_grant_once() {
    let fixture = Fixture::new(true);
    let barrier = std::sync::Barrier::new(2);
    let completed = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..2 {
            workers.push(scope.spawn(|| {
                let prepared = fixture.prepare();
                barrier.wait();
                match prepared.commit() {
                    Ok(Some(mut outcome)) => {
                        outcome
                            .record(DeclassificationDispatchOutcome::Released)
                            .unwrap_or_else(|error| panic!("release: {error}"));
                        true
                    }
                    Ok(None) => panic!("declassification owner missing"),
                    Err(_) => false,
                }
            }));
        }
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|_| panic!("commit worker panicked"))
            })
            .filter(|completed| *completed)
            .count()
    });
    assert_eq!(completed, 1);
    assert_eq!(fixture.classifier.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.receipts.bodies().len(), 2);
}
