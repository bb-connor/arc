//! Evidence from real durable ports. Faults lose an acknowledgement after commit.
use super::*;
use crate::security::adapters::effect_port::{ResponseEffectBackend, SessionThrottleBackend};
use chio_core::canonical::canonical_json_bytes;
use chio_core::receipt::signing::ChioReceiptSigningBody;
use chio_security_types::ports::{
    empty_session_throttle_snapshot, session_throttle_version_hash, SessionThrottleKey,
    SessionThrottleLimits, SessionThrottleStore,
};
use chio_store_sqlite::SqliteReceiptStore;
use serde_json::{json, Map, Value};
use std::path::Path;
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

#[derive(Clone, Default)]
struct Capture {
    events: Arc<Mutex<Vec<Value>>>,
    commits: Arc<Mutex<BTreeMap<u64, String>>>,
    store: Arc<Mutex<std::sync::Weak<SqliteSecurityStateStore>>>,
}
struct Fields(Map<String, Value>);
impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), json!(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), json!(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), json!(value));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), json!(format!("{value:?}")));
    }
}
impl<S: tracing::Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() == "chio::response_lifecycle" {
            let mut fields = Fields(Map::new());
            event.record(&mut fields);
            if fields.0.get("boundary") == Some(&json!("response_commit")) {
                // Production drops its connection guard before this callback. Use
                // a weak reference so collecting readbacks cannot retain an owner
                // across the restart boundary exercised below.
                let store = require_success(self.store.lock(), "capture store")
                    .upgrade()
                    .unwrap_or_else(|| panic!("commit without a live store"));
                let field = |name: &str| {
                    fields
                        .0
                        .get(name)
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| panic!("missing commit field {name}"))
                };
                let record = require_success(
                    store.load_plan(&ResponsePlanKey {
                        tenant_id: require_success(
                            TenantId::new(field("tenant_id")),
                            "commit tenant",
                        ),
                        action_id: require_success(
                            ActionId::new(field("action_id")),
                            "commit action",
                        ),
                    }),
                    "read committed snapshot",
                )
                .unwrap_or_else(|| panic!("missing committed snapshot"));
                assert_eq!(
                    Some(record.generation),
                    fields.0.get("generation").and_then(Value::as_u64)
                );
                let prior = require_success(self.commits.lock(), "capture commits").insert(
                    record.generation,
                    hex::encode(record.canonical_body.as_bytes()),
                );
                assert!(prior.is_none(), "duplicate committed generation");
            }
            require_success(self.events.lock(), "capture lock").push(Value::Object(fields.0));
        }
    }
}

struct Effects {
    backend: SessionThrottleBackend,
    lose_ack: AtomicBool,
}
impl EffectPort for Effects {
    fn ensure_effects_ready(&self) -> PortResult<()> {
        self.backend.ensure_ready()
    }
    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult> {
        let result = self.backend.execute(request)?;
        if self.lose_ack.swap(false, Ordering::SeqCst) {
            Err(PortError::unavailable())
        } else {
            Ok(result)
        }
    }
    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        self.backend.load_result(query)
    }
}
struct Receipts {
    inner: NativeSecurityReceiptSink,
    lose_ack: AtomicBool,
}
impl SecurityReceiptSink for Receipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        self.inner.ensure_receipts_ready()
    }
    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        let result = self.inner.sign_and_append(request)?;
        if self.lose_ack.swap(false, Ordering::SeqCst) {
            Err(PortError::unavailable())
        } else {
            Ok(result)
        }
    }
}
impl ActiveResponseReceiptProofSource for Receipts {
    fn ensure_active_response_receipt_proofs_ready(
        &self,
    ) -> Result<(), ActiveResponseExecutorError> {
        self.inner.ensure_active_response_receipt_proofs_ready()
    }
    fn load_signed_active_response_receipt(
        &self,
        id: &OpaqueReceiptRef,
    ) -> Result<Option<ChioReceipt>, ActiveResponseExecutorError> {
        self.inner.load_signed_active_response_receipt(id)
    }
}
struct Owners {
    store: Arc<SqliteSecurityStateStore>,
    evidence: Arc<SqliteReceiptStore>,
    effects: Arc<Effects>,
    receipts: Arc<Receipts>,
}
impl Owners {
    fn open(root: &Path, clock: &Arc<FixedClock>, scenario: &str, capture: &Capture) -> Self {
        let store = Arc::new(require_success(
            SqliteSecurityStateStore::open_with_trusted_clock(
                root.join("state.db"),
                Arc::new(TestStoreClock {
                    clock: Arc::clone(clock),
                }),
            ),
            "open state",
        ));
        *require_success(capture.store.lock(), "attach capture") = Arc::downgrade(&store);
        let evidence = Arc::new(require_success(
            SqliteReceiptStore::open(root.join("receipts.db")),
            "open receipts",
        ));
        let effects = Arc::new(Effects {
            backend: SessionThrottleBackend::new(store.clone()),
            lose_ack: AtomicBool::new(scenario == "effect_ack_loss"),
        });
        let signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[7; 32])));
        let receipts = Arc::new(Receipts {
            inner: NativeSecurityReceiptSink::new(evidence.clone(), signer),
            lose_ack: AtomicBool::new(scenario == "receipt_ack_loss"),
        });
        Self {
            store,
            evidence,
            effects,
            receipts,
        }
    }
    fn executor(
        &self,
        clock: &Arc<FixedClock>,
    ) -> DurableActiveResponseExecutor<SqliteSecurityStateStore, Effects, Receipts, TestAlerts>
    {
        require_success(
            DurableActiveResponseExecutor::new(
                identity(7),
                require_success(
                    LeaseOwnerId::new(TEST_ACTIVE_RESPONSE_LEASE_OWNER_ID),
                    "lease owner",
                ),
                self.store.clone(),
                self.effects.clone(),
                self.receipts.clone(),
                Arc::new(TestAlerts::ready()),
                clock.clone(),
                30_000,
            ),
            "executor",
        )
    }
}
fn throttle_plan(now: u64) -> ResponsePlan {
    let base = plan(
        now,
        &identity(7),
        ResponseApprovalRequirement::Automatic,
        false,
    );
    let session_id = require_success(SessionId::new("session-durable-response"), "session");
    let key = SessionThrottleKey {
        tenant_id: base.tenant_id.clone(),
        session_id: session_id.clone(),
    };
    let canonical_contribution = require_success(
        CanonicalBody::new(require_success(
            canonical_json_bytes(&SessionThrottleLimits {
                window_ms: 1_000,
                max_invocations: 2,
            }),
            "limits JSON",
        )),
        "limits body",
    );
    let contribution_hash =
        Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
    require_success(
        build_response_plan(ResponsePlanInput {
            execution: base.execution,
            action_id: base.action_id,
            trigger_finding_id: base.trigger_finding_id,
            trigger_finding_hash: base.trigger_finding_hash,
            trigger_finding_receipt_id: base.trigger_finding_receipt_id,
            tenant_id: base.tenant_id,
            policy_version: base.policy_version,
            policy_hash: base.policy_hash,
            affected_ids: base.affected_ids.as_slice().to_vec(),
            effects: vec![ResponseEffectSpec {
                kind: ResponseEffectKind::ThrottleSession,
                target: ResponseTarget::Session { session_id },
                canonical_contribution,
                contribution_hash,
                observed_base_version_hash: require_success(
                    session_throttle_version_hash(&require_success(
                        empty_session_throttle_snapshot(key),
                        "empty throttle",
                    )),
                    "base hash",
                ),
            }],
            ttl_ms: base.ttl_ms,
            created_at_unix_ms: base.created_at_unix_ms,
            operator_capability: base.operator_capability,
            approval_requirement: base.approval_requirement,
            submitter: base.submitter,
            reason_hash: base.reason_hash,
        }),
        "throttle plan",
    )
}

// tracing-core's single-dispatch callsite cache can first observe these shared
// production callsites on a parallel test thread with no subscriber. Keep the
// collector in its own process so a normal parallel suite cannot suppress it.
fn isolated_capture_child() -> bool {
    const CHILD_ENV: &str = "CHIO_DURABLE_LIFECYCLE_CHILD";
    let module = module_path!()
        .split_once("::")
        .unwrap_or_else(|| panic!("test module"));
    let name = format!(
        "{}::durable_lifecycle_trace_links_commits_effects_and_signed_receipts",
        module.1
    );
    if std::env::var(CHILD_ENV).as_deref() == Ok(name.as_str()) {
        return true;
    }
    let log = require_success(tempfile::NamedTempFile::new(), "child log");
    let mut child = require_success(
        std::process::Command::new(require_success(std::env::current_exe(), "test executable"))
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD_ENV, &name)
            .stdout(require_success(log.as_file().try_clone(), "child stdout"))
            .stderr(require_success(log.as_file().try_clone(), "child stderr"))
            .spawn(),
        "spawn isolated trace",
    );
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = require_success(child.try_wait(), "wait trace child") {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "isolated trace timed out: {}",
                require_success(std::fs::read_to_string(log.path()), "child timeout log")
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = require_success(std::fs::read_to_string(log.path()), "child output");
    assert!(
        status.success() && output.contains("test result: ok. 1 passed; 0 failed;"),
        "isolated trace failed ({status}): {output}"
    );
    false
}

#[test]
fn durable_lifecycle_trace_links_commits_effects_and_signed_receipts() {
    if !isolated_capture_child() {
        return;
    }
    let mut scenarios = Map::new();
    for scenario in ["happy", "effect_ack_loss", "receipt_ack_loss"] {
        let capture = Capture::default();
        let _subscriber =
            tracing::subscriber::set_default(Registry::default().with(capture.clone()));
        let root = require_success(tempfile::tempdir(), "trace directory");
        let now = 1_800_000_000_000;
        let clock = Arc::new(FixedClock::new(now));
        let request = raw_request(
            throttle_plan(now),
            identity(7),
            ActiveResponseExecutionApproval::Automatic,
        );
        {
            let owners = Owners::open(root.path(), &clock, scenario, &capture);
            let first = owners.executor(&clock).execute_source(&request);
            if scenario == "happy" {
                require_success(first, "activate");
            } else {
                assert!(
                    matches!(first, Err(ActiveResponseExecutorError::OutcomeUnknown(_))),
                    "{scenario}: {first:?}"
                );
            }
        }
        // Every store, writer, executor and backend owner is dropped before recovery.
        tracing::debug!(target: "chio::response_lifecycle", boundary = "restart");
        {
            let owners = Owners::open(root.path(), &clock, "recovery", &capture);
            let executor = owners.executor(&clock);
            let recovered =
                require_success(executor.execute_source(&request), "recover activation");
            let replay = require_success(executor.execute_source(&request), "replay activation");
            assert_eq!(recovered.proof_evidence_id(), replay.proof_evidence_id());
            let expires = request.response_plan.expires_at_unix_ms;
            clock.set(expires);
            let key = ResponsePlanKey {
                tenant_id: request.response_plan.tenant_id.clone(),
                action_id: request.response_plan.action_id.clone(),
            };
            let active = require_success(owners.store.load_plan(&key), "active readback")
                .unwrap_or_else(|| panic!("missing active"));
            let mut work = require_success(
                owners.store.claim_due(&SchedulerClaimRequest {
                    tenant_id: key.tenant_id.clone(),
                    claim_id: record_id("trace-expiry"),
                    lease_owner_id: require_success(
                        LeaseOwnerId::new(TEST_ACTIVE_RESPONSE_LEASE_OWNER_ID),
                        "lease owner",
                    ),
                    now_unix_ms: expires,
                    lease_expires_at_unix_ms: expires + 30_000,
                    max_claims: 1,
                }),
                "claim expiry",
            );
            assert_eq!(work.len(), 1);
            let work = work.remove(0);
            let rolling = require_success(
                ResponseStateMachine::new(owners.store.clone()).handle_due_scheduled(
                    &active,
                    &work,
                    active.generation,
                    expires,
                ),
                "expire active",
            );
            let lifted = require_success(
                ResponseExecutor::new(
                    owners.store.clone(),
                    owners.effects.clone(),
                    owners.receipts.clone(),
                    Arc::new(TestAlerts::ready()),
                )
                .execute(&rolling, &work, expires),
                "restore throttle",
            );
            assert_eq!(
                require_success(decode_response_record(&lifted), "lifted").state,
                ResponseState::Lifted
            );
        }
        tracing::debug!(target: "chio::response_lifecycle", boundary = "restart");
        let owners = Owners::open(root.path(), &clock, "readback", &capture);
        let key = ResponsePlanKey {
            tenant_id: request.response_plan.tenant_id.clone(),
            action_id: request.response_plan.action_id.clone(),
        };
        let record = require_success(owners.store.load_plan(&key), "final readback")
            .unwrap_or_else(|| panic!("missing final"));
        let snapshot = require_success(decode_response_record(&record), "final snapshot");
        assert_eq!(snapshot.state, ResponseState::Lifted);
        let throttle = require_success(
            owners.store.load_session_throttles(&SessionThrottleKey {
                tenant_id: key.tenant_id,
                session_id: require_success(SessionId::new("session-durable-response"), "session"),
            }),
            "restored throttle",
        )
        .unwrap_or_else(|| panic!("missing throttle journal"));
        assert!(throttle.contributions.as_slice().is_empty());
        let journal = require_success(
            Connection::open_with_flags(
                root.path().join("state.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ),
            "read command journal",
        );
        let mut statement = require_success(journal.prepare("SELECT request_body, result_body FROM security_session_throttle_commands ORDER BY idempotency_key"), "command query");
        let commands = require_success(
            statement.query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            }),
            "commands",
        );
        let commands: Vec<Value> = commands.map(|row| {
            let (request, result) = require_success(row, "command row");
            json!({"request": require_success(serde_json::from_slice::<Value>(&request), "command request"),
                "result": require_success(serde_json::from_slice::<Value>(&result), "command result")})
        }).collect();
        assert_eq!(
            commands.len(),
            2,
            "exactly one durable command per apply/remove"
        );
        let events = require_success(capture.events.lock(), "captured events").clone();
        let mut receipts = Map::new();
        for event in &events {
            if event["boundary"] != "receipt_persisted" {
                continue;
            }
            let id = event["evidence_id"]
                .as_str()
                .unwrap_or_else(|| panic!("receipt id"));
            let receipt = require_success(
                owners
                    .evidence
                    .load_indexed_security_evidence(&require_success(
                        OpaqueReceiptRef::new(id),
                        "receipt id",
                    )),
                "durable signed receipt",
            )
            .unwrap_or_else(|| panic!("missing signed receipt"));
            assert!(require_success(
                receipt.verify_signature(),
                "verify receipt"
            ));
            let signing = ChioReceiptSigningBody::from(&receipt.body());
            receipts.insert(id.to_owned(), json!({"signing_bytes": hex::encode(require_success(canonical_json_bytes(&signing), "signing bytes")), "signature": receipt.signature.to_hex()}));
        }
        assert_eq!(
            events
                .iter()
                .filter(|e| e["boundary"] == "response_commit")
                .map(|e| e["generation"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("generation"))
                    - e["first_generation"]
                        .as_u64()
                        .unwrap_or_else(|| panic!("first generation"))
                    + 1)
                .sum::<u64>() as usize,
            snapshot.mutations.as_slice().len(),
            "every committed generation must be observed"
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e["boundary"] == "effect_commit")
                .count(),
            2,
            "apply and remove each commit once across replay"
        );
        assert_eq!(
            receipts.len(),
            snapshot.mutations.as_slice().len(),
            "every generation has a durable signed receipt"
        );
        scenarios.insert(scenario.into(), json!({"events": events, "committed_snapshots": require_success(capture.commits.lock(), "committed snapshots").clone(), "commands": commands, "snapshot": snapshot, "snapshot_canonical": hex::encode(record.canonical_body.as_bytes()), "receipts": receipts}));
    }
    if let Ok(path) = std::env::var("CHIO_DURABLE_LIFECYCLE_TRACE") {
        require_success(
            std::fs::write(
                path,
                require_success(
                    serde_json::to_vec_pretty(&json!({
                        "schema": "chio.response-durable-trace.v1", "scenarios": scenarios,
                        "scope": "SQLite response and throttle commits, native Ed25519 receipts; single worker with store-owner restart"
                    })),
                    "trace JSON",
                ),
            ),
            "trace artifact",
        );
    }
}
