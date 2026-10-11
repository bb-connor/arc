//! Exercise the manager and actual payload encoders against sensitive receipts.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{body::ChioReceipt, decision::Decision, metadata::GuardEvidence};
use chio_egress_contract::HttpEgressContract;
use chio_kernel::{
    BlockingToolServerAdapter, BlockingToolServerConnection, ChioKernel, Guard, GuardContext,
    GuardDecision, KernelConfig, KernelError, ReceiptReadContext, ReceiptStore, ReceiptStoreError,
    ToolCallRequest, Verdict,
};
use chio_siem::*;
use rusqlite::{params, Connection};
use serde_json::json;
use tokio::sync::watch;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CANARIES: [&str; 10] = [
    "ordinary-argument-canary-91f2",
    "ordinary-reason-canary-d001",
    "ordinary-evidence-canary-3141",
    "ordinary-metadata-canary-5926",
    "ordinary-tool-canary-5358",
    "ordinary-server-canary-9793",
    "ordinary-guard-canary-2384",
    "ordinary-payment-canary-6264",
    "ordinary-holder-canary-3383",
    "ordinary-currency-canary-2795",
];

// This fixture persists the real kernel's signed output in the schema consumed
// by the manager. Production SQLite store trust/tenant qualification belongs to
// chio-store-sqlite and is not substituted by this fixture.
struct FixtureReceiptStore(Mutex<Connection>);

impl ReceiptStore for FixtureReceiptStore {
    fn append_child_receipt(
        &self,
        _: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported("child fixture".into()))
    }

    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        let raw = serde_json::to_string(receipt)?;
        self.0
            .lock()
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?
            .execute(
                "INSERT INTO chio_tool_receipts(raw_json) VALUES (?1)",
                params![raw],
            )?;
        Ok(())
    }
}

struct CanaryGuard;

struct CanaryServer;

impl BlockingToolServerConnection for CanaryServer {
    fn server_id(&self) -> &str {
        CANARIES[5]
    }
    fn tool_names(&self) -> Vec<String> {
        vec![CANARIES[4].into()]
    }
    fn invoke_blocking(
        &self,
        _: &str,
        _: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        panic!("the denied tool must never run")
    }
}

impl Guard for CanaryGuard {
    fn name(&self) -> &str {
        "SecretLeakGuard::ordinary-reason-canary-d001::ordinary-guard-canary-2384"
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::deny(vec![
            GuardEvidence {
                guard_name: format!("SecretLeakGuard::{}", CANARIES[6]),
                verdict: false,
                details: Some(CANARIES[1].into()),
            },
            GuardEvidence {
                guard_name: CANARIES[6].into(),
                verdict: false,
                details: Some(CANARIES[2].into()),
            },
        ]))
    }
}

fn kernel_receipt(db: &std::path::Path) -> ChioReceipt {
    let key = Keypair::from_seed(&[91; 32]);
    let config = KernelConfig {
        keypair: key.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"ordinary-sink-policy"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: 0,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    };
    let conn = Connection::open(db).unwrap();
    conn.execute_batch(
        "CREATE TABLE chio_tool_receipts(seq INTEGER PRIMARY KEY, raw_json TEXT NOT NULL)",
    )
    .unwrap();
    let mut kernel = ChioKernel::new(config);
    kernel
        .set_receipt_store(Box::new(FixtureReceiptStore(Mutex::new(conn))))
        .unwrap();
    kernel.add_guard(Box::new(CanaryGuard));
    kernel.register_tool_server(Box::new(
        BlockingToolServerAdapter::new(Arc::new(CanaryServer)).unwrap(),
    ));
    let subject = Keypair::from_seed(&[92; 32]);
    let cap = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: CANARIES[5].into(),
                    tool_name: CANARIES[4].into(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            300,
        )
        .unwrap();
    let request = ToolCallRequest {
        request_id: "canary-denial".into(),
        capability: cap,
        tool_name: CANARIES[4].into(),
        server_id: CANARIES[5].into(),
        agent_id: subject.public_key().to_hex(),
        arguments: json!({"token": CANARIES[0]}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = kernel
        .evaluate_tool_call_blocking_with_metadata(
            &request,
            Some(json!({
                "actor_subject": CANARIES[3],
                "redaction_status": CANARIES[3],
                "checkpoint_id": CANARIES[3],
                "billing_fixture": {
                    "grant_index": 0, "cost_charged": 0,
                    "currency": CANARIES[9], "budget_remaining": 20,
                    "budget_total": 20, "delegation_depth": 0,
                    "root_budget_holder": CANARIES[8],
                    "payment_reference": CANARIES[7],
                    "settlement_status": "not_applicable",
                    "cost_breakdown": {"private": CANARIES[3]},
                    "attempted_cost": 7
                }
            })),
        )
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(matches!(
        response.receipt.decision,
        Some(Decision::Deny { .. })
    ));
    let Some(Decision::Deny { reason, .. }) = &response.receipt.decision else {
        panic!("guard denial receipt required")
    };
    assert!(
        reason.contains(CANARIES[1]),
        "kernel deny reason must contain its canary"
    );
    assert!(
        response
            .receipt
            .evidence
            .iter()
            .any(|e| e.guard_name.contains(CANARIES[6])),
        "kernel evidence must contain the guard canary"
    );
    assert!(response.receipt.verify_signature().unwrap());
    // Financial metadata is reserved at public invocation ingress. A trusted
    // test producer adds this adversarial signed financial shape to the real
    // guard denial; no production ingress bypass is introduced.
    let mut body = response.receipt.body();
    let metadata = body.metadata.as_mut().unwrap().as_object_mut().unwrap();
    let financial = metadata.remove("billing_fixture").unwrap();
    metadata.insert("financial".into(), financial);
    let receipt = ChioReceipt::sign(body, &key).unwrap();
    Connection::open(db)
        .unwrap()
        .execute(
            "UPDATE chio_tool_receipts SET raw_json=?1 WHERE seq=1",
            params![serde_json::to_string(&receipt).unwrap()],
        )
        .unwrap();
    let raw = serde_json::to_string(&receipt).unwrap();
    for canary in CANARIES {
        assert!(raw.contains(canary), "fixture must retain {canary}");
    }
    receipt
}

struct CaptureCef(Arc<Mutex<Vec<String>>>);

impl Exporter for CaptureCef {
    fn name(&self) -> &str {
        "cef-capture"
    }
    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move {
            let lines = CefExporter::default().format_events(events)?;
            self.0.lock().unwrap().extend(lines);
            Ok(events.len())
        })
    }
}

async fn manager_to_sink(sink: &str) {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("receipts.sqlite3");
    let receipt = kernel_receipt(&db);
    let original = serde_json::to_value(&receipt).unwrap();
    let server = MockServer::start().await;
    let endpoint = match sink {
        "splunk" => "/services/collector/event",
        "elastic" => "/_bulk",
        "datadog" => "/api/v2/logs",
        "pagerduty" => "/v2/enqueue",
        "opsgenie" => "/v2/alerts",
        _ => "/receiver",
    };
    let response = if sink == "elastic" {
        ResponseTemplate::new(200)
            .set_body_json(json!({"errors":false,"items":[{"index":{"status":201}}]}))
    } else if sink == "splunk" {
        ResponseTemplate::new(200).set_body_json(json!({"text":"Success","code":0}))
    } else {
        ResponseTemplate::new(202)
    };
    Mock::given(method("POST"))
        .and(path(endpoint))
        .respond_with(response)
        .expect(if sink == "cef" { 0 } else { 1 })
        .mount(&server)
        .await;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let exporter: Box<dyn Exporter> = match sink {
        "splunk" => Box::new(
            SplunkHecExporter::new_plaintext_for_tests(SplunkConfig {
                endpoint: server.uri(),
                hec_token: "test".into(),
                ..SplunkConfig::default()
            })
            .unwrap(),
        ),
        "elastic" => Box::new(
            ElasticsearchExporter::new_plaintext_for_tests(ElasticConfig {
                endpoint: server.uri(),
                ..ElasticConfig::default()
            })
            .unwrap(),
        ),
        "datadog" => Box::new(
            DatadogExporter::new_with_base_url_for_tests(DatadogConfig::default(), &server.uri())
                .unwrap(),
        ),
        "webhook" => Box::new(
            WebhookExporter::new_plaintext_for_tests(WebhookConfig {
                url: format!("{}{endpoint}", server.uri()),
                ..WebhookConfig::default()
            })
            .unwrap(),
        ),
        "ocsf" | "ocsf_array" => Box::new(
            OcsfExporter::new_plaintext_for_tests(OcsfExporterConfig {
                endpoint: format!("{}{endpoint}", server.uri()),
                payload_format: if sink == "ocsf" {
                    OcsfPayloadFormat::Ndjson
                } else {
                    OcsfPayloadFormat::JsonArray
                },
                ..OcsfExporterConfig::default()
            })
            .unwrap(),
        ),
        "sumo_json" | "sumo_text" | "sumo_kv" => Box::new(
            SumoLogicExporter::new_plaintext_for_tests(SumoLogicConfig {
                http_source_url: format!("{}{endpoint}", server.uri()),
                format: match sink {
                    "sumo_json" => SumoLogicFormat::Json,
                    "sumo_text" => SumoLogicFormat::Text,
                    _ => SumoLogicFormat::KeyValue,
                },
                ..SumoLogicConfig::default()
            })
            .unwrap(),
        ),
        "cef" => Box::new(CaptureCef(Arc::clone(&captured))),
        "pagerduty" | "opsgenie" => {
            let authority = server.address().to_string();
            let contract = HttpEgressContract::permissive_for_tests(&authority);
            let backend: Box<dyn AlertBackend> = if sink == "pagerduty" {
                Box::new(
                    PagerDutyBackend::with_endpoint_and_contract(
                        "routing".into(),
                        server.uri(),
                        contract,
                    )
                    .unwrap(),
                )
            } else {
                Box::new(
                    OpsGenieBackend::with_endpoint_and_contract(
                        "key".into(),
                        server.uri(),
                        contract,
                    )
                    .unwrap(),
                )
            };
            Box::new(
                AlertingExporter::builder(AlertingConfig::default())
                    .with_trusted_kernel_keys(vec![Keypair::from_seed(&[91; 32]).public_key()])
                    .with_backend(backend)
                    .build(),
            )
        }
        _ => panic!("unknown sink {sink}"),
    };
    let mut manager = ExporterManager::new(SiemConfig {
        db_path: db.clone(),
        poll_interval: Duration::from_secs(60),
        max_retries: 0,
        trusted_kernel_keys: BTreeSet::from([Keypair::from_seed(&[91; 32]).public_key().to_hex()]),
        read_context: ReceiptReadContext::local_operator_admin_all(),
        ..SiemConfig::default()
    })
    .unwrap();
    manager.add_exporter(exporter);
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        manager.run(cancel_rx).await;
        manager
    });
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if if sink == "cef" {
                !captured.lock().unwrap().is_empty()
            } else {
                !server.received_requests().await.unwrap().is_empty()
            } {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager must deliver");
    cancel_tx.send(true).unwrap();
    let manager = task.await.unwrap();
    assert_eq!(manager.dlq_len(), 0, "actual exporter must accept payload");
    let wire = if sink == "cef" {
        captured.lock().unwrap()[0].clone()
    } else {
        String::from_utf8(server.received_requests().await.unwrap()[0].body.clone()).unwrap()
    };
    for canary in CANARIES {
        assert!(!wire.contains(canary), "{sink} leaked {canary}");
    }
    assert!(
        wire.contains(&receipt.id),
        "{sink} lost canonical receipt reference"
    );
    assert!(
        wire.contains(&receipt.action.parameter_hash),
        "{sink} lost parameter commitment"
    );
    assert!(wire.contains("payload_included") || wire.contains("payloadIncluded"));
    // The operator-owned original path still returns the exact signed body.
    let conn = Connection::open(&db).unwrap();
    let raw: String = conn
        .query_row(
            "SELECT raw_json FROM chio_tool_receipts WHERE seq=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let retrieved: ChioReceipt = serde_json::from_str(&raw).unwrap();
    assert_eq!(serde_json::to_value(&retrieved).unwrap(), original);
    assert!(retrieved.verify_signature().unwrap());
    assert!(retrieved.action.verify_hash().unwrap());
}

macro_rules! sink_test {
    ($name:ident, $sink:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            manager_to_sink($sink).await;
        }
    };
}

sink_test!(ocsf_manager_omits_every_payload_canary, "ocsf");
sink_test!(ocsf_array_manager_omits_every_payload_canary, "ocsf_array");
sink_test!(splunk_manager_omits_every_payload_canary, "splunk");
sink_test!(elastic_manager_omits_every_payload_canary, "elastic");
sink_test!(datadog_manager_omits_every_payload_canary, "datadog");
sink_test!(sumo_json_manager_omits_every_payload_canary, "sumo_json");
sink_test!(sumo_text_manager_omits_every_payload_canary, "sumo_text");
sink_test!(sumo_kv_manager_omits_every_payload_canary, "sumo_kv");
sink_test!(webhook_manager_omits_every_payload_canary, "webhook");
sink_test!(cef_manager_omits_every_payload_canary, "cef");
sink_test!(pagerduty_manager_omits_identifier_canaries, "pagerduty");
sink_test!(opsgenie_manager_omits_identifier_canaries, "opsgenie");

#[test]
fn public_cached_authority_flags_cannot_promote_original_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let mut receipt = kernel_receipt(&dir.path().join("receipt.sqlite"));
    let key = Keypair::from_seed(&[93; 32]);
    let mut body = receipt.body();
    body.decision = Some(Decision::Allow);
    body.kernel_key = key.public_key();
    receipt = ChioReceipt::sign(body, &key).unwrap();
    let mut event = SiemEvent::from_receipt(receipt);
    event.authorized = true;
    event.authoritative = true;
    event.signer_trusted = true;
    event.signature_valid = true;
    event.result = "Authorized".into();
    event.receipt_kind = CANARIES[3].into();
    let mapped = OcsfExporter::format_events(&[event]);
    assert_eq!(mapped[0]["unmapped"]["chio"]["authorized"], false);
    assert_eq!(mapped[0]["unmapped"]["chio"]["signer_trusted"], false);
    assert_ne!(mapped[0]["status"], "Success");
    assert!(!serde_json::to_string(&mapped)
        .unwrap()
        .contains(CANARIES[3]));
}

#[test]
fn serialized_event_cannot_supply_independent_signer_trust() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = kernel_receipt(&dir.path().join("receipt.sqlite"));
    let key = Keypair::from_seed(&[91; 32]);
    let mut body = receipt.body();
    body.decision = Some(Decision::Allow);
    let receipt = ChioReceipt::sign(body, &key).unwrap();
    let trusted = BTreeSet::from([key.public_key().to_hex()]);
    let event = SiemEvent::from_receipt_with_trusted_kernel_keys(receipt, Some(&trusted));
    assert!(event.is_authorized());
    let mut wire = serde_json::to_value(event).unwrap();
    wire["trusted_kernel_keys"] = json!([key.public_key().to_hex()]);
    wire["trusted_kernel_key"] = serde_json::to_value(key.public_key()).unwrap();
    let replay: SiemEvent = serde_json::from_value(wire).unwrap();
    let mapped = OcsfExporter::format_events(&[replay]);
    assert_eq!(mapped[0]["unmapped"]["chio"]["authorized"], false);
    assert_eq!(mapped[0]["unmapped"]["chio"]["signer_trusted"], false);
}

#[test]
fn replacing_receipt_invalidates_cached_pinned_authority() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = kernel_receipt(&dir.path().join("receipt.sqlite"));
    let trusted_key = Keypair::from_seed(&[91; 32]);
    let mut body = receipt.body();
    body.decision = Some(Decision::Allow);
    let receipt = ChioReceipt::sign(body.clone(), &trusted_key).unwrap();
    let trusted = BTreeSet::from([trusted_key.public_key().to_hex()]);
    let mut event = SiemEvent::from_receipt_with_trusted_kernel_keys(receipt, Some(&trusted));
    assert!(event.is_authorized());
    let foreign = Keypair::from_seed(&[94; 32]);
    body.kernel_key = foreign.public_key();
    event.receipt = ChioReceipt::sign(body, &foreign).unwrap();
    let mapped = OcsfExporter::format_events(&[event]);
    assert_eq!(mapped[0]["unmapped"]["chio"]["authorized"], false);
    assert_eq!(mapped[0]["unmapped"]["chio"]["signer_trusted"], false);
}

#[test]
fn pinned_prevent_allow_and_observations_keep_distinct_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = kernel_receipt(&dir.path().join("receipt.sqlite"));
    let key = Keypair::from_seed(&[91; 32]);
    let trusted = BTreeSet::from([key.public_key().to_hex()]);
    let mut body = receipt.body();
    body.decision = Some(Decision::Allow);
    let allow = SiemEvent::from_receipt_with_trusted_kernel_keys(
        ChioReceipt::sign(body.clone(), &key).unwrap(),
        Some(&trusted),
    );
    let mapped = OcsfExporter::format_events(&[allow]);
    assert_eq!(mapped[0]["status"], "Success");
    assert_eq!(mapped[0]["unmapped"]["chio"]["authorized"], true);
    for semantics in [
        chio_core::receipt::metadata::ReceiptSemanticFields::trace_detect_only(),
        chio_core::receipt::metadata::ReceiptSemanticFields::advisory_only(),
    ] {
        body.decision = None;
        body.receipt_kind = semantics.receipt_kind;
        body.boundary_class = semantics.boundary_class;
        body.observation_outcome = semantics.observation_outcome;
        body.tool_origin = semantics.tool_origin;
        body.trust_level =
            if semantics.receipt_kind == chio_core::receipt::kinds::ReceiptKind::TraceObservation {
                chio_core::receipt::kinds::TrustLevel::Verified
            } else {
                chio_core::receipt::kinds::TrustLevel::Advisory
            };
        let event = SiemEvent::from_receipt_with_trusted_kernel_keys(
            ChioReceipt::sign(body.clone(), &key).unwrap(),
            Some(&trusted),
        );
        let mapped = OcsfExporter::format_events(&[event]);
        assert_ne!(mapped[0]["status"], "Success");
        assert_ne!(mapped[0]["activity_name"], "Grant");
        assert_eq!(mapped[0]["unmapped"]["chio"]["authorized"], false);
        assert_eq!(
            mapped[0]["unmapped"]["chio"]["receipt_kind"],
            semantics.receipt_kind.as_str()
        );
    }
}

#[test]
fn receipt_derived_projection_strings_have_fixed_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = kernel_receipt(&dir.path().join("receipt.sqlite"));
    let key = Keypair::from_seed(&[91; 32]);
    let mut body = receipt.body();
    body.capability_id = CANARIES[0].repeat(1000);
    body.tenant_id = Some(CANARIES[3].repeat(1000));
    body.policy_hash = CANARIES[4].repeat(1000);
    body.content_hash = CANARIES[5].repeat(1000);
    body.action.parameter_hash = CANARIES[7].repeat(1000);
    let event = SiemEvent::from_receipt(ChioReceipt::sign(body, &key).unwrap());
    let mapped = OcsfExporter::format_events(&[event]);
    let wire = serde_json::to_string(&mapped).unwrap();
    assert!(
        wire.len() < 8192,
        "ordinary receipt projection must have a fixed bound"
    );
    for canary in CANARIES {
        assert!(!wire.contains(canary));
    }
    assert_eq!(mapped[0]["unmapped"]["chio"]["parameter_hash_valid"], false);
    assert_eq!(
        mapped[0]["unmapped"]["chio"]["parameter_hash"],
        serde_json::Value::Null
    );
}
