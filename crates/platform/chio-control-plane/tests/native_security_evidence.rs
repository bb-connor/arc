use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chio_control_plane::security::{
    AlertOutboxConfig, AttestedCorrelationWriter, NativeActiveResponseFindingAuthority,
    NativeSecurityReceiptSink, SqliteSiemOutbox,
};
use chio_core::crypto::{Ed25519Backend, Keypair};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::kinds::ToolOrigin;
use chio_core::receipt::metadata::ActorRef;
use chio_core::receipt::security::ActiveDefenseReceiptBody;
use chio_kernel::{
    ActiveResponseFindingAuthority, IndexedSecurityEvidenceStore, ReceiptStoreError,
};
use chio_quarantine::{CorrelationOutcome, CorrelationStatus};
use chio_security_types::ports::{
    ActionId, AlertDeliveryQuery, AlertDeliveryStatus, CanonicalBody, Digest32, ErrorCode, EventId,
    ExactSecurityReceiptSink, OpaqueReceiptRef, PortErrorKind, ReceiptAppendRequest, RecordId,
    RuleId, SchedulerHealthPageRequest, SchedulerHealthPort, SecurityAlert, SecurityAlertPort,
    SecurityReceiptSink, TenantId,
};
use chio_security_types::{
    CorrelatedFinding, DetectorGroupBindingEvidence, DetectorHealthEvidence, DetectorHealthKind,
    DetectorWatermarkEvidence,
};
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::SqliteReceiptStore;
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

const OCCURRED_AT_UNIX_MS: u64 = 1_700_000_000_123;

fn digest(byte: u8) -> Digest32 {
    Digest32::new([byte; 32])
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

#[track_caller]
fn rejection<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

fn native_body() -> ActiveDefenseReceiptBody {
    serde_json::from_value(json!({
        "kind": "flow_denial",
        "body": {
            "header": {
                "schema_version": 1,
                "occurred_at_unix_ms": OCCURRED_AT_UNIX_MS,
                "tenant_id": "tenant-native",
                "transition_id": "transition-native-001",
                "prior_receipt_ids": ["prior-native-001"]
            },
            "policy": {
                "policy_version": "policy-native-v1",
                "policy_hash": vec![1_u8; 32]
            },
            "request_hash": vec![2_u8; 32],
            "source_label_hash": vec![3_u8; 32],
            "destination_label_hash": vec![4_u8; 32],
            "guard_evidence_hash": vec![5_u8; 32],
            "denial_code": "flow.clearance_denied",
            "event_id": "event-native-001"
        }
    }))
    .unwrap_or_else(|error| panic!("native receipt fixture: {error}"))
}

fn correlated_finding_body() -> ActiveDefenseReceiptBody {
    serde_json::from_value(json!({
        "kind": "correlated_finding",
        "body": {
            "header": {
                "schema_version": 1,
                "occurred_at_unix_ms": OCCURRED_AT_UNIX_MS,
                "tenant_id": "tenant-native",
                "transition_id": "transition-finding-native-001",
                "prior_receipt_ids": ["source-receipt-native-001"]
            },
            "policy": {
                "policy_version": "policy-native-v1",
                "policy_hash": vec![1_u8; 32]
            },
            "finding_id": "finding-native-001",
            "finding_hash": vec![6_u8; 32],
            "rule_id": "rule-native-001",
            "rule_version_hash": vec![7_u8; 32],
            "group_key_hash": vec![8_u8; 32],
            "ordered_event_ids": ["event-finding-native-001"],
            "ordered_evidence_digests": [vec![9_u8; 32]],
            "ordered_source_receipt_ids": ["source-receipt-native-001"],
            "first_event_time_unix_ms": OCCURRED_AT_UNIX_MS - 10,
            "last_event_time_unix_ms": OCCURRED_AT_UNIX_MS,
            "lineage_seed": "lineage-native-001"
        }
    }))
    .unwrap_or_else(|error| panic!("correlated finding fixture: {error}"))
}

fn receipt_request(body: &ActiveDefenseReceiptBody) -> ReceiptAppendRequest {
    let canonical = chio_core::canonical::canonical_json_bytes(body)
        .unwrap_or_else(|error| panic!("canonical native body: {error}"));
    ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: RecordId::new(body.kind().as_str())
            .unwrap_or_else(|error| panic!("evidence type: {error}")),
        evidence_id: body
            .evidence_id()
            .unwrap_or_else(|error| panic!("evidence id: {error}")),
        canonical_body: CanonicalBody::new(canonical)
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        body_hash: body
            .body_digest()
            .unwrap_or_else(|error| panic!("body digest: {error}")),
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    }
}

enum FixedIndexedLoad {
    Receipt(Box<ChioReceipt>),
    Missing,
    AppendOutage,
    Outage,
}

struct FixedIndexedEvidenceStore {
    load: FixedIndexedLoad,
    append_attempts: AtomicUsize,
}

impl IndexedSecurityEvidenceStore for FixedIndexedEvidenceStore {
    fn ensure_indexed_security_evidence_ready(&self) -> Result<(), ReceiptStoreError> {
        if matches!(&self.load, FixedIndexedLoad::Outage) {
            Err(ReceiptStoreError::Pool("injected outage".to_string()))
        } else {
            Ok(())
        }
    }

    fn append_indexed_security_evidence(
        &self,
        _: &OpaqueReceiptRef,
        receipt: &ChioReceipt,
    ) -> Result<ChioReceipt, ReceiptStoreError> {
        self.append_attempts.fetch_add(1, Ordering::SeqCst);
        if matches!(&self.load, FixedIndexedLoad::AppendOutage) {
            Err(ReceiptStoreError::Pool(
                "injected append outage".to_string(),
            ))
        } else {
            Ok(receipt.clone())
        }
    }

    fn load_indexed_security_evidence(
        &self,
        _: &OpaqueReceiptRef,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        match &self.load {
            FixedIndexedLoad::Receipt(receipt) => Ok(Some(receipt.as_ref().clone())),
            FixedIndexedLoad::Missing | FixedIndexedLoad::AppendOutage => Ok(None),
            FixedIndexedLoad::Outage => Err(ReceiptStoreError::Pool("injected outage".to_string())),
        }
    }
}

#[test]
fn native_sink_signs_appends_idempotently_and_verifies_the_exact_stored_receipt() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let database_path = tempdir.path().join("receipts.sqlite");
    let store = Arc::new(
        SqliteReceiptStore::open(&database_path)
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let sink = NativeSecurityReceiptSink::new(
        Arc::clone(&store) as Arc<dyn IndexedSecurityEvidenceStore>,
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[77_u8; 32]))),
    );
    sink.ensure_receipts_ready()
        .unwrap_or_else(|error| panic!("receipt readiness: {error}"));

    let body = native_body();
    let request = receipt_request(&body);
    let first = sink
        .sign_and_append(&request)
        .unwrap_or_else(|error| panic!("first append: {error}"));
    let second = sink
        .sign_and_append(&request)
        .unwrap_or_else(|error| panic!("idempotent append: {error}"));
    assert_eq!(first, request.evidence_id);
    assert_eq!(second, request.evidence_id);
    assert_ne!(first.as_str(), request.transition_id.as_str());
    let exact = sink
        .load_exact(&request.evidence_id)
        .unwrap_or_else(|error| panic!("load exact native receipt: {error}"))
        .unwrap_or_else(|| panic!("exact native receipt missing"));
    assert_eq!(exact.receipt, request);
    assert!(exact
        .durable_record_hash
        .as_bytes()
        .iter()
        .any(|byte| *byte != 0));
    let exact_replay = sink
        .load_exact(&request.evidence_id)
        .unwrap_or_else(|error| panic!("replay exact native receipt: {error}"))
        .unwrap_or_else(|| panic!("exact native replay missing"));
    assert_eq!(exact, exact_replay);
    assert!(sink
        .load_exact(
            &OpaqueReceiptRef::new("missing-native-evidence")
                .unwrap_or_else(|error| { panic!("missing native evidence identifier: {error}") })
        )
        .unwrap_or_else(|error| panic!("load missing native receipt: {error}"))
        .is_none());

    let mut rebound = request.clone();
    rebound.occurred_at_unix_ms = rebound.occurred_at_unix_ms.saturating_add(1);
    let error = rejection(
        sink.sign_and_append(&rebound),
        "an existing logical evidence ID cannot be rebound",
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);

    let connection = Connection::open(&database_path)
        .unwrap_or_else(|error| panic!("inspect receipt database: {error}"));
    let (count, raw_json): (i64, String) = connection
        .query_row(
            "SELECT COUNT(*), MIN(raw_json) FROM chio_tool_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("inspect stored receipt: {error}"));
    assert_eq!(count, 1);
    let signed: ChioReceipt = serde_json::from_str(&raw_json)
        .unwrap_or_else(|error| panic!("decode signed receipt: {error}"));
    assert!(signed
        .verify_signature()
        .unwrap_or_else(|error| panic!("verify signed receipt: {error}")));
    assert_eq!(signed.tenant_id.as_deref(), Some("tenant-native"));
    assert_eq!(
        signed
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("active_defense_body")),
        Some(&serde_json::to_value(&body).unwrap_or_else(|error| panic!("body value: {error}")))
    );
    assert!(!raw_json.contains("seeded-secret-material"));

    let indexed = store
        .load_indexed_security_evidence(&request.evidence_id)
        .unwrap_or_else(|error| panic!("load indexed evidence: {error}"))
        .unwrap_or_else(|| panic!("indexed evidence missing"));
    assert_eq!(indexed.id, signed.id);
    let reopened = SqliteReceiptStore::open(&database_path)
        .unwrap_or_else(|error| panic!("reopen receipt store: {error}"));
    let reopened_receipt = reopened
        .load_indexed_security_evidence(&request.evidence_id)
        .unwrap_or_else(|error| panic!("load reopened indexed evidence: {error}"))
        .unwrap_or_else(|| panic!("reopened indexed evidence missing"));
    assert_eq!(reopened_receipt.id, signed.id);
}

#[test]
fn indexed_evidence_rejects_conflicting_logical_mapping() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteReceiptStore::open(tempdir.path().join("receipts.sqlite"))
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let signer = Keypair::from_seed(&[79_u8; 32]);
    let sink = NativeSecurityReceiptSink::new(
        store.clone() as Arc<dyn IndexedSecurityEvidenceStore>,
        Arc::new(Ed25519Backend::new(signer.clone())),
    );
    let body = native_body();
    let request = receipt_request(&body);
    sink.sign_and_append(&request)
        .unwrap_or_else(|error| panic!("append indexed receipt: {error}"));
    let persisted = store
        .load_indexed_security_evidence(&request.evidence_id)
        .unwrap_or_else(|error| panic!("load indexed receipt: {error}"))
        .unwrap_or_else(|| panic!("indexed receipt missing"));
    let mut conflicting_body = persisted.body();
    conflicting_body.id.clear();
    conflicting_body.actor_chain.push(ActorRef {
        actor_id: "different-internal-actor".to_string(),
        actor_kind: Some("system".to_string()),
    });
    let conflicting = ChioReceipt::sign(conflicting_body, &signer)
        .unwrap_or_else(|error| panic!("sign conflicting receipt: {error}"));
    let error = rejection(
        store.append_indexed_security_evidence(&request.evidence_id, &conflicting),
        "logical evidence must not be rebound",
    );
    assert!(error.to_string().contains("different receipt"));
    let connection = Connection::open(tempdir.path().join("receipts.sqlite"))
        .unwrap_or_else(|error| panic!("inspect receipt database: {error}"));
    let receipt_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("count receipts after conflict: {error}"));
    assert_eq!(receipt_count, 1);
}

#[test]
fn native_finding_authority_loads_only_trusted_indexed_correlated_findings() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteReceiptStore::open(tempdir.path().join("receipts.sqlite"))
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let signer = Keypair::from_seed(&[80_u8; 32]);
    let sink = NativeSecurityReceiptSink::new(
        store.clone() as Arc<dyn IndexedSecurityEvidenceStore>,
        Arc::new(Ed25519Backend::new(signer.clone())),
    );
    let body = correlated_finding_body();
    let request = receipt_request(&body);
    sink.sign_and_append(&request)
        .unwrap_or_else(|error| panic!("append correlated finding: {error}"));

    let authority = NativeActiveResponseFindingAuthority::new(
        store.clone() as Arc<dyn IndexedSecurityEvidenceStore>,
        vec![signer.public_key()],
    )
    .unwrap_or_else(|error| panic!("finding authority: {error}"));
    authority
        .ensure_ready()
        .unwrap_or_else(|error| panic!("finding authority readiness: {error}"));
    let evidence = authority
        .load_correlated_finding(&request.evidence_id)
        .unwrap_or_else(|error| panic!("load correlated finding: {error}"))
        .unwrap_or_else(|| panic!("correlated finding missing"));
    assert_eq!(
        evidence.body(),
        match &body {
            ActiveDefenseReceiptBody::CorrelatedFinding(body) => body,
            _ => panic!("fixture is not a correlated finding"),
        }
    );
    let unknown = OpaqueReceiptRef::new("active_defense_evidence_unknown")
        .unwrap_or_else(|error| panic!("unknown evidence id: {error}"));
    assert!(authority
        .load_correlated_finding(&unknown)
        .unwrap_or_else(|error| panic!("unknown lookup: {error}"))
        .is_none());

    let wrong_kind = native_body();
    let wrong_kind_request = receipt_request(&wrong_kind);
    sink.sign_and_append(&wrong_kind_request)
        .unwrap_or_else(|error| panic!("append wrong-kind evidence: {error}"));
    assert!(authority
        .load_correlated_finding(&wrong_kind_request.evidence_id)
        .is_err());

    let untrusted = NativeActiveResponseFindingAuthority::new(
        store as Arc<dyn IndexedSecurityEvidenceStore>,
        vec![Keypair::generate().public_key()],
    )
    .unwrap_or_else(|error| panic!("untrusted authority: {error}"));
    assert!(untrusted
        .load_correlated_finding(&request.evidence_id)
        .is_err());
}

#[test]
fn native_finding_authority_restarts_from_the_durable_index_without_a_caller_body() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let database_path = tempdir.path().join("restart-findings.sqlite");
    let signer = Keypair::from_seed(&[79_u8; 32]);
    let evidence_id = {
        let store = Arc::new(
            SqliteReceiptStore::open(&database_path)
                .unwrap_or_else(|error| panic!("initial receipt store: {error}")),
        );
        let sink = NativeSecurityReceiptSink::new(
            store as Arc<dyn IndexedSecurityEvidenceStore>,
            Arc::new(Ed25519Backend::new(signer.clone())),
        );
        let request = receipt_request(&correlated_finding_body());
        sink.sign_and_append(&request)
            .unwrap_or_else(|error| panic!("append restart finding: {error}"));
        request.evidence_id
    };

    let reopened = Arc::new(
        SqliteReceiptStore::open(&database_path)
            .unwrap_or_else(|error| panic!("reopened receipt store: {error}")),
    );
    let authority = NativeActiveResponseFindingAuthority::new(
        reopened as Arc<dyn IndexedSecurityEvidenceStore>,
        vec![signer.public_key()],
    )
    .unwrap_or_else(|error| panic!("restarted finding authority: {error}"));
    let reloaded = authority
        .load_correlated_finding(&evidence_id)
        .unwrap_or_else(|error| panic!("reload finding by durable evidence id: {error}"))
        .unwrap_or_else(|| panic!("durable finding missing after restart"));
    assert_eq!(reloaded.evidence_id(), &evidence_id);
    assert_eq!(reloaded.body().finding_id.as_str(), "finding-native-001");
    assert_eq!(reloaded.body().finding_hash, digest(6));
}

fn correlated_finding() -> CorrelatedFinding {
    serde_json::from_value(json!({
        "finding_id": "finding-writer-001",
        "tenant_id": "tenant-native",
        "rule_id": "rule-writer-001",
        "rule_version_hash": vec![7_u8; 32],
        "policy_version": "policy-native-v1",
        "group_key_hash": vec![8_u8; 32],
        "ordered_event_ids": ["event-writer-001", "event-writer-002"],
        "ordered_evidence_digests": [vec![9_u8; 32], vec![10_u8; 32]],
        "ordered_source_receipt_ids": [
            "source-receipt-native-002",
            "source-receipt-native-001"
        ],
        "first_event_time_unix_ms": OCCURRED_AT_UNIX_MS - 10,
        "last_event_time_unix_ms": OCCURRED_AT_UNIX_MS,
        "lineage_seed": "lineage-writer-001"
    }))
    .unwrap_or_else(|error| panic!("correlated finding: {error}"))
}

fn detector_health_outcome() -> CorrelationOutcome {
    CorrelationOutcome {
        status: CorrelationStatus::Suppressed,
        findings: Vec::new(),
        detector_health: vec![DetectorHealthEvidence {
            tenant_id: TenantId::new("tenant-native")
                .unwrap_or_else(|error| panic!("tenant id: {error}")),
            policy_version: record("policy-native-v1"),
            rule_id: RuleId::new("rule-writer-001")
                .unwrap_or_else(|error| panic!("rule id: {error}")),
            rule_version_hash: digest(7),
            group_binding: DetectorGroupBindingEvidence::Resolved {
                group_key_hash: digest(8),
            },
            kind: DetectorHealthKind::StoreUnavailable,
            event_id: EventId::new("event-health-001")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            observed_at_unix_ms: OCCURRED_AT_UNIX_MS,
            watermark: DetectorWatermarkEvidence::Committed {
                unix_ms: OCCURRED_AT_UNIX_MS.saturating_sub(1),
            },
        }],
        automatic_response_suppressed: true,
        watermark_unix_ms: OCCURRED_AT_UNIX_MS.saturating_sub(1),
    }
}

#[test]
fn detector_health_evidence_is_signed_persisted_and_append_failure_propagates() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let database_path = tempdir.path().join("detector-health.sqlite");
    let store = Arc::new(
        SqliteReceiptStore::open(&database_path)
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let signer = Keypair::from_seed(&[84_u8; 32]);
    let indexed_store = store.clone() as Arc<dyn IndexedSecurityEvidenceStore>;
    let sink = Arc::new(NativeSecurityReceiptSink::new(
        Arc::clone(&indexed_store),
        Arc::new(Ed25519Backend::new(signer.clone())),
    ));
    let authority = Arc::new(
        NativeActiveResponseFindingAuthority::new(indexed_store, vec![signer.public_key()])
            .unwrap_or_else(|error| panic!("finding authority: {error}")),
    );
    let writer = AttestedCorrelationWriter::new(
        sink,
        authority,
        BTreeMap::from([(
            RecordId::new("policy-native-v1")
                .unwrap_or_else(|error| panic!("policy version: {error}")),
            digest(1),
        )]),
    );
    let outcome = detector_health_outcome();
    let findings = writer
        .attest_outcome(&outcome)
        .unwrap_or_else(|error| panic!("attest detector health: {error}"));
    assert!(findings.is_empty());

    let connection = Connection::open(&database_path)
        .unwrap_or_else(|error| panic!("inspect detector health database: {error}"));
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("count detector health receipts: {error}"));
    assert_eq!(count, 1);
    let raw_json: String = connection
        .query_row(
            "SELECT raw_json FROM chio_tool_receipts ORDER BY seq ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("load detector health receipt: {error}"));
    let receipt: ChioReceipt = serde_json::from_str(&raw_json)
        .unwrap_or_else(|error| panic!("decode detector health receipt: {error}"));
    assert!(receipt
        .verify_signature()
        .unwrap_or_else(|error| panic!("verify detector health receipt: {error}")));
    assert_eq!(receipt.kernel_key, signer.public_key());
    let body: ActiveDefenseReceiptBody = serde_json::from_value(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("active_defense_body"))
            .cloned()
            .unwrap_or_else(|| panic!("detector health body missing")),
    )
    .unwrap_or_else(|error| panic!("decode detector health body: {error}"));
    let ActiveDefenseReceiptBody::DetectorHealth(body) = body else {
        panic!("persisted evidence is not detector health");
    };
    assert_eq!(body.rule_id, outcome.detector_health[0].rule_id);
    assert_eq!(body.event_id, outcome.detector_health[0].event_id);
    assert_eq!(body.health_kind, outcome.detector_health[0].kind);
    assert_eq!(body.header.tenant_id, outcome.detector_health[0].tenant_id);
    assert_eq!(
        body.header.occurred_at_unix_ms,
        outcome.detector_health[0].observed_at_unix_ms
    );
    assert_eq!(body.policy.policy_version, record("policy-native-v1"));
    assert_eq!(body.policy.policy_hash, digest(1));
    assert_eq!(body.group_binding, outcome.detector_health[0].group_binding);
    assert_eq!(body.watermark, outcome.detector_health[0].watermark);
    assert_eq!(
        body.rule_version_hash,
        outcome.detector_health[0].rule_version_hash
    );
    assert!(body.evidence_hash.as_bytes().iter().any(|byte| *byte != 0));

    let failing_store = Arc::new(FixedIndexedEvidenceStore {
        load: FixedIndexedLoad::AppendOutage,
        append_attempts: AtomicUsize::new(0),
    });
    let failing_indexed_store = Arc::clone(&failing_store) as Arc<dyn IndexedSecurityEvidenceStore>;
    let failing_sink = Arc::new(NativeSecurityReceiptSink::new(
        Arc::clone(&failing_indexed_store),
        Arc::new(Ed25519Backend::new(signer.clone())),
    ));
    let failing_authority = Arc::new(
        NativeActiveResponseFindingAuthority::new(failing_indexed_store, vec![signer.public_key()])
            .unwrap_or_else(|error| panic!("failing finding authority: {error}")),
    );
    let failing_writer = AttestedCorrelationWriter::new(
        failing_sink,
        failing_authority,
        BTreeMap::from([(
            RecordId::new("policy-native-v1")
                .unwrap_or_else(|error| panic!("policy version: {error}")),
            digest(1),
        )]),
    );
    let error = rejection(
        failing_writer.attest_outcome(&outcome),
        "detector health append failure must propagate",
    );
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert_eq!(failing_store.append_attempts.load(Ordering::SeqCst), 1);
}

#[test]
fn attested_correlation_writer_publishes_only_read_back_authoritative_evidence() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let database_path = tempdir.path().join("correlated-findings.sqlite");
    let store = Arc::new(
        SqliteReceiptStore::open(&database_path)
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let signer = Keypair::from_seed(&[82_u8; 32]);
    let indexed_store = store.clone() as Arc<dyn IndexedSecurityEvidenceStore>;
    let sink = Arc::new(NativeSecurityReceiptSink::new(
        Arc::clone(&indexed_store),
        Arc::new(Ed25519Backend::new(signer.clone())),
    ));
    let authority = Arc::new(
        NativeActiveResponseFindingAuthority::new(indexed_store, vec![signer.public_key()])
            .unwrap_or_else(|error| panic!("finding authority: {error}")),
    );
    let finding = correlated_finding();
    let writer = AttestedCorrelationWriter::new(
        sink,
        authority,
        BTreeMap::from([(finding.policy_version.clone(), digest(1))]),
    );
    let outcome = CorrelationOutcome {
        status: CorrelationStatus::Matched,
        findings: vec![finding.clone()],
        detector_health: Vec::new(),
        automatic_response_suppressed: false,
        watermark_unix_ms: OCCURRED_AT_UNIX_MS,
    };

    let authoritative = writer
        .attest_outcome(&outcome)
        .unwrap_or_else(|error| panic!("attest correlated finding: {error}"));
    assert_eq!(authoritative.len(), 1);
    let body = authoritative[0].body();
    assert_eq!(body.finding_id, finding.finding_id);
    assert_eq!(body.rule_id, finding.rule_id);
    assert_eq!(body.rule_version_hash, finding.rule_version_hash);
    assert_eq!(body.group_key_hash, finding.group_key_hash);
    assert_eq!(body.ordered_event_ids, finding.ordered_event_ids);
    assert_eq!(
        body.ordered_evidence_digests,
        finding.ordered_evidence_digests
    );
    assert_eq!(
        body.ordered_source_receipt_ids,
        finding.ordered_source_receipt_ids
    );
    assert_eq!(
        body.header.prior_receipt_ids.as_slice(),
        [
            OpaqueReceiptRef::new("source-receipt-native-001")
                .unwrap_or_else(|error| panic!("source receipt: {error}")),
            OpaqueReceiptRef::new("source-receipt-native-002")
                .unwrap_or_else(|error| panic!("source receipt: {error}")),
        ]
    );
    let mut suppressed = outcome;
    suppressed.status = CorrelationStatus::Suppressed;
    suppressed.automatic_response_suppressed = true;
    assert!(writer
        .attest_outcome(&suppressed)
        .unwrap_or_else(|error| panic!("attest suppressed finding: {error}"))
        .is_empty());
    let persisted = store
        .load_indexed_security_evidence(authoritative[0].evidence_id())
        .unwrap_or_else(|error| panic!("load indexed finding: {error}"))
        .unwrap_or_else(|| panic!("indexed finding is missing"));
    assert!(persisted
        .verify_signature()
        .unwrap_or_else(|error| panic!("verify finding signature: {error}")));
}

#[test]
fn attested_correlation_writer_fails_closed_before_append_without_exact_policy_hash() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let database_path = tempdir.path().join("missing-policy.sqlite");
    let store = Arc::new(
        SqliteReceiptStore::open(&database_path)
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let signer = Keypair::from_seed(&[83_u8; 32]);
    let indexed_store = store.clone() as Arc<dyn IndexedSecurityEvidenceStore>;
    let sink = Arc::new(NativeSecurityReceiptSink::new(
        Arc::clone(&indexed_store),
        Arc::new(Ed25519Backend::new(signer.clone())),
    ));
    let authority = Arc::new(
        NativeActiveResponseFindingAuthority::new(indexed_store, vec![signer.public_key()])
            .unwrap_or_else(|error| panic!("finding authority: {error}")),
    );
    let writer = AttestedCorrelationWriter::new(sink, authority, BTreeMap::new());
    let outcome = CorrelationOutcome {
        status: CorrelationStatus::Matched,
        findings: vec![correlated_finding()],
        detector_health: Vec::new(),
        automatic_response_suppressed: false,
        watermark_unix_ms: OCCURRED_AT_UNIX_MS,
    };

    let error = rejection(
        writer.attest_outcome(&outcome),
        "missing policy hash must fail closed",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    let connection = Connection::open(database_path)
        .unwrap_or_else(|error| panic!("inspect receipt database: {error}"));
    let receipt_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("count receipts: {error}"));
    assert_eq!(receipt_count, 0);
}

#[test]
fn native_finding_authority_fails_closed_on_tampering_mismatch_and_outage() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteReceiptStore::open(tempdir.path().join("receipts.sqlite"))
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let signer = Keypair::from_seed(&[81_u8; 32]);
    let sink = NativeSecurityReceiptSink::new(
        store.clone() as Arc<dyn IndexedSecurityEvidenceStore>,
        Arc::new(Ed25519Backend::new(signer.clone())),
    );
    let body = correlated_finding_body();
    let request = receipt_request(&body);
    sink.sign_and_append(&request)
        .unwrap_or_else(|error| panic!("append finding: {error}"));
    let persisted = store
        .load_indexed_security_evidence(&request.evidence_id)
        .unwrap_or_else(|error| panic!("load finding receipt: {error}"))
        .unwrap_or_else(|| panic!("finding receipt missing"));

    let authority_for = |receipt: ChioReceipt| {
        NativeActiveResponseFindingAuthority::new(
            Arc::new(FixedIndexedEvidenceStore {
                load: FixedIndexedLoad::Receipt(Box::new(receipt)),
                append_attempts: AtomicUsize::new(0),
            }) as Arc<dyn IndexedSecurityEvidenceStore>,
            vec![signer.public_key()],
        )
        .unwrap_or_else(|error| panic!("fixed finding authority: {error}"))
    };

    let mut signature_tampered = persisted.clone();
    signature_tampered.tool_name = "correlated_finding_tampered".to_string();
    assert!(authority_for(signature_tampered)
        .load_correlated_finding(&request.evidence_id)
        .is_err());

    let mut malformed_body = persisted.body();
    malformed_body.id.clear();
    malformed_body
        .metadata
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .unwrap_or_else(|| panic!("active-defense metadata is not an object"))
        .insert(
            "active_defense_body".to_string(),
            json!({"malformed": true}),
        );
    let malformed = ChioReceipt::sign(malformed_body, &signer)
        .unwrap_or_else(|error| panic!("sign malformed body receipt: {error}"));
    assert!(authority_for(malformed)
        .load_correlated_finding(&request.evidence_id)
        .is_err());

    let mut external_origin_body = persisted.body();
    external_origin_body.id.clear();
    external_origin_body.tool_origin = ToolOrigin::HostExecutedProviderReported;
    let external_origin = ChioReceipt::sign(external_origin_body, &signer)
        .unwrap_or_else(|error| panic!("sign external-origin receipt: {error}"));
    assert!(authority_for(external_origin)
        .load_correlated_finding(&request.evidence_id)
        .is_err());

    let wrong_evidence_id = OpaqueReceiptRef::new("active_defense_evidence_wrong_binding")
        .unwrap_or_else(|error| panic!("wrong evidence id: {error}"));
    assert!(authority_for(persisted)
        .load_correlated_finding(&wrong_evidence_id)
        .is_err());

    let missing = NativeActiveResponseFindingAuthority::new(
        Arc::new(FixedIndexedEvidenceStore {
            load: FixedIndexedLoad::Missing,
            append_attempts: AtomicUsize::new(0),
        }) as Arc<dyn IndexedSecurityEvidenceStore>,
        vec![signer.public_key()],
    )
    .unwrap_or_else(|error| panic!("missing authority: {error}"));
    assert!(missing
        .load_correlated_finding(&request.evidence_id)
        .unwrap_or_else(|error| panic!("missing lookup: {error}"))
        .is_none());

    let outage = NativeActiveResponseFindingAuthority::new(
        Arc::new(FixedIndexedEvidenceStore {
            load: FixedIndexedLoad::Outage,
            append_attempts: AtomicUsize::new(0),
        }) as Arc<dyn IndexedSecurityEvidenceStore>,
        vec![signer.public_key()],
    )
    .unwrap_or_else(|error| panic!("outage authority: {error}"));
    assert!(outage.ensure_ready().is_err());
    assert!(outage
        .load_correlated_finding(&request.evidence_id)
        .is_err());
}

#[test]
fn native_sink_rejects_every_claim_that_disagrees_with_the_closed_body() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteReceiptStore::open(tempdir.path().join("receipts.sqlite"))
            .unwrap_or_else(|error| panic!("receipt store: {error}")),
    );
    let sink = NativeSecurityReceiptSink::new(
        store as Arc<dyn IndexedSecurityEvidenceStore>,
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[78_u8; 32]))),
    );
    let body = native_body();
    let base = receipt_request(&body);

    let mut cases = Vec::new();
    let mut wrong_transition = base.clone();
    wrong_transition.transition_id = RecordId::new("transition-native-other")
        .unwrap_or_else(|error| panic!("transition: {error}"));
    cases.push(wrong_transition);
    let mut wrong_time = base.clone();
    wrong_time.occurred_at_unix_ms = wrong_time.occurred_at_unix_ms.saturating_add(1);
    cases.push(wrong_time);
    let mut wrong_digest = base.clone();
    wrong_digest.body_hash = digest(99);
    cases.push(wrong_digest);
    let mut wrong_evidence = base;
    wrong_evidence.evidence_id = OpaqueReceiptRef::new("active_defense_evidence_wrong")
        .unwrap_or_else(|error| panic!("evidence: {error}"));
    cases.push(wrong_evidence);

    for request in cases {
        let error = rejection(
            sink.sign_and_append(&request),
            "mismatched receipt claim must fail closed",
        );
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
}

#[derive(Default)]
struct AckLossBackend {
    fail_first_after_recording: AtomicBool,
    alerts: Mutex<Vec<Alert>>,
}

impl AckLossBackend {
    fn with_first_ack_loss() -> Self {
        Self {
            fail_first_after_recording: AtomicBool::new(true),
            alerts: Mutex::new(Vec::new()),
        }
    }

    fn alerts(&self) -> Vec<Alert> {
        self.alerts
            .lock()
            .unwrap_or_else(|_| panic!("alert mutex poisoned"))
            .clone()
    }
}

impl AlertBackend for AckLossBackend {
    fn name(&self) -> &str {
        "ack-loss-backend"
    }

    fn dispatch<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
    {
        let alert = alert.clone();
        Box::pin(async move {
            self.alerts
                .lock()
                .map_err(|_| ExportError::HttpError("recording lock unavailable".to_owned()))?
                .push(alert);
            if self
                .fail_first_after_recording
                .swap(false, Ordering::SeqCst)
            {
                return Err(ExportError::HttpError(
                    "simulated response acknowledgement loss".to_owned(),
                ));
            }
            Ok(())
        })
    }
}

fn security_alert() -> SecurityAlert {
    SecurityAlert {
        tenant_id: TenantId::new("tenant-alert").unwrap_or_else(|error| panic!("tenant: {error}")),
        event_id: RecordId::new("event-alert-001").unwrap_or_else(|error| panic!("event: {error}")),
        idempotency_key: RecordId::new("alert-command-001")
            .unwrap_or_else(|error| panic!("idempotency: {error}")),
        occurred_at_unix_ms: 1_000,
        alert_type: RecordId::new("response_rollback_partial")
            .unwrap_or_else(|error| panic!("alert type: {error}")),
        finding_id_hash: digest(41),
        action_id_hash: Some(digest(42)),
        evidence_hash: digest(43),
    }
}

#[tokio::test]
async fn sqlite_siem_outbox_recovers_ack_loss_with_the_same_dedup_key_and_durable_status() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let database_path = tempdir.path().join("alerts.sqlite");
    let backend = Arc::new(AckLossBackend::with_first_ack_loss());
    let config = AlertOutboxConfig {
        base_retry_ms: 10,
        max_retry_ms: 100,
        max_attempts: 3,
    };
    let outbox = SqliteSiemOutbox::open(
        &database_path,
        vec![Arc::clone(&backend) as Arc<dyn AlertBackend>],
        config,
    )
    .unwrap_or_else(|error| panic!("outbox: {error}"));
    outbox
        .ensure_alerts_ready()
        .unwrap_or_else(|error| panic!("outbox readiness: {error}"));

    let alert = security_alert();
    assert_eq!(
        outbox
            .page(&alert)
            .unwrap_or_else(|error| panic!("enqueue: {error}")),
        AlertDeliveryStatus::Pending {
            attempts: 0,
            next_attempt_at_unix_ms: 1_000,
        }
    );
    assert!(outbox.deliver_due(1_000, 1).await.is_err());
    assert_eq!(
        SecurityAlertPort::load_delivery(
            &outbox,
            &AlertDeliveryQuery {
                alert: alert.clone(),
            },
        )
        .unwrap_or_else(|error| panic!("load pending: {error}")),
        Some(AlertDeliveryStatus::Pending {
            attempts: 1,
            next_attempt_at_unix_ms: 1_010,
        })
    );

    let report = outbox
        .deliver_due(1_010, 1)
        .await
        .unwrap_or_else(|error| panic!("retry delivery: {error}"));
    assert_eq!(report.delivered, 1);
    let delivered = AlertDeliveryStatus::Delivered {
        attempts: 2,
        delivered_at_unix_ms: 1_010,
    };
    assert_eq!(
        SecurityAlertPort::load_delivery(
            &outbox,
            &AlertDeliveryQuery {
                alert: alert.clone(),
            },
        )
        .unwrap_or_else(|error| panic!("load delivered: {error}")),
        Some(delivered)
    );
    let dispatched = backend.alerts();
    assert_eq!(dispatched.len(), 2);
    assert_eq!(dispatched[0].dedup_key, alert.idempotency_key.as_str());
    assert_eq!(dispatched[1].dedup_key, dispatched[0].dedup_key);
    assert!(!dispatched[0]
        .receipt_json
        .to_string()
        .contains("seeded-secret-material"));

    drop(outbox);
    let reopened = SqliteSiemOutbox::open(
        &database_path,
        vec![backend as Arc<dyn AlertBackend>],
        config,
    )
    .unwrap_or_else(|error| panic!("reopen outbox: {error}"));
    assert_eq!(
        reopened
            .page(&alert)
            .unwrap_or_else(|error| panic!("idempotent delivered page: {error}")),
        delivered
    );
    assert_eq!(
        reopened
            .deliver_due(2_000, 10)
            .await
            .unwrap_or_else(|error| panic!("empty delivery: {error}"))
            .delivered,
        0
    );
}

#[test]
fn outbox_rejects_idempotency_rebinding_and_scheduler_wrapper_mismatch() {
    let tempdir = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let backend = Arc::new(AckLossBackend::default());
    let outbox = SqliteSiemOutbox::open(
        tempdir.path().join("alerts.sqlite"),
        vec![backend as Arc<dyn AlertBackend>],
        AlertOutboxConfig::default(),
    )
    .unwrap_or_else(|error| panic!("outbox: {error}"));
    let alert = security_alert();
    SecurityAlertPort::page(&outbox, &alert).unwrap_or_else(|error| panic!("enqueue: {error}"));

    let mut rebound = alert.clone();
    rebound.evidence_hash = digest(44);
    let error = rejection(
        SecurityAlertPort::page(&outbox, &rebound),
        "same idempotency key with a different alert must conflict",
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);

    let page = SchedulerHealthPageRequest {
        event_id: alert.event_id.clone(),
        idempotency_key: alert.idempotency_key.clone(),
        occurred_at_unix_ms: alert.occurred_at_unix_ms,
        tenant_id: alert.tenant_id.clone(),
        action_id: ActionId::new("action-alert").unwrap_or_else(|error| panic!("action: {error}")),
        first_failure_at_unix_ms: alert.occurred_at_unix_ms,
        attempts: 1,
        scheduler_fencing_token: 1,
        error_code: ErrorCode::new("response.scheduler_unavailable")
            .unwrap_or_else(|error| panic!("error code: {error}")),
        alert: alert.clone(),
    };
    let status = SchedulerHealthPort::page_once(&outbox, &page)
        .unwrap_or_else(|error| panic!("exact scheduler page: {error}"));
    assert_eq!(
        SchedulerHealthPort::load_delivery(
            &outbox,
            &AlertDeliveryQuery {
                alert: alert.clone(),
            },
        )
        .unwrap_or_else(|error| panic!("scheduler query: {error}")),
        Some(status)
    );

    let mut mismatched = page;
    mismatched.occurred_at_unix_ms = mismatched.occurred_at_unix_ms.saturating_add(1);
    let error = rejection(
        SchedulerHealthPort::page_once(&outbox, &mismatched),
        "scheduler wrapper mismatch must fail closed",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}
