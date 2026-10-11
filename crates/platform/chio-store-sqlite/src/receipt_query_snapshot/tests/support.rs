//! Fixtures: signed receipts, stores with background checkpoints, archives,
//! out-of-band edits with triggers disabled, and walker contexts.
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core::crypto::Keypair;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::lineage::{ChildRequestReceipt, ChildRequestReceiptBody};
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_kernel::ReceiptStore;
use rusqlite::config::DbConfig;
use rusqlite::Connection;

use super::super::pass::Target;
use super::super::walk::{observe, WalkContext, WalkLimits};
use crate::receipt_store::{BackgroundCheckpointSigner, SqliteReceiptStore};

pub(super) fn keypair() -> Keypair {
    Keypair::from_seed(&[0x42; 32])
}

pub(super) fn other_keypair() -> Keypair {
    Keypair::from_seed(&[0x24; 32])
}

/// Shape of one synthetic tool receipt.
#[derive(Clone)]
pub(super) struct Spec {
    pub(super) id: String,
    pub(super) timestamp: u64,
    pub(super) tenant: Option<String>,
    pub(super) capability: String,
    pub(super) tool_server: String,
    pub(super) tool_name: String,
    pub(super) deny: bool,
    pub(super) cost: Option<(u64, &'static str)>,
    pub(super) subject: Option<String>,
}

impl Spec {
    pub(super) fn new(id: impl Into<String>, timestamp: u64) -> Self {
        Self {
            id: id.into(),
            timestamp,
            tenant: None,
            capability: "cap-1".into(),
            tool_server: "shell".into(),
            tool_name: "bash".into(),
            deny: false,
            cost: None,
            subject: None,
        }
    }

    /// A deterministic variety of tenants, tools, outcomes, costs and subjects.
    pub(super) fn varied(index: u64) -> Self {
        let mut spec = Self::new(format!("rcpt-{index:05}"), 1_700_000_000 + index * 600);
        spec.tenant = match index % 4 {
            0 => None,
            1 | 2 => Some("tenant-a".into()),
            _ => Some("tenant-b".into()),
        };
        spec.capability = format!("cap-{}", index % 5);
        spec.tool_server = if index.is_multiple_of(3) {
            "web"
        } else {
            "shell"
        }
        .into();
        spec.tool_name = if index.is_multiple_of(2) {
            "fetch"
        } else {
            "bash"
        }
        .into();
        spec.deny = index.is_multiple_of(7);
        spec.cost = match index % 6 {
            0 => Some((index * 10, "USD")),
            1 => Some((index * 3, "EUR")),
            _ => None,
        };
        spec.subject = index
            .is_multiple_of(5)
            .then(|| format!("subject-{}", index % 3));
        spec
    }

    pub(super) fn sign(&self, keypair: &Keypair) -> ChioReceipt {
        let mut metadata = serde_json::Map::new();
        if let Some((charged, currency)) = self.cost {
            metadata.insert(
                "financial".into(),
                serde_json::json!({
                    "grant_index": 0u32,
                    "cost_charged": charged,
                    "currency": currency,
                    "budget_remaining": 1000u64,
                    "budget_total": 2000u64,
                    "delegation_depth": 0u32,
                    "root_budget_holder": "root-agent",
                    "settlement_status": "pending"
                }),
            );
        }
        if let Some(subject) = &self.subject {
            metadata.insert(
                "attribution".into(),
                serde_json::json!({
                    "subject_key": subject,
                    "issuer_key": "issuer-1",
                    "delegation_depth": 0u32
                }),
            );
        }
        let decision = if self.deny {
            Decision::Deny {
                reason: "policy".into(),
                guard: "test".into(),
            }
        } else {
            Decision::Allow
        };
        ChioReceipt::sign(
            ChioReceiptBody {
                id: self.id.clone(),
                timestamp: self.timestamp,
                capability_id: self.capability.clone(),
                tool_server: self.tool_server.clone(),
                tool_name: self.tool_name.clone(),
                action: ToolCallAction::from_parameters(serde_json::json!({"receipt": self.id}))
                    .unwrap(),
                decision: Some(decision),
                receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
                boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
                redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: format!("content-{}", self.id),
                policy_hash: "policy-1".into(),
                evidence: Vec::new(),
                metadata: (!metadata.is_empty()).then_some(serde_json::Value::Object(metadata)),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: self.tenant.clone(),
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            keypair,
        )
        .unwrap()
    }
}

pub(super) fn child(id: &str, timestamp: u64, keypair: &Keypair) -> ChildRequestReceipt {
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: id.to_string(),
            timestamp,
            session_id: SessionId::new("sess-snapshot"),
            parent_request_id: RequestId::new("parent-snapshot"),
            request_id: RequestId::new(format!("request-{id}")),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: format!("outcome-{id}"),
            policy_hash: "policy-1".to_string(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        keypair,
    )
    .unwrap()
}

/// A live store, its archive path and the directory that owns both.
pub(super) struct Fixture {
    pub(super) _directory: tempfile::TempDir,
    pub(super) live: PathBuf,
    pub(super) archive: PathBuf,
    pub(super) store: Arc<SqliteReceiptStore>,
}

impl Fixture {
    /// A store that checkpoints every `batch` claim entries.
    pub(super) fn new(batch: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let live = directory.path().join("live.db");
        let archive = directory.path().join("archive.db");
        let store = SqliteReceiptStore::open(&live).unwrap();
        if batch > 0 {
            store
                .enable_background_checkpoints(BackgroundCheckpointSigner {
                    keypair: Arc::new(keypair()),
                    max_batch: batch,
                })
                .unwrap();
        }
        Self {
            _directory: directory,
            live,
            archive,
            store: Arc::new(store),
        }
    }

    pub(super) fn append(&self, spec: &Spec) -> u64 {
        self.store
            .append_chio_receipt_returning_seq(&spec.sign(&keypair()))
            .unwrap()
    }

    pub(super) fn append_varied(&self, range: std::ops::Range<u64>) {
        for index in range {
            self.append(&Spec::varied(index));
        }
        self.flush();
    }

    pub(super) fn append_child(&self, id: &str, timestamp: u64) {
        self.store
            .append_child_receipt(&child(id, timestamp, &keypair()))
            .unwrap();
    }

    pub(super) fn flush(&self) {
        self.store.flush_receipt_writes().unwrap();
    }

    /// Archive every checkpointed receipt older than `cutoff`.
    pub(super) fn rotate(&self, cutoff: u64) -> u64 {
        self.flush();
        self.store
            .archive_receipts_before(cutoff, self.archive.to_str().unwrap())
            .unwrap()
    }

    /// A connection that edits history with triggers disabled, as an
    /// out-of-band writer could.
    pub(super) fn tamper(&self) -> Connection {
        tamper_connection(&self.live)
    }

    pub(super) fn tamper_archive(&self) -> Connection {
        tamper_connection(&self.archive)
    }
}

pub(super) fn tamper_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection.busy_timeout(Duration::from_secs(5)).unwrap();
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
        .unwrap();
    connection
}

pub(super) fn limits() -> WalkLimits {
    WalkLimits {
        step_rows: 3,
        step_bytes: 16 * 1024 * 1024,
        max_receipt_bytes: 128 * 1024 * 1024,
        sql_steps: 50_000_000,
        insert_rows: 2,
        checkpoint_page: 2,
        busy_timeout: Duration::from_millis(50),
    }
}

pub(super) fn context<'a>(
    store: &'a SqliteReceiptStore,
    cancel: &'a Arc<AtomicBool>,
    limits: WalkLimits,
) -> WalkContext<'a> {
    WalkContext {
        store,
        limits,
        cancel,
        fresh_reads: true,
    }
}

pub(super) fn target(ctx: &WalkContext<'_>) -> Target {
    let observation = observe(ctx).unwrap();
    Target {
        head: observation.head,
        checkpoint: observation.checkpoint,
        lineage_rowid: observation.lineage_rowid,
        max_source_seqs: observation.max_source_seqs,
        observed_at_ms: 1,
        observed_at: Instant::now(),
    }
}

/// Replace a stored tool receipt with a different, validly signed one,
/// keeping its source row and claim entry consistent with each other. Receipt
/// ids derive from signed content, so the substitute carries a new id.
pub(super) fn substitute(fixture: &Fixture, original: &ChioReceipt, replacement: &ChioReceipt) {
    let raw = serde_json::to_string(replacement).unwrap();
    let timestamp = i64::try_from(replacement.timestamp).unwrap();
    let tamper = fixture.tamper();
    for table in ["chio_tool_receipts", "claim_receipt_log_entries"] {
        let changed = tamper
            .execute(
                &format!(
                    "UPDATE {table} SET raw_json = ?1, timestamp = ?2, receipt_id = ?3 WHERE receipt_id = ?4"
                ),
                rusqlite::params![raw, timestamp, replacement.id, original.id],
            )
            .unwrap();
        assert_eq!(changed, 1, "{table}");
    }
}

/// The receipt seqs and total of a per-call authenticated query.
pub(super) fn per_call(
    store: &SqliteReceiptStore,
    query: &chio_kernel::ReceiptQuery,
) -> (Vec<u64>, u64, Option<u64>) {
    let result = store.query_receipts(query).unwrap();
    (
        result.receipts.iter().map(|row| row.seq).collect(),
        result.total_count,
        result.next_cursor,
    )
}
