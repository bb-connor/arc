#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use chio_core::capability::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::budget_store::BudgetQuotaKey;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::{
    BudgetStore, ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest,
    ToolServerConnection,
};

/// Builds the tool server a runtime registers when a test replaces the
/// in-process counting server, for example with a transport over a socket.
pub type ToolServerFactory =
    Box<dyn Fn() -> Result<Box<dyn ToolServerConnection>, KernelError> + Send + Sync>;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub const SERVER_ID: &str = "nonce-server";
pub const TOOL_NAME: &str = "mutate";

/// The fixture directory: owned by the process that provisioned it, or
/// borrowed by a child process that attaches to an existing one.
pub enum FixtureDirectory {
    Owned(tempfile::TempDir),
    Borrowed(PathBuf),
}

impl FixtureDirectory {
    pub fn path(&self) -> &Path {
        match self {
            Self::Owned(directory) => directory.path(),
            Self::Borrowed(path) => path,
        }
    }
}

pub struct Fixture {
    pub directory: FixtureDirectory,
    pub signer: Keypair,
    pub agent: Keypair,
    pub invocations: Arc<AtomicUsize>,
    /// When set, every tool invocation signals `started` and then parks until
    /// `release` fires, so a test can drop the evaluation mid-dispatch.
    pub parking: Option<Arc<Parking>>,
    pub nonce_ttl_secs: u64,
    pub require_nonce: bool,
    /// Whether the strict nonce profile is installed at all. A fixture without
    /// it runs the ordinary durable admission path for the same grant.
    pub nonce_enabled: bool,
    /// Replaces the counting server for every runtime the fixture opens.
    pub tool_server: Option<ToolServerFactory>,
}

pub struct Runtime {
    pub kernel: Arc<ChioKernel>,
    pub authority: SqliteAuthorityStore,
}

impl Fixture {
    pub fn new() -> TestResult<Self> {
        Self::with_nonce_ttl(30)
    }

    pub fn with_nonce_ttl(nonce_ttl_secs: u64) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        std::fs::create_dir(directory.path().join("locks"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(
                directory.path().join("locks"),
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        let fixture = Self {
            directory: FixtureDirectory::Owned(directory),
            signer: Keypair::generate(),
            agent: Keypair::generate(),
            invocations: Arc::new(AtomicUsize::new(0)),
            parking: None,
            nonce_ttl_secs,
            require_nonce: true,
            nonce_enabled: true,
            tool_server: None,
        };
        SqliteAuthorityStore::provision(
            fixture.database(),
            fixture.directory.path().join("locks"),
        )?;
        Ok(fixture)
    }

    /// Attach to a directory another process provisioned, with that process's
    /// signer and agent keys, so a child can open the same authority as the
    /// same kernel claimant.
    pub fn attach(
        directory: PathBuf,
        signer_seed_hex: &str,
        agent_seed_hex: &str,
    ) -> TestResult<Self> {
        Ok(Self {
            directory: FixtureDirectory::Borrowed(directory),
            signer: Keypair::from_seed_hex(signer_seed_hex)?,
            agent: Keypair::from_seed_hex(agent_seed_hex)?,
            invocations: Arc::new(AtomicUsize::new(0)),
            parking: None,
            nonce_ttl_secs: 30,
            require_nonce: true,
            nonce_enabled: true,
            tool_server: None,
        })
    }

    pub fn database(&self) -> PathBuf {
        self.directory.path().join("admission.db")
    }

    pub fn open(&self) -> TestResult<Runtime> {
        self.open_with_reconcile(true)
    }

    pub fn open_with_reconcile(&self, reconcile: bool) -> TestResult<Runtime> {
        let authority = SqliteAuthorityStore::open_serving(
            self.database(),
            self.directory.path().join("locks"),
        )?;
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: self.signer.clone(),
            ca_public_keys: vec![self.signer.public_key()],
            max_delegation_depth: 5,
            policy_hash: chio_core::sha256_hex(b"kernel-nonce-lifecycle-policy"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            allow_ephemeral_revocation_store: false,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        });
        kernel.set_receipt_store_handle(Arc::new(SqliteReceiptStore::open(
            self.directory.path().join("receipts.db"),
        )?))?;
        kernel.set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
        if self.nonce_enabled {
            let config = ExecutionNonceConfig {
                nonce_ttl_secs: self.nonce_ttl_secs,
                nonce_store_capacity: 64,
                require_nonce: self.require_nonce,
            };
            kernel.set_execution_nonce_store(
                config.clone(),
                Box::new(InMemoryExecutionNonceStore::from_config(&config)),
            );
        }
        match self.tool_server.as_ref() {
            Some(factory) => kernel.register_tool_server(factory()?),
            None => kernel.register_tool_server(Box::new(CountingServer {
                invocations: self.invocations.clone(),
                parking: self.parking.clone(),
            })),
        }
        if reconcile {
            kernel.reconcile_durable_admission_startup()?;
        }
        Ok(Runtime {
            kernel: Arc::new(kernel),
            authority,
        })
    }

    pub fn request(&self, runtime: &Runtime, id: &str) -> TestResult<ToolCallRequest> {
        self.request_with_constraints(runtime, id, Vec::new())
    }

    pub fn request_with_constraints(
        &self,
        runtime: &Runtime,
        id: &str,
        constraints: Vec<Constraint>,
    ) -> TestResult<ToolCallRequest> {
        let capability = runtime.kernel.issue_capability(
            &self.agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER_ID.into(),
                    tool_name: TOOL_NAME.into(),
                    operations: vec![Operation::Invoke],
                    constraints,
                    max_invocations: Some(1),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            600,
        )?;
        Ok(serde_json::from_value(serde_json::json!({
            "request_id": id, "capability": capability, "tool_name": TOOL_NAME, "server_id": SERVER_ID,
            "agent_id": self.agent.public_key().to_hex(), "arguments": {"record": id}
        }))?)
    }

    pub fn cumulative_constraint() -> Constraint {
        Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".into(),
            },
            approval_budget_id: "collection-budget".into(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        }
    }
}

/// `(operation_id, state)` of the retained operation for a request id.
pub fn operation_state(
    fixture: &Fixture,
    request_id: &str,
) -> TestResult<Option<(String, String)>> {
    let connection = rusqlite::Connection::open(fixture.database())?;
    let mut statement = connection
        .prepare("SELECT operation_id, state FROM admission_operations WHERE request_id = ?1")?;
    let rows = statement
        .query_map([request_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<(String, String)>, _>>()?;
    assert!(rows.len() <= 1, "one operation per request id");
    Ok(rows.into_iter().next())
}

pub fn count_rows(fixture: &Fixture, table: &str) -> TestResult<i64> {
    assert!(matches!(
        table,
        "admission_nonce_preflight_holds"
            | "admission_execution_nonce_issuances"
            | "admission_execution_nonce_reservations"
            | "admission_execution_nonce_transitions"
            | "budget_authorization_holds"
    ));
    Ok(rusqlite::Connection::open(fixture.database())?.query_row(
        &format!("SELECT COUNT(*) FROM {table}"),
        [],
        |row| row.get(0),
    )?)
}

/// `(reserved, captured)` invocation counters of the request's grant quota.
pub fn grant_quota(runtime: &Runtime, request: &ToolCallRequest) -> TestResult<(u32, u32)> {
    let usage = runtime
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(request.capability.id.as_str(), 0))?;
    Ok(usage
        .map(|usage| (usage.reserved_invocations, usage.captured_invocations))
        .unwrap_or((0, 0)))
}

pub fn execute_sql(fixture: &Fixture, sql: &str) -> TestResult {
    rusqlite::Connection::open(fixture.database())?.execute_batch(sql)?;
    Ok(())
}

#[derive(Default)]
pub struct Parking {
    pub started: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}

struct CountingServer {
    invocations: Arc<AtomicUsize>,
    parking: Option<Arc<Parking>>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.into()]
    }

    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        if let Some(parking) = self.parking.as_ref() {
            parking.started.notify_one();
            parking.release.notified().await;
        }
        Ok(arguments)
    }
}
