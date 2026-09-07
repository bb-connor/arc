#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, RwLock,
};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, ThresholdApprovalProposal,
};
use chio_core::capability::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_core::{canonical::canonical_json_bytes, crypto::Keypair, sha256_hex};
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::threshold_approval::ThresholdApprovalCollectionPolicy;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ThresholdApprovalCollector,
    ToolCallOutput, ToolCallRequest, ToolServerConnection, Verdict,
};
use chio_store_sqlite::{SqliteApprovalStore, SqliteAuthorityStore, SqliteReceiptStore};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub fn now() -> u64 {
    chio_kernel::fixed_runtime_unix_secs_for_current_thread().unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    })
}

pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub signer: Keypair,
    pub agent: Keypair,
    pub reviewer: Keypair,
    pub policy_hash: String,
    pub requirement: Arc<RwLock<ThresholdApprovalRequirement>>,
    pub invocations: Arc<AtomicUsize>,
    /// Installs the strict execution nonce profile with this issuance lifetime.
    pub nonce_ttl_secs: Option<u64>,
}

pub struct Runtime {
    pub kernel: Arc<ChioKernel>,
    pub authority: SqliteAuthorityStore,
    pub approvals: Arc<SqliteApprovalStore>,
}

impl Fixture {
    pub fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let reviewer = Keypair::generate();
        let policy_hash = sha256_hex(b"kernel-collector-lifecycle-policy");
        let requirement = approval_requirement(&policy_hash, &reviewer, &agent, 300)?;
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
            directory,
            signer,
            agent,
            reviewer,
            policy_hash,
            requirement: Arc::new(RwLock::new(requirement)),
            invocations: Arc::new(AtomicUsize::new(0)),
            nonce_ttl_secs: None,
        };
        SqliteAuthorityStore::provision(
            fixture.database(),
            fixture.directory.path().join("locks"),
        )?;
        Ok(fixture)
    }

    pub fn database(&self) -> PathBuf {
        self.directory.path().join("admission.db")
    }

    /// Replace the approval requirement with the same policy, approvers and
    /// directory and a different proposal timeout, so a parked operation's
    /// deadline can elapse inside a test.
    pub fn set_proposal_timeout(&self, timeout_seconds: u64) -> TestResult {
        let requirement = approval_requirement(
            &self.policy_hash,
            &self.reviewer,
            &self.agent,
            timeout_seconds,
        )?;
        *self
            .requirement
            .write()
            .map_err(|_| "directory lock poisoned")? = requirement;
        Ok(())
    }

    pub fn open(&self) -> TestResult<Runtime> {
        self.open_with_policy(&self.policy_hash, true)
    }

    pub fn open_with_policy(&self, policy_hash: &str, reconcile: bool) -> TestResult<Runtime> {
        let authority = SqliteAuthorityStore::open_serving(
            self.database(),
            self.directory.path().join("locks"),
        )?;
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: self.signer.clone(),
            ca_public_keys: vec![self.signer.public_key()],
            max_delegation_depth: 5,
            policy_hash: policy_hash.into(),
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
        let requirement = self.requirement.clone();
        kernel.set_threshold_approval_requirement_resolver(Arc::new(
            move |_: &str, server: &str, tool: &str| {
                if server != "collector-server" || tool != "mutate" {
                    return Ok(None);
                }
                requirement
                    .read()
                    .map(|value| Some(value.clone()))
                    .map_err(|_| "directory lock poisoned".to_owned())
            },
        ));
        if let Some(nonce_ttl_secs) = self.nonce_ttl_secs {
            let config = ExecutionNonceConfig {
                nonce_ttl_secs,
                nonce_store_capacity: 64,
                require_nonce: true,
            };
            kernel.set_execution_nonce_store(
                config.clone(),
                Box::new(InMemoryExecutionNonceStore::from_config(&config)),
            );
        }
        kernel.register_tool_server(Box::new(CountingServer(self.invocations.clone())));
        if reconcile {
            kernel.reconcile_durable_admission_startup()?;
        }
        Ok(Runtime {
            kernel: Arc::new(kernel),
            authority,
            approvals: Arc::new(SqliteApprovalStore::open(
                self.directory.path().join("approvals.db"),
            )?),
        })
    }

    pub fn request(&self, runtime: &Runtime, id: &str) -> TestResult<ToolCallRequest> {
        let capability = runtime.kernel.issue_capability(
            &self.agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "collector-server".into(),
                    tool_name: "mutate".into(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![Constraint::RequireCumulativeApprovalAbove {
                        threshold: MonetaryAmount {
                            units: 100,
                            currency: "USD".into(),
                        },
                        approval_budget_id: "collection-budget".into(),
                        approval_budget_epoch: 1,
                        cumulative_approval_root_binding: None,
                    }],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            600,
        )?;
        let mut request: ToolCallRequest = serde_json::from_value(serde_json::json!({
            "request_id": id, "capability": capability, "tool_name": "mutate", "server_id": "collector-server",
            "agent_id": self.agent.public_key().to_hex(), "arguments": {"record": "original", "private": "no substitution"}
        }))?;
        request.governed_intent = Some(GovernedTransactionIntent {
            id: format!("intent:{id}"),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            purpose: "bounded collector lifecycle".into(),
            max_amount: Some(MonetaryAmount {
                units: 100,
                currency: "USD".into(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        });
        Ok(request)
    }

    pub fn collector(
        &self,
        runtime: &Runtime,
        separation: bool,
    ) -> TestResult<ThresholdApprovalCollector> {
        Ok(runtime.kernel.create_threshold_approval_collector(
            runtime.approvals.clone(),
            ThresholdApprovalCollectionPolicy::new(self.policy_hash.clone(), separation)?,
        )?)
    }

    pub fn vote(
        &self,
        proposal: &ThresholdApprovalProposal,
        signer: &Keypair,
    ) -> TestResult<GovernedApprovalToken> {
        Ok(GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("vote:{}", signer.public_key().to_hex()),
                approver: signer.public_key(),
                subject: proposal.body.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                request_id: proposal.body.request_id.clone(),
                threshold_proposal_hash: Some(proposal.artifact_digest()?),
                issued_at: now(),
                expires_at: proposal.body.proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            signer,
        )?)
    }
}

pub fn pending(
    runtime: &Runtime,
    request: &ToolCallRequest,
) -> TestResult<ThresholdApprovalProposal> {
    let response = runtime.kernel.evaluate_tool_call_blocking(request)?;
    assert_eq!(
        response.verdict,
        Verdict::PendingApproval,
        "{:?}",
        response.reason
    );
    let Some(ToolCallOutput::Value(value)) = response.output else {
        return Err("missing pending proposal".into());
    };
    Ok(serde_json::from_value(value)?)
}

pub fn collector_bytes(fixture: &Fixture) -> TestResult<Vec<u8>> {
    Ok(
        rusqlite::Connection::open(fixture.directory.path().join("approvals.db"))?.query_row(
            "SELECT record_json FROM chio_threshold_approval_collectors",
            [],
            |row| row.get(0),
        )?,
    )
}

pub fn canonical<T: serde::Serialize>(value: &T) -> TestResult<Vec<u8>> {
    Ok(canonical_json_bytes(value)?)
}

struct CountingServer(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "collector-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

fn approval_requirement(
    policy_hash: &str,
    reviewer: &Keypair,
    agent: &Keypair,
    timeout_seconds: u64,
) -> TestResult<ThresholdApprovalRequirement> {
    Ok(ThresholdApprovalRequirement::new(
        policy_hash.to_owned(),
        1,
        vec![
            ThresholdApproverIdentity {
                identifier: "reviewer".into(),
                public_key: reviewer.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "agent".into(),
                public_key: agent.public_key(),
            },
        ],
        "directory-v1".into(),
        timeout_seconds,
    )?)
}

/// The retained operation state for a request id.
pub fn operation_state(fixture: &Fixture, request_id: &str) -> TestResult<Option<String>> {
    let connection = rusqlite::Connection::open(fixture.database())?;
    let mut statement =
        connection.prepare("SELECT state FROM admission_operations WHERE request_id = ?1")?;
    let states = statement
        .query_map([request_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(states.len() <= 1, "one operation per request id");
    Ok(states.into_iter().next())
}

/// Budget holds that are still open.
pub fn open_holds(fixture: &Fixture) -> TestResult<i64> {
    let connection = rusqlite::Connection::open(fixture.database())?;
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM budget_authorization_holds WHERE disposition = 'open'",
        [],
        |row| row.get(0),
    )?)
}
