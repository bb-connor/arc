//! Legacy governed active-response admission from a federation peer pinned
//! through a real handshake whose negotiated profile advertises the governed
//! feature, against the published runtime and real V1 and replay stores.
use super::*;
use chio_core::capability::features::{CapabilityNegotiation, GOVERNED_ACTIVE_RESPONSE_PLAN};
use chio_federation::trust_establishment::{
    FederationPeer, KernelTrustExchange, PeerHandshakeEnvelope,
};

const LOCAL_KERNEL_ID: &str = "kernel.legacy-local";
const REMOTE_KERNEL_ID: &str = "kernel.legacy-remote";

struct FederatedLegacyRuntime {
    _directory: tempfile::TempDir,
    databases: Vec<PathBuf>,
    kernel: ChioKernel,
    authority: chio_store_sqlite::SqliteAuthorityStore,
    executor: Arc<RealAdapterRecordingExecutor>,
    effects: Arc<RealAdapterEffects>,
    operator_authority: Keypair,
    requirement: ThresholdApprovalRequirement,
    approvers: [Keypair; 2],
    subject: Keypair,
    now: u64,
}

impl FederatedLegacyRuntime {
    fn new() -> Self {
        let base = real_adapter_fixture();
        let response_plan = base.native_request().response_plan().clone();
        let RealAdapterFixture {
            _directory,
            paths,
            operator_authority,
            executor_signer,
            submission_authority,
            threshold_policy_authority,
            finding,
            clock,
            runtime,
            ..
        } = base;
        drop(runtime);
        let approvers = [Keypair::generate(), Keypair::generate()];
        let requirement = ThresholdApprovalRequirement::new(
            hex::encode(response_plan.policy_hash.as_bytes()),
            2,
            vec![
                ThresholdApproverIdentity {
                    identifier: "alice".into(),
                    public_key: approvers[0].public_key(),
                },
                ThresholdApproverIdentity {
                    identifier: "bob".into(),
                    public_key: approvers[1].public_key(),
                },
            ],
            "legacy-federated-directory".into(),
            300,
        )
        .test_unwrap();
        let RealAdapterRuntime {
            kernel,
            coordinator,
            executor,
            effects,
            ..
        } = build_real_adapter_runtime(
            &paths,
            &operator_authority,
            &executor_signer,
            &submission_authority,
            &threshold_policy_authority,
            &requirement,
            &finding,
            &response_plan,
            clock,
            false,
        );
        drop(coordinator);
        let Ok(kernel) = Arc::try_unwrap(kernel) else {
            panic!("sole published kernel handle");
        };
        let now = kernel
            .authority_clock_reading()
            .test_unwrap()
            .unix_millis()
            .as_secs();
        let mut kernel =
            kernel.with_federation_peers(vec![negotiated_remote_peer(&operator_authority, now)]);
        kernel.set_federation_local_kernel_id(LOCAL_KERNEL_ID);
        assert!(
            kernel
                .governed_security_runtime_status()
                .active_response_enabled
        );
        let database = _directory.path().join("legacy-v1.db");
        let locks = _directory.path().join("legacy-v1-locks");
        crate::create_private_directory(&locks).test_unwrap();
        chio_store_sqlite::SqliteAuthorityStore::provision(&database, &locks).test_unwrap();
        let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
            database.clone(),
            locks,
            kernel.authority_clock(),
        )
        .test_unwrap();
        kernel
            .set_durable_admission_store(
                Arc::new(authority.admission_operation_store()),
                Arc::new(authority.tool_outcome_store()),
                authority.mutation_fence(),
            )
            .test_unwrap();
        kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
        Self {
            _directory,
            databases: vec![
                database,
                paths.admission_operations,
                paths.approvals,
                paths.budgets,
                paths.responses,
                paths.receipts,
            ],
            kernel,
            authority,
            executor,
            effects,
            operator_authority,
            requirement,
            approvers,
            subject: Keypair::generate(),
            now,
        }
    }

    fn request(
        &self,
        request_id: &str,
        federated_origin: Option<&str>,
    ) -> GovernedActiveResponseRequest {
        let effects = vec![
            GovernedResponseEffect::RestrictEgress,
            GovernedResponseEffect::SuspendSession,
        ];
        let grants = effects
            .iter()
            .map(|effect| legacy_grant(ACTIVE_RESPONSE_SERVER_ID, effect.tool_name()))
            .collect();
        let mut request = LegacyResponseFixture {
            issuer: &self.operator_authority,
            requirement: &self.requirement,
            policy_authority: &self.operator_authority,
            approvers: [&self.approvers[0], &self.approvers[1]],
            executor: &self.subject,
            now: self.now,
        }
        .request(request_id, effects, grants);
        request.federated_origin_kernel_id = federated_origin.map(ToOwned::to_owned);
        request
    }

    fn assert_remote_peer_negotiates_governed_plans(&self) {
        let peer = self
            .kernel
            .federation_peer(REMOTE_KERNEL_ID, self.now)
            .test_expect("fresh pinned federation peer");
        assert!(peer.capabilities.supports(GOVERNED_ACTIVE_RESPONSE_PLAN));
    }

    /// Row counts of every table in the V1 authority database and in every
    /// fixture store, keyed by database file and table.
    fn durable_rows(&self) -> BTreeMap<String, u64> {
        let mut rows = BTreeMap::new();
        for database in &self.databases {
            let connection = Connection::open(database).test_unwrap();
            let tables = {
                let mut statement = connection
                    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
                    .test_unwrap();
                statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .test_unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .test_unwrap()
            };
            let file = database
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("database");
            for table in tables {
                let count: i64 = connection
                    .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
                        row.get(0)
                    })
                    .test_unwrap();
                rows.insert(
                    format!("{file}/{table}"),
                    u64::try_from(count).test_unwrap(),
                );
            }
        }
        rows
    }

    fn retained_state(
        &self,
        admission: &chio_kernel::governed_active_response::GovernedActiveResponseAdmission,
    ) -> AdmissionOperationState {
        self.authority
            .admission_operation_store()
            .load_by_operation_id(admission.operation().binding().operation_id())
            .test_unwrap()
            .test_expect("retained legacy operation")
            .state()
    }
}

fn negotiated_remote_peer(local: &Keypair, now: u64) -> FederationPeer {
    let remote = Keypair::generate();
    let trust = KernelTrustExchange::new(LOCAL_KERNEL_ID, local.clone())
        .with_trusted_peer(REMOTE_KERNEL_ID, remote.public_key())
        .with_capabilities(CapabilityNegotiation::t1_default());
    let envelope = PeerHandshakeEnvelope::sign_with_capabilities(
        REMOTE_KERNEL_ID,
        LOCAL_KERNEL_ID,
        "legacy-federated-admission",
        now,
        &remote,
        CapabilityNegotiation::t1_default(),
    )
    .test_unwrap();
    trust
        .accept_envelope(&envelope, REMOTE_KERNEL_ID, now)
        .test_unwrap()
}

fn changed_rows(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> Vec<(String, Option<u64>, u64)> {
    after
        .iter()
        .filter(|(table, rows)| before.get(*table) != Some(*rows))
        .map(|(table, rows)| (table.clone(), before.get(table).copied(), *rows))
        .collect()
}

#[test]
fn disabled_legacy_federated_active_response_admission_has_no_durable_side_effects() {
    let mut runtime = FederatedLegacyRuntime::new();
    runtime.kernel.deactivate_governed_active_response_plans();
    assert!(
        !runtime
            .kernel
            .governed_security_runtime_status()
            .active_response_enabled
    );
    runtime.assert_remote_peer_negotiates_governed_plans();
    let request = runtime.request("active-response-federated", Some(REMOTE_KERNEL_ID));
    let before = runtime.durable_rows();

    let result = runtime.kernel.admit_governed_active_response(&request);
    let changed = changed_rows(&before, &runtime.durable_rows());
    assert!(
        changed.is_empty(),
        "a locally disabled runtime admitted a federated legacy response: {changed:?} {result:?}"
    );
    assert!(
        matches!(
            &result,
            Err(KernelError::GovernedTransactionDenied(reason))
                if reason.contains("active-response plan support is disabled")
        ),
        "{result:?}"
    );
    assert_eq!(runtime.executor.calls(), 0);
    assert_eq!(runtime.effects.executions(), 0);
}

#[test]
fn disabled_legacy_local_active_response_admission_still_refuses_without_side_effects() {
    let mut runtime = FederatedLegacyRuntime::new();
    runtime.kernel.deactivate_governed_active_response_plans();
    let request = runtime.request("active-response-local", None);
    let before = runtime.durable_rows();

    let result = runtime.kernel.admit_governed_active_response(&request);
    assert!(
        matches!(
            &result,
            Err(KernelError::GovernedTransactionDenied(reason))
                if reason == "governed active-response plans were not negotiated"
        ),
        "{result:?}"
    );
    assert_eq!(changed_rows(&before, &runtime.durable_rows()), Vec::new());
    assert_eq!(runtime.executor.calls(), 0);
    assert_eq!(runtime.effects.executions(), 0);
}

#[test]
fn enabled_legacy_federated_active_response_admission_still_reserves_and_cleans_up() {
    let mut runtime = FederatedLegacyRuntime::new();
    runtime.assert_remote_peer_negotiates_governed_plans();
    let request = runtime.request("active-response-federated-enabled", Some(REMOTE_KERNEL_ID));

    let mut admitted = runtime
        .kernel
        .admit_governed_active_response(&request)
        .test_unwrap();
    assert_eq!(admitted.state(), AdmissionOperationState::ApprovalReserved);
    assert_eq!(
        runtime.retained_state(&admitted),
        AdmissionOperationState::ApprovalReserved
    );

    let mut substituted = request.clone();
    substituted.approval_tokens = substituted
        .approval_tokens
        .iter()
        .zip(&runtime.approvers)
        .enumerate()
        .map(|(index, (token, approver))| {
            let mut body = token.body();
            body.id = format!("replacement-federated-token-{index}");
            GovernedApprovalToken::sign(body, approver).test_unwrap()
        })
        .collect();
    assert!(runtime
        .kernel
        .admit_governed_active_response(&substituted)
        .test_unwrap_err()
        .to_string()
        .contains("retained approval reservation"));
    let replayed = runtime
        .kernel
        .admit_governed_active_response(&request)
        .test_unwrap();
    assert_eq!(replayed.operation_id(), admitted.operation_id());
    assert_eq!(replayed.approval_set_hash(), admitted.approval_set_hash());
    assert_eq!(replayed.state(), AdmissionOperationState::ApprovalReserved);

    assert!(matches!(
        runtime
            .kernel
            .commit_governed_active_response_dispatch(&mut admitted),
        Err(KernelError::GovernedTransactionDenied(_))
    ));
    assert_eq!(
        runtime.retained_state(&admitted),
        AdmissionOperationState::ApprovalReserved
    );

    runtime.kernel.deactivate_governed_active_response_plans();
    runtime
        .kernel
        .cancel_governed_active_response(&admitted)
        .test_unwrap();
    assert_eq!(
        runtime.retained_state(&admitted),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(runtime.executor.calls(), 0);
    assert_eq!(runtime.effects.executions(), 0);
}
