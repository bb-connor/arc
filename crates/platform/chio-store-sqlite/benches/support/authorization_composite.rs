//! Populated store-call composition for one allowed authorization. This includes
//! admission create/read, suspension lookup, budget hold/release and signed
//! receipt append. It measures their combined persistence cost, not the kernel's
//! complete policy, guard, broker or tool-execution path.

use super::*;
use chio_core::crypto::Keypair;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_kernel::admission_operation::{
    AdmissionBeginResult, AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationKind,
    AdmissionOperationStore as DurableAdmissionStore, AdmissionOperationV1,
    AdmissionParticipantRequirements, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
    SideEffectClass, StoreMutationFence,
};
use chio_kernel::budget_store::BudgetAdmissionBinding;
use chio_kernel::CanonicalRevocationSet;
use chio_store_sqlite::{SqliteAdmissionOperationStore, SqliteAuthorityStore, SqliteReceiptStore};

fn require<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => fail_bench(&format!("{context}: {error}")),
    }
}

struct Stores {
    admission: SqliteAdmissionOperationStore,
    authority: SqliteAuthorityStore,
    fence: StoreMutationFence,
    budget: SqliteBudgetStore,
    security: SqliteSecurityStateStore,
    receipts: SqliteReceiptStore,
    signer: Keypair,
}

impl Stores {
    fn authorization(&self, index: usize) {
        let expected = self.create_admission(index);
        let observed = require(
            self.admission
                .load_by_operation_id(expected.binding().operation_id()),
            "read admission",
        );
        if observed.as_ref() != Some(&expected) {
            fail_bench("composite admission readback differs");
        }
        let decision = require(
            self.security
                .evaluate_capability_suspension(&CapabilitySuspensionQuery {
                    tenant_id: suspension_tenant(),
                    capability_id: require(
                        RecordId::new(expected.binding().capability_id().as_str()),
                        "capability id",
                    ),
                }),
            "read security state",
        );
        if decision.denied {
            fail_bench("composite capability was suspended");
        }
        black_box(decision);
        self.budget_and_receipt(index, &expected);
    }

    fn budget_and_receipt(&self, index: usize, expected: &AdmissionOperationV1) {
        let mut request = authorize_request(index);
        request.authority = Some(self.budget_authority());
        request.admission_binding = Some(BudgetAdmissionBinding {
            operation_id: expected.binding().operation_id().as_str().to_owned(),
            revocation_set: require(
                CanonicalRevocationSet::canonicalize(vec![expected
                    .binding()
                    .capability_id()
                    .as_str()
                    .to_owned()]),
                "revocation set",
            ),
            authorization_artifact_digests: Vec::new(),
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        });
        let hold = require(
            self.budget.authorize_budget_hold(request),
            "authorize budget",
        );
        if !matches!(hold, BudgetAuthorizeHoldDecision::Authorized(_)) {
            fail_bench("composite budget was denied");
        }
        let mut release = release_request(index);
        release.authority = Some(self.budget_authority());
        require(self.budget.release_budget_hold(release), "release budget");
        let receipt = self.receipt(index, expected);
        black_box(require(
            self.receipts.append_chio_receipt_returning_seq(&receipt),
            "append signed receipt",
        ));
    }

    fn budget_authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: self.fence.store_uuid.clone(),
            lease_id: self.fence.lease_id.clone(),
            lease_epoch: self.fence.owner_epoch,
        }
    }

    fn create_admission(&self, index: usize) -> AdmissionOperationV1 {
        let identifier = |field, value| require(AdmissionIdentifier::try_new(field, value), field);
        let digest =
            |field, byte: &str| require(AdmissionDigest::try_new(field, byte.repeat(32)), field);
        let namespace = require(
            AuthenticatedRequestNamespace::for_local_system(identifier(
                "coordinator_authority_id",
                self.fence.store_uuid.clone(),
            )),
            "local namespace",
        );
        let binding = require(
            AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
                kind: AdmissionOperationKind::ToolDispatch,
                namespace,
                request_id: identifier("request_id", format!("bench-request-{index}")),
                capability_id: identifier("capability_id", bench_capability(index)),
                authorization_capability_hash: digest("authorization_capability_hash", "11"),
                request_binding: require(
                    AdmissionRequestBindingV1::new(
                        digest("immutable_request_hash", "22"),
                        AdmissionParticipantRequirements {
                            broker_attempt: true,
                            budget_capture: true,
                            ..AdmissionParticipantRequirements::NONE
                        },
                    ),
                    "request binding",
                ),
                policy_hash: digest("policy_hash", "33"),
                effect_class: SideEffectClass::SideEffecting,
            }),
            "admission binding",
        );
        let operation = require(
            AdmissionOperationV1::prepare(binding, self.fence.owner_epoch),
            "prepare admission",
        );
        let created = require(
            self.admission.begin(&operation, &self.fence, now_unix_ms()),
            "create admission",
        );
        if !matches!(created, AdmissionBeginResult::Created(_)) {
            fail_bench("composite admission reused an operation");
        }
        operation
    }

    fn receipt(&self, index: usize, operation: &AdmissionOperationV1) -> ChioReceipt {
        let action = require(
            ToolCallAction::from_parameters(serde_json::json!({"index": index})),
            "receipt action",
        );
        require(
            ChioReceipt::sign(
                ChioReceiptBody {
                    id: format!("authorization-bench-{index}"),
                    timestamp: 1_700_000_000 + index as u64,
                    capability_id: operation.binding().capability_id().as_str().to_owned(),
                    tool_server: "authorization-bench".to_owned(),
                    tool_name: "allow".to_owned(),
                    action,
                    decision: Some(Decision::Allow),
                    receipt_kind: Default::default(),
                    boundary_class: Default::default(),
                    observation_outcome: None,
                    tool_origin: Default::default(),
                    redaction_mode: Default::default(),
                    actor_chain: Vec::new(),
                    content_hash: "55".repeat(32),
                    policy_hash: "33".repeat(32),
                    evidence: Vec::new(),
                    metadata: Some(serde_json::json!({
                        "benchmark_admission_operation_id": operation.binding().operation_id().as_str(),
                        "benchmark_budget_hold_id": format!("bench-hold-{index}"),
                    })),
                    trust_level: Default::default(),
                    tenant_id: Some(SUSPENSION_TENANT.to_owned()),
                    kernel_key: self.signer.public_key(),
                    bbs_projection_version: None,
                },
                &self.signer,
            ),
            "sign composite receipt",
        )
    }
}

pub(super) fn bench_authorization_composite(c: &mut Criterion) {
    let directory = require(tempfile::tempdir(), "composite directory");
    let (security, _) = populate_suspensions(&directory.path().join("security.db"));
    let database = directory.path().join("authority.db");
    let locks = directory.path().join("locks");
    require(
        std::fs::create_dir(&locks),
        "create authority lock directory",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        require(
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)),
            "secure authority parent directory",
        );
        require(
            std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)),
            "secure lock directory",
        );
    }
    require(
        SqliteAuthorityStore::provision(&database, &locks),
        "provision authority",
    );
    let authority = require(
        SqliteAuthorityStore::open_serving(&database, &locks),
        "open authority",
    );
    let stores = Stores {
        admission: authority.admission_operation_store(),
        budget: authority.budget_store(),
        fence: authority.mutation_fence(),
        authority,
        security,
        receipts: require(
            SqliteReceiptStore::open(directory.path().join("receipts.db")),
            "open composite receipts",
        ),
        signer: Keypair::from_seed(&[89; 32]),
    };
    // Populate every mutation and signed receipt, retaining the same identities.
    // Readback and suspension reads add no rows, so perform those only in the
    // measured operation instead of repeating 20,000 nonmutating setup scans.
    for index in 0..populated_rows() {
        let operation = stores.create_admission(index);
        stores.budget_and_receipt(index, &operation);
    }
    require(
        stores.receipts.flush_receipt_writes(),
        "flush populated receipts",
    );
    require(
        stores.authority.verify_database_path(&database),
        "verify populated authority",
    );
    let mut index = populated_rows();
    c.bench_function("authorization_store_composite_populated", |b| {
        b.iter(|| {
            stores.authorization(index);
            index += 1;
        });
    });
    require(
        stores.receipts.flush_receipt_writes(),
        "flush measured receipts",
    );
}
