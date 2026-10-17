//! DPoP proofs use a domain activated by the same durable admission authority.
use super::*;
use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
use chio_kernel::caller_delivery::CallerExecutorIdentityV1;
use chio_kernel::dpop::authority::{DpopReplayAuthority, DpopReplayAuthorityInput};
use chio_kernel::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};

#[path = "dpop_authority/startup.rs"]
mod startup;

pub(super) struct DpopFixture {
    pub state: Arc<ProxyState>,
    pub domain: DpopReplayAuthority,
    pub budget: Arc<dyn BudgetStore>,
    executor_key: Keypair,
    _directory: tempfile::TempDir,
}

fn activated_authority(
    directory: &std::path::Path,
) -> (chio_store_sqlite::SqliteAuthorityStore, DpopReplayAuthority) {
    let authority = durable_admission_authority(directory);
    let durable = DurableAdmissionStores::serving(&authority);
    let operations = authority.admission_operation_store();
    let source = chio_kernel::dpop::DpopNonceStore::with_clock(
        8,
        8,
        chio_kernel::dpop::DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
        std::time::Duration::from_secs(3600),
        chio_test_support::clock::clock(),
    )
    .test_unwrap();
    let authority_id =
        AdmissionIdentifier::try_new("dpop_authority", "api-protect-dpop").test_unwrap();
    let snapshot = source
        .preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: authority_id.clone(),
            destination_authority_id: AdmissionIdentifier::try_new(
                "destination",
                &durable.fence.store_uuid,
            )
            .test_unwrap(),
        })
        .test_unwrap();
    let instance = AdmissionIdentifier::try_new("instance", snapshot.instance_id()).test_unwrap();
    let now = chio_test_support::clock::clock()
        .unix_millis()
        .test_unwrap()
        .get();
    let pinned = operations
        .expect_dpop_replay_source(&instance, &authority_id, &source, &durable.fence, now)
        .test_unwrap();
    let imported = operations
        .import_dpop_replay_source(
            &authority_id,
            pinned.expectation_id(),
            &source,
            &durable.fence,
            now,
        )
        .test_unwrap();
    let domain = DpopReplayAuthority::new(DpopReplayAuthorityInput {
        destination_store_uuid: AdmissionIdentifier::try_new(
            "destination",
            imported.snapshot().destination_authority_id(),
        )
        .test_unwrap(),
        dpop_authority_id: authority_id,
        expectation_id: AdmissionDigest::try_new("expectation", imported.expectation_id().as_str())
            .test_unwrap(),
        proof_ttl_secs: 60,
        max_clock_skew_secs: 30,
    })
    .test_unwrap();
    assert!(operations
        .activate_dpop_replay_source(&domain, &source, &durable.fence, now)
        .test_unwrap()
        .is_active());
    (authority, domain)
}

impl DpopFixture {
    pub fn new(signer: Keypair) -> Self {
        let fixture = Self::without_caller_executor(signer);
        let executor = CallerExecutorIdentityV1 {
            executor_id: AdmissionIdentifier::try_new("executor_id", "api-protect-dpop-executor")
                .test_unwrap(),
            public_key: fixture.executor_key.public_key(),
            key_epoch: 1,
        };
        fixture
            .state
            .mediation_kernel
            .as_ref()
            .test_unwrap()
            .try_lock()
            .test_unwrap()
            .set_caller_executor(executor)
            .test_unwrap();
        fixture
    }

    fn without_caller_executor(signer: Keypair) -> Self {
        let directory = tempfile::tempdir().test_unwrap();
        let (authority, domain) = activated_authority(directory.path());
        let durable = DurableAdmissionStores::serving(&authority);
        let budget = Arc::clone(&durable.budget_store);
        let state = mediated_test_state_with_durable_admission(
            signer,
            MediationBudget::Durable(durable),
            Vec::new(),
            Some(MEDIATED_CONTROL_TOKEN.to_owned()),
            None,
            true,
            None,
            None,
            Some(domain.clone()),
        );
        Self {
            state,
            domain,
            budget,
            executor_key: Keypair::generate(),
            _directory: directory,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_dpop_refuses_reservation_without_authenticated_caller_executor() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let fixture = DpopFixture::without_caller_executor(signer.clone());
    let issuer = issuing_kernel(&signer, fixture.budget.clone(), &[]);
    let capability = issue_dpop_capability(&issuer, &agent, "cost-srv", "compute");
    let parameters = serde_json::json!({"invoice": "unconfigured-caller"});
    let proof = dpop_proof_for(
        &agent,
        &capability,
        "cost-srv",
        "compute",
        &parameters,
        &fixture.domain,
    );
    let (status, refused) = post_evaluate(
        fixture.state.clone(),
        &serde_json::json!({
            "capability": capability, "tool_server": "cost-srv", "tool_name": "compute",
            "parameters": parameters, "dpop_proof": proof,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["status"], "deny", "{refused}");
    assert_eq!(
        refused["receipt"]["decision"]["reason"],
        "caller execution requires authenticated start and operation-owned credential custody"
    );
    assert_eq!(refused["execution_authorized"], false);
    assert_eq!(refused["start_required"], false);
    assert_eq!(refused["execution_nonce"], serde_json::Value::Null);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_dpop_rejects_missing_and_null_replay_authority() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let fixture = DpopFixture::new(signer.clone());
    let issuer = issuing_kernel(&signer, fixture.budget.clone(), &[]);
    let capability = issue_dpop_capability(&issuer, &agent, "cost-srv", "compute");
    let parameters = serde_json::json!({"invoice": "invalid-profile"});
    let proof = dpop_proof_for(
        &agent,
        &capability,
        "cost-srv",
        "compute",
        &parameters,
        &fixture.domain,
    );
    for authority in [None, Some(serde_json::Value::Null)] {
        let mut proof = serde_json::to_value(&proof).test_unwrap();
        let body = proof["body"].as_object_mut().test_unwrap();
        match authority {
            None => {
                body.remove("replay_authority");
            }
            Some(value) => {
                body.insert("replay_authority".into(), value);
            }
        }
        let (status, refused) = post_evaluate(
            fixture.state.clone(),
            &serde_json::json!({
                "capability": capability, "tool_server": "cost-srv", "tool_name": "compute",
                "parameters": parameters, "dpop_proof": proof,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert!(refused.get("execution_nonce").is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_dpop_refuses_proof_without_configured_authority() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let fixture = DpopFixture::new(signer.clone());
    let issuer = issuing_kernel(&signer, fixture.budget.clone(), &[]);
    let capability = issue_dpop_capability(&issuer, &agent, "cost-srv", "compute");
    let state = mediated_test_state(signer, Arc::new(InMemoryBudgetStore::new()), Vec::new());
    let parameters = serde_json::json!({"invoice": "unconfigured"});
    let proof = dpop_proof_for(
        &agent,
        &capability,
        "cost-srv",
        "compute",
        &parameters,
        &fixture.domain,
    );
    let (status, refused) = post_evaluate(
        state,
        &serde_json::json!({
            "capability": capability, "tool_server": "cost-srv", "tool_name": "compute",
            "parameters": parameters, "dpop_proof": proof,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["status"], "deny", "{refused}");
    assert_eq!(
        refused["receipt"]["decision"]["reason"],
        "DPoP replay authority not configured"
    );
    assert!(!refused["execution_nonce"].is_object());
}

#[test]
fn mediation_refuses_configured_dpop_without_durable_admission() {
    let signer = Keypair::generate();
    let fixture = DpopFixture::new(signer.clone());
    let error = build_mediation_kernel(
        &signer,
        MediationBudget::Configured(Arc::new(InMemoryBudgetStore::new())),
        MediationPolicy {
            dpop_replay_authority: Some(&fixture.domain),
            issuers: &[],
            hash: None,
            receipt_store: None,
        },
        Vec::new(),
        None,
        Arc::new(clock::ProxyClock::default()),
    )
    .err()
    .test_unwrap();
    assert_eq!(error.to_string(), "configuration error: durable admission failed: qualified admission operation store is unavailable");
}

#[test]
fn evaluator_refuses_configured_dpop_without_durable_admission() {
    let signer = Keypair::generate();
    let fixture = DpopFixture::new(signer.clone());
    let error = RequestEvaluator::new_with_durable_stores_and_admission(
        Vec::new(),
        signer,
        chio_core_types::sha256_hex(b"dpop-http-policy"),
        Arc::new(InMemoryApprovalStore::new()),
        Vec::new(),
        None,
        None,
        None,
        Some(fixture.domain),
        true,
        Arc::new(clock::ProxyClock::default()),
    )
    .err()
    .test_unwrap();
    assert_eq!(error.to_string(), "kernel-backed authorization failed: durable admission failed: qualified admission operation store is unavailable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_dpop_refuses_retired_profile() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let fixture = DpopFixture::new(signer.clone());
    let issuer = issuing_kernel(&signer, fixture.budget.clone(), &[]);
    let capability = issue_dpop_capability(&issuer, &agent, "cost-srv", "compute");
    let parameters = serde_json::json!({"invoice": "retired-profile"});
    let proof = dpop_proof_for(
        &agent,
        &capability,
        "cost-srv",
        "compute",
        &parameters,
        &fixture.domain,
    );
    let mut proof = serde_json::to_value(proof).test_unwrap();
    proof["body"]["schema"] = serde_json::json!("chio.dpop_proof.v2");
    let (status, refused) = post_evaluate(
        fixture.state.clone(),
        &serde_json::json!({
            "capability": capability, "tool_server": "cost-srv", "tool_name": "compute",
            "parameters": parameters, "dpop_proof": proof,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["status"], "deny", "{refused}");
    assert_eq!(
        refused["receipt"]["decision"]["reason"],
        "unsupported DPoP schema"
    );
    assert!(!refused["execution_nonce"].is_object());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mediated_dpop_refuses_another_signed_authority() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let fixture = DpopFixture::new(signer.clone());
    let issuer = issuing_kernel(&signer, fixture.budget.clone(), &[]);
    let capability = issue_dpop_capability(&issuer, &agent, "cost-srv", "compute");
    let parameters = serde_json::json!({"invoice": "other-authority"});
    let other = DpopReplayAuthority::new(DpopReplayAuthorityInput {
        destination_store_uuid: fixture.domain.destination_store_uuid().clone(),
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "other-dpop-authority")
            .test_unwrap(),
        expectation_id: fixture.domain.expectation_id().clone(),
        proof_ttl_secs: 60,
        max_clock_skew_secs: 30,
    })
    .test_unwrap();
    let proof = dpop_proof_for(
        &agent,
        &capability,
        "cost-srv",
        "compute",
        &parameters,
        &other,
    );
    let (status, refused) = post_evaluate(
        fixture.state.clone(),
        &serde_json::json!({
            "capability": capability, "tool_server": "cost-srv", "tool_name": "compute",
            "parameters": parameters, "dpop_proof": proof,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["status"], "deny", "{refused}");
    assert_eq!(
        refused["receipt"]["decision"]["reason"],
        "DPoP replay authority does not match the configured authority"
    );
    assert!(!refused["execution_nonce"].is_object());
}
