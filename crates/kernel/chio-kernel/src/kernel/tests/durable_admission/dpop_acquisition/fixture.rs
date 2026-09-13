use super::*;

pub(super) fn fixture(
    mode: Mode,
) -> (
    ChioKernel,
    ToolCallRequest,
    Arc<TestAdmissionOperationStore>,
    Arc<AtomicU64>,
) {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"dpop-admission-test-policy");
    let mut kernel = make_kernel(config);
    let fence = StoreMutationFence {
        store_uuid: "018f47a0-7261-7000-8000-000000000001".into(),
        ..admission_test_fence()
    };
    let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence.clone())
        .expect("qualified test store");
    kernel.set_budget_store_handle(store.budget_store());
    let authority =
        DpopReplayAuthorityV1::new(crate::dpop::authority::DpopReplayAuthorityInputV1 {
            destination_store_uuid: id(&fence.store_uuid),
            dpop_authority_id: id("test-dpop-authority"),
            expectation_id: digest('b'),
            proof_ttl_secs: 60,
            max_clock_skew_secs: 30,
        })
        .expect("domain");
    *store.dpop_recovery.0.lock().expect("state") = State {
        authority: Some(authority.clone()),
        mode,
        ..Default::default()
    };
    kernel
        .set_operation_owned_dpop_authority(authority.clone())
        .expect("active domain");
    let calls = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".into(),
        tools: vec!["mutate".into()],
        invocations: calls.clone(),
        store: store.clone(),
    }));
    let agent = make_keypair();
    let mut grant = make_grant("durable-server", "mutate");
    grant.dpop_required = Some(true);
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
    let mut request = make_request_with_arguments(
        "prepared-dpop-owner",
        &capability,
        "mutate",
        "durable-server",
        serde_json::json!({"record": "ledger-7"}),
    );
    request.dpop_proof = Some(
        crate::dpop::DpopProof::sign(
            crate::dpop::DpopProofBody {
                schema: crate::dpop::authority::DPOP_AUTHORITY_SCHEMA.into(),
                replay_authority: Some(authority),
                capability_id: capability.id.clone(),
                tool_server: request.server_id.clone(),
                tool_name: request.tool_name.clone(),
                action_hash: sha256_hex(
                    &canonical_json_bytes(&request.arguments).expect("arguments"),
                ),
                nonce: "prepared-dpop-nonce".into(),
                issued_at: current_unix_timestamp(),
                agent_key: agent.public_key(),
            },
            &agent,
        )
        .expect("signed proof"),
    );
    (kernel, request, store, calls)
}

pub(super) fn digest(c: char) -> AdmissionDigest {
    AdmissionDigest::try_new("test", c.to_string().repeat(64)).expect("digest")
}
pub(super) fn id(value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new("test", value).expect("identifier")
}
