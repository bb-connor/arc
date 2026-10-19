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
    let store = install_fixture_authority(&mut kernel);
    let authority = fixture_authority();
    store.dpop_recovery.0.lock().expect("state").mode = mode;
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
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 3600);
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
                schema: crate::dpop::DPOP_SCHEMA.into(),
                replay_authority: authority,
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

pub(in crate::kernel::tests) fn fixture_authority() -> DpopReplayAuthority {
    DpopReplayAuthority::new(crate::dpop::authority::DpopReplayAuthorityInput {
        destination_store_uuid: id("018f47a0-7261-7000-8000-000000000001"),
        dpop_authority_id: id("test-dpop-authority"),
        expectation_id: digest('b'),
        proof_ttl_secs: 300,
        max_clock_skew_secs: 30,
    })
    .expect("test replay authority")
}

pub(in crate::kernel::tests) fn install_fixture_authority(
    kernel: &mut ChioKernel,
) -> Arc<TestAdmissionOperationStore> {
    let authority = fixture_authority();
    let fence = StoreMutationFence {
        store_uuid: authority.destination_store_uuid().as_str().to_owned(),
        ..admission_test_fence()
    };
    let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    store.dpop_recovery.0.lock().expect("state").authority = Some(authority.clone());
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified test store");
    kernel.set_budget_store_handle(store.budget_store());
    kernel
        .set_operation_owned_dpop_authority(authority)
        .expect("independently activated test authority");
    store
}
