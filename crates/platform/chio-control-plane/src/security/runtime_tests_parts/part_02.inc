#[test]
fn shadow_mode_does_not_run_the_mutating_pre_dispatch_hook() {
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Shadow,
        Some(shadow_runtime(SecurityDurability::persistent())),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install shadow runtime: {error}"));

    assert_eq!(
        kernel.security_pre_dispatch_policy(),
        SecurityPreDispatchPolicy::Optional
    );
    assert_eq!(kernel.security_pre_dispatch_hook_name(), None);
}

#[test]
fn shadow_mode_neither_requires_nor_installs_an_executor() {
    let executor = Arc::new(RecordingActiveResponseExecutor::new(false));
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Shadow,
        Some(shadow_runtime(SecurityDurability::persistent())),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install shadow runtime: {error}"));

    assert_eq!(executor.readiness_checks(), 0);
    kernel
        .set_active_response_requirement_resolver(Arc::new(
            |_: &ActiveResponsePolicyRequest, _: &str| {
                Err(ActiveResponsePolicyResolutionError::Unavailable(
                    "resolution is outside this installation test".to_string(),
                ))
            },
        ))
        .unwrap_or_else(|error| panic!("install policy resolver: {error}"));
    assert!(kernel.enable_governed_active_response_plans().is_err());
}

#[test]
fn enforce_mode_rejects_each_ephemeral_authority_before_mutation() {
    let profiles = [
        SecurityDurability::new(
            AuthorityDurability::Ephemeral,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
        ),
        SecurityDurability::new(
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::Ephemeral,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
        ),
        SecurityDurability::new(
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::Ephemeral,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
        ),
        SecurityDurability::new(
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::Ephemeral,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
        ),
        SecurityDurability::new(
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::Ephemeral,
            AuthorityDurability::FilesystemBacked,
        ),
        SecurityDurability::new(
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::Ephemeral,
        ),
    ];

    for durability in profiles {
        let authorities = ProductionAuthorityFixture::new(true, true, 1);
        let error = production_runtime(durability, &authorities)
            .err()
            .unwrap_or_else(|| panic!("ephemeral production runtime unexpectedly built"));
        assert_eq!(error, SecurityRuntimeBuildError::EphemeralAuthority);
    }
}

#[test]
fn enforce_mode_rejects_missing_threshold_authority_without_partial_publication() {
    let mut kernel = kernel();
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let (configured_pre, configured_post) = configured();
    let error = require_install_error(install_security_runtime_with_governance(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(
            production_runtime(SecurityDurability::persistent(), &authorities)
                .unwrap_or_else(|error| panic!("build production runtime: {error}")),
        ),
        None,
        Vec::new(),
        profile(),
        configured_pre,
        configured_post,
    ));
    assert_eq!(error, SecurityInstallError::ThresholdResolverMissing);
    assert_eq!(kernel.guard_count(), 0);
    assert_eq!(kernel.post_invocation_hook_count(), 0);
    assert_eq!(
        kernel
            .governed_security_runtime_status()
            .publication_generation,
        0
    );

    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let (configured_pre, configured_post) = configured();
    let error = require_install_error(install_security_runtime_with_governance(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(
            production_runtime(SecurityDurability::persistent(), &authorities)
                .unwrap_or_else(|error| panic!("build production runtime: {error}")),
        ),
        Some(threshold_resolver()),
        Vec::new(),
        profile(),
        configured_pre,
        configured_post,
    ));
    assert_eq!(error, SecurityInstallError::ThresholdPolicyAuthorityMissing);
    assert_eq!(kernel.guard_count(), 0);
    assert_eq!(kernel.post_invocation_hook_count(), 0);
    assert_eq!(
        kernel
            .governed_security_runtime_status()
            .publication_generation,
        0
    );
}

#[test]
fn governed_security_runtime_replacement_is_atomic_and_exact() {
    let first = ProductionAuthorityFixture::new(true, true, 1);
    let mut kernel = kernel();
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(
            production_runtime(SecurityDurability::persistent(), &first)
                .unwrap_or_else(|error| panic!("build first production runtime: {error}")),
        ),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install first production runtime: {error}"));
    let initial_status = kernel.governed_security_runtime_status();
    let initial_guards = kernel
        .guard_names()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let initial_hooks = kernel
        .post_invocation_hook_names()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();

    let finding_outage = ProductionAuthorityFixture::new(true, true, 2);
    let rejected_runtime = production_runtime(SecurityDurability::persistent(), &finding_outage)
        .unwrap_or_else(|error| panic!("build finding-outage replacement: {error}"));
    finding_outage.indexed_finding_store.set_ready(false);
    let (configured_pre, configured_post) = configured();
    let error = require_install_error(install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(rejected_runtime),
        profile(),
        configured_pre,
        configured_post,
    ));
    assert!(matches!(error, SecurityInstallError::AtomicPublication(_)));
    assert_eq!(kernel.governed_security_runtime_status(), initial_status);
    assert_eq!(kernel.guard_names(), initial_guards);
    assert_eq!(kernel.post_invocation_hook_names(), initial_hooks);

    let replacement = ProductionAuthorityFixture::new(true, true, 2);
    let rejected_runtime = production_runtime(SecurityDurability::persistent(), &replacement)
        .unwrap_or_else(|error| panic!("build rejected replacement: {error}"));
    replacement.executor_authority.set_ready(false);
    let (configured_pre, configured_post) = configured();
    let error = require_install_error(install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(rejected_runtime),
        profile(),
        configured_pre,
        configured_post,
    ));
    assert!(matches!(error, SecurityInstallError::AtomicPublication(_)));
    assert_eq!(kernel.governed_security_runtime_status(), initial_status);
    assert_eq!(kernel.guard_names(), initial_guards);
    assert_eq!(kernel.post_invocation_hook_names(), initial_hooks);

    replacement.executor_authority.set_ready(true);
    let accepted_runtime = production_runtime(SecurityDurability::persistent(), &replacement)
        .unwrap_or_else(|error| panic!("build accepted replacement: {error}"));
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(accepted_runtime),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install replacement runtime: {error}"));
    let replaced = kernel.governed_security_runtime_status();
    assert_eq!(replaced.publication_generation, 2);
    assert_eq!(
        replaced.executor_authority,
        Some(replacement.executor_authority.identity())
    );
    assert_eq!(replaced.threshold_policy_authorities, [kernel.public_key()]);

    let partial_mutation_error = rejected(
        kernel.set_active_response_requirement_resolver(Arc::clone(
            &replacement.active_response_requirement_resolver,
        )),
        "partial security authority mutation must fail",
    );
    assert!(partial_mutation_error
        .to_string()
        .contains("partial security authority mutation is disabled"));
}

#[test]
fn governed_publication_rejects_every_partial_authority_replacement() {
    let (mut kernel, authorities) = installed_production_kernel();
    let admission_operation_store: Arc<dyn chio_kernel::AdmissionOperationStore> =
        authorities.admission_operation_store.clone();
    let approval_store: Arc<dyn chio_kernel::ApprovalStore> = authorities.approval_store.clone();
    let budget_store: Arc<dyn chio_kernel::BudgetStore> = authorities.budget_store.clone();
    let replacement_executor: Arc<dyn ActiveResponseExecutorAuthority> =
        Arc::new(RecordingActiveResponseExecutor::with_generation(true, 2));
    let replacement_finding: Arc<dyn ActiveResponseFindingAuthority> =
        Arc::new(RejectingActiveResponseFindingAuthority);

    let results = [
        (
            "active-response resolver replacement",
            kernel.set_active_response_requirement_resolver(Arc::new(
                |_: &ActiveResponsePolicyRequest, _: &str| {
                    Err(ActiveResponsePolicyResolutionError::Unavailable(
                        "replacement resolver must never execute".to_string(),
                    ))
                },
            )),
        ),
        (
            "active-response executor replacement",
            kernel.set_active_response_executor_authority(replacement_executor),
        ),
        (
            "active-response finding replacement",
            kernel.set_active_response_finding_authority(replacement_finding),
        ),
        (
            "threshold resolver replacement",
            kernel.set_threshold_approval_requirement_resolver(threshold_resolver()),
        ),
        (
            "threshold policy-authority replacement",
            kernel.set_threshold_approval_policy_authority(Keypair::generate().public_key()),
        ),
        (
            "admission operation-store replacement",
            kernel.set_admission_operation_store_handle(admission_operation_store),
        ),
        (
            "approval-store replacement",
            kernel.set_approval_store_handle(approval_store),
        ),
        (
            "budget-store replacement",
            kernel.set_budget_store_handle(budget_store),
        ),
        (
            "supplemental quota-verifier replacement",
            kernel.set_supplemental_quota_verifier(Arc::new(RejectingSupplementalQuotaVerifier)),
        ),
        (
            "supplemental admission-registrar replacement",
            kernel.set_supplemental_admission_registrar(Arc::new(
                RejectingSupplementalAdmissionRegistrar,
            )),
        ),
        (
            "supplemental capture-authority replacement",
            kernel.set_admission_capture_authority(Arc::new(RejectingAdmissionCaptureAuthority)),
        ),
    ];

    for (operation, result) in results {
        assert_publication_freeze(result, operation);
    }
}

#[test]
fn governed_publication_rejects_all_security_activation_state_mutators() {
    let mut kernel = kernel();
    kernel
        .set_supplemental_quota_verifier(Arc::new(RejectingSupplementalQuotaVerifier))
        .unwrap_or_else(|error| panic!("install supplemental verifier fixture: {error}"));
    kernel
        .set_supplemental_admission_registrar(Arc::new(RejectingSupplementalAdmissionRegistrar))
        .unwrap_or_else(|error| panic!("install supplemental registrar fixture: {error}"));
    kernel
        .set_admission_capture_authority(Arc::new(RejectingAdmissionCaptureAuthority))
        .unwrap_or_else(|error| panic!("install supplemental capture fixture: {error}"));
    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(
            production_runtime(SecurityDurability::persistent(), &authorities)
                .unwrap_or_else(|error| panic!("build production runtime: {error}")),
        ),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install production runtime: {error}"));

    kernel.deactivate_governed_active_response_plans();
    let active_response = kernel.enable_governed_active_response_plans();
    kernel.deactivate_threshold_governed_approvals();
    let threshold = kernel.enable_threshold_governed_approvals();
    kernel.deactivate_aggregate_invocation_admission();
    let aggregate = kernel.enable_aggregate_invocation_admission();
    kernel.deactivate_supplemental_broker_admission();
    let supplemental = kernel.enable_supplemental_broker_admission();

    for (operation, result) in [
        ("active-response activation toggle", active_response),
        ("threshold activation toggle", threshold),
        ("aggregate admission activation toggle", aggregate),
        ("supplemental admission activation toggle", supplemental),
    ] {
        assert_publication_freeze(result, operation);
    }
}

#[test]
fn governed_publication_rejects_all_authority_teardown_without_partial_state() {
    let (mut kernel, _authorities) = installed_production_kernel();
    let initial = kernel.governed_security_runtime_status();

    kernel.clear_active_response_requirement_resolver();
    kernel.clear_active_response_executor_authority();
    kernel.clear_active_response_finding_authority();
    kernel.deactivate_governed_active_response_plans();
    kernel.clear_threshold_approval_requirement_resolver();
    kernel.disable_threshold_approval_policy();
    kernel.deactivate_threshold_governed_approvals();
    kernel.clear_admission_operation_store();
    kernel.clear_approval_store();

    assert_eq!(kernel.governed_security_runtime_status(), initial);
}

#[test]
fn governed_publication_freezes_guards_post_hooks_and_pre_dispatch_authority() {
    let (mut kernel, _authorities) = installed_production_kernel();
    let initial_guards = kernel
        .guard_names()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let initial_post_hooks = kernel
        .post_invocation_hook_names()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let initial_policy = kernel.security_pre_dispatch_policy();
    let initial_pre_dispatch_hook = kernel.security_pre_dispatch_hook_name().map(str::to_string);

    kernel.add_guard(Box::new(NamedGuard("replacement-guard")));
    kernel.set_post_invocation_pipeline(PostInvocationPipeline::new());
    kernel.add_post_invocation_hook(Box::new(NamedHook("replacement-post")));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Optional);
    kernel
        .set_security_pre_dispatch_hook(Arc::new(NamedPreDispatchHook("replacement-pre-dispatch")));
    kernel.clear_security_pre_dispatch_hook();

    let observed = (
        kernel
            .guard_names()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
        kernel
            .post_invocation_hook_names()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
        kernel.security_pre_dispatch_policy(),
        kernel.security_pre_dispatch_hook_name().map(str::to_string),
    );
    assert_eq!(
        observed,
        (
            initial_guards,
            initial_post_hooks,
            initial_policy,
            initial_pre_dispatch_hook,
        )
    );
}

#[test]
fn governed_publication_prevents_replacement_of_an_existing_tool_route() {
    let mut kernel = kernel();
    let _receipt_directory = install_contextual_receipt_store(&mut kernel);
    let original_inner: Arc<dyn BlockingToolServerConnection> =
        Arc::new(MarkerToolServer { marker: "original" });
    let original = BlockingToolServerAdapter::new(original_inner)
        .unwrap_or_else(|error| panic!("build original route: {error}"));
    kernel.register_tool_server(Box::new(original));
    let subject = Keypair::generate().public_key();
    let capability = kernel
        .issue_capability(
            &subject,
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "frozen-route".to_string(),
                    tool_name: "marker".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            300,
        )
        .unwrap_or_else(|error| panic!("issue route capability: {error}"));

    let authorities = ProductionAuthorityFixture::new(true, true, 1);
    let (configured_pre, configured_post) = configured();
    install_security_runtime(
        &mut kernel,
        ActiveDefenseMode::Enforce,
        Some(
            production_runtime(SecurityDurability::persistent(), &authorities)
                .unwrap_or_else(|error| panic!("build production runtime: {error}")),
        ),
        profile(),
        configured_pre,
        configured_post,
    )
    .unwrap_or_else(|error| panic!("install production runtime: {error}"));

    let replacement_inner: Arc<dyn BlockingToolServerConnection> = Arc::new(MarkerToolServer {
        marker: "replacement",
    });
    let replacement = BlockingToolServerAdapter::new(replacement_inner)
        .unwrap_or_else(|error| panic!("build replacement route: {error}"));
    kernel.register_tool_server(Box::new(replacement));

    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("tenant-frozen-route")
            .unwrap_or_else(|error| panic!("invalid frozen-route tenant: {error}")),
        SessionId::new("session-frozen-route")
            .unwrap_or_else(|error| panic!("invalid frozen-route session: {error}")),
        PrincipalId::new("principal-frozen-route")
            .unwrap_or_else(|error| panic!("invalid frozen-route principal: {error}")),
        IsolationEpochId::new("epoch-frozen-route")
            .unwrap_or_else(|error| panic!("invalid frozen-route isolation epoch: {error}")),
        LineageId::new("lineage-frozen-route")
            .unwrap_or_else(|error| panic!("invalid frozen-route lineage: {error}")),
        1,
    ));
    let request = ToolCallRequest {
        request_id: "frozen-route-request".to_string(),
        capability,
        tool_name: "marker".to_string(),
        server_id: "frozen-route".to_string(),
        agent_id: subject.to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let context = bind_security_context_to_request(&context, &request);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context)
        .unwrap_or_else(|error| panic!("evaluate frozen route: {error}"));
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({ "marker": "original" })
        ))
    );
}

#[test]
fn enabled_mode_requires_a_complete_runtime() {
    for mode in [ActiveDefenseMode::Shadow, ActiveDefenseMode::Enforce] {
        let mut kernel = kernel();
        let (configured_pre, configured_post) = configured();
        let error = require_install_error(install_security_runtime(
            &mut kernel,
            mode,
            None,
            profile(),
            configured_pre,
            configured_post,
        ));
        assert_eq!(error, SecurityInstallError::RuntimeMissing);
        assert_eq!(kernel.guard_count(), 0);
        assert_eq!(kernel.post_invocation_hook_count(), 0);
    }
}
