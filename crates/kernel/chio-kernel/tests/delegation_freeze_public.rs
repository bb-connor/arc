#[path = "delegation_freeze_public/support.rs"]
mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core::capability::{scope::ChioScope, token::CapabilityToken};
use chio_core::PublicKey;
use chio_kernel::{
    CapabilityAuthority, CapabilityAuthorityWorkloadBinding, KernelError, NestedFlowBridge,
    ReceiptStore, SecurityInvocationContext, SecurityInvocationContextV1, ToolCallRequest,
    ToolServerConnection,
};
use chio_security_types::ports::{
    CapabilityIssuanceOperation, IsolationEpochId, LineageId, SessionId, TenantId,
};
use chio_security_types::PrincipalId;
use support::*;

#[test]
fn frozen_bound_delegation_cannot_subscribe_a_live_session() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-frozen-subscription", Some(FROZEN))?;
    let session = fixture.open_for(&token)?;
    let authority = fixture.install()?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI);
    assert!(
        matches!(&result, Err(KernelError::CapabilityIssuanceDenied(reason))
            if reason == "active issuance freeze rejected delegated capability admission: Conflict: store.conflict"),
        "an active frozen lineage must refuse the public subscription: {result:?}"
    );
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    let queries = authority.queries()?;
    let query = queries.last().ok_or("no delegation freeze query")?;
    assert_eq!(query.operation, CapabilityIssuanceOperation::Delegate);
    assert_eq!(query.tenant_id.as_str(), TENANT);
    assert_eq!(query.lineage_id.as_str(), FROZEN);
    assert_eq!(
        query.parent_capability_id.as_ref().map(|id| id.as_str()),
        Some(fixture.root.id.as_str())
    );
    Ok(())
}

#[test]
fn sibling_lineage_can_subscribe_the_registered_resource() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-sibling-subscription", Some(SIBLING))?;
    let session = fixture.open_for(&token)?;
    fixture.install()?;
    fixture
        .kernel
        .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI)?;
    assert!(fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn bound_delegation_without_a_freeze_authority_cannot_subscribe() -> TestResult {
    let fixture = Fixture::new()?;
    let token = fixture.delegated("child-no-authority-subscription", Some(SIBLING))?;
    let session = fixture.open_for(&token)?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI);
    assert!(
        matches!(&result, Err(KernelError::CapabilityIssuanceDenied(reason))
            if reason == "delegated capability issuance admission authority is unavailable"),
        "bound delegation requires its authority on the public subscription: {result:?}"
    );
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn configured_freeze_authority_refuses_delegation_without_signed_binding() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-unbound-configured", None)?;
    let session = fixture.open_for(&token)?;
    fixture.install()?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI);
    assert!(
        matches!(&result, Err(KernelError::CapabilityIssuanceDenied(reason))
            if reason == "signed tenant and lineage binding is required for delegation admission"),
        "configured authority cannot classify an unbound delegation as standalone: {result:?}"
    );
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn delegation_refuses_missing_signed_ancestor_evidence() -> TestResult {
    for bound in [false, true] {
        let mut fixture = Fixture::new()?;
        let token =
            fixture.delegated("child-missing-ancestor-evidence", bound.then_some(SIBLING))?;
        let session = fixture.open_for(&token)?;
        if !bound {
            fixture.install()?;
        }
        fixture.omit_ancestor_evidence()?;
        let result = fixture.kernel.subscribe_session_resource(
            &session,
            &token,
            &token.subject.to_hex(),
            URI,
        );
        let expected = format!(
            "capability root snapshot {} has no signed token evidence",
            fixture.root.id
        );
        assert!(
            matches!(&result, Err(KernelError::GuardDenied(reason)) if *reason == expected),
            "delegation requires its signed ancestor evidence, bound={bound}: {result:?}"
        );
        assert!(!fixture
            .kernel
            .session_has_resource_subscription(&session, URI)?);
    }
    Ok(())
}

#[test]
fn standalone_unbound_delegation_can_subscribe_without_an_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let token = fixture.delegated("child-unbound-standalone", None)?;
    let session = fixture.open_for(&token)?;
    fixture
        .kernel
        .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI)?;
    assert!(fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn already_issued_roots_are_unchanged_by_a_delegation_freeze() -> TestResult {
    for bound in [false, true] {
        let mut fixture = Fixture::new()?;
        let token = if bound {
            fixture.bound_root()?
        } else {
            fixture.root.clone()
        };
        let session = fixture.open_for(&token)?;
        let authority = fixture.install()?;
        fixture.kernel.subscribe_session_resource(
            &session,
            &token,
            &token.subject.to_hex(),
            URI,
        )?;
        assert!(fixture
            .kernel
            .session_has_resource_subscription(&session, URI)?);
        fixture.kernel.register_delegation_parent(&token)?;
        assert!(
            authority.queries()?.is_empty(),
            "an already issued root is not a Delegate operation"
        );
    }
    Ok(())
}

#[test]
fn frozen_bound_delegation_cannot_be_registered_as_a_parent() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-frozen-parent-registration", Some(FROZEN))?;
    assert!(fixture.store.get_capability_snapshot(&token.id)?.is_none());
    let authority = fixture.install()?;
    let result = fixture.kernel.register_delegation_parent(&token);
    assert!(
        matches!(&result, Err(KernelError::CapabilityIssuanceDenied(reason))
            if reason == "active issuance freeze rejected delegated capability admission: Conflict: store.conflict"),
        "public parent registration must reject the frozen delegation: {result:?}"
    );
    assert!(
        fixture.store.get_capability_snapshot(&token.id)?.is_none(),
        "denied registration cannot retain an accepted child snapshot"
    );
    let queries = authority.queries()?;
    let query = queries
        .last()
        .ok_or("no parent-registration freeze query")?;
    assert_eq!(query.operation, CapabilityIssuanceOperation::Delegate);
    assert_eq!(
        query.parent_capability_id.as_ref().map(|id| id.as_str()),
        Some(fixture.root.id.as_str())
    );
    Ok(())
}

struct PinnedWorkloadAuthority {
    key: PublicKey,
    workload: CapabilityAuthorityWorkloadBinding,
}

impl CapabilityAuthority for PinnedWorkloadAuthority {
    fn authority_public_key(&self) -> Result<PublicKey, KernelError> {
        Ok(self.key.clone())
    }

    fn workload_binding(&self) -> Option<CapabilityAuthorityWorkloadBinding> {
        Some(self.workload.clone())
    }

    fn issue_capability(
        &self,
        _subject: &PublicKey,
        _scope: ChioScope,
        _ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        Err(KernelError::CapabilityIssuanceDenied(
            "this test authority only pins already issued capabilities".into(),
        ))
    }
}

struct CountingEchoServer(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for CountingEchoServer {
    fn server_id(&self) -> &str {
        SERVER
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["echo".into()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

#[test]
fn public_tool_invocation_preserves_the_bound_delegation_ban_after_exact_binding() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-public-tool-binding", Some(SIBLING))?;
    let _session = fixture.open_for(&token)?;
    let binding = token.security_binding()?.ok_or("missing signed binding")?;
    let invocations = Arc::new(AtomicUsize::new(0));
    fixture
        .kernel
        .register_tool_server(Box::new(CountingEchoServer(invocations.clone())));
    fixture
        .kernel
        .set_capability_authority(Box::new(PinnedWorkloadAuthority {
            key: fixture.issuer.public_key(),
            workload: CapabilityAuthorityWorkloadBinding {
                tenant_id: binding.tenant_id.clone(),
                workload_id: binding.workload_id.clone(),
                server_id: binding.server_id.clone(),
                signer_public_key: fixture.issuer.public_key(),
            },
        }));
    let authority = fixture.install()?;
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new(binding.tenant_id)?,
        SessionId::new(binding.session_id)?,
        PrincipalId::new(binding.principal_id)?,
        IsolationEpochId::new(binding.isolation_epoch_id)?,
        LineageId::new(binding.lineage_id)?,
        binding.context_generation,
    ));
    let request = ToolCallRequest {
        request_id: "public-bound-delegation-tool".into(),
        agent_id: token.subject.to_hex(),
        capability: token,
        tool_name: "echo".into(),
        server_id: SERVER.into(),
        arguments: serde_json::json!({"message": "checked public tool path"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let result = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context);
    assert!(
        matches!(
            &result,
            Err(KernelError::GuardDenied(reason))
                if reason == "security-bound remote capabilities cannot be delegated"
        ),
        "the public evaluator must refuse the exactly bound delegation: {result:?}"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(
        authority.queries()?.is_empty(),
        "the explicit tool binding ban precedes delegation freeze admission"
    );
    Ok(())
}

#[test]
fn child_rebound_to_a_sibling_lineage_of_a_frozen_parent_is_denied() -> TestResult {
    let mut fixture = Fixture::new()?;
    let parent = fixture.recorded_bound_root(FROZEN)?;
    let token = fixture.delegated_from(&parent, "child-rebound-sibling", Some(SIBLING))?;
    let session = fixture.open_for(&token)?;
    fixture.install()?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI);
    let expected = format!(
        "delegated capability tenant and lineage binding differs from ancestor {}",
        parent.id
    );
    assert!(
        matches!(&result, Err(KernelError::CapabilityIssuanceDenied(reason)) if *reason == expected),
        "a child cannot leave its frozen parent lineage: {result:?}"
    );
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn unbound_child_of_a_bound_parent_is_denied_without_an_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let parent = fixture.recorded_bound_root(SIBLING)?;
    let token = fixture.delegated_from(&parent, "child-unbound-under-bound", None)?;
    let session = fixture.open_for(&token)?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI);
    let expected = format!(
        "delegated capability omits the tenant and lineage binding of ancestor {}",
        parent.id
    );
    assert!(
        matches!(&result, Err(KernelError::CapabilityIssuanceDenied(reason)) if *reason == expected),
        "an unbound child cannot drop its parent binding: {result:?}"
    );
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn child_bound_to_its_parent_lineage_subscribes_under_an_authority() -> TestResult {
    let mut fixture = Fixture::new()?;
    let parent = fixture.recorded_bound_root(SIBLING)?;
    let token = fixture.delegated_from(&parent, "child-same-lineage", Some(SIBLING))?;
    let session = fixture.open_for(&token)?;
    fixture.install()?;
    fixture
        .kernel
        .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI)?;
    assert!(fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn matching_intermediate_cannot_hide_a_frozen_root_binding() -> TestResult {
    let mut fixture = Fixture::new()?;
    let root = fixture.recorded_bound_root(FROZEN)?;
    let (intermediate, holder) = fixture.delegated_by(
        &root,
        &fixture.root_holder,
        "intermediate-rebound",
        Some(SIBLING),
    )?;
    fixture
        .store
        .record_capability_snapshot(&intermediate, Some(&root.id))?;
    let (leaf, _) = fixture.delegated_by(
        &intermediate,
        &holder,
        "leaf-matching-intermediate",
        Some(SIBLING),
    )?;
    let session = fixture.open_for(&leaf)?;
    let authority = fixture.install()?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &leaf, &leaf.subject.to_hex(), URI);
    let expected = format!(
        "delegated capability tenant and lineage binding differs from ancestor {}",
        root.id
    );
    assert!(
        matches!(&result, Err(KernelError::CapabilityIssuanceDenied(reason)) if *reason == expected),
        "a matching intermediate must not hide a different root binding: {result:?}"
    );
    assert!(authority.queries()?.is_empty());
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn matching_root_and_intermediate_bindings_allow_delegation() -> TestResult {
    let mut fixture = Fixture::new()?;
    let root = fixture.recorded_bound_root(SIBLING)?;
    let (intermediate, holder) = fixture.delegated_by(
        &root,
        &fixture.root_holder,
        "intermediate-matching-root",
        Some(SIBLING),
    )?;
    fixture
        .store
        .record_capability_snapshot(&intermediate, Some(&root.id))?;
    let (leaf, _) =
        fixture.delegated_by(&intermediate, &holder, "leaf-matching-chain", Some(SIBLING))?;
    let session = fixture.open_for(&leaf)?;
    let authority = fixture.install()?;
    fixture
        .kernel
        .subscribe_session_resource(&session, &leaf, &leaf.subject.to_hex(), URI)?;
    assert_eq!(authority.queries()?.len(), 1);
    assert!(fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}
