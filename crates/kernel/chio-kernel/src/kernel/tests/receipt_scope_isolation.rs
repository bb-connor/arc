//! Receipt authority must belong to an evaluation, not its executor thread.

use super::*;
use std::sync::Arc;
use tokio::sync::Notify;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
struct Gates {
    anonymous_started: Notify,
    tenant_started: Notify,
    release_anonymous: Notify,
    release_tenant: Notify,
}

struct GatedServer(Arc<Gates>);

#[async_trait::async_trait]
impl ToolServerConnection for GatedServer {
    fn server_id(&self) -> &str {
        "scope-server"
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
        if arguments["anonymous"] == true {
            self.0.anonymous_started.notify_one();
            self.0.release_anonymous.notified().await;
        } else {
            self.0.anonymous_started.notified().await;
            self.0.tenant_started.notify_one();
            self.0.release_anonymous.notify_one();
            self.0.release_tenant.notified().await;
        }
        Ok(arguments)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn anonymous_async_receipt_cannot_inherit_a_concurrent_tenant() -> TestResult {
    concurrent_receipts(false).await
}

#[tokio::test(flavor = "current_thread")]
async fn anonymous_nested_receipt_cannot_inherit_a_concurrent_tenant() -> TestResult {
    concurrent_receipts(true).await
}

fn operation(request: &ToolCallRequest) -> ToolCallOperation {
    ToolCallOperation {
        capability: request.capability.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    }
}

fn client() -> MockNestedFlowClient {
    MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".into(),
            content: serde_json::json!({"text": "unused"}),
            model: "unused".into(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    }
}

async fn concurrent_receipts(anonymous_nested: bool) -> TestResult {
    let mut kernel = make_kernel(make_config());
    let gates = Arc::new(Gates::default());
    kernel.register_tool_server(Box::new(GatedServer(Arc::clone(&gates))));
    let subject = make_keypair();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("scope-server", "echo")]),
        300,
    );
    let session = kernel.open_session(subject.public_key().to_hex(), vec![cap.clone()])?;
    kernel.set_session_auth_context(&session, oauth_auth_with_enterprise_tenant("tenant-B"))?;
    kernel.activate_session(&session)?;
    // Equal correlation IDs are legal across unrelated evaluation namespaces.
    let anonymous = make_request_with_arguments(
        "shared-correlation-id",
        &cap,
        "echo",
        "scope-server",
        serde_json::json!({"anonymous": true}),
    );
    let tenant = make_request_with_arguments(
        "shared-correlation-id",
        &cap,
        "echo",
        "scope-server",
        serde_json::json!({"anonymous": false}),
    );
    let context = OperationContext::new(
        session,
        RequestId::new(tenant.request_id.clone()),
        tenant.agent_id.clone(),
    );
    let anonymous_session =
        kernel.open_session(subject.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&anonymous_session)?;
    let anonymous_context = OperationContext::new(
        anonymous_session,
        RequestId::new(anonymous.request_id.clone()),
        anonymous.agent_id.clone(),
    );
    let anonymous_operation = operation(&anonymous);
    let tenant_operation = operation(&tenant);
    let mut anonymous_client = client();
    let mut tenant_client = client();
    let (anonymous, tenant) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            async {
                let result = if anonymous_nested {
                    Box::pin(
                        kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
                            &anonymous_context,
                            &anonymous_operation,
                            &mut anonymous_client,
                        ),
                    )
                    .await
                } else {
                    Box::pin(kernel.evaluate_tool_call(&anonymous)).await
                };
                gates.release_tenant.notify_one();
                result
            },
            Box::pin(
                kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
                    &context,
                    &tenant_operation,
                    &mut tenant_client,
                )
            )
        )
    })
    .await?;
    let anonymous = anonymous?;
    let tenant = tenant?;
    assert_eq!(anonymous.verdict, Verdict::Allow);
    assert_eq!(tenant.verdict, Verdict::Allow);
    assert_eq!(anonymous.receipt.tenant_id, None);
    assert_eq!(tenant.receipt.tenant_id.as_deref(), Some("tenant-B"));
    assert!(anonymous.receipt.verify_signature()?);
    assert!(tenant.receipt.verify_signature()?);
    assert!(kernel.receipt_tenant_ids.is_empty());
    Ok(())
}

fn federation(remote: &str) -> ReceiptFederationAdmission {
    ReceiptFederationAdmission {
        remote_kernel_id: Some(remote.into()),
        peer: None,
        verified_treaty_material: None,
    }
}

fn assert_scope(tenant: Option<&str>, remote: Option<&str>) {
    assert_eq!(current_scoped_receipt_tenant_id().as_deref(), tenant);
    assert_eq!(
        current_scoped_receipt_federation_admission()
            .as_ref()
            .and_then(|admission| admission.remote_kernel_id.as_deref()),
        remote,
    );
}

#[tokio::test(flavor = "current_thread")]
async fn nested_receipt_evaluations_clear_and_restore_both_authority_scopes() {
    let _tenant = scope_receipt_tenant_id(Some("ambient".into()));
    let _federation = scope_receipt_federation_admission(Some(federation("ambient-peer")));
    scope_async_receipt_context(async {
        assert_scope(None, None);
        let _tenant = scope_receipt_tenant_id(Some("parent".into()));
        let _federation = scope_receipt_federation_admission(Some(federation("parent-peer")));
        scope_async_receipt_context(async {
            assert_scope(None, None);
            let _tenant = scope_receipt_tenant_id(Some("child".into()));
            let _federation = scope_receipt_federation_admission(Some(federation("child-peer")));
            tokio::task::yield_now().await;
            assert_scope(Some("child"), Some("child-peer"));
        })
        .await;
        assert_scope(Some("parent"), Some("parent-peer"));
        {
            let _tenant = scope_receipt_tenant_id(None);
            let _federation = scope_receipt_federation_admission(None);
            tokio::task::yield_now().await;
            assert_scope(None, None);
        }
        assert_scope(Some("parent"), Some("parent-peer"));
    })
    .await;
    assert_scope(Some("ambient"), Some("ambient-peer"));
}

#[test]
fn suspended_receipt_context_migrates_and_cleans_up_on_its_own_context() -> TestResult {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    for complete in [false, true] {
        let _tenant = scope_receipt_tenant_id(Some("first-thread".into()));
        let _federation = scope_receipt_federation_admission(Some(federation("first-peer")));
        let release = Arc::new(AtomicBool::new(false));
        let evaluation_release = Arc::clone(&release);
        let mut evaluation = Box::pin(scope_async_receipt_context(async move {
            let _tenant = scope_receipt_tenant_id(Some("evaluation".into()));
            let _federation =
                scope_receipt_federation_admission(Some(federation("evaluation-peer")));
            std::future::poll_fn(|_| {
                assert_scope(Some("evaluation"), Some("evaluation-peer"));
                if evaluation_release.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }));
        assert!(evaluation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert_scope(Some("first-thread"), Some("first-peer"));
        std::thread::scope(|threads| {
            threads
                .spawn(move || {
                    let _tenant = scope_receipt_tenant_id(Some("second-thread".into()));
                    let _federation =
                        scope_receipt_federation_admission(Some(federation("second-peer")));
                    release.store(complete, Ordering::SeqCst);
                    assert_eq!(
                        evaluation
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop()))
                            .is_ready(),
                        complete,
                    );
                    assert_scope(Some("second-thread"), Some("second-peer"));
                    drop(evaluation);
                    assert_scope(Some("second-thread"), Some("second-peer"));
                })
                .join()
                .map_err(|_| "receipt context migration thread panicked")
        })?;
        assert_scope(Some("first-thread"), Some("first-peer"));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_a_suspended_evaluation_does_not_clear_the_current_one() {
    use std::future::Future;
    use std::task::{Context, Waker};

    let mut abandoned = Box::pin(scope_async_receipt_context(async {
        let _tenant = scope_receipt_tenant_id(Some("abandoned".into()));
        let _federation = scope_receipt_federation_admission(Some(federation("abandoned-peer")));
        std::future::pending::<()>().await;
    }));
    assert!(abandoned
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    scope_async_receipt_context(async {
        let _tenant = scope_receipt_tenant_id(Some("current".into()));
        let _federation = scope_receipt_federation_admission(Some(federation("current-peer")));
        drop(abandoned);
        tokio::task::yield_now().await;
        assert_scope(Some("current"), Some("current-peer"));
    })
    .await;
    assert_scope(None, None);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_session_evaluation_releases_only_its_receipt_context() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let gates = Arc::new(Gates::default());
    kernel.register_tool_server(Box::new(GatedServer(Arc::clone(&gates))));
    let subject = make_keypair();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("scope-server", "echo")]),
        300,
    );
    let session = kernel.open_session(subject.public_key().to_hex(), vec![cap.clone()])?;
    kernel.set_session_auth_context(&session, oauth_auth_with_enterprise_tenant("cancelled"))?;
    kernel.activate_session(&session)?;
    let request = make_request_with_arguments(
        "cancelled-evaluation",
        &cap,
        "echo",
        "scope-server",
        serde_json::json!({"anonymous": false}),
    );
    let context = OperationContext::new(
        session,
        RequestId::new(&request.request_id),
        request.agent_id.clone(),
    );
    let operation = operation(&request);
    let mut client = client();
    let _tenant = scope_receipt_tenant_id(Some("host-thread".into()));
    let _federation = scope_receipt_federation_admission(Some(federation("host-peer")));
    let mut evaluation = Box::pin(
        kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
            &context,
            &operation,
            &mut client,
        ),
    );
    gates.anonymous_started.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            _ = gates.tenant_started.notified() => Ok(()),
            _ = &mut evaluation => Err("evaluation did not remain suspended at the tool"),
        }
    })
    .await??;
    assert_scope(Some("host-thread"), Some("host-peer"));
    drop(evaluation);
    assert_scope(Some("host-thread"), Some("host-peer"));
    assert!(kernel.receipt_tenant_ids.is_empty());
    assert!(kernel.receipt_federation_admissions.is_empty());
    // This verifies receipt-scope cleanup, not complete session-operation
    // cancellation or durable tool-outcome recovery.
    Ok(())
}
