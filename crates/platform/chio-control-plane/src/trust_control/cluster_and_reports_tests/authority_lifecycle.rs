//! Lifecycle transitions must change real admission through both peer consumers.
use super::*;
use chio_kernel::{
    CapabilityAuthority, KernelError, ToolCallRequest, ToolServerConnection, Verdict,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct FaultClock {
    failed: AtomicBool,
    inner: Arc<dyn Clock>,
}
impl Clock for FaultClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.failed.load(Ordering::SeqCst) {
            Err(ClockError::Unavailable)
        } else {
            self.inner.read()
        }
    }
}

struct Effects(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for Effects {
    fn server_id(&self) -> &str {
        "test-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["echo".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

fn request(capability: &CapabilityToken, id: &str) -> ToolCallRequest {
    ToolCallRequest {
        request_id: id.into(),
        capability: capability.clone(),
        tool_name: "echo".into(),
        server_id: "test-server".into(),
        agent_id: capability.subject.to_hex(),
        arguments: json!({"message":"authorized"}),
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
    }
}

fn full_import(
    state: &TrustServiceState,
    template: &Value,
    signed: AuthoritySnapshotView,
) -> Result<(), CliError> {
    let mut full: ClusterStateSnapshotResponse = serde_json::from_value(template.clone())?;
    full.authority = Some(signed);
    apply_cluster_snapshot(state, "http://127.0.0.1:3301", full)?;
    Ok(())
}

#[test]
fn kg2_build_kernel_follows_both_import_paths_and_retains_receipt_evidence() -> TestResult {
    let root = chio_test_support::private_tempdir()?;
    let source = SqliteCapabilityAuthority::open(root.path().join("source.db"))?;
    let follower_path = root.path().join("follower.db");
    let follower = SqliteCapabilityAuthority::open(&follower_path)?;
    let recovery = Keypair::generate();
    let anchor = source
        .initialize_replication_with_recovery("live-admission", Some(&recovery.public_key()))?;
    follower.pin_replication_anchor(&anchor)?;
    let mut state = state_with_cluster(
        "http://127.0.0.1:3300",
        &["http://127.0.0.1:3301"],
        None,
        None,
        None,
    );
    let template = serde_json::to_value(build_cluster_state_snapshot(&state)?)?;
    state.config.authority_db_path = Some(follower_path.clone());
    let policy = root.path().join("kernel.yaml");
    std::fs::write(
        &policy,
        "kernel:\n  allow_ephemeral_receipt_log: true\n  allow_ephemeral_revocation_store: true\n",
    )?;
    let admission = crate::DurableAdmissionRuntime::open(&root.path().join("admission.db"))?;
    let receipt_signer = admission.kernel_keypair();
    let mut kernel = crate::build_kernel(crate::policy::load_policy(&policy)?, &receipt_signer);
    admission.attach(&mut kernel)?;
    let fault = Arc::new(FaultClock {
        failed: AtomicBool::new(false),
        inner: chio_test_support::clock::clock(),
    });
    kernel.set_capability_authority(Box::new(SqliteCapabilityAuthority::open_with_clock(
        &follower_path,
        fault.clone(),
    )?));
    let effects = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(Effects(effects.clone())));
    let scope: ChioScope = serde_json::from_value(json!({"grants":[{
        "server_id":"test-server", "tool_name":"echo", "operations":["invoke"], "constraints":[]
    }], "resource_grants":[], "prompt_grants":[]}))?;
    let subject = Keypair::generate().public_key();
    let a = source.issue_capability(&subject, scope.clone(), 300)?;
    let allowed = kernel.evaluate_tool_call_blocking(&request(&a, "before-rotation"))?;
    assert_eq!(allowed.verdict, Verdict::Allow, "{:?}", allowed.reason);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    source.rotate()?;
    let rotation = source.signed_snapshot()?;
    super::authority_replication::pull_snapshot(&state, &rotation)?;
    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&request(&a, "during-grace"))?
            .verdict,
        Verdict::Allow
    );
    assert_eq!(effects.load(Ordering::SeqCst), 2);
    let b = source.issue_capability(&subject, scope.clone(), 300)?;
    source.retire_issuer(&a.issuer)?;
    full_import(&state, &template, source.signed_snapshot()?)?;
    let denied = kernel.evaluate_tool_call_blocking(&request(&a, "retired"))?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("issuer lifecycle denied")));
    assert_eq!(effects.load(Ordering::SeqCst), 2);
    assert!(allowed.receipt.verify_signature()?);
    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&request(&b, "new-head"))?
            .verdict,
        Verdict::Allow
    );
    source.revoke_issuer(&a.issuer)?;
    super::authority_replication::pull_snapshot(&state, &source.signed_snapshot()?)?;
    for full in [false, true] {
        let result = if full {
            full_import(&state, &template, rotation.clone())
        } else {
            super::authority_replication::pull_snapshot(&state, &rotation)
        };
        assert!(
            matches!(result, Err(CliError::AuthorityStore(chio_kernel::AuthorityStoreError::Fence(message))) if message == "authority replay regression")
        );
    }
    source.recover_authority(&recovery)?;
    full_import(&state, &template, source.signed_snapshot()?)?;
    let denied = kernel.evaluate_tool_call_blocking(&request(&b, "revoked-by-recovery"))?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("issuer lifecycle denied")));
    assert_eq!(effects.load(Ordering::SeqCst), 3);
    let c = source.issue_capability(&subject, scope, 300)?;
    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&request(&c, "recovered-head"))?
            .verdict,
        Verdict::Allow
    );
    assert_eq!(effects.load(Ordering::SeqCst), 4);
    fault.failed.store(true, Ordering::SeqCst);
    let denied = kernel.evaluate_tool_call_blocking(&request(&c, "failed-authority-clock"))?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("trusted clock unavailable")));
    assert_eq!(effects.load(Ordering::SeqCst), 4);
    assert!(allowed.receipt.verify_signature()?);
    Ok(())
}
