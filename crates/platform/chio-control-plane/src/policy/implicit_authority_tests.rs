use super::load_policy;
use chio_core::capability::{scope::ChioScope, token::CapabilityToken};
use chio_core::{Keypair, PublicKey};
use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolCallRequest, ToolCallResponse,
    ToolServerConnection, Verdict,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct ReadServer(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for ReadServer {
    fn server_id(&self) -> &str {
        "kg5-reader"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["inspect".to_owned(), "other".to_owned()]
    }

    fn tool_is_read_only(&self, tool_name: &str) -> bool {
        matches!(tool_name, "inspect" | "other")
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"observed_tool": tool_name}))
    }
}

struct Fixture {
    kernel: ChioKernel,
    subject: PublicKey,
    capabilities: Vec<CapabilityToken>,
    invocations: Arc<AtomicUsize>,
    policy_hash: String,
    // Keep the real SQLite stores' directory alive until after kernel drop.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn load(yaml: &str, parent: Option<&str>) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("policy.yaml");
        std::fs::write(&path, yaml)?;
        if let Some(parent) = parent {
            std::fs::write(directory.path().join("parent.yaml"), parent)?;
        }
        let loaded = load_policy(&path)?;
        let defaults = loaded.default_capabilities.clone();
        let policy_hash = loaded.identity.runtime_hash.clone();
        let issuer = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let mut kernel = crate::build_kernel(loaded, &issuer);
        crate::configure_receipt_store(
            &mut kernel,
            Some(&directory.path().join("receipts.sqlite3")),
            None,
            None,
        )?;
        crate::configure_revocation_store(
            &mut kernel,
            Some(&directory.path().join("revocations.sqlite3")),
            None,
            None,
        )?;
        let invocations = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(ReadServer(Arc::clone(&invocations))));
        let capabilities = crate::issue_default_capabilities(&kernel, &subject, &defaults)?;
        for capability in &capabilities {
            assert!(capability.verify_signature()?);
            assert_eq!(capability.subject, subject);
        }
        Ok(Self {
            kernel,
            subject,
            capabilities,
            invocations,
            policy_hash,
            _directory: directory,
        })
    }

    fn call(&self, capability: CapabilityToken, tool_name: &str) -> TestResult<ToolCallResponse> {
        let response = self.kernel.evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: format!("kg5-{}-{tool_name}", capability.id),
            agent_id: self.subject.to_hex(),
            capability,
            tool_name: tool_name.to_owned(),
            server_id: "kg5-reader".to_owned(),
            arguments: serde_json::json!({}),
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
        })?;
        assert_eq!(response.receipt.policy_hash, self.policy_hash);
        Ok(response)
    }
}

#[test]
fn kg5_load_and_issue_requires_enabled_tool_rules() -> TestResult {
    let mut widened = Vec::new();
    for (name, rules) in [
        ("missing-rules", ""),
        ("empty-rules", "rules: {}"),
        ("guard-only", "rules:\n  shell_commands:\n    enabled: true"),
        (
            "disabled-tools",
            "rules:\n  tool_access:\n    enabled: false\n    default: allow",
        ),
    ] {
        let fixture = Fixture::load(&format!("hushspec: \"0.1.0\"\n{rules}\n"), None)?;
        let capability = match fixture.capabilities.first() {
            Some(capability) => capability.clone(),
            None => fixture
                .kernel
                .issue_capability(&fixture.subject, ChioScope::default(), 300)?,
        };
        let response = fixture.call(capability, "other")?;
        let invocations = fixture.invocations.load(Ordering::SeqCst);
        if !fixture.capabilities.is_empty() || response.verdict != Verdict::Deny || invocations != 0
        {
            widened.push((
                name,
                fixture.capabilities.len(),
                response.verdict,
                invocations,
            ));
        }
    }
    assert!(
        widened.is_empty(),
        "implicit authority reached issuance/dispatch: {widened:?}"
    );
    Ok(())
}

#[test]
fn kg5_explicit_permissive_policy_issues_usable_authority() -> TestResult {
    for yaml in [
        "hushspec: \"0.1.0\"\nrules:\n  tool_access:\n    enabled: true\n    default: allow\n",
        chio_policy::builtin_yaml("permissive").ok_or("missing permissive builtin")?,
    ] {
        let fixture = Fixture::load(yaml, None)?;
        assert_eq!(fixture.capabilities.len(), 1);
        let response = fixture.call(fixture.capabilities[0].clone(), "other")?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn kg5_inherited_allowlist_issues_only_declared_tool_authority() -> TestResult {
    let fixture = Fixture::load(
        "hushspec: \"0.1.0\"\nextends: parent.yaml\n",
        Some("hushspec: \"0.1.0\"\nrules:\n  tool_access:\n    default: block\n    allow: [inspect]\n"),
    )?;
    assert_eq!(fixture.capabilities.len(), 1);
    let capability = fixture.capabilities[0].clone();
    assert_eq!(
        fixture.call(capability.clone(), "inspect")?.verdict,
        Verdict::Allow
    );
    assert_eq!(fixture.call(capability, "other")?.verdict, Verdict::Deny);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn kg5_disabling_inherited_tool_rules_cannot_widen_issuance() -> TestResult {
    let fixture = Fixture::load(
        "hushspec: \"0.1.0\"\nextends: parent.yaml\nrules:\n  tool_access:\n    enabled: false\n",
        Some("hushspec: \"0.1.0\"\nrules:\n  tool_access:\n    default: block\n    allow: [inspect]\n"),
    )?;
    assert!(fixture.capabilities.is_empty());
    Ok(())
}
