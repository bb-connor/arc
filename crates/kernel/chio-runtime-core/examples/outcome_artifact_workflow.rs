//! Run with `cargo run -p chio-runtime-core --example outcome_artifact_workflow`.
//! The optional first argument is a new output directory. This local experiment
//! uses two kernel identities and an owner-selected native scope contract. It
//! does not execute candidate code or change the repository being worked on.

use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::capability::attenuation::validate_attenuation;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolCallResponse,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_runtime_core::outcome_continuation::{
    ArtifactOutcome, OutcomeEffectArguments, OutcomeEffectRequest, OutcomeEffectRule,
    OutcomeEffectSlot, OutcomeEffectState, SignedArtifactOutcome, ARTIFACT_OUTCOME_SCHEMA,
};
use chio_runtime_core::SqliteRuntimeOrchestrationStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

type DemoResult<T> = Result<T, Box<dyn Error>>;

#[path = "outcome_artifact_workflow/verify.rs"]
mod verify;

fn now_ms() -> DemoResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn kernel_error(error: impl std::fmt::Display) -> KernelError {
    KernelError::ToolServerError(error.to_string())
}

fn tool_scope(server: &str, tool: &str) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: server.into(),
            tool_name: tool.into(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeContract {
    schema: String,
    ceiling: ChioScope,
    required: ChioScope,
}

impl ScopeContract {
    fn accepts(&self, artifact: &[u8]) -> bool {
        let Ok(candidate) = serde_json::from_slice::<ChioScope>(artifact) else {
            return false;
        };
        validate_attenuation(&self.ceiling, &candidate).is_ok()
            && validate_attenuation(&candidate, &self.required).is_ok()
    }
}

/// The owner picks the contract, destination slot, and verifier key at startup.
/// The caller can propose only artifact bytes; it cannot choose an easier test.
struct ContractVerifier {
    key: Keypair,
    rule: OutcomeEffectRule,
    contract: ScopeContract,
}

#[async_trait::async_trait]
impl ToolServerConnection for ContractVerifier {
    fn server_id(&self) -> &str {
        "contract-verifier"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["verify_scope".into()]
    }
    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        if tool != "verify_scope" {
            return Err(kernel_error("unknown verifier tool"));
        }
        let bytes = arguments
            .get("artifact")
            .and_then(Value::as_str)
            .ok_or_else(|| kernel_error("artifact text missing"))?
            .as_bytes();
        if bytes.len() > 64 * 1024 {
            return Err(kernel_error("artifact exceeds verifier bound"));
        }
        let outcome = SignedArtifactOutcome::sign(
            ArtifactOutcome {
                schema: ARTIFACT_OUTCOME_SCHEMA.into(),
                slot: self.rule.slot.clone(),
                predecessor_step_id: self.rule.predecessor_step_id.clone(),
                contract_sha256: self.rule.contract_sha256.clone(),
                artifact_sha256: sha256_hex(bytes),
                passed: self.contract.accepts(bytes),
                verified_at_unix_ms: now_ms().map_err(kernel_error)?,
            },
            &self.key,
        )
        .map_err(kernel_error)?;
        serde_json::to_value(outcome).map_err(kernel_error)
    }
}

/// The registered kernel tool owns the final claim and effect boundary. There
/// is no separately registered raw publishing tool that bypasses this gate.
struct ApprovedArtifactPublisher {
    root: PathBuf,
    store: Arc<SqliteRuntimeOrchestrationStore>,
    effects: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for ApprovedArtifactPublisher {
    fn server_id(&self) -> &str {
        "artifact-registry"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["publish".into()]
    }
    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let request: OutcomeEffectRequest =
            serde_json::from_value(arguments).map_err(kernel_error)?;
        self.store
            .preview_outcome_effect(
                &request,
                self.server_id(),
                tool,
                now_ms().map_err(kernel_error)?,
            )
            .map_err(kernel_error)?;
        // Preview validates the fixed-length hex digest before using it as a
        // filename. Read once and publish those same hashed bytes, eliminating
        // a path re-read between verification and the external write.
        let path = self
            .root
            .join("artifacts")
            .join(format!("{}.json", request.arguments.artifact_sha256));
        let file = std::fs::File::open(path).map_err(kernel_error)?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(file, 64 * 1024 + 1), &mut bytes)
            .map_err(kernel_error)?;
        if bytes.len() > 64 * 1024 || sha256_hex(&bytes) != request.arguments.artifact_sha256 {
            return Err(kernel_error(
                "artifact bytes do not match the verified outcome",
            ));
        }
        let permit = self
            .store
            .claim_outcome_effect(
                &request,
                self.server_id(),
                tool,
                "kernel-publish-dispatch",
                now_ms().map_err(kernel_error)?,
            )
            .map_err(kernel_error)?;
        self.effects.fetch_add(1, Ordering::SeqCst);
        let mut published = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("publication.log"))
            .map_err(kernel_error)?;
        writeln!(
            published,
            "{}",
            serde_json::to_string(&request.arguments).map_err(kernel_error)?
        )
        .map_err(kernel_error)?;
        published.sync_all().map_err(kernel_error)?;
        let mut approved = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.root.join("approved.scope.json"))
            .map_err(kernel_error)?;
        approved.write_all(&bytes).map_err(kernel_error)?;
        approved.sync_all().map_err(kernel_error)?;
        #[cfg(unix)]
        std::fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(kernel_error)?;
        let result = json!({
            "publishedArtifactSha256": request.arguments.artifact_sha256,
            "resource": request.arguments.resource,
            "effectClaim": permit.claim(),
        });
        self.store
            .complete_outcome_effect(permit, &result)
            .map_err(kernel_error)?;
        Ok(result)
    }
}

fn kernel(key: Keypair, receipts: &Path) -> DemoResult<ChioKernel> {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: key,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"outcome-artifact-local-experiment"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
    });
    let store = chio_store_sqlite::SqliteReceiptStore::open(receipts)?;
    store.wait_for_writer_ready(std::time::Duration::from_secs(5))?;
    kernel.set_receipt_store_handle(Arc::new(store))?;
    Ok(kernel)
}

/// Every attempt uses a newly issued receiver capability and a fresh agent key.
/// Logical slot consumption must survive those changes.
fn invoke(
    kernel: &ChioKernel,
    id: &str,
    server: &str,
    tool: &str,
    arguments: Value,
) -> DemoResult<ToolCallResponse> {
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(&agent.public_key(), tool_scope(server, tool), 300)?;
    Ok(kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: id.into(),
        agent_id: agent.public_key().to_hex(),
        capability,
        server_id: server.into(),
        tool_name: tool.into(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        declassification_grant: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })?)
}

fn verify_candidate(
    kernel: &ChioKernel,
    id: &str,
    bytes: &[u8],
) -> DemoResult<(SignedArtifactOutcome, ToolCallResponse)> {
    let response = invoke(
        kernel,
        id,
        "contract-verifier",
        "verify_scope",
        json!({"artifact": std::str::from_utf8(bytes)?}),
    )?;
    if response.verdict != Verdict::Allow {
        return Err(format!("verifier denied: {:?}", response.reason).into());
    }
    let Some(chio_kernel::ToolCallOutput::Value(output)) = response.output.as_ref() else {
        return Err("verifier did not return a complete value".into());
    };
    let evidence = serde_json::from_value(output.clone())?;
    Ok((evidence, response))
}

fn effect_request(evidence: SignedArtifactOutcome, resource: &str) -> OutcomeEffectRequest {
    OutcomeEffectRequest {
        arguments: OutcomeEffectArguments {
            artifact_sha256: evidence.body.artifact_sha256.clone(),
            resource: resource.into(),
        },
        evidence,
    }
}

fn save(root: &Path, name: &str, value: &impl Serialize) -> DemoResult<()> {
    std::fs::write(root.join(name), serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn run(root: &Path) -> DemoResult<Value> {
    std::fs::create_dir(root.join("artifacts"))?;
    let verifier_key = Keypair::generate();
    let publisher_key = Keypair::generate();
    let expected = tool_scope("source-checkout", "read");
    let contract = ScopeContract {
        schema: "scope-contract.experimental.v1".into(),
        ceiling: expected.clone(),
        required: expected.clone(),
    };
    let now = now_ms()?;
    let rule = OutcomeEffectRule {
        slot: OutcomeEffectSlot {
            receiver_id: publisher_key.public_key().to_hex(),
            workflow_id: "repair-read-policy".into(),
            step_id: "publish-approved-scope".into(),
        },
        predecessor_step_id: "verify-owner-scope-contract".into(),
        verifier_key: verifier_key.public_key(),
        contract_sha256: sha256_hex(&canonical_json_bytes(&contract)?),
        server_id: "artifact-registry".into(),
        tool_name: "publish".into(),
        resource: "review-queue".into(),
        valid_from_unix_ms: now,
        valid_until_unix_ms: now + 300_000,
    };
    save(root, "owner-contract.json", &contract)?;
    save(root, "receiver-rule.json", &rule)?;
    let mut verifier = kernel(verifier_key.clone(), &root.join("verifier-receipts.db"))?;
    verifier.register_tool_server(Box::new(ContractVerifier {
        key: verifier_key,
        rule: rule.clone(),
        contract,
    }));
    let broad = canonical_json_bytes(&tool_scope("*", "*"))?;
    let repaired = canonical_json_bytes(&expected)?;
    for bytes in [&broad, &repaired] {
        std::fs::write(
            root.join("artifacts")
                .join(format!("{}.json", sha256_hex(bytes))),
            bytes,
        )?;
    }
    let (failed, failed_receipt) =
        verify_candidate(&verifier, "worker-1-overbroad-policy", &broad)?;
    let (passed, passed_receipt) =
        verify_candidate(&verifier, "worker-2-repaired-policy", &repaired)?;
    if failed.body.passed || !passed.body.passed {
        return Err("owner-selected policy contract did not distinguish the repair".into());
    }
    save(
        root,
        "failed-verification-receipt.json",
        &failed_receipt.receipt,
    )?;
    save(
        root,
        "passed-verification-receipt.json",
        &passed_receipt.receipt,
    )?;
    save(root, "verified-outcome.json", &passed)?;
    drop(verifier);

    let effects = Arc::new(AtomicU64::new(0));
    let open_publisher = || -> DemoResult<ChioKernel> {
        let store = Arc::new(SqliteRuntimeOrchestrationStore::open(
            root.join("publisher-state.db"),
        )?);
        store.activate_outcome_effect(&rule)?;
        let mut receiver = kernel(publisher_key.clone(), &root.join("publisher-receipts.db"))?;
        receiver.register_tool_server(Box::new(ApprovedArtifactPublisher {
            root: root.into(),
            store,
            effects: effects.clone(),
        }));
        Ok(receiver)
    };
    let publisher = open_publisher()?;
    let reject = invoke(
        &publisher,
        "delivery-1-failed-proof",
        "artifact-registry",
        "publish",
        serde_json::to_value(effect_request(failed, &rule.resource))?,
    )?;
    if reject.verdict == Verdict::Allow || effects.load(Ordering::SeqCst) != 0 {
        return Err("failed artifact reached the effect".into());
    }
    let mut substitution = effect_request(passed.clone(), &rule.resource);
    substitution.arguments.artifact_sha256 = sha256_hex(&broad);
    let reject_substitution = invoke(
        &publisher,
        "delivery-2-substituted-artifact",
        "artifact-registry",
        "publish",
        serde_json::to_value(substitution)?,
    )?;
    if reject_substitution.verdict == Verdict::Allow || effects.load(Ordering::SeqCst) != 0 {
        return Err("substituted artifact reached the effect".into());
    }
    let accepted = invoke(
        &publisher,
        "delivery-3-verified-artifact",
        "artifact-registry",
        "publish",
        serde_json::to_value(effect_request(passed.clone(), &rule.resource))?,
    )?;
    if accepted.verdict != Verdict::Allow || effects.load(Ordering::SeqCst) != 1 {
        return Err(format!("verified publication failed: {:?}", accepted.reason).into());
    }
    if !accepted.receipt.verify_signature()? {
        return Err("publication receipt signature invalid".into());
    }
    let Some(chio_kernel::ToolCallOutput::Value(result)) = accepted.output.as_ref() else {
        return Err("publication did not return a complete result".into());
    };
    if accepted.receipt.content_hash != sha256_hex(&canonical_json_bytes(result)?) {
        return Err("publication result is not bound to its kernel receipt".into());
    }
    save(root, "publication-result.json", result)?;
    save(root, "publication-receipt.json", &accepted.receipt)?;
    drop(publisher);

    let replacement = open_publisher()?;
    let replay = invoke(
        &replacement,
        "replacement-agent-fresh-capability",
        "artifact-registry",
        "publish",
        serde_json::to_value(effect_request(passed, &rule.resource))?,
    )?;
    if replay.verdict == Verdict::Allow || effects.load(Ordering::SeqCst) != 1 {
        return Err("replacement agent recreated effect authority".into());
    }
    save(root, "replacement-denial-receipt.json", &replay.receipt)?;
    drop(replacement);
    let status = SqliteRuntimeOrchestrationStore::open(root.join("publisher-state.db"))?
        .outcome_effect_status(&rule.slot)?;
    if !matches!(status.state, OutcomeEffectState::Completed { .. }) {
        return Err("publication result did not survive reopening".into());
    }
    let published = std::fs::read(root.join("approved.scope.json"))?;
    let lines = std::fs::read_to_string(root.join("publication.log"))?
        .lines()
        .count();
    if sha256_hex(&published) != sha256_hex(&repaired) || lines != 1 {
        return Err("publication bytes or physical effect count differ".into());
    }
    let summary = json!({
        "experiment": "receiver-owned-outcome-continuation",
        "artifact": "repaired Chio capability scope", "artifactSha256": sha256_hex(&published),
        "contractSha256": rule.contract_sha256,
        "failedCandidatePublished": false, "substitutedArtifactPublished": false,
        "verifiedArtifactPublished": true, "receiverReopened": true,
        "replacementAgentPublishedAgain": false, "physicalPublicationRecords": lines,
        "verifierKey": rule.verifier_key, "publisherKey": publisher_key.public_key(),
        "limits": ["Local in-process kernels, not independently operated remote hosts", "Verifier remains trusted for the native scope contract", "No matched baseline or integration-cost result yet", "Receipt logs are persistent; this demo does not qualify full kernel crash recovery"]
    });
    save(root, "summary.json", &summary)?;
    Ok(summary)
}

fn main() -> DemoResult<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--verify") {
        if args.len() != 4 {
            return Err(
                "usage: --verify DIRECTORY PUBLISHER_PUBLIC_KEY VERIFIER_PUBLIC_KEY".into(),
            );
        }
        let publisher = PublicKey::from_hex(args[2].to_str().ok_or("publisher key is not UTF-8")?)?;
        let verifier = PublicKey::from_hex(args[3].to_str().ok_or("verifier key is not UTF-8")?)?;
        let report = verify::export(&PathBuf::from(&args[1]), &publisher, &verifier)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args.len() > 1 {
        return Err("usage: outcome_artifact_workflow [NEW_OUTPUT_DIRECTORY]".into());
    }
    let root = if let Some(path) = args.first() {
        let path = PathBuf::from(path);
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        path
    } else {
        tempfile::tempdir()?.keep()
    };
    let summary = run(&root)?;
    let publisher = PublicKey::from_hex(
        summary["publisherKey"]
            .as_str()
            .ok_or("publisher key absent")?,
    )?;
    let verifier = PublicKey::from_hex(
        summary["verifierKey"]
            .as_str()
            .ok_or("verifier key absent")?,
    )?;
    save(
        &root,
        "offline-verification.json",
        &verify::export(&root, &publisher, &verifier)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    println!("Artifacts: {}", root.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn repaired_policy_crosses_the_verified_outcome_boundary_once() -> super::DemoResult<()> {
        let directory = tempfile::tempdir()?;
        let summary = super::run(directory.path())?;
        let publisher = super::PublicKey::from_hex(
            summary["publisherKey"]
                .as_str()
                .ok_or("publisher key absent")?,
        )?;
        let verifier = super::PublicKey::from_hex(
            summary["verifierKey"]
                .as_str()
                .ok_or("verifier key absent")?,
        )?;
        super::verify::export(directory.path(), &publisher, &verifier)?;
        assert!(super::verify::export(
            directory.path(),
            &super::Keypair::generate().public_key(),
            &verifier
        )
        .is_err());
        std::fs::write(directory.path().join("approved.scope.json"), b"{}")?;
        assert!(super::verify::export(directory.path(), &publisher, &verifier).is_err());
        Ok(())
    }
}
