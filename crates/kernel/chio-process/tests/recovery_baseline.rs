//! Local native baseline and exhaustive review tests. Measurements cover original admission/capture
//! behavior, not qualification of a native recovery participant or grant v2.
mod support;

use chio_core_types::{
    canonical_json_bytes, capability::scope::ModelMetadata,
    capability::supplemental_authorization::OpaqueSupplementalAuthorization,
    SignedDeclassificationGrant,
};
use chio_kernel::{
    KernelError, NativeSecurityDispatchCaptureAuthority, NestedFlowBridge, ToolServerConnection,
    Verdict,
};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};
use support::Result;

struct CountingServer(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into(), "read".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

#[tokio::test]
async fn exhaustive_request_review_preserves_native_owned_attachment_boundary() -> Result {
    let directory = tempfile::tempdir()?;
    let kernel = support::kernel_with_artifacts(
        directory.path(),
        Box::new(CountingServer(Arc::new(AtomicUsize::new(0)))),
        false,
        true,
        false,
    )?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    support::root(&runtime, &kernel, 8)?;
    let request = runtime.tool_request(
        "root",
        "review",
        "tools",
        "append",
        json!({"private":"payload-canary"}),
    )?;
    let projection = request.recovery_review_projection();
    assert!(!format!("{projection:?}").contains("payload-canary"));
    let semantics = projection.canonical_semantics()?;
    let wire = serde_json::to_value(&projection)?;
    assert_eq!(
        wire["semantics"]["capability_signing_body"],
        serde_json::to_value(request.capability.signing_body())?
    );
    // Positive binding inventory: every current field has exactly one custody
    // class, and the capability's unsigned body is also reviewed explicitly.
    let fields = [
        ("request_id", "semantics"),
        ("capability", "fixed_authorization"),
        ("tool_name", "semantics"),
        ("server_id", "semantics"),
        ("agent_id", "semantics"),
        ("arguments", "semantics"),
        ("dpop_proof", "fixed_authorization"),
        ("governed_intent", "semantics"),
        ("approval_token", "fixed_authorization"),
        ("approval_tokens", "fixed_authorization"),
        ("threshold_approval_proposal", "fixed_authorization"),
        ("supplemental_authorization", "fixed_authorization"),
        ("model_metadata", "semantics"),
        ("federated_origin_kernel_id", "semantics"),
        ("declassification_grant", "fixed_authorization"),
    ];
    let original = serde_json::to_value(&request)?;
    for (field, class) in fields {
        assert!(
            wire[class].get(field).is_some(),
            "missing custody field {field}"
        );
        let absent = if field == "approval_tokens" {
            json!([])
        } else {
            Value::Null
        };
        assert_eq!(
            wire[class][field],
            original.get(field).unwrap_or(&absent).clone(),
            "omitted {field}"
        );
    }
    let response = runtime.invoke("root", "review", &request).await?;
    assert_eq!(response.verdict, Verdict::Allow);
    let mut with_nonce = request.clone();
    with_nonce.execution_nonce = response.execution_nonce.as_deref().cloned();
    assert!(with_nonce.execution_nonce.is_some());
    assert_eq!(
        semantics,
        with_nonce
            .recovery_review_projection()
            .canonical_semantics()?
    );
    assert_ne!(
        canonical_json_bytes(&projection)?,
        canonical_json_bytes(&with_nonce.recovery_review_projection())?
    );

    let mut variants = Vec::new();
    let mut changed = request.clone();
    changed.request_id.push_str("-other");
    variants.push(changed);
    let mut changed = request.clone();
    changed.agent_id.push_str("-other");
    variants.push(changed);
    let mut changed = request.clone();
    changed.server_id.push_str("-other");
    variants.push(changed);
    let mut changed = request.clone();
    changed.tool_name.push_str("-other");
    variants.push(changed);
    let mut changed = request.clone();
    changed.arguments = json!({"private":"different"});
    variants.push(changed);
    let mut changed = request.clone();
    changed.capability.id.push_str("-other");
    variants.push(changed);
    let mut changed = request.clone();
    changed.federated_origin_kernel_id = Some("other-origin".into());
    variants.push(changed);
    let mut changed = request.clone();
    changed.model_metadata = Some(serde_json::from_value::<ModelMetadata>(
        json!({"model_id":"model-other"}),
    )?);
    variants.push(changed);
    let mut changed = request.clone();
    changed.governed_intent = Some(serde_json::from_value(
        json!({"id":"intent-a","server_id":"tools","tool_name":"append","purpose":"other-purpose"}),
    )?);
    variants.push(changed);
    for changed in variants {
        assert_ne!(
            semantics,
            changed.recovery_review_projection().canonical_semantics()?
        );
    }
    // Independently mutate every fixed authorization class. These artifacts
    // are review data only and are never submitted to the native dispatcher.
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../tests/bindings/fixtures/protocol-primitives-v1.json"
    ))?;
    let fixture = |name: &str| -> Result<Value> {
        Ok(corpus["cases"]
            .as_array()
            .ok_or("missing cases")?
            .iter()
            .find(|case| case["name"] == name)
            .ok_or("missing artifact fixture")?["instance"]
            .clone())
    };
    let signer = support::issuer();
    let mut approval = fixture("governed-approval-token")?;
    approval["approver"] = serde_json::to_value(signer.public_key())?;
    approval["subject"] = serde_json::to_value(signer.public_key())?;
    let mut proposal = fixture("threshold-proposal")?;
    proposal["subject"] = serde_json::to_value(signer.public_key())?;
    proposal["policy_authority"] = serde_json::to_value(signer.public_key())?;
    let grant_body = serde_json::from_value(json!({
        "domain_version":1,"grant_id":"review-grant","capability_id":request.capability.id,
        "tenant_id":"review-tenant","subject_id":"review-subject","agent_id":"review-agent",
        "session_id":"review-session","source_label_hash":vec![1;32],
        "target_label":{"kind":"known","owners":{},"compartments":[]},
        "destination_id":"tools","tool_name":"append","purpose":"review-binding",
        "request_hash":vec![2;32],"issued_at_unix_seconds":100,"expires_at_unix_seconds":200,
        "authority_key_id":"review-authority"
    }))?;
    let mut fixed_variants = Vec::new();
    let mut changed = request.clone();
    changed.capability.signature = serde_json::from_value(json!("a".repeat(128)))?;
    fixed_variants.push((changed, "capability"));
    let mut changed = request.clone();
    changed.dpop_proof = Some(chio_kernel::dpop::DpopProof::sign(
        chio_kernel::dpop::DpopProofBody {
            schema: chio_kernel::dpop::DPOP_SCHEMA.into(),
            replay_authority: None,
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action_hash: "1".repeat(64),
            nonce: "review-nonce".into(),
            issued_at: 100,
            agent_key: signer.public_key(),
        },
        &signer,
    )?);
    fixed_variants.push((changed, "dpop_proof"));
    let mut changed = request.clone();
    changed.approval_token = Some(serde_json::from_value(approval.clone())?);
    fixed_variants.push((changed, "approval_token"));
    let mut changed = request.clone();
    changed.approval_tokens = vec![serde_json::from_value(approval)?];
    fixed_variants.push((changed, "approval_tokens"));
    let mut changed = request.clone();
    changed.threshold_approval_proposal = Some(serde_json::from_value(proposal)?);
    fixed_variants.push((changed, "threshold_approval_proposal"));
    let mut changed = request.clone();
    changed.supplemental_authorization = Some(OpaqueSupplementalAuthorization {
        signed_extension: "review-extension".into(),
    });
    fixed_variants.push((changed, "supplemental_authorization"));
    let mut changed = request.clone();
    changed.declassification_grant =
        Some(SignedDeclassificationGrant::sign(grant_body, &signer)?.into());
    fixed_variants.push((changed, "declassification_grant"));
    for (changed, field) in fixed_variants {
        let reviewed = changed.recovery_review_projection();
        let changed_wire = serde_json::to_value(&changed)?;
        assert_eq!(
            semantics,
            reviewed.canonical_semantics()?,
            "changed semantics: {field}"
        );
        assert_eq!(
            serde_json::to_value(&reviewed)?["fixed_authorization"][field],
            changed_wire[field]
        );
        assert_ne!(
            canonical_json_bytes(&projection)?,
            canonical_json_bytes(&reviewed)?,
            "lost artifact: {field}"
        );
    }
    // Send is deliberate for an exclusively borrowed owner. Shared dispatch
    // is forbidden by capture(&mut self), covered by the kernel compile failure.
    fn assert_send<T: Send>() {}
    assert_send::<NativeSecurityDispatchCaptureAuthority<'static, 'static>>();
    Ok(())
}

#[tokio::test]
#[ignore = "explicit local performance baseline; run with --ignored --nocapture"]
async fn measured_native_baseline() -> Result {
    let directory = tempfile::tempdir()?;
    let effects = Arc::new(AtomicUsize::new(0));
    let kernel = support::kernel(directory.path(), Box::new(CountingServer(effects.clone())))?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    support::root(&runtime, &kernel, 80)?;
    let mut samples = Vec::new();
    let mut receipts = Vec::new();
    let mut requests = Vec::new();
    let baseline_started = Instant::now();
    for index in 0..72 {
        let key = format!("sample-{index:03}");
        let request =
            runtime.tool_request("root", &key, "tools", "append", json!({"value":index}))?;
        let start = Instant::now();
        let response = runtime.invoke("root", &key, &request).await?;
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(response.output.is_some());
        assert!(response.receipt.verify_signature()?);
        if index >= 8 {
            samples.push(elapsed);
        }
        receipts.push(response.receipt);
        requests.push((key, request));
    }
    for ((key, request), receipt) in requests.iter().zip(&receipts).take(8) {
        let replay = runtime.invoke("root", key, request).await?;
        assert_eq!(
            canonical_json_bytes(&replay.receipt)?,
            canonical_json_bytes(receipt)?
        );
    }
    assert_eq!(effects.load(Ordering::SeqCst), 72);
    assert_eq!(runtime.process("root")?.tree_calls, 72);
    let samples_ns = samples.clone();
    samples.sort_unstable();
    println!(
        "NATIVE_RECOVERY_BASELINE {}",
        json!({
            "profile":if cfg!(debug_assertions) { "debug" } else { "release" },
            "elapsed_ns":baseline_started.elapsed().as_nanos(),
            "warmups":8,"samples":samples.len(),"replays":8,
            "samples_ns":samples_ns,"sample_unit":"nanoseconds","percentile_method":"nearest_rank",
            "effect_count":72,"logical_call_charges":72,"errors":0,
            "p50_ns":samples[31],"p95_ns":samples[60],"p99_ns":samples[63],"max_ns":samples[63],
            "fixture":"native admission + SQLite authority/process stores + counting connector"
        })
    );
    Ok(())
}
