use super::*;
use chio_kernel::Verdict;
use std::sync::atomic::Ordering;
#[path = "swarm_binding/fixtures.rs"]
mod fixtures;
use fixtures::{join_bundle, resign};
#[path = "swarm_binding/kernel.rs"]
mod kernel;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct BindingFixture {
    inner: operation_owned::Fixture,
    hook: ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>,
    kernel: chio_kernel::ChioKernel,
    request: ToolCallRequest,
    swarm: SwarmAuthorityBundle,
}
impl BindingFixture {
    fn new() -> TestResult<Self> {
        Self::with_swarm(runtime_swarm_bundle(false)?)
    }
    fn with_swarm(swarm: SwarmAuthorityBundle) -> TestResult<Self> {
        Self::with_capability(
            swarm,
            swarm_fixtures::runtime_swarm_capability("task-child-a")?,
        )
    }
    fn with_capability(
        swarm: SwarmAuthorityBundle,
        capability: CapabilityToken,
    ) -> TestResult<Self> {
        chio_swarm_authority::verify_swarm_authority_for_admission(
            &swarm,
            &trusted_swarm_witness_keys(),
        )?;
        let inner = operation_owned::Fixture::with_request(true, |source, authority| {
            let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
            let mut request =
                chio_swarm_runtime_request(args, String::new(), swarm_runtime_context(&swarm)?)?;
            request.agent_id = capability.subject.to_hex();
            request.capability = capability;
            let mut admission = bundle();
            admission.destructive = false;
            admission.lease_id = None;
            admission.governance_receipt_id = None;
            admission.binding =
                RuntimeRequestBinding::from_tool_call_request(&request, "kernel.vendor-b")?;
            request
                .governed_intent
                .as_mut()
                .and_then(|i| i.context.as_mut())
                .ok_or("runtime context")?["chioAdmission"]["bundleSha256"] =
                serde_json::json!(runtime_admission_bundle_sha256(&admission)?);
            source.insert_bundle(admission)?;
            issue_root(authority, &swarm)?;
            Ok(request)
        })?;
        let hook = inner
            .hook()?
            .with_swarm_witness_keys(trusted_swarm_witness_keys());
        let mut kernel = inner.kernel(
            inner
                .hook()?
                .with_swarm_witness_keys(trusted_swarm_witness_keys()),
            true,
            false,
        )?;
        kernel.require_swarm_admission();
        kernel.configure_durable_admission(
            chio_kernel::admission_operation::DurableAdmissionMode::All,
            false,
        )?;
        kernel.set_revocation_store(Box::new(inner.authority.revocation_store()));
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(
            inner.directory().join("binding-receipts.sqlite3"),
        )?;
        receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
        kernel.set_receipt_store(Box::new(receipts))?;
        kernel.reconcile_durable_admission_startup()?;
        let request = inner.request.clone();
        Ok(Self {
            inner,
            hook,
            kernel,
            request,
            swarm,
        })
    }
    fn evaluate(&self, request: &ToolCallRequest) -> TestResult<chio_kernel::ToolCallResponse> {
        let response = self
            .kernel
            .evaluate_tool_call_blocking_with_metadata(request, Some(swarm_route_metadata()))?;
        assert!(response.receipt.verify_signature()?);
        Ok(response)
    }
    fn revalidate(&self, request: &ToolCallRequest, metadata: &serde_json::Value) -> TestResult {
        let source = self
            .inner
            .authority
            .admission_operation_store()
            .load_runtime_source_qualification(
                &self.inner.binding,
                &self.inner.authority.mutation_fence(),
                1_800_000_001_000,
            )?;
        self.hook.revalidate_operation_owned_before_dispatch(
            &RuntimeAdmissionRevalidationContext {
                request,
                admission_metadata: Some(metadata),
                now_unix_secs: 1_800_000_001,
                now_unix_ms: 1_800_000_001_000,
                matched_grant_index: Some(0),
                local_kernel_id: "kernel.vendor-b".to_string(),
            },
            &source,
        )?;
        Ok(())
    }
}

#[test]
fn swarm_binding_revalidates_exact_capability_at_dispatch() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_001);
    let fixture = BindingFixture::new()?;
    let decision = fixture.evaluate(&fixture.request)?;
    assert!(decision.verdict == Verdict::Allow, "{decision:#?}");
    let metadata = decision
        .receipt
        .metadata
        .ok_or_else(|| io::Error::other("missing allow metadata"))?;
    let mut request = fixture.request.clone();
    let mut body = request.capability.body();
    body.expires_at -= 1;
    request.capability = CapabilityToken::sign(body, &swarm_witness_keypair())?;
    let error = fixture
        .revalidate(&request, &metadata)
        .err()
        .ok_or_else(|| io::Error::other("changed capability must not dispatch"))?;
    assert!(
        error
            .to_string()
            .contains("runtime swarm authority revalidation failed"),
        "{error}"
    );
    fixture.revalidate(&fixture.request, &metadata)?;
    let replay = fixture.evaluate(&fixture.request)?;
    assert!(
        replay.verdict == Verdict::Allow,
        "committed request replay must recover the original result"
    );
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn swarm_binding_resumable_revalidation_rejects_stripped_context_and_metadata() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_001);
    let mut swarm = runtime_swarm_bundle(false)?;
    swarm.continuation_tokens[0].mode = SwarmContinuationMode::Resumable;
    resign(&mut swarm)?;
    let fixture = BindingFixture::with_swarm(swarm)?;
    let decision = fixture.evaluate(&fixture.request)?;
    assert!(decision.verdict == Verdict::Allow, "{decision:#?}");
    let metadata = decision
        .receipt
        .metadata
        .ok_or_else(|| io::Error::other("missing metadata"))?;
    for strip in ["swarm", "all", "metadata"] {
        let mut request = fixture.request.clone();
        let mut changed_metadata = metadata.clone();
        match strip {
            "swarm" => {
                request
                    .governed_intent
                    .as_mut()
                    .and_then(|intent| intent.context.as_mut())
                    .and_then(serde_json::Value::as_object_mut)
                    .ok_or_else(|| io::Error::other("missing context"))?
                    .remove("chioSwarm");
            }
            "all" => request.governed_intent = None,
            _ => {
                changed_metadata["chio_runtime"]
                    .as_object_mut()
                    .ok_or_else(|| io::Error::other("missing runtime"))?
                    .remove("verified_swarm_request_binding");
            }
        }
        assert!(
            fixture.revalidate(&request, &changed_metadata).is_err(),
            "stripped {strip} dispatched"
        );
    }
    fixture.revalidate(&fixture.request, &metadata)?;
    Ok(())
}

#[test]
fn swarm_binding_revalidation_pins_even_an_alternative_valid_witness() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_001);
    let fixture = BindingFixture::with_capability(
        join_bundle()?,
        swarm_fixtures::runtime_swarm_capability("task-root")?,
    )?;
    let decision = fixture.evaluate(&fixture.request)?;
    assert!(decision.verdict == Verdict::Allow, "{decision:#?}");
    let metadata = decision
        .receipt
        .metadata
        .ok_or_else(|| io::Error::other("missing metadata"))?;
    let mut request = fixture.request.clone();
    let context = request
        .governed_intent
        .as_mut()
        .and_then(|intent| intent.context.as_mut())
        .ok_or_else(|| io::Error::other("missing context"))?;
    let alternative = &fixture.swarm.witness_chains[1];
    context["chioSwarm"]["delegationWitness"] = serde_json::json!({
        "id": alternative.chain_id,
        "sha256": canonical_test_hash(alternative)?
    });
    let error = fixture
        .revalidate(&request, &metadata)
        .err()
        .ok_or_else(|| io::Error::other("changed evidence selection dispatched"))?;
    assert!(
        error
            .to_string()
            .contains("runtime swarm request binding changed before dispatch"),
        "{error}"
    );
    fixture.revalidate(&fixture.request, &metadata)?;
    let fresh = BindingFixture::with_capability(
        join_bundle()?,
        swarm_fixtures::runtime_swarm_capability("task-root")?,
    )?;
    let decision = fresh.evaluate(&request)?;
    assert!(decision.verdict == Verdict::Allow, "{decision:#?}");
    Ok(())
}
