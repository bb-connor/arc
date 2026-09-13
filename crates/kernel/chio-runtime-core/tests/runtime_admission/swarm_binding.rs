use super::*;

#[path = "swarm_binding/fixtures.rs"]
mod fixtures;
#[path = "swarm_binding/kernel.rs"]
mod kernel;
use fixtures::{join_bundle, multihop_bundle, resign};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct BindingFixture {
    hook: ChioRuntimeAdmissionHook<InMemoryRuntimeAdmissionStore>,
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
        verify_swarm_authority_bundle(&swarm, &trusted_swarm_witness_keys())?;
        let store = InMemoryRuntimeAdmissionStore::new();
        let mut admission = bundle();
        admission.destructive = false;
        admission.lease_id = None;
        admission.governance_receipt_id = None;
        let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
        admission.binding.tool_args_sha256 = tool_args_sha256(&args)?;
        admission.binding.origin_kernel_id = None;
        admission.binding.capability_id = capability.id.clone();
        let bundle_hash = runtime_admission_bundle_sha256(&admission)?;
        store.insert_bundle(admission)?;
        store.insert_swarm_authority_bundle(swarm.clone())?;
        let mut request =
            chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm)?)?;
        request.agent_id = capability.subject.to_hex();
        request.capability = capability;
        let hook =
            allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
        Ok(Self {
            hook,
            request,
            swarm,
        })
    }

    fn evaluate(
        &self,
        request: &ToolCallRequest,
    ) -> TestResult<chio_kernel::RuntimeAdmissionDecision> {
        let route = &self.swarm.route_plan_receipts[0];
        let route_metadata = serde_json::json!({"route": {
            "bridge": route.bridge_id,
            "protocolTarget": route.protocol_target,
            "selectedRoute": route.selected_route
        }});
        Ok(self.hook.evaluate(&RuntimeAdmissionContext {
            request,
            extra_metadata: Some(&route_metadata),
            now_unix_secs: 1_800_000_001,
            now_unix_ms: 1_800_000_001_000,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".to_string(),
        })?)
    }

    fn revalidate(
        &self,
        request: &ToolCallRequest,
        metadata: &serde_json::Value,
    ) -> Result<(), chio_kernel::KernelError> {
        self.hook
            .revalidate_before_dispatch(&RuntimeAdmissionRevalidationContext {
                request,
                admission_metadata: Some(metadata),
                now_unix_secs: 1_800_000_001,
                now_unix_ms: 1_800_000_001_000,
                matched_grant_index: Some(0),
                local_kernel_id: "kernel.vendor-b".to_string(),
            })
    }

    fn assert_denied_without_consuming(&self, request: &ToolCallRequest, code: &str) -> TestResult {
        let decision = self.evaluate(request)?;
        assert!(!decision.allowed, "unexpected allow: {decision:#?}");
        let metadata = decision
            .metadata
            .ok_or_else(|| io::Error::other("missing deny metadata"))?;
        assert_eq!(metadata["chio_runtime"]["failure_code"], code);
        assert!(metadata["chio_runtime"]
            .get("reserved_swarm_continuation_id")
            .is_none());
        let valid = self.evaluate(&self.request)?;
        assert!(
            valid.allowed,
            "rejected request consumed the continuation: {valid:#?}"
        );
        Ok(())
    }
}

#[test]
fn swarm_binding_denies_same_id_same_scope_reissued_capability() -> TestResult {
    let fixture = BindingFixture::new()?;
    let mut request = fixture.request.clone();
    let mut body = request.capability.body();
    body.expires_at -= 1;
    request.capability = CapabilityToken::sign(body, &swarm_witness_keypair())?;
    assert!(request.capability.verify_signature()?);
    assert_eq!(request.capability.id, fixture.request.capability.id);
    assert_eq!(
        scope_hash(&request.capability.scope)?,
        scope_hash(&fixture.request.capability.scope)?
    );
    fixture.assert_denied_without_consuming(&request, "chio_swarm_authority_rejected")
}

#[test]
fn swarm_binding_denies_referenced_sibling_witness() -> TestResult {
    let fixture = BindingFixture::new()?;
    let mut request = fixture.request.clone();
    let context = request
        .governed_intent
        .as_mut()
        .and_then(|intent| intent.context.as_mut())
        .ok_or_else(|| io::Error::other("missing fixture context"))?;
    let sibling = &fixture.swarm.witness_chains[1];
    context["chioSwarm"]["delegationWitness"] = serde_json::json!({
        "id": sibling.chain_id,
        "sha256": canonical_test_hash(sibling)?
    });
    fixture.assert_denied_without_consuming(&request, "chio_swarm_authority_ref_mismatch")
}

#[test]
fn swarm_binding_revalidates_exact_capability_at_dispatch() -> TestResult {
    let fixture = BindingFixture::new()?;
    let decision = fixture.evaluate(&fixture.request)?;
    assert!(decision.allowed, "{decision:#?}");
    let metadata = decision
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
        !replay.allowed,
        "failed revalidation must not erase the reservation"
    );
    Ok(())
}

#[test]
fn swarm_binding_denies_changed_subject_issuer_scope_and_signature() -> TestResult {
    for mutation in ["subject", "issuer", "scope", "signature"] {
        let fixture = BindingFixture::new()?;
        let mut request = fixture.request.clone();
        let mut body = request.capability.body();
        let mut signer = swarm_witness_keypair();
        match mutation {
            "subject" => body.subject = Keypair::from_seed(&[57; 32]).public_key(),
            "issuer" => {
                signer = Keypair::from_seed(&[58; 32]);
                body.issuer = signer.public_key();
            }
            "scope" => body.scope.grants[0].max_invocations = Some(2),
            _ => {}
        }
        request.capability = CapabilityToken::sign(body, &signer)?;
        request.agent_id = request.capability.subject.to_hex();
        if mutation == "signature" {
            request.capability.signature = signer.sign(b"unrelated payload");
        } else {
            assert!(request.capability.verify_signature()?);
        }
        fixture.assert_denied_without_consuming(&request, "chio_swarm_authority_rejected")?;
    }
    Ok(())
}

#[test]
fn swarm_binding_checks_graph_scope_even_when_witness_digest_matches_request() -> TestResult {
    let capability = capability("cap-live-1")?; // Unlimited scope, unlike the signed task.
    let mut swarm = runtime_swarm_bundle(false)?;
    swarm.witness_chains[0].hops[0].child_capability_digest = canonical_test_hash(&capability)?;
    resign(&mut swarm)?;
    let fixture = BindingFixture::with_capability(swarm, capability)?;
    let decision = fixture.evaluate(&fixture.request)?;
    assert!(
        !decision.allowed,
        "matching digest must not authorize a different graph scope"
    );
    assert_eq!(
        decision
            .metadata
            .ok_or_else(|| io::Error::other("missing denial"))?["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn swarm_binding_allows_leaf_of_multihop_witness_and_records_exact_binding() -> TestResult {
    let fixture = BindingFixture::with_swarm(multihop_bundle()?)?;
    let decision = fixture.evaluate(&fixture.request)?;
    assert!(decision.allowed, "{decision:#?}");
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("missing metadata"))?;
    let binding = &metadata["chio_runtime"]["verified_swarm_request_binding"];
    assert_eq!(binding["task_id"], "task-child-a");
    assert_eq!(binding["graph_id"], fixture.swarm.task_graph.graph_id);
    assert_eq!(
        binding["capability_sha256"],
        canonical_test_hash(&fixture.request.capability)?
    );
    assert_eq!(
        binding["scope_sha256"],
        scope_hash(&fixture.request.capability.scope)?
    );
    fixture.revalidate(&fixture.request, &metadata)?;
    Ok(())
}

#[test]
fn swarm_binding_join_root_requires_consistent_capability_on_every_outgoing_edge() -> TestResult {
    let root_cap = swarm_fixtures::runtime_swarm_capability("task-root")?;
    let valid = BindingFixture::with_capability(join_bundle()?, root_cap.clone())?;
    let decision = valid.evaluate(&valid.request)?;
    assert!(
        decision.allowed,
        "valid join continuation denied: {decision:#?}"
    );
    valid.revalidate(
        &valid.request,
        &decision
            .metadata
            .ok_or_else(|| io::Error::other("missing metadata"))?,
    )?;

    let mut swarm = join_bundle()?;
    // The referenced first chain still matches. A contradictory second edge
    // must not let a task claim two different capabilities under one identity.
    swarm.witness_chains[1].hops[0].parent_capability_digest = sha256_hex(b"different root");
    resign(&mut swarm)?;
    let invalid = BindingFixture::with_capability(swarm, root_cap)?;
    let decision = invalid.evaluate(&invalid.request)?;
    assert!(!decision.allowed, "{decision:#?}");
    assert_eq!(
        decision
            .metadata
            .ok_or_else(|| io::Error::other("missing denial"))?["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}

#[test]
fn swarm_binding_resumable_revalidation_rejects_stripped_context_and_metadata() -> TestResult {
    let mut swarm = runtime_swarm_bundle(false)?;
    swarm.continuation_tokens[0].mode = SwarmContinuationMode::Resumable;
    resign(&mut swarm)?;
    let fixture = BindingFixture::with_swarm(swarm)?;
    let decision = fixture.evaluate(&fixture.request)?;
    assert!(decision.allowed, "{decision:#?}");
    let metadata = decision
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
    let fixture = BindingFixture::with_capability(
        join_bundle()?,
        swarm_fixtures::runtime_swarm_capability("task-root")?,
    )?;
    let decision = fixture.evaluate(&fixture.request)?;
    assert!(decision.allowed, "{decision:#?}");
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("missing metadata"))?;
    let mut request = fixture.request.clone();
    let context = request
        .governed_intent
        .as_mut()
        .and_then(|intent| intent.context.as_mut())
        .ok_or_else(|| io::Error::other("missing context"))?;
    let alternative = &fixture.swarm.witness_chains[1];
    // Both witnesses legitimately bind the root's capability. The initial
    // admission must still pin which evidence was selected for this dispatch.
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
    // A fresh admission can choose that other witness, proving that the denial
    // above comes from changing the admitted binding, not invalid evidence.
    let fresh = BindingFixture::with_capability(
        join_bundle()?,
        swarm_fixtures::runtime_swarm_capability("task-root")?,
    )?;
    let decision = fresh.evaluate(&request)?;
    assert!(decision.allowed, "{decision:#?}");
    Ok(())
}
