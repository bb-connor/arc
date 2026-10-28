use super::*;

#[path = "swarm_binding/fixtures.rs"]
mod fixtures;
use fixtures::{join_bundle, multihop_bundle, resign};

#[path = "swarm_binding/live_admission.rs"]
mod live_admission;

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
        chio_swarm_authority::verify_swarm_authority_for_admission(
            &swarm,
            &trusted_swarm_witness_keys(),
        )?;
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
        let graphs = retained_swarm_graphs(&swarm);
        let mut request =
            chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm)?)?;
        request.agent_id = capability.subject.to_hex();
        request.capability = capability;
        let hook = allowing_chio_policy_hook(store)?
            .with_swarm_witness_keys(trusted_swarm_witness_keys())
            .with_swarm_graph_source(graphs);
        Ok(Self {
            hook,
            request,
            swarm,
        })
    }

    fn prepared(
        &self,
        request: &ToolCallRequest,
    ) -> TestResult<
        super::super::preparation::PreparedHookAdmission<'_, InMemoryRuntimeAdmissionStore>,
    > {
        let route_metadata = swarm_route_metadata();
        match self.hook.prepare_request(&RuntimeAdmissionContext {
            request,
            extra_metadata: Some(&route_metadata),
            now_unix_secs: 1_800_000_001,
            now_unix_ms: 1_800_000_001_000,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".to_string(),
        })? {
            super::super::preparation::HookAdmissionPreparation::Prepared(prepared) => {
                Ok(*prepared)
            }
            super::super::preparation::HookAdmissionPreparation::Immediate(_) => {
                Err("valid swarm evidence did not prepare".into())
            }
        }
    }

    fn denied(
        &self,
        request: &ToolCallRequest,
    ) -> TestResult<chio_kernel::RuntimeAdmissionDecision> {
        prepare_denial(
            &self.hook,
            &RuntimeAdmissionContext {
                request,
                extra_metadata: Some(&swarm_route_metadata()),
                now_unix_secs: 1_800_000_001,
                now_unix_ms: 1_800_000_001_000,
                matched_grant_index: Some(0),
                local_kernel_id: "kernel.vendor-b".to_string(),
            },
        )
        .map_err(Into::into)
    }

    fn assert_denied_without_consuming(&self, request: &ToolCallRequest, code: &str) -> TestResult {
        let decision = self.denied(request)?;
        let metadata = decision.metadata.ok_or("missing denial metadata")?;
        assert_eq!(metadata["chio_runtime"]["failure_code"], code);
        assert!(metadata["chio_runtime"]
            .get("reserved_swarm_continuation_id")
            .is_none());
        self.prepared(&self.request)?;
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
    let capability = capability("cap-live-1")?;
    let mut swarm = runtime_swarm_bundle(false)?;
    swarm.witness_chains[0].hops[0].child_capability_digest = canonical_test_hash(&capability)?;
    resign(&mut swarm)?;
    let fixture = BindingFixture::with_capability(swarm, capability)?;
    let decision = fixture.denied(&fixture.request)?;
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
fn swarm_preparation_pins_leaf_of_multihop_witness() -> TestResult {
    let fixture = BindingFixture::with_swarm(multihop_bundle()?)?;
    let prepared = fixture.prepared(&fixture.request)?;
    let binding = prepared
        .verified_swarm_request_binding
        .as_ref()
        .ok_or("missing prepared binding")?;
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
    Ok(())
}

#[test]
fn swarm_binding_join_root_requires_consistent_capability_on_every_outgoing_edge() -> TestResult {
    let root_cap = swarm_fixtures::runtime_swarm_capability("task-root")?;
    let valid = BindingFixture::with_capability(join_bundle()?, root_cap.clone())?;
    valid.prepared(&valid.request)?;

    let mut swarm = join_bundle()?;
    swarm.witness_chains[1].hops[0].parent_capability_digest = sha256_hex(b"different root");
    resign(&mut swarm)?;
    let invalid = BindingFixture::with_capability(swarm, root_cap)?;
    let decision = invalid.denied(&invalid.request)?;
    assert!(!decision.allowed, "{decision:#?}");
    assert_eq!(
        decision
            .metadata
            .ok_or_else(|| io::Error::other("missing denial"))?["chio_runtime"]["failure_code"],
        "chio_swarm_authority_rejected"
    );
    Ok(())
}
