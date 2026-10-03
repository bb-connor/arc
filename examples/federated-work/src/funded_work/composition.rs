//! Protected deployment adapter joining existing authority owners. Incoming
//! requests cannot call provisioning or install a trust root.
use crate::common::{digest, Result};
use chio_core_types::{Keypair, PublicKey};
use chio_federation::trust_establishment::{
    FederationPeer, KernelTrustExchange, PeerHandshakeEnvelope,
};
use chio_kernel::{
    admission_operation::{
        runtime_participant::RuntimeParticipantAuthorityBindingV1, AdmissionIdentifier,
    },
    ChioKernel, Guard, GuardContext, GuardDecision, KernelError, ToolCallRequest,
};
use chio_runtime_core::{
    ChioRuntimeAdmissionHook, RuntimeAdmissionProfile, RuntimeAdmissionStore,
    SqliteRuntimeOrchestrationStore, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
};
use chio_store_sqlite::SqliteAuthorityStore;
use chio_workflow::delegation::{DispatchPermit, Signed};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) mod treaty;

pub(super) struct Provision {
    pub allocator: PublicKey,
    pub witness: PublicKey,
    pub program_id: String,
    pub buyer: Keypair,
    pub issued: u64,
    pub until: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub profile: RuntimeAdmissionProfile,
    pub replay: RuntimeParticipantAuthorityBindingV1,
    pub allocator: PublicKey,
    pub witness: PublicKey,
    pub program_id: String,
    pub peer: FederationPeer,
}

pub(super) fn kernel_id(key: &PublicKey) -> String {
    format!("did:chio:{}", key.to_hex())
}

/// Single-host fixture wiring. A deployed receiver supplies an authenticated
/// remote co-signer; no caller request may supply this private signing handle.
pub(super) fn connect_local_cosigner(
    native: &mut super::native::Native,
    buyer: &Keypair,
) -> Result<()> {
    let config = native
        .policy
        .composition
        .as_ref()
        .ok_or("composed policy absent")?;
    if buyer.public_key() != config.peer.public_key || buyer.public_key() != native.policy.buyer_key
    {
        return Err("local fixture co-signer differs from protected peer".into());
    }
    native.kernel.set_federation_cosigner(Arc::new(
        chio_federation::bilateral::InProcessCoSigner::new(
            &config.peer.kernel_id,
            buyer.clone(),
            native.policy.provider_key.clone(),
        ),
    ));
    Ok(())
}

pub(super) fn provision(
    state: &Path,
    authority: &SqliteAuthorityStore,
    receiver: &Keypair,
    input: Provision,
) -> Result<Config> {
    let source = SqliteRuntimeOrchestrationStore::open(state.join("runtime.sqlite"))?;
    let owner = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let runtime =
        AdmissionIdentifier::try_new("runtime_id", format!("runtime-{}", fence.store_uuid))?;
    let source_id =
        AdmissionIdentifier::try_new("source_id", format!("source-{}", fence.store_uuid))?;
    let now = super::now_ms()?;
    let expected =
        owner.expect_runtime_replay_source(&source_id, &runtime, &source, &fence, now)?;
    owner.import_runtime_replay_source(
        &runtime,
        expected.expectation_id(),
        &source,
        &fence,
        now,
    )?;
    let replay =
        RuntimeParticipantAuthorityBindingV1::new(runtime, expected.expectation_id().clone());
    owner.activate_runtime_replay_source(&replay, &source, &fence, now)?;
    let local = kernel_id(&receiver.public_key());
    let remote = kernel_id(&input.buyer.public_key());
    let handshake =
        PeerHandshakeEnvelope::sign(&remote, &local, &fence.store_uuid, now / 1000, &input.buyer)?;
    let peer = KernelTrustExchange::new(&local, receiver.clone())
        .with_trusted_peer(&remote, input.buyer.public_key())
        .accept_envelope(&handshake, &remote, now / 1000)?;
    Ok(Config {
        profile: RuntimeAdmissionProfile {
            schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.into(),
            profile_id: "evolving-funded-review".into(),
            local_kernel_id: local,
            verifier_id: kernel_id(&receiver.public_key()),
            issued_at_unix_ms: input.issued,
            expires_at_unix_ms: input.until,
        },
        replay,
        allocator: input.allocator,
        witness: input.witness,
        program_id: input.program_id,
        peer,
    })
}

pub(super) fn install(mut kernel: ChioKernel, state: &Path, config: &Config) -> Result<ChioKernel> {
    if config.profile.local_kernel_id != kernel_id(&kernel.public_key()) {
        return Err("composed admission changed receiver authority".into());
    }
    let source = open_store(state)?;
    let hook = ChioRuntimeAdmissionHook::new(config.profile.clone(), source)
        .with_operation_owned_runtime_replay(config.replay.clone())
        .with_swarm_witness_keys(vec![config.witness.clone()]);
    kernel.set_federation_local_kernel_id(&config.profile.local_kernel_id);
    kernel = kernel.with_federation_peers(vec![config.peer.clone()]);
    kernel.set_runtime_admission_hook(Arc::new(hook));
    kernel.require_swarm_admission();
    chio_kernel::delegated_work::install_delegated_work_with_layout(
        &mut kernel,
        vec![config.allocator.clone()],
        chio_kernel::delegated_work::DelegatedWorkLayout::GovernedContext,
    )?;
    kernel.add_guard(Box::new(Bindings {
        state: state.to_owned(),
        config: config.clone(),
    }));
    Ok(kernel)
}

/// Join the D1 and S1 names before the existing verifiers authenticate their
/// evidence. The signed funded agreement then commits to this entire request.
pub(super) fn validate(state: &Path, config: &Config, request: &ToolCallRequest) -> Result<Value> {
    let context = request
        .governed_intent
        .as_ref()
        .and_then(|i| i.context.as_ref())
        .ok_or("composed admission requires governed context")?;
    let permit: Signed<DispatchPermit> =
        serde_json::from_value(context["chioDelegation"]["allocation"].clone())?;
    let slot = &permit.body.slot;
    if request.federated_origin_kernel_id.as_deref() != Some(config.peer.kernel_id.as_str())
        || context.get("chioTreaty").is_none()
        || slot.id != request.request_id
        || context["chioDelegation"]["slot_id"] != slot.id
    {
        return Err("composed admission changed treaty, origin or task identity".into());
    }
    let swarm = &context["chioSwarm"];
    let id = swarm["taskGraph"]["id"].as_str().ok_or("graph id absent")?;
    let hash = swarm["taskGraph"]["sha256"]
        .as_str()
        .ok_or("graph hash absent")?;
    let store = open_store(state)?;
    let bundle = store
        .swarm_authority_bundle_for_graph(id, hash)?
        .ok_or("original graph absent")?;
    let token = bundle
        .continuation_tokens
        .iter()
        .find(|t| swarm["continuationToken"]["id"] == t.token_id)
        .ok_or("selected continuation absent")?;
    let allocation = bundle
        .budget_pool
        .allocations
        .iter()
        .find(|a| a.allocation_id == token.budget_allocation_id)
        .ok_or("selected graph allocation absent")?;
    if digest(&bundle.task_graph)? != hash
        || bundle.task_graph.root_transaction_ref != config.program_id
        || bundle.budget_pool.pool_id != config.program_id
        || permit.body.root_id != "program"
        || token.child_task_id != slot.id
        || allocation.task_id != slot.id
        || allocation.allocation_id != permit.body.allocation_hash
        || allocation.max_units != slot.contract.max_units
        || bundle.budget_pool.currency != slot.contract.currency
        || allocation.dimension_id != "xts_base_units"
        || slot.contract.max_units != 100
        || slot.contract.currency != super::native::CURRENCY
    {
        return Err("composed admission changed original delegated graph allocation".into());
    }
    let route = bundle
        .route_plan_receipts
        .iter()
        .find(|r| r.route_plan_id == token.route_plan_receipt_id)
        .ok_or("selected route absent")?;
    let receiver = config
        .profile
        .local_kernel_id
        .strip_prefix("did:chio:")
        .ok_or("unsupported receiver identity")?;
    if route.bridge_id != "native"
        || route.protocol_target != format!("native://{receiver}")
        || route.selected_route != format!("native:{}", slot.id)
    {
        return Err("composed route does not target this receiver and task".into());
    }
    Ok(
        json!({"route":{"bridge":route.bridge_id,"protocolTarget":route.protocol_target,
        "selectedRoute":route.selected_route}}),
    )
}

struct Bindings {
    state: PathBuf,
    config: Config,
}
impl Guard for Bindings {
    fn name(&self) -> &str {
        "evolving-funded-bindings-v1"
    }
    fn evaluate(&self, ctx: &GuardContext<'_>) -> std::result::Result<GuardDecision, KernelError> {
        validate(&self.state, &self.config, ctx.request)
            .map_err(|e| KernelError::GuardDenied(e.to_string()))?;
        Ok(GuardDecision::allow())
    }
    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }
    fn revalidate_before_dispatch(
        &self,
        ctx: &GuardContext<'_>,
    ) -> std::result::Result<(), KernelError> {
        self.evaluate(ctx).map(|_| ())
    }
}

fn open_store(state: &Path) -> Result<SqliteRuntimeOrchestrationStore> {
    let path = state.join("runtime.sqlite");
    if !std::fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err("protected composed runtime store missing".into());
    }
    Ok(SqliteRuntimeOrchestrationStore::open(path)?)
}

/// Export public inputs for an independently written receiver. Operator policy
/// is an explicit enrollment input, never trust imported from the request.
pub(super) fn package(state: &Path, request: &ToolCallRequest) -> Result<Value> {
    let store = open_store(state)?;
    let context = request
        .governed_intent
        .as_ref()
        .and_then(|i| i.context.as_ref())
        .ok_or("context absent")?;
    let treaty = &context["chioTreaty"];
    let mut artifacts = Vec::new();
    for (kind, id) in [
        ("treaty_scope", treaty["treatyScopeId"].as_str()),
        (
            "ladder_intersection",
            treaty["ladderIntersectionId"].as_str(),
        ),
        (
            "cross_kernel_continuation",
            treaty["crossKernelContinuation"]["id"].as_str(),
        ),
        (
            "receipt_lineage_bundle",
            treaty["receiptLineageBundle"]["id"].as_str(),
        ),
        (
            "bilateral_invocation",
            treaty["bilateralInvocation"]["id"].as_str(),
        ),
        (
            "bilateral_dsse_envelope",
            treaty["bilateralDsse"]["id"].as_str(),
        ),
    ] {
        let id = id.ok_or("treaty reference absent")?;
        let record = store
            .treaty_runtime_artifact(kind, id)?
            .ok_or("treaty artifact absent")?;
        artifacts.push(
            json!({"kind":kind,"id":id,"sha256":record.artifact_sha256,"artifact":record.raw_json}),
        );
    }
    let id = context["chioAdmission"]["admissionId"]
        .as_str()
        .ok_or("admission absent")?;
    let admission = store.bundle(id)?.ok_or("admission bundle absent")?;
    for (kind, id) in [
        ("capability_lease", admission.lease_id.as_deref()),
        (
            "governance_receipt",
            admission.governance_receipt_id.as_deref(),
        ),
    ] {
        let id = id.ok_or("treaty presentation reference absent")?;
        let record = store
            .treaty_runtime_artifact(kind, id)?
            .ok_or("presentation record absent")?;
        artifacts.push(
            json!({"kind":kind,"id":id,"sha256":record.artifact_sha256,"artifact":record.raw_json}),
        );
    }
    let policy: Value = super::evidence::read(state.join("funding-policy.json"))?;
    Ok(json!({"receiverPolicy":policy,"admissionBundle":admission,"treatyArtifacts":artifacts}))
}
