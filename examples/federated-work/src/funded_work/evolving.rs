//! One local execution of D1 allocation, S1 evolution, native treaty admission
//! and the existing F1 escrow. All operators share this experimental host.
use super::{
    agreement::{Agreement, WorkTerms, AGREEMENT_SCHEMA},
    composition::{self, Provision},
    local_chain::LocalChain,
    native::Native,
    smoke::Scenario,
};
use crate::common::{self, digest, Result};
use chio_core_types::{
    capability::token::{CapabilityToken, CapabilityTokenBody},
    Keypair,
};
use chio_kernel::ToolCallRequest;
use chio_runtime_core::SqliteRuntimeOrchestrationStore;
use chio_workflow::delegation::*;
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::Path, sync::Arc};
mod graph;
#[cfg(test)]
mod tests;

struct Prepared {
    native: Native,
    request: ToolCallRequest,
    work: WorkTerms,
    waiver: chio_kernel::payment::SignedContractualCaptureWaiverTermsV1,
}

fn prepare(
    state: &Path,
    mut native: Native,
    setup: &Value,
    buyer: &Keypair,
    id: &str,
) -> Result<Prepared> {
    composition::connect_local_cosigner(&mut native, buyer)?;
    let work: WorkTerms = serde_json::from_value(setup["work"].clone())?;
    let mut request = native.request(
        id,
        include_str!("../../fixtures/openapi.json"),
        work.submit_by,
    )?;
    let waiver = super::waiver_terms::authorize(
        &native.policy,
        &work,
        &mut request,
        &common::key(state)?,
        buyer,
    )?;
    composition::treaty::attach(
        state,
        native
            .policy
            .composition
            .as_ref()
            .ok_or("composed policy absent")?,
        &mut request,
        buyer,
        &common::key(state)?,
    )?;
    Ok(Prepared {
        native,
        request,
        work,
        waiver,
    })
}

fn seal(
    store: &DelegationStore,
    prepared: &mut Prepared,
    holder: &Keypair,
    allocator: &Keypair,
) -> Result<()> {
    let request = &mut prepared.request;
    let id = &request.request_id;
    let receiver = common::key(&prepared.native.state)?;
    let slot = store.slot(id)?;
    let input = work_input_digest(id, &request.arguments)?;
    store.select(
        &Signed::sign(
            Selection {
                offer: Signed::sign(
                    WorkOffer {
                        slot_id: id.clone(),
                        allocation_hash: store.allocation_digest(id)?,
                        contract_hash: binding_digest(&slot)?,
                        receiver: receiver.public_key(),
                        effect: Effect {
                            server: request.server_id.clone(),
                            tool: request.tool_name.clone(),
                        },
                        arguments_hash: input.clone(),
                        price_units: 100,
                        expires_at: slot.contract.expires_at,
                    },
                    &receiver,
                )?,
                request_id: id.clone(),
                capability_hash: binding_digest(&request.capability)?,
                expected_revision: 0,
            },
            holder,
        )?,
        common::now()?,
        &[receiver.public_key()],
    )?;
    let permit = store.seal_dispatch(
        &DispatchBinding {
            slot_id: id.clone(),
            receiver: receiver.public_key(),
            subject: holder.public_key(),
            request_id: id.clone(),
            capability_hash: binding_digest(&request.capability)?,
            arguments_hash: input,
            effect: Effect {
                server: request.server_id.clone(),
                tool: request.tool_name.clone(),
            },
            max_units: 100,
            currency: "XTS".into(),
        },
        common::now()?,
        allocator,
    )?;
    request
        .governed_intent
        .as_mut()
        .and_then(|i| i.context.as_mut())
        .ok_or("context absent")?["chioDelegation"] = json!({"slot_id":id,"allocation":permit});
    Ok(())
}

fn fund(
    mut prepared: Prepared,
    bundle: &chio_swarm_authority::SwarmAuthorityBundle,
    buyer: &Keypair,
    chain: Arc<LocalChain>,
) -> Result<Scenario> {
    let request = &mut prepared.request;
    let context = graph::context(bundle, &request.request_id)?;
    request
        .governed_intent
        .as_mut()
        .and_then(|i| i.context.as_mut())
        .ok_or("context absent")?["chioSwarm"] = context;
    let p = &prepared.native.policy;
    let agreement = Agreement {
        schema: AGREEMENT_SCHEMA.into(),
        policy_sha256: digest(p)?,
        authority_uuid: p.authority_uuid.clone(),
        buyer_key: p.buyer_key.clone(),
        provider_key: p.provider_key.clone(),
        request_id: request.request_id.clone(),
        request_sha256: digest(request)?,
        finding_context_sha256: digest(&p.finding_context)?,
        required_finding_facets: p.required_finding_facets.clone(),
        domain: p.domain.clone(),
        work: prepared.work,
        capture_waiver_terms: Some(prepared.waiver),
    }
    .sign(buyer, &common::key(&prepared.native.state)?)?;
    let funding = chain.request(json!({"method":"fund","terms":agreement.body.terms()?}))?;
    chain.request(json!({"method":"pin-verifier","allocation":funding["allocationId"],"key":p.verifier_key.to_hex()}))?;
    Ok(Scenario {
        chain,
        native: prepared.native,
        agreement,
        request: prepared.request,
        funding,
    })
}

fn subdivide(
    store: &DelegationStore,
    parent: &str,
    signer: &Keypair,
    mut child: WorkSlot,
) -> Result<()> {
    child.contract.depth = store
        .slot(parent)?
        .contract
        .depth
        .checked_sub(1)
        .ok_or("depth exhausted")?;
    store.subdivide(
        &Signed::sign(
            Subdivision {
                parent_id: parent.into(),
                parent_allocation_hash: store.allocation_digest(parent)?,
                child,
            },
            signer,
        )?,
        common::now()?,
    )?;
    Ok(())
}

fn progress(state: &Path, scenario: &Scenario, mode: &str) -> Result<Value> {
    super::lifecycle::progress(
        state,
        &scenario.native,
        &scenario.request,
        mode,
        &checkpoint(),
        &|phase| {
            scenario.chain.request(json!({"method":"advance","allocation":scenario.funding["allocationId"],"phase":phase}))?;
            Ok(())
        },
    )
}

pub fn run(state: &Path) -> Result<Value> {
    use std::os::unix::process::ExitStatusExt;
    if !state.is_dir() || std::fs::read_dir(state)?.next().is_some() {
        return Err("evolving work requires an empty disposable directory".into());
    }
    let chain = Arc::new(LocalChain::start()?);
    let setup = chain.request(json!({"method":"initialize"}))?;
    let child_setup = chain.request(json!({"method":"initialize-child"}))?;
    common::init(&state.join("buyer"))?;
    let buyer = common::key(&state.join("buyer"))?;
    let allocator = Keypair::generate();
    let now = super::now_ms()?;
    let until = now + 600_000;
    let program = digest(&("evolving-program", allocator.public_key()))?;
    // Enrollment precedes discovery. The program may select only these owner-
    // approved readers; it cannot disclose input to an arbitrary new principal.
    for role in ["scout", "parent", "child"] {
        let selected = if role == "child" {
            common::key(&state.join("parent"))?
        } else {
            buyer.clone()
        };
        Native::provision_composed(
            &state.join(role),
            selected.public_key(),
            serde_json::from_value(setup["domain"].clone())?,
            vec![
                chio_finding::FindingFacetKind::ArtifactIntegrity,
                chio_finding::FindingFacetKind::ReceiptAuthenticity,
                chio_finding::FindingFacetKind::CheckpointMembership,
                chio_finding::FindingFacetKind::GuaranteeConsistency,
            ],
            true,
            Some(Provision {
                allocator: allocator.public_key(),
                witness: allocator.public_key(),
                program_id: program.clone(),
                buyer: selected,
                issued: now,
                until,
            }),
        )?;
    }
    let parent_key = common::key(&state.join("parent"))?;
    let readers = [
        buyer.public_key(),
        allocator.public_key(),
        common::key(&state.join("scout"))?.public_key(),
        parent_key.public_key(),
        common::key(&state.join("child"))?.public_key(),
    ]
    .into_iter()
    .map(|k| k.to_hex())
    .collect();
    let root = WorkSlot {
        id: "program".into(),
        holder: buyer.public_key(),
        contract: WorkContract {
            effects: BTreeSet::from([Effect {
                server: super::native::SERVER.into(),
                tool: "review".into(),
            }]),
            readers,
            max_units: 300,
            currency: "XTS".into(),
            expires_at: until / 1000,
            depth: 3,
            acceptance: Acceptance {
                clauses: vec![Clause::Equals {
                    pointer: "/0/path".into(),
                    value: json!("/accounts"),
                }],
            },
        },
    };
    let store = DelegationStore::open(state.join("delegation.sqlite"))?;
    store.create_root(root.clone())?;
    let leaf = |id: &str, holder: &Keypair, units: u64| {
        let mut slot = root.clone();
        slot.id = id.into();
        slot.holder = holder.public_key();
        slot.contract.max_units = units;
        slot
    };
    subdivide(&store, "program", &buyer, leaf("scout", &buyer, 100))?;
    subdivide(
        &store,
        "program",
        &buyer,
        leaf("intermediary", &parent_key, 200),
    )?;
    subdivide(
        &store,
        "intermediary",
        &parent_key,
        leaf("parent", &buyer, 100),
    )?;
    let mut scout = prepare(
        &state.join("scout"),
        Native::open(&state.join("scout"), chain.clone())?,
        &setup,
        &buyer,
        "scout",
    )?;
    let mut parent = prepare(
        &state.join("parent"),
        Native::open(&state.join("parent"), chain.clone())?,
        &setup,
        &buyer,
        "parent",
    )?;
    seal(&store, &mut scout, &buyer, &allocator)?;
    seal(&store, &mut parent, &buyer, &allocator)?;
    let mut scope = scout.request.capability.scope.clone();
    scope.grants[0].max_invocations = Some(3);
    scope.grants[0]
        .max_total_cost
        .as_mut()
        .ok_or("root ceiling")?
        .units = 300;
    let root_capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "planning-envelope".into(),
            issuer: allocator.public_key(),
            subject: buyer.public_key(),
            scope,
            issued_at: now / 1000,
            expires_at: until / 1000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &allocator,
    )?;
    let config = scout
        .native
        .policy
        .composition
        .as_ref()
        .ok_or("profile absent")?;
    let mut initial = graph::new(config, &root_capability, &allocator)?;
    graph::add(
        &mut initial,
        &scout.request,
        store.allocation_digest("scout")?,
        &root_capability,
        &allocator,
    )?;
    graph::add(
        &mut initial,
        &parent.request,
        store.allocation_digest("parent")?,
        &root_capability,
        &allocator,
    )?;
    chio_swarm_authority::verify_swarm_authority_for_admission(
        &initial,
        &[allocator.public_key()],
    )?;
    let graph_owner = SqliteRuntimeOrchestrationStore::open(state.join("graph-owner.sqlite"))?;
    graph_owner.insert_swarm_authority_bundle(initial.clone())?;
    for role in ["scout", "parent", "child"] {
        SqliteRuntimeOrchestrationStore::open(state.join(role).join("runtime.sqlite"))?
            .insert_swarm_authority_bundle(initial.clone())?;
    }
    let scout = fund(scout, &initial, &buyer, chain.clone())?;
    let parent = fund(parent, &initial, &buyer, chain.clone())?;
    let first = scout.native.execute(&scout.agreement, &scout.request)?;
    if first["executions"] != 1 {
        return Err(format!("scout stopped before tool dispatch: {first}").into());
    }
    let original_evidence = scout.native.evidence(&scout.request)?;
    if !original_evidence
        .output
        .as_array()
        .is_some_and(|rows| rows.iter().any(|r| r["authenticationRequired"] == false))
    {
        return Err("scout did not discover work requiring the enrolled specialist".into());
    }
    if store.slot("child").is_ok() {
        return Err("child was allocated before discovery".into());
    }
    // No child task, capability, selection, agreement or deposit exists before
    // this observed result. Enrollment alone did not authorize the work.
    subdivide(
        &store,
        "intermediary",
        &parent_key,
        leaf("child", &parent_key, 100),
    )?;
    let mut child = prepare(
        &state.join("child"),
        Native::open(&state.join("child"), chain.clone())?,
        &child_setup,
        &parent_key,
        "child",
    )?;
    seal(&store, &mut child, &parent_key, &allocator)?;
    let mut next = initial.clone();
    graph::add(
        &mut next,
        &child.request,
        store.allocation_digest("child")?,
        &root_capability,
        &allocator,
    )?;
    // Construct and sign the exact future request before backing it. Installation
    // follows backing; a crash between the stores strands capacity, not identity.
    let graph_hash = digest(&initial)?;
    let mut refresh = next.clone();
    refresh.continuation_tokens[0].nonce = "refreshed-old-work".into();
    refresh.continuation_tokens[0].signature = chio_swarm_authority::sign_swarm_continuation_token(
        &refresh.continuation_tokens[0],
        &allocator,
    )?;
    let continuation_error = graph_owner
        .extend_swarm_authority_bundle(&graph_hash, refresh, &[allocator.public_key()])
        .err()
        .ok_or("continuation refresh was accepted")?
        .to_string();
    let continuation_rejected = continuation_error.contains("issued continuation changed");
    let child = fund(child, &next, &parent_key, chain.clone())?;
    graph_owner.extend_swarm_authority_bundle(
        &graph_hash,
        next.clone(),
        &[allocator.public_key()],
    )?;
    for role in ["scout", "parent", "child"] {
        SqliteRuntimeOrchestrationStore::open(state.join(role).join("runtime.sqlite"))?
            .extend_swarm_authority_bundle(&graph_hash, next.clone(), &[allocator.public_key()])?;
    }
    let mut stripped = child.request.clone();
    stripped
        .governed_intent
        .as_mut()
        .and_then(|i| i.context.as_mut())
        .and_then(Value::as_object_mut)
        .ok_or("context")?
        .remove("chioTreaty");
    let mut rebound = child.agreement.body.clone();
    rebound.request_sha256 = digest(&stripped)?;
    let rebound = rebound.sign(&parent_key, &common::key(&state.join("child"))?)?;
    rebound.validate(&child.native.policy, &stripped)?;
    let treaty_error = child
        .native
        .execute(&rebound, &stripped)
        .err()
        .ok_or("missing treaty accepted")?
        .to_string();
    let treaty_rejected =
        treaty_error == "composed admission changed treaty, origin or task identity";
    let receiver_error = parent
        .native
        .execute(&child.agreement, &child.request)
        .err()
        .ok_or("foreign receiver accepted")?
        .to_string();
    let receiver_rejected =
        receiver_error == "agreement changes pinned native funding authority or request";
    let permit: Signed<DispatchPermit> = serde_json::from_value(
        child
            .request
            .governed_intent
            .as_ref()
            .and_then(|i| i.context.as_ref())
            .ok_or("context")?["chioDelegation"]["allocation"]
            .clone(),
    )?;
    let mut selection = permit.body.selection.body.clone();
    selection.request_id = "another-child".into();
    selection.expected_revision = 1;
    let allocation_rejected = matches!(
        store.select(
            &Signed::sign(selection, &parent_key)?,
            common::now()?,
            std::slice::from_ref(&child.native.policy.provider_key)
        ),
        Err(chio_workflow::delegation::DelegationError::Conflict)
    );
    if child.native.operation(&child.request)?.is_some()
        || parent.native.operation(&parent.request)?.is_some()
        || child.native.journal.execution_count()? != 0
        || parent.native.journal.execution_count()? != 0
    {
        return Err("rejected request created native work".into());
    }
    if ![
        treaty_rejected,
        receiver_rejected,
        allocation_rejected,
        continuation_rejected,
    ]
    .into_iter()
    .all(|v| v)
    {
        return Err("an authority substitution was accepted".into());
    }
    super::child::retain(state, &parent, &child)?;
    // Submit the already completed scout before the child's challenge window
    // advances the shared chain past the scout's submission deadline.
    let submitted = super::evidence::submit(
        &original_evidence,
        &original_evidence.output,
        &common::key(&state.join("scout"))?,
        &scout.native.journal,
    )?;
    let scout_entry = scout
        .native
        .journal
        .by_request("scout")?
        .ok_or("scout entry")?;
    scout
        .native
        .journal
        .retain(&scout_entry.allocation, "submission", &submitted)?;
    super::settlement::drive(
        &scout_entry,
        super::settlement::Action::Submit,
        &scout.native.policy,
        &scout.native.journal,
        scout.native.source.as_ref(),
        &checkpoint(),
    )?;
    let public = json!({"initialGraph":initial,"extendedGraph":next,"rootAllocationSha256":store.allocation_digest("program")?,
        "scout":{"request":scout.request,"agreement":scout.agreement,"receiverPackage":composition::package(&state.join("scout"), &scout.request)?},
        "parent":{"request":parent.request,"agreement":parent.agreement,"receiverPackage":composition::package(&state.join("parent"), &parent.request)?},
        "child":{"request":child.request,"agreement":child.agreement,"receiverPackage":composition::package(&state.join("child"), &child.request)?}});
    let child_id = child.funding["allocationId"]
        .as_str()
        .ok_or("child allocation")?
        .to_owned();
    let parent_id = parent.funding["allocationId"]
        .as_str()
        .ok_or("parent allocation")?
        .to_owned();
    let parent_request = parent.request.clone();
    let child_request = child.request.clone();
    drop(parent.native);
    drop(child.native);
    let mut parent_server = super::process::Server::start(
        &state.join("parent.sock"),
        parent_id.clone(),
        chain.clone(),
    )?;
    let mut child_server =
        super::process::Server::start(&state.join("child.sock"), child_id.clone(), chain.clone())?;
    let killed = std::process::Command::new(std::env::current_exe()?)
        .arg("experimental-funded-parent-worker")
        .arg(state)
        .output()?;
    if killed.status.signal() != Some(9) {
        return Err(format!(
            "evolving parent missed earned-child SIGKILL: status={} stdout={} stderr={}",
            killed.status,
            String::from_utf8_lossy(&killed.stdout),
            String::from_utf8_lossy(&killed.stderr)
        )
        .into());
    }
    parent_server.finish()?;
    let earned = chain.request(json!({"method":"summary","allocation":child_id}))?;
    if earned["state"] != "Payable" || earned["paid"] != "0" {
        return Err("child was not payable at parent loss".into());
    }
    let parent_native = Native::open(&state.join("parent"), chain.clone())?;
    let child_native = Native::open(&state.join("child"), chain.clone())?;
    let original = json!({"scout":first,"parent":parent_native.report(&parent_request)?,"child":child_native.report(&child_request)?});
    drop(child_native);
    // The scout must submit while the parent funding remains open. All three
    // invocations already exist; advancing the rail cannot admit fresh work.
    progress(&state.join("scout"), &scout, "pay")?;
    let after_growth = scout.native.evidence(&scout.request)?;
    let preserved = evidence_digest(&original_evidence)? == evidence_digest(&after_growth)?;
    super::lifecycle::progress(
        &state.join("parent"),
        &parent_native,
        &parent_request,
        "absent",
        &checkpoint(),
        &|phase| {
            chain.request(json!({"method":"advance","allocation":parent_id,"phase":phase}))?;
            Ok(())
        },
    )?;
    let parent_report = parent_native.report(&parent_request)?;
    drop(parent_native);
    let retired = chain.request(json!({"method":"retire-parent"}))?;
    let collect = || -> Result<Value> {
        let output = std::process::Command::new(std::env::current_exe()?)
            .arg("experimental-funded-child-collector")
            .arg(state.join("child"))
            .arg(state.join("child.sock"))
            .arg("none")
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "evolving child collection failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    };
    let collected = collect()?;
    let repeated = collect()?;
    // The first open may finish the local operation while remote co-signing is
    // unavailable. A later open has no unfinished local operation to reconcile.
    // Retain both diagnostics; only that startup observation may differ.
    let stable_collection = |value: &Value| -> Result<Value> {
        let mut value = value.clone();
        value["replay"]
            .as_object_mut()
            .ok_or("collector report absent")?
            .remove("startupReconciliationError");
        Ok(value)
    };
    if stable_collection(&collected)? != stable_collection(&repeated)? {
        return Err("repeated child collection changed execution or payment identity".into());
    }
    child_server.finish()?;
    let scout_request = scout.request;
    let scout_agreement = scout.agreement;
    let scout_id = scout.funding["allocationId"].clone();
    drop(scout.native);
    let scout = Native::open(&state.join("scout"), chain.clone())?;
    let scout_report = scout.execute(&scout_agreement, &scout_request)?;
    let preserved = preserved
        && evidence_digest(&scout.evidence(&scout_request)?)?
            == evidence_digest(&original_evidence)?;
    Ok(
        json!({"schema":"chio.experimental.evolving-funded-run.v1","scope":"one host, locally enrolled receivers, private chain and mock tokens",
        "parentKilledSignal":killed.status.signal(),"discoveredAfterScout":true,"originalScoutPreserved":preserved,
        "discovery":{"sourceOperation":first["operationId"],"output":original_evidence.output,
            "outputSha256":digest(&original_evidence.output)?,"selectedTask":"child"},
        "graphNodeCounts":[initial.task_graph.nodes.len(),next.task_graph.nodes.len()],
        "rejections":{"receiver":receiver_rejected,"allocation":allocation_rejected,"continuation":continuation_rejected,"treaty":treaty_rejected},
        "rejectionReasons":{"receiver":receiver_error,"treaty":treaty_error,"continuation":continuation_error,
            "allocation":"allocation or dispatch identity conflicts with durable state"},
        "earned":earned,"original":original,"scout":scout_report,"parent":parent_report,"child":collected["replay"],"retired":retired,
        "collection":collected,"collectionReplay":repeated,
        "publicArtifacts":public,"final":{"scout":chain.request(json!({"method":"summary","allocation":scout_id}))?,
            "parent":chain.request(json!({"method":"summary","allocation":parent_id}))?,"child":chain.request(json!({"method":"summary","allocation":child_id}))?,
            "balances":chain.request(json!({"method":"family-balances"}))?}}),
    )
}

fn checkpoint() -> super::Checkpoint {
    Arc::new(|_| Ok(()))
}
fn evidence_digest(e: &super::evidence::Evidence) -> Result<String> {
    digest(&(&e.binding, &e.input, &e.output, &e.execution))
}
