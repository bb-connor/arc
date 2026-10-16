//! Authored positives for every `chio.work.v1` variant. Signed D1 records
//! use fixed seeds so the corpus is reproducible byte for byte.

use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_workflow::delegation::{
    binding_digest, Acceptance, Clause, DispatchBinding, DispatchPermit, Effect, Selection, Signed,
    Subdivision, WorkContract, WorkOffer, WorkSlot,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn digest(tag: &str) -> String {
    sha256_hex(tag.as_bytes())
}

fn bytes32(fill: u8) -> Value {
    json!(vec![fill; 32])
}

pub fn scope() -> Value {
    json!({"authority_domain": "domain-a", "tenant_id": "tenant-a", "process_id": "process-a"})
}

pub fn operation() -> Value {
    json!({"operation_id": "operation-a", "native_admission_digest": bytes32(1), "operation_version": 1})
}

fn owner_ref() -> Value {
    json!({"operation": operation(), "scope": scope()})
}

fn artifact_ref() -> Value {
    json!({"scope": scope(), "artifact": "artifact-a", "version": "revision-a", "provenance": bytes32(2)})
}

fn contract() -> WorkContract {
    WorkContract {
        effects: BTreeSet::from([Effect {
            server: "research".into(),
            tool: "analyze".into(),
        }]),
        readers: (1..=4).map(|n| key(n).public_key().to_hex()).collect(),
        max_units: 100,
        currency: "USD".into(),
        expires_at: 2000,
        depth: 2,
        acceptance: Acceptance {
            clauses: vec![Clause::IntegerRange {
                pointer: "/count".into(),
                min: 1,
                max: 10,
            }],
        },
    }
}

pub fn slot(id: &str) -> WorkSlot {
    WorkSlot {
        id: id.into(),
        holder: key(2).public_key(),
        contract: contract(),
    }
}

pub fn subdivision() -> TestResult<Signed<Subdivision>> {
    let mut child = slot("leaf");
    child.contract.depth = 1;
    child.contract.max_units = 40;
    Ok(Signed::sign(
        Subdivision {
            parent_id: "root".into(),
            parent_allocation_hash: digest("allocation-root"),
            child,
        },
        &key(2),
    )?)
}

pub fn offer() -> TestResult<Signed<WorkOffer>> {
    Ok(Signed::sign(
        WorkOffer {
            slot_id: "leaf".into(),
            allocation_hash: digest("allocation-leaf"),
            contract_hash: binding_digest(&slot("leaf"))?,
            receiver: key(3).public_key(),
            effect: Effect {
                server: "research".into(),
                tool: "analyze".into(),
            },
            arguments_hash: digest("arguments"),
            price_units: 20,
            expires_at: 1900,
        },
        &key(3),
    )?)
}

pub fn selection() -> TestResult<Signed<Selection>> {
    Ok(Signed::sign(
        Selection {
            offer: offer()?,
            request_id: "request-a".into(),
            capability_hash: digest("capability"),
            expected_revision: 0,
        },
        &key(2),
    )?)
}

pub fn binding() -> DispatchBinding {
    DispatchBinding {
        slot_id: "leaf".into(),
        receiver: key(3).public_key(),
        subject: key(2).public_key(),
        request_id: "request-a".into(),
        capability_hash: digest("capability"),
        arguments_hash: digest("arguments"),
        effect: Effect {
            server: "research".into(),
            tool: "analyze".into(),
        },
        max_units: 20,
        currency: "USD".into(),
    }
}

pub fn permit() -> TestResult<Signed<DispatchPermit>> {
    Ok(Signed::sign(
        DispatchPermit {
            root_id: "root".into(),
            allocation_hash: digest("allocation-leaf"),
            slot: slot("leaf"),
            selection: selection()?,
            issued_at: 1000,
        },
        &key(1),
    )?)
}

pub fn handle() -> Value {
    json!({
        "program_id": "program-a",
        "slot_id": "leaf",
        "allocation_hash": digest("allocation-leaf"),
        "receiver_kernel_id": "kernel-b",
        "request_id": "request-a"
    })
}

fn profile_ref() -> Value {
    json!({
        "owner": "owner-a",
        "catalog_entry": "entry-a",
        "deployment_digest": bytes32(3),
        "policy_generation": 1,
        "profile_digest": bytes32(4)
    })
}

pub fn commitment() -> TestResult<Value> {
    Ok(json!({
        "handle": handle(),
        "permit": serde_json::to_value(permit()?)?,
        "profile_ref": profile_ref(),
        "invocation_ref": digest("invocation"),
        "graph_ref": digest("graph")
    }))
}

fn command_ref() -> Value {
    json!({"program_id": "program-a", "command_id": "command-a", "command_digest": digest("command")})
}

fn preparation_ref() -> Value {
    json!({"program_id": "program-a", "preparation_id": "preparation-a", "command_digest": digest("command")})
}

fn graph_draft() -> Value {
    json!({"draft_id": "draft-a", "graph_sha256": digest("graph")})
}

pub fn new_task(index: usize) -> Value {
    json!({"task_id": format!("task-{index}"), "handle": handle()})
}

pub fn edge(index: usize) -> Value {
    json!({"fromTaskId": "task-0", "toTaskId": format!("task-{index}"), "edgeType": "sequence"})
}

pub fn join_draft(index: usize) -> Value {
    json!({"draft_id": format!("join-draft-{index}"), "graph_sha256": digest("graph")})
}

pub fn parent_handle(index: usize) -> Value {
    let mut handle = handle();
    handle["request_id"] = json!(format!("request-{index}"));
    handle
}

pub fn catalog_entry(index: usize) -> Value {
    let mut entry = profile_ref();
    entry["catalog_entry"] = json!(format!("entry-{index}"));
    entry
}

pub fn join_parent(index: usize) -> Value {
    json!({
        "task_id": format!("task-{index:02}"),
        "receipt_id": format!("receipt-{index}"),
        "artifact_ref": artifact_ref(),
        "artifact_digest": digest("artifact"),
        "acceptance_evidence_digest": digest("acceptance")
    })
}

fn acceptance() -> Value {
    json!({
        "handle": handle(),
        "producer": operation(),
        "artifact": artifact_ref(),
        "artifact_digest": digest("artifact"),
        "contract_digest": bytes32(5),
        "procedure_digest": digest("procedure"),
        "evaluator": "evaluator-a",
        "decision": "accepted",
        "evidence": ["evidence-a"]
    })
}

pub fn recovery_link() -> Value {
    json!({
        "schema": "chio.recovery.observation.v1",
        "version": 1,
        "scope": scope(),
        "workflow_id": "workflow-a",
        "step_id": "step-a",
        "continuation_id": "continuation-a",
        "control": "active",
        "available": ["inspect_workflow", "resume_workflow"]
    })
}

fn available(value: Value) -> Value {
    json!({"kind": "available", "source": "owner-a", "revision": 1, "observed_at": 1000, "value": value})
}

pub fn view() -> Value {
    json!({
        "handle": handle(),
        "execution": available(json!({"kind": "unknown", "operation": operation()})),
        "acceptance": available(acceptance()),
        "result_reference": available(json!({"artifact": artifact_ref(), "release": {"kind": "not_available"}})),
        "recovery": available(recovery_link()),
        "settlement": {"kind": "pending", "owner_ref": owner_ref()},
        "bilateral_delivery": {"kind": "unavailable", "code": "audience"}
    })
}

pub fn profile() -> Value {
    json!({
        "profile_ref": profile_ref(),
        "server_id": "research",
        "tool_name": "analyze",
        "tool_schema_digest": digest("schema"),
        "implementation_digest": digest("implementation"),
        "max_units": 100,
        "currency": "USD",
        "acceptance_procedure": digest("procedure"),
        "recovery_operations": ["inspect_workflow", "submit_approval"],
        "valid_until_unix_ms": 2000000,
        "conditions": [{"source": "manifest-a", "enforcement": "local", "statement_digest": digest("statement")}]
    })
}

pub fn catalog_page(entries: usize) -> Value {
    json!({
        "catalog_ref": {"owner": "owner-a", "catalog_id": "catalog-a"},
        "entries": (0..entries).map(catalog_entry).collect::<Vec<_>>(),
        "next": {"catalog_generation": 1, "position": digest("cursor")}
    })
}

pub fn request(body: Value) -> Value {
    json!({"schema": "chio.work.request.v1", "version": 1, "body": body})
}

pub fn prepare(proposal: Value) -> Value {
    request(json!({"kind": "prepare", "preparation": {
        "schema": "chio.work.preparation.v1", "version": 1,
        "program_id": "program-a", "command_id": "command-a", "proposal": proposal
    }}))
}

pub fn submit(action: Value) -> Value {
    request(json!({"kind": "submit", "command": {
        "schema": "chio.work.command.v1", "version": 1,
        "program_id": "program-a", "command_id": "command-a", "action": action
    }}))
}

pub fn query(query: Value) -> Value {
    request(json!({"kind": "query", "query": query}))
}

fn response(body: Value) -> Value {
    json!({"schema": "chio.work.response.v1", "version": 1, "body": body})
}

fn command_result(outcome: Value) -> Value {
    response(
        json!({"kind": "command", "result": {"command_ref": command_ref(), "outcome": outcome}}),
    )
}

pub fn extend(tasks: usize, edges: usize, drafts: usize) -> Value {
    json!({
        "kind": "extend",
        "expected_bundle_sha256": digest("bundle"),
        "new_work": (1..=tasks).map(new_task).collect::<Vec<_>>(),
        "dependencies": (1..=edges).map(edge).collect::<Vec<_>>(),
        "join_draft_refs": (1..=drafts).map(join_draft).collect::<Vec<_>>()
    })
}

pub fn join(parents: usize) -> Value {
    json!({
        "kind": "join",
        "expected_bundle_sha256": digest("bundle"),
        "join": {"joinId": "join-a", "parentTaskIds": ["task-1", "task-2"], "nextTaskId": "task-3"},
        "parents": (1..=parents).map(parent_handle).collect::<Vec<_>>()
    })
}

pub fn offer_proposal(arguments: Value) -> Value {
    json!({
        "kind": "offer",
        "slot_id": "leaf",
        "allocation_hash": digest("allocation-leaf"),
        "profile_ref": profile_ref(),
        "receiver_kernel_id": "kernel-b",
        "server_id": "research",
        "tool_name": "analyze",
        "arguments": arguments,
        "request_id": "request-a"
    })
}

pub fn join_inputs(parents: Vec<Value>) -> Value {
    json!({
        "schema": "chio.work.join-inputs.v1",
        "version": 1,
        "graph_sha256": digest("graph"),
        "join_id": "join-a",
        "next_task_id": "task-99",
        "parents": parents
    })
}

/// Every positive as `(name, contract, value)`.
pub fn positives() -> TestResult<Vec<(String, &'static str, Value)>> {
    let subdivision = serde_json::to_value(subdivision()?)?;
    let offer = serde_json::to_value(offer()?)?;
    let selection = serde_json::to_value(selection()?)?;
    let binding = serde_json::to_value(binding())?;
    let permit = serde_json::to_value(permit()?)?;
    let commitment = commitment()?;
    let rejection =
        json!({"code": "binding_mismatch", "field": "allocation_hash", "reference": command_ref()});
    let mut out: Vec<(String, &'static str, Value)> = Vec::new();
    let mut add = |name: &str, contract: &'static str, value: Value| {
        out.push((name.to_owned(), contract, value));
    };
    add(
        "prepare-delegate",
        "request",
        prepare(json!({
            "kind": "delegate", "parent_id": "root",
            "parent_allocation_hash": digest("allocation-root"),
            "child": serde_json::to_value(slot("leaf"))?
        })),
    );
    add(
        "prepare-offer",
        "request",
        prepare(offer_proposal(json!({"query": "ledger", "ratio": 0.5}))),
    );
    add(
        "prepare-select",
        "request",
        prepare(json!({
            "kind": "select", "offer": offer, "request_id": "request-a",
            "capability_hash": digest("capability"), "expected_revision": 0
        })),
    );
    add("prepare-extend", "request", prepare(extend(2, 2, 1)));
    add("prepare-join", "request", prepare(join(2)));
    add(
        "prepare-agreement-unpaid",
        "request",
        prepare(json!({
            "kind": "agreement", "commitment": commitment,
            "terms": {"kind": "unpaid", "terms_reference": "terms-a"}
        })),
    );
    add(
        "submit-delegate",
        "request",
        submit(json!({"kind": "delegate", "subdivision": subdivision})),
    );
    add(
        "submit-select",
        "request",
        submit(json!({"kind": "select", "selection": selection})),
    );
    add(
        "submit-seal",
        "request",
        submit(json!({"kind": "seal", "binding": binding})),
    );
    add(
        "submit-extend",
        "request",
        submit(json!({
            "kind": "extend", "expected_bundle_sha256": digest("bundle"), "draft_ref": graph_draft()
        })),
    );
    add(
        "submit-submit",
        "request",
        submit(json!({"kind": "submit", "commitment": commitment})),
    );
    add(
        "submit-reconcile",
        "request",
        submit(json!({"kind": "reconcile", "handle": handle()})),
    );
    add(
        "submit-cancel",
        "request",
        submit(json!({"kind": "cancel", "handle": handle()})),
    );
    add(
        "query-work",
        "request",
        query(json!({"kind": "work", "handle": handle()})),
    );
    add(
        "query-command",
        "request",
        query(json!({"kind": "command", "command_ref": command_ref()})),
    );
    add(
        "query-preparation",
        "request",
        query(json!({"kind": "preparation", "preparation_ref": preparation_ref()})),
    );
    add(
        "query-catalog",
        "request",
        query(json!({
            "kind": "catalog", "catalog_ref": {"owner": "owner-a", "catalog_id": "catalog-a"},
            "cursor": {"catalog_generation": 1, "position": digest("cursor")}
        })),
    );
    add(
        "query-profile",
        "request",
        query(json!({"kind": "profile", "profile_ref": profile_ref()})),
    );
    add(
        "response-prepared",
        "response",
        response(json!({"kind": "prepared", "prepared": {
            "kind": "prepared", "preparation_ref": preparation_ref(),
            "artifact": {"kind": "subdivision", "subdivision": subdivision}
        }})),
    );
    add(
        "response-prepared-offer",
        "response",
        response(json!({"kind": "prepared", "prepared": {
            "kind": "prepared", "preparation_ref": preparation_ref(),
            "artifact": {"kind": "offer", "offer": offer, "invocation_ref": digest("invocation")}
        }})),
    );
    add(
        "response-prepared-pending",
        "response",
        response(json!({"kind": "prepared", "prepared": {
            "kind": "pending", "preparation_ref": preparation_ref(), "owner_operation_ref": owner_ref()
        }})),
    );
    add(
        "response-prepared-refused",
        "response",
        response(json!({"kind": "prepared", "prepared": {
            "kind": "refused", "preparation_ref": preparation_ref(), "rejection": rejection
        }})),
    );
    for (name, result) in [
        (
            "delegated",
            json!({"kind": "delegated", "slot": serde_json::to_value(slot("leaf"))?}),
        ),
        ("selected", json!({"kind": "selected", "revision": 1})),
        ("sealed", json!({"kind": "sealed", "permit": permit})),
        (
            "extended",
            json!({"kind": "extended", "bundle_sha256": digest("bundle")}),
        ),
        (
            "submitted",
            json!({"kind": "submitted", "owner_operation_ref": owner_ref()}),
        ),
        ("reconciled", json!({"kind": "reconciled", "view": view()})),
        (
            "cancel-observed",
            json!({"kind": "cancel_observed", "control": "cancel_requested"}),
        ),
    ] {
        add(
            &format!("response-applied-{name}"),
            "response",
            command_result(json!({
                "kind": "applied", "revision": 1, "result": result
            })),
        );
    }
    add(
        "response-command-pending",
        "response",
        command_result(json!({"kind": "pending", "owner_operation_ref": owner_ref()})),
    );
    add(
        "response-command-refused",
        "response",
        command_result(json!({"kind": "refused", "rejection": rejection})),
    );
    add(
        "response-query-work",
        "response",
        response(json!({"kind": "query", "result": {"kind": "work", "view": view()}})),
    );
    add(
        "response-query-catalog",
        "response",
        response(json!({"kind": "query", "result": {"kind": "catalog", "page": catalog_page(2)}})),
    );
    add(
        "response-query-profile",
        "response",
        response(json!({"kind": "query", "result": {"kind": "profile", "profile": profile()}})),
    );
    add(
        "response-query-unavailable",
        "response",
        response(
            json!({"kind": "query", "result": {"kind": "unavailable", "code": "stale_catalog"}}),
        ),
    );
    add(
        "join-inputs",
        "join_inputs",
        join_inputs((1..=3).map(join_parent).collect()),
    );
    Ok(out)
}
