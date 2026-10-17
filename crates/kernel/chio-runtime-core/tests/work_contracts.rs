//! `chio.work.v1` contract vectors: every positive decodes, and every
//! derived negative is refused with its exact rejection code.

#[path = "work_contracts/positives.rs"]
mod positives;
#[path = "work_contracts/rec0a.rs"]
mod rec0a;

use chio_runtime_core::work::{
    decode_work_join_inputs, decode_work_request, decode_work_response, WorkContractError,
    MAX_WORK_ENTRIES, MAX_WORK_NODES, MAX_WORK_REQUEST_BYTES,
};
use positives::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

const CORPUS: &str = "spec/vectors/work/v1/contracts.json";
const BLESS: &str = "CHIO_BLESS_WORK_VECTORS";

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Corpus {
    format_version: u8,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Vector {
    name: String,
    contract: String,
    valid: bool,
    schema_valid: bool,
    wire: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

fn vector(
    name: &str,
    contract: &str,
    value: &Value,
    schema_valid: bool,
    error: Option<&str>,
) -> TestResult<Vector> {
    raw(
        name,
        contract,
        serde_json::to_string(value)?,
        schema_valid,
        error,
    )
}

fn raw(
    name: &str,
    contract: &str,
    wire: String,
    schema_valid: bool,
    error: Option<&str>,
) -> TestResult<Vector> {
    Ok(Vector {
        name: name.to_owned(),
        contract: contract.to_owned(),
        valid: error.is_none(),
        schema_valid,
        wire,
        error: error.map(str::to_owned),
        field: None,
    })
}

fn binding(name: &str, value: &Value, field: &str) -> TestResult<Vector> {
    let mut vector = vector(name, "request", value, true, Some("work.binding_mismatch"))?;
    vector.field = Some(field.to_owned());
    Ok(vector)
}

fn nested(depth: usize) -> Value {
    (0..depth).fold(json!(1), |inner, _| json!([inner]))
}

/// Nodes and entries as the decoder charges them: one node per container,
/// key, string and scalar; one entry per container and per separator.
fn charges(value: &Value) -> (usize, usize) {
    let container =
        |len: usize, inner: (usize, usize)| (1 + inner.0, 1 + len.saturating_sub(1) + inner.1);
    let sum = |items: Vec<(usize, usize)>| {
        items
            .into_iter()
            .fold((0, 0), |(n, e), (dn, de)| (n + dn, e + de))
    };
    match value {
        Value::Object(map) => container(
            map.len(),
            sum(map
                .values()
                .map(|v| {
                    let (n, e) = charges(v);
                    (n + 1, e)
                })
                .collect()),
        ),
        Value::Array(items) => container(items.len(), sum(items.iter().map(charges).collect())),
        _ => (1, 0),
    }
}

/// An Offer frame charging exactly `nodes` nodes. Well-formed JSON spends at
/// least one entry per two nodes, so the entry bound always fires first; the
/// node bound is reached only by scalars without separators, which the
/// preflight charges before the parser refuses the text.
fn offer_with_nodes(nodes: usize) -> TestResult<String> {
    let frame = prepare(offer_proposal(json!({"pad": []})));
    let (base, _) = charges(&frame);
    let room = nodes.checked_sub(base).ok_or("node base over budget")?;
    let text = serde_json::to_string(&frame)?;
    if text.matches("\"pad\":[]").count() != 1 {
        return Err("pad is not unique in the node frame".into());
    }
    Ok(text.replacen(
        "\"pad\":[]",
        &format!("\"pad\":[{}]", vec!["0"; room].join(" ")),
        1,
    ))
}

/// An Offer whose arguments bring the frame to exactly `entries` entries.
fn offer_with_entries(entries: usize) -> TestResult<Value> {
    let (_, base) = charges(&prepare(offer_proposal(json!({"list": [0]}))));
    let room = entries.checked_sub(base).ok_or("entry base over budget")?;
    let frame = prepare(offer_proposal(json!({"list": vec![0; room + 1]})));
    let (nodes, used) = charges(&frame);
    if used != entries || nodes > MAX_WORK_NODES {
        return Err(format!("entry frame charges {nodes} nodes and {used} entries").into());
    }
    Ok(frame)
}

fn corpus() -> TestResult<Corpus> {
    let mut vectors = Vec::new();
    for (name, contract, value) in positives()? {
        vectors.push(vector(&name, contract, &value, true, None)?);
    }
    let base = prepare(offer_proposal(json!({"query": "ledger"})));

    let mut unknown_field = base.clone();
    unknown_field["unexpected"] = json!(true);
    vectors.push(vector(
        "unknown-field",
        "request",
        &unknown_field,
        false,
        Some("work.malformed"),
    )?);
    let mut unknown_kind = base.clone();
    unknown_kind["body"]["kind"] = json!("execute");
    vectors.push(vector(
        "unknown-kind",
        "request",
        &unknown_kind,
        false,
        Some("work.malformed"),
    )?);
    let mut nested_unknown = base.clone();
    nested_unknown["body"]["preparation"]["proposal"]["extra"] = json!(1);
    vectors.push(vector(
        "unknown-proposal-field",
        "request",
        &nested_unknown,
        false,
        Some("work.malformed"),
    )?);
    let mut wrong_schema = base.clone();
    wrong_schema["schema"] = json!("chio.work.request.v2");
    vectors.push(vector(
        "wrong-schema",
        "request",
        &wrong_schema,
        false,
        Some("work.schema"),
    )?);
    let mut wrong_version = base.clone();
    wrong_version["version"] = json!(2);
    vectors.push(vector(
        "wrong-version",
        "request",
        &wrong_version,
        false,
        Some("work.schema"),
    )?);
    let mut nested_schema = base.clone();
    nested_schema["body"]["preparation"]["schema"] = json!("chio.work.preparation.v9");
    vectors.push(vector(
        "wrong-nested-schema",
        "request",
        &nested_schema,
        false,
        Some("work.schema"),
    )?);

    vectors.push(vector(
        "opaque-arguments-schema",
        "request",
        &prepare(offer_proposal(
            json!({"schema": "chio.work.notes", "version": 2}),
        )),
        true,
        None,
    )?);

    let text = serde_json::to_string(&base)?;
    vectors.push(raw(
        "trailing-comma",
        "request",
        text.replacen('}', ",}", 1),
        false,
        Some("work.malformed"),
    )?);
    vectors.push(raw(
        "duplicate-top-level-key",
        "request",
        text.replacen('{', "{\"version\":1,", 1),
        true,
        Some("work.duplicate_key"),
    )?);
    vectors.push(raw(
        "duplicate-nested-key",
        "request",
        text.replacen("\"arguments\":{", "\"arguments\":{\"query\":\"x\",", 1),
        true,
        Some("work.duplicate_key"),
    )?);
    let select = prepare(
        json!({"kind": "select", "offer": serde_json::to_value(offer()?)?,
        "request_id": "request-a", "capability_hash": "0".repeat(64), "expected_revision": 0}),
    );
    let select_text = serde_json::to_string(&select)?;
    if select_text.matches("\"price_units\":").count() != 1 {
        return Err("offer price is not unique in the select frame".into());
    }
    vectors.push(raw(
        "duplicate-d1-envelope-key",
        "request",
        select_text.replacen("\"price_units\":", "\"price_units\":20,\"price_units\":", 1),
        true,
        Some("work.duplicate_key"),
    )?);
    let observed = serde_json::to_string(&json!({"schema": "chio.work.response.v1", "version": 1,
        "body": {"kind": "query", "result": {"kind": "work", "view": view()}}}))?;
    if observed.matches("\"kind\":\"unknown\"").count() != 1 {
        return Err("execution observation is not unique in the view frame".into());
    }
    vectors.push(raw(
        "duplicate-rec0a-observation-key",
        "response",
        observed.replacen(
            "\"kind\":\"unknown\"",
            "\"kind\":\"unknown\",\"kind\":\"unknown\"",
            1,
        ),
        true,
        Some("work.duplicate_key"),
    )?);

    vectors.push(vector(
        "safe-integer-maximum",
        "request",
        &prepare(offer_proposal(json!({"n": 9_007_199_254_740_991_u64}))),
        true,
        None,
    )?);
    vectors.push(vector(
        "unsafe-integer",
        "request",
        &prepare(offer_proposal(json!({"n": 9_007_199_254_740_992_u64}))),
        true,
        Some("work.unsafe_integer"),
    )?);
    vectors.push(raw(
        "unsafe-negative-integer",
        "request",
        serde_json::to_string(&prepare(offer_proposal(json!({"n": 1}))))?.replacen(
            "\"n\":1",
            "\"n\":-9007199254740992",
            1,
        ),
        true,
        Some("work.unsafe_integer"),
    )?);
    let mut unsafe_revision = prepare(
        json!({"kind": "select", "offer": serde_json::to_value(offer()?)?,
        "request_id": "request-a", "capability_hash": "0".repeat(64), "expected_revision": 0}),
    );
    unsafe_revision["body"]["preparation"]["proposal"]["expected_revision"] =
        json!(9_007_199_254_740_992_u64);
    vectors.push(vector(
        "unsafe-revision",
        "request",
        &unsafe_revision,
        false,
        Some("work.unsafe_integer"),
    )?);

    let depth_base = 5;
    vectors.push(vector(
        "depth-maximum",
        "request",
        &prepare(offer_proposal(json!({"deep": nested(32 - depth_base)}))),
        true,
        None,
    )?);
    vectors.push(vector(
        "depth-one-over",
        "request",
        &prepare(offer_proposal(json!({"deep": nested(33 - depth_base)}))),
        true,
        Some("work.bounds"),
    )?);
    vectors.push(raw(
        "nodes-maximum",
        "request",
        offer_with_nodes(MAX_WORK_NODES)?,
        false,
        Some("work.malformed"),
    )?);
    vectors.push(raw(
        "nodes-one-over",
        "request",
        offer_with_nodes(MAX_WORK_NODES + 1)?,
        false,
        Some("work.bounds"),
    )?);
    vectors.push(vector(
        "entries-maximum",
        "request",
        &offer_with_entries(MAX_WORK_ENTRIES)?,
        true,
        None,
    )?);
    vectors.push(vector(
        "entries-one-over",
        "request",
        &offer_with_entries(MAX_WORK_ENTRIES + 1)?,
        true,
        Some("work.bounds"),
    )?);
    vectors.push(vector(
        "entries-over",
        "request",
        &prepare(offer_proposal(json!({"list": vec![0; 8_192]}))),
        true,
        Some("work.bounds"),
    )?);

    vectors.push(vector(
        "new-work-maximum",
        "request",
        &prepare(extend(16, 1, 1)),
        true,
        None,
    )?);
    vectors.push(vector(
        "new-work-one-over",
        "request",
        &prepare(extend(17, 1, 1)),
        false,
        Some("work.bounds"),
    )?);
    vectors.push(vector(
        "dependencies-maximum",
        "request",
        &prepare(extend(1, 64, 1)),
        true,
        None,
    )?);
    vectors.push(vector(
        "dependencies-one-over",
        "request",
        &prepare(extend(1, 65, 1)),
        false,
        Some("work.bounds"),
    )?);
    vectors.push(vector(
        "join-drafts-maximum",
        "request",
        &prepare(extend(1, 1, 16)),
        true,
        None,
    )?);
    vectors.push(vector(
        "join-drafts-one-over",
        "request",
        &prepare(extend(1, 1, 17)),
        false,
        Some("work.bounds"),
    )?);
    vectors.push(vector(
        "join-parents-maximum",
        "request",
        &prepare(join(16)),
        true,
        None,
    )?);
    vectors.push(vector(
        "join-parents-one-over",
        "request",
        &prepare(join(17)),
        false,
        Some("work.bounds"),
    )?);
    let mut duplicate_tasks = prepare(extend(2, 1, 1));
    duplicate_tasks["body"]["preparation"]["proposal"]["new_work"][1]["task_id"] = json!("task-1");
    vectors.push(vector(
        "duplicate-new-task",
        "request",
        &duplicate_tasks,
        true,
        Some("work.conflict"),
    )?);

    let mut program = base.clone();
    program["body"]["preparation"]["program_id"] = json!(format!("p{}", "a".repeat(127)));
    vectors.push(vector(
        "identifier-maximum",
        "request",
        &program,
        true,
        None,
    )?);
    program["body"]["preparation"]["program_id"] = json!(format!("p{}", "a".repeat(128)));
    vectors.push(vector(
        "identifier-one-over",
        "request",
        &program,
        false,
        Some("work.identifier"),
    )?);
    let mut padded = base.clone();
    padded["body"]["preparation"]["command_id"] = json!("-leading-dash");
    vectors.push(vector(
        "identifier-grammar",
        "request",
        &padded,
        false,
        Some("work.identifier"),
    )?);
    let mut slot_id = base.clone();
    slot_id["body"]["preparation"]["proposal"]["slot_id"] = json!("a".repeat(257));
    vectors.push(vector(
        "slot-identifier-one-over",
        "request",
        &slot_id,
        false,
        Some("work.identifier"),
    )?);
    let mut digest = base.clone();
    digest["body"]["preparation"]["proposal"]["allocation_hash"] = json!("A".repeat(64));
    vectors.push(vector(
        "digest-uppercase",
        "request",
        &digest,
        false,
        Some("work.identifier"),
    )?);

    let submit_commitment = submit(json!({"kind": "submit", "commitment": commitment()?}));
    for (name, path, field) in [
        ("commitment-slot-mismatch", "slot_id", "slot_id"),
        (
            "commitment-allocation-mismatch",
            "allocation_hash",
            "allocation_hash",
        ),
        ("commitment-request-mismatch", "request_id", "request_id"),
    ] {
        let mut value = submit_commitment.clone();
        value["body"]["command"]["action"]["commitment"]["handle"][path] = match path {
            "allocation_hash" => json!("f".repeat(64)),
            _ => json!("other"),
        };
        vectors.push(binding(name, &value, field)?);
    }
    let mut other_program = submit_commitment.clone();
    other_program["body"]["command"]["action"]["commitment"]["handle"]["program_id"] =
        json!("program-b");
    vectors.push(binding(
        "commitment-program-mismatch",
        &other_program,
        "program_id",
    )?);
    let mut agreement_program = prepare(json!({"kind": "agreement", "commitment": commitment()?,
        "terms": {"kind": "unpaid", "terms_reference": "terms-a"}}));
    agreement_program["body"]["preparation"]["proposal"]["commitment"]["handle"]["program_id"] =
        json!("program-b");
    vectors.push(binding(
        "agreement-program-mismatch",
        &agreement_program,
        "program_id",
    )?);
    let funded = prepare(json!({"kind": "agreement", "commitment": commitment()?,
        "terms": {"kind": "funded", "funding_profile_id": "funding-a", "terms_reference": "terms-a"}}));
    vectors.push(vector(
        "agreement-funded",
        "request",
        &funded,
        true,
        Some("work.unsupported_profile"),
    )?);

    let page = |entries| {
        json!({"schema": "chio.work.response.v1", "version": 1,
        "body": {"kind": "query", "result": {"kind": "catalog", "page": catalog_page(entries)}}})
    };
    vectors.push(vector(
        "catalog-maximum",
        "response",
        &page(64),
        true,
        None,
    )?);
    vectors.push(vector(
        "catalog-one-over",
        "response",
        &page(65),
        false,
        Some("work.bounds"),
    )?);
    let mut too_many_ops = json!({"schema": "chio.work.response.v1", "version": 1,
        "body": {"kind": "query", "result": {"kind": "work", "view": view()}}});
    too_many_ops["body"]["result"]["view"]["recovery"]["value"]["available"] =
        json!(["inspect_workflow", "inspect_workflow"]);
    vectors.push(vector(
        "recovery-duplicate-operation",
        "response",
        &too_many_ops,
        false,
        Some("work.conflict"),
    )?);
    let mut evidence = json!({"schema": "chio.work.response.v1", "version": 1,
        "body": {"kind": "query", "result": {"kind": "work", "view": view()}}});
    evidence["body"]["result"]["view"]["acceptance"]["value"]["evidence"] =
        json!((0..17).map(|n| format!("evidence-{n}")).collect::<Vec<_>>());
    vectors.push(vector(
        "acceptance-evidence-one-over",
        "response",
        &evidence,
        false,
        Some("work.bounds"),
    )?);

    let reconciled = |view: Value| {
        json!({"schema": "chio.work.response.v1", "version": 1,
        "body": {"kind": "command", "result": {
            "command_ref": {"program_id": "program-a", "command_id": "command-a",
                "command_digest": "0".repeat(64)},
            "outcome": {"kind": "applied", "revision": 1,
                "result": {"kind": "reconciled", "view": view}}}}})
    };
    let mut over_evidence = view();
    over_evidence["acceptance"]["value"]["evidence"] =
        json!((0..17).map(|n| format!("evidence-{n}")).collect::<Vec<_>>());
    vectors.push(vector(
        "reconciled-acceptance-evidence-one-over",
        "response",
        &reconciled(over_evidence.clone()),
        false,
        Some("work.bounds"),
    )?);
    let mut duplicate_operation = view();
    duplicate_operation["recovery"]["value"]["available"] =
        json!(["cancel_workflow", "cancel_workflow"]);
    vectors.push(vector(
        "reconciled-recovery-duplicate-operation",
        "response",
        &reconciled(duplicate_operation),
        false,
        Some("work.conflict"),
    )?);
    let mut queried = reconciled(over_evidence);
    queried["body"] = json!({"kind": "query", "result": {
        "kind": "command", "result": queried["body"]["result"].take()}});
    vectors.push(vector(
        "queried-command-acceptance-evidence-one-over",
        "response",
        &queried,
        false,
        Some("work.bounds"),
    )?);

    let worked = |view: Value| {
        json!({"schema": "chio.work.response.v1", "version": 1,
        "body": {"kind": "query", "result": {"kind": "work", "view": view}}})
    };
    for slot in [
        "execution",
        "acceptance",
        "result_reference",
        "recovery",
        "settlement",
        "bilateral_delivery",
    ] {
        let name = slot.replace('_', "-");
        let mut unit = view();
        unit[slot] = json!({"kind": "not_applicable"});
        vectors.push(vector(
            &format!("observation-{name}-not-applicable"),
            "response",
            &worked(unit.clone()),
            true,
            None,
        )?);
        unit[slot]["pad"] = json!(0);
        vectors.push(vector(
            &format!("observation-{name}-not-applicable-unknown-field"),
            "response",
            &worked(unit),
            false,
            Some("work.malformed"),
        )?);
    }
    let mut reconciled_unit = view();
    reconciled_unit["settlement"] = json!({"kind": "not_applicable", "pad": 0});
    vectors.push(vector(
        "reconciled-observation-not-applicable-unknown-field",
        "response",
        &reconciled(reconciled_unit),
        false,
        Some("work.malformed"),
    )?);
    let mut never_admitted = view();
    never_admitted["execution"]["value"] = json!({"kind": "never_admitted"});
    vectors.push(vector(
        "execution-never-admitted",
        "response",
        &worked(never_admitted.clone()),
        true,
        None,
    )?);
    never_admitted["execution"]["value"]["pad"] = json!(0);
    vectors.push(vector(
        "execution-never-admitted-unknown-field",
        "response",
        &worked(never_admitted),
        false,
        Some("work.malformed"),
    )?);

    let mut unsorted = (1..=3).map(join_parent).collect::<Vec<_>>();
    unsorted.swap(0, 1);
    vectors.push(vector(
        "join-inputs-unsorted",
        "join_inputs",
        &join_inputs(unsorted),
        true,
        Some("work.conflict"),
    )?);
    let mut duplicate = (1..=2).map(join_parent).collect::<Vec<_>>();
    duplicate[1]["receipt_id"] = json!("receipt-1");
    vectors.push(vector(
        "join-inputs-duplicate-receipt",
        "join_inputs",
        &join_inputs(duplicate),
        true,
        Some("work.conflict"),
    )?);
    vectors.push(vector(
        "join-inputs-empty",
        "join_inputs",
        &join_inputs(Vec::new()),
        false,
        Some("work.bounds"),
    )?);
    vectors.push(vector(
        "join-inputs-one-over",
        "join_inputs",
        &join_inputs((1..=17).map(join_parent).collect()),
        false,
        Some("work.bounds"),
    )?);
    for (name, contract, value, error) in rec0a::vectors()? {
        vectors.push(vector(&name, contract, &value, false, Some(error))?);
    }
    Ok(Corpus {
        format_version: 1,
        vectors,
    })
}

fn decode(contract: &str, wire: &[u8]) -> Result<(), WorkContractError> {
    match contract {
        "request" => decode_work_request(wire).map(|_| ()),
        "response" => decode_work_response(wire).map(|_| ()),
        _ => decode_work_join_inputs(wire).map(|_| ()),
    }
}

#[test]
fn every_vector_decodes_or_refuses_with_its_exact_code() -> TestResult {
    let corpus = corpus()?;
    for vector in &corpus.vectors {
        let result = decode(&vector.contract, vector.wire.as_bytes());
        assert_eq!(result.is_ok(), vector.valid, "{}: {result:?}", vector.name);
        if let Err(error) = result {
            assert_eq!(
                Some(error.code().as_str()),
                vector.error.as_deref(),
                "{}",
                vector.name
            );
            let field = error.field().map(serde_json::to_value).transpose()?;
            assert_eq!(
                field,
                vector.field.as_ref().map(|field| json!(field)),
                "{}",
                vector.name
            );
        }
    }
    Ok(())
}

#[test]
fn schemas_agree_with_every_vector() -> TestResult {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/schemas/chio-wire/v1/work");
    let validator = |name: &str| -> TestResult<jsonschema::Validator> {
        let schema: Value =
            serde_json::from_slice(&std::fs::read(root.join(format!("{name}.schema.json")))?)?;
        Ok(jsonschema::validator_for(&schema)?)
    };
    let (request, response, join_inputs) = (
        validator("request")?,
        validator("response")?,
        validator("join-inputs")?,
    );
    for vector in corpus()?.vectors {
        let validator = match vector.contract.as_str() {
            "request" => &request,
            "response" => &response,
            _ => &join_inputs,
        };
        let Ok(value) = serde_json::from_str::<Value>(&vector.wire) else {
            assert!(
                !vector.schema_valid,
                "{} is not JSON but claims schema validity",
                vector.name
            );
            continue;
        };
        let errors = validator
            .iter_errors(&value)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .take(3)
            .collect::<Vec<_>>();
        assert_eq!(
            errors.is_empty(),
            vector.schema_valid,
            "schema disagrees on {}: {errors:?}",
            vector.name
        );
    }
    Ok(())
}

#[test]
fn frame_bound_is_exact() -> TestResult {
    let frame =
        |pad: usize| serde_json::to_vec(&prepare(offer_proposal(json!({"pad": "a".repeat(pad)}))));
    let room = MAX_WORK_REQUEST_BYTES - frame(0)?.len();
    assert!(decode_work_request(&frame(room)?).is_ok());
    let over = decode_work_request(&frame(room + 1)?)
        .map(|_| ())
        .map_err(|error| error.code().as_str());
    assert_eq!(over, Err("work.bounds"));
    Ok(())
}

#[test]
fn committed_corpus_is_current() -> TestResult {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(CORPUS);
    let mut generated = serde_json::to_string_pretty(&corpus()?)?;
    generated.push('\n');
    if std::env::var_os(BLESS).is_some() {
        std::fs::create_dir_all(path.parent().ok_or("corpus directory")?)?;
        std::fs::write(&path, &generated)?;
    }
    let committed = std::fs::read_to_string(&path)?;
    assert!(
        committed == generated,
        "{CORPUS} is stale; rerun with {BLESS}=1"
    );
    Ok(())
}
