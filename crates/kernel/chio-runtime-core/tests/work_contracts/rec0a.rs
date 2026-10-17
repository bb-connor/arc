//! Embedded REC-0a contracts at each inner limit and one over. The pad is an
//! unknown field, so a contract at the limit still fails its typed decoder.

use super::positives::*;
use chio_security_types::recovery::{
    MAX_RECOVERY_CONTAINER_ENTRIES, MAX_RECOVERY_DEPTH, MAX_RECOVERY_NODES,
    MAX_RECOVERY_STRING_BYTES, MAX_RECOVERY_WIRE_BYTES,
};
use serde_json::{json, Value};

/// What the REC-0a preflight charges over a contract's canonical bytes.
#[derive(Default)]
struct Charge {
    depth: usize,
    nodes: usize,
    entries: usize,
    strings: usize,
    bytes: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum Dimension {
    Depth,
    Nodes,
    Entries,
    Strings,
    Bytes,
}

const ALL: [Dimension; 5] = [
    Dimension::Depth,
    Dimension::Nodes,
    Dimension::Entries,
    Dimension::Strings,
    Dimension::Bytes,
];

impl Dimension {
    const fn name(self) -> &'static str {
        match self {
            Self::Depth => "depth",
            Self::Nodes => "nodes",
            Self::Entries => "entries",
            Self::Strings => "strings",
            Self::Bytes => "bytes",
        }
    }

    const fn limit(self) -> usize {
        match self {
            Self::Depth => MAX_RECOVERY_DEPTH,
            Self::Nodes => MAX_RECOVERY_NODES,
            Self::Entries => MAX_RECOVERY_CONTAINER_ENTRIES,
            Self::Strings => MAX_RECOVERY_STRING_BYTES,
            Self::Bytes => MAX_RECOVERY_WIRE_BYTES,
        }
    }

    const fn read(self, charge: &Charge) -> usize {
        match self {
            Self::Depth => charge.depth,
            Self::Nodes => charge.nodes,
            Self::Entries => charge.entries,
            Self::Strings => charge.strings,
            Self::Bytes => charge.bytes,
        }
    }
}

fn encoded(text: &str) -> TestResult<usize> {
    Ok(serde_json::to_string(text)?.len() - 2)
}

fn walk(value: &Value, depth: usize, charge: &mut Charge) -> TestResult {
    charge.nodes += 1;
    let mut enter = |len: usize| {
        charge.depth = charge.depth.max(depth + 1);
        charge.entries = charge.entries.max(len.max(1));
    };
    match value {
        Value::Object(map) => {
            enter(map.len());
            for (key, item) in map {
                charge.nodes += 1;
                charge.strings += encoded(key)?;
                walk(item, depth + 1, charge)?;
            }
        }
        Value::Array(items) => {
            enter(items.len());
            for item in items {
                walk(item, depth + 1, charge)?;
            }
        }
        Value::String(text) => charge.strings += encoded(text)?,
        _ => {}
    }
    Ok(())
}

fn measure(value: &Value) -> TestResult<Charge> {
    let mut charge = Charge {
        bytes: serde_json::to_string(value)?.len(),
        ..Charge::default()
    };
    walk(value, 0, &mut charge)?;
    Ok(charge)
}

fn with_pad(contract: &Value, pad: Value) -> TestResult<Value> {
    let mut padded = contract.clone();
    padded
        .as_object_mut()
        .ok_or("pad needs an object contract")?
        .insert("pad".to_owned(), pad);
    Ok(padded)
}

/// `contract` padded until `dimension` charges exactly `target`.
fn padded(contract: &Value, dimension: Dimension, target: usize) -> TestResult<Value> {
    if contract.is_string() {
        return match dimension {
            Dimension::Strings => Ok(json!("a".repeat(target))),
            _ => Err("a string contract is padded only by length".into()),
        };
    }
    match dimension {
        Dimension::Depth => {
            let room = target.checked_sub(1).ok_or("depth target")?;
            with_pad(
                contract,
                (0..room).fold(json!(0), |inner, _| json!([inner])),
            )
        }
        Dimension::Entries => with_pad(contract, json!(vec![0; target])),
        Dimension::Strings => {
            let base = measure(&with_pad(contract, json!(""))?)?.strings;
            let room = target.checked_sub(base).ok_or("string base over target")?;
            with_pad(contract, json!("a".repeat(room)))
        }
        Dimension::Nodes => {
            let base = measure(&with_pad(contract, json!([]))?)?.nodes;
            let room = target.checked_sub(base).ok_or("node base over target")?;
            let mut chunks = vec![json!(vec![0; 255]); room / 256];
            if room % 256 > 0 {
                chunks.push(json!(vec![0; room % 256 - 1]));
            }
            with_pad(contract, json!(chunks))
        }
        Dimension::Bytes => {
            let mut chunks = vec![json!(vec![9_007_199_254_740_991_u64; 200]); 12];
            let base = measure(&with_pad(contract, json!(chunks.clone()))?)?.bytes;
            let room = target
                .checked_sub(base + ",\"\"".len())
                .ok_or("byte base over target")?;
            chunks.push(json!("a".repeat(room)));
            with_pad(contract, json!(chunks))
        }
    }
}

fn view_frame() -> Value {
    json!({"schema": "chio.work.response.v1", "version": 1,
        "body": {"kind": "query", "result": {"kind": "work", "view": view()}}})
}

fn outcome_frame(outcome: Value) -> Value {
    json!({"schema": "chio.work.response.v1", "version": 1,
        "body": {"kind": "command", "result": {
            "command_ref": {"program_id": "program-a", "command_id": "command-a",
                "command_digest": "0".repeat(64)},
            "outcome": outcome}}})
}

/// Every embedded position at the limit refuses as `work.malformed` on the
/// pad; one over refuses as `work.bounds` before the typed decoder runs.
/// A unit variant that would silently drop an unknown field is malformed.
pub fn vectors() -> TestResult<Vec<(String, &'static str, Value, &'static str)>> {
    let view = "/body/result/view";
    let pending = outcome_frame(json!({"kind": "pending",
        "owner_operation_ref": {"operation": operation(), "scope": scope()}}));
    let mut withheld = view_frame();
    withheld["body"]["result"]["view"]["result_reference"]["value"]["release"] =
        json!({"kind": "withheld", "evidence": "evidence-a"});
    let cancel = outcome_frame(json!({"kind": "applied", "revision": 1,
        "result": {"kind": "cancel_observed", "control": "cancel_requested"}}));
    let positions: [(&str, &'static str, Value, String, &[Dimension]); 9] = [
        (
            "execution",
            "response",
            view_frame(),
            format!("{view}/execution/value"),
            &ALL,
        ),
        (
            "producer",
            "response",
            view_frame(),
            format!("{view}/acceptance/value/producer"),
            &[Dimension::Nodes],
        ),
        (
            "acceptance-artifact",
            "response",
            view_frame(),
            format!("{view}/acceptance/value/artifact"),
            &[Dimension::Entries],
        ),
        (
            "release",
            "response",
            withheld,
            format!("{view}/result_reference/value/release"),
            &[Dimension::Depth],
        ),
        (
            "recovery-link",
            "response",
            view_frame(),
            format!("{view}/recovery/value"),
            &[Dimension::Nodes],
        ),
        (
            "owner-scope",
            "response",
            pending.clone(),
            "/body/result/outcome/owner_operation_ref/scope".to_owned(),
            &[Dimension::Depth],
        ),
        (
            "owner-operation",
            "response",
            pending,
            "/body/result/outcome/owner_operation_ref/operation".to_owned(),
            &[Dimension::Entries],
        ),
        (
            "cancel-control",
            "response",
            cancel,
            "/body/result/outcome/result/control".to_owned(),
            &[Dimension::Strings],
        ),
        (
            "join-artifact",
            "join_inputs",
            join_inputs(vec![join_parent(1)]),
            "/parents/0/artifact_ref".to_owned(),
            &[Dimension::Depth],
        ),
    ];
    let mut vectors = Vec::new();
    let mut dropped = view_frame();
    dropped["body"]["result"]["view"]["result_reference"]["value"]["release"] =
        json!({"kind": "not_available", "pad": 0});
    vectors.push((
        "rec0a-release-unit-variant-unknown-field".to_owned(),
        "response",
        dropped,
        "work.malformed",
    ));
    for (position, contract, frame, path, dimensions) in positions {
        let embedded = frame.pointer(&path).ok_or("embedded contract path")?;
        for &dimension in dimensions {
            for (suffix, target, error) in [
                ("maximum", dimension.limit(), "work.malformed"),
                ("one-over", dimension.limit() + 1, "work.bounds"),
            ] {
                let contract_value = padded(embedded, dimension, target)?;
                let charge = measure(&contract_value)?;
                if dimension.read(&charge) != target
                    || ALL
                        .iter()
                        .any(|&other| other != dimension && other.read(&charge) > other.limit())
                {
                    return Err(
                        format!("{position} {} pad misses {target}", dimension.name()).into(),
                    );
                }
                let mut value = frame.clone();
                *value.pointer_mut(&path).ok_or("embedded contract path")? = contract_value;
                vectors.push((
                    format!("rec0a-{position}-{}-{suffix}", dimension.name()),
                    contract,
                    value,
                    error,
                ));
            }
        }
    }
    Ok(vectors)
}
