//! Bounded architecture seam models, not production implementations.
#![forbid(unsafe_code)]
#![deny(warnings)]

mod review_states;

use review_states::{Admission, Knowledge, Model, Mutation, PartialEffect, Replay};
use std::collections::{HashSet, VecDeque};

struct ResultSet {
    states: usize,
    transitions: usize,
    counterexample: Option<(&'static str, Vec<&'static str>)>,
}

fn explore<M: Model>(mutation: Mutation) -> Result<ResultSet, String> {
    let initial = M::initial();
    let mut visited = HashSet::from([initial]);
    let mut queue = VecDeque::from([(initial, Vec::<&'static str>::new())]);
    let mut transitions = 0usize;
    while let Some((state, trace)) = queue.pop_front() {
        if let Err(reason) = state.invariant() {
            return Ok(ResultSet {
                states: visited.len(),
                transitions,
                counterexample: Some((reason, trace)),
            });
        }
        for (event, next) in state.successors(mutation) {
            transitions = transitions.checked_add(1).ok_or("transition overflow")?;
            if visited.insert(next) {
                if visited.len() > 100_000 {
                    return Err("state bound exceeded; exploration incomplete".into());
                }
                let mut path = trace.clone();
                path.push(event);
                queue.push_back((next, path));
            }
        }
    }
    Ok(ResultSet {
        states: visited.len(),
        transitions,
        counterexample: None,
    })
}

fn baseline<M: Model>(name: &str) -> Result<(), String> {
    let result = explore::<M>(Mutation::None)?;
    if let Some((reason, trace)) = result.counterexample {
        return Err(format!("{name} baseline violated {reason}: {trace:?}"));
    }
    println!(
        "REVIEW BASELINE PASS {name}: {} reachable states, {} transitions; exhaustive within stated bounds.",
        result.states, result.transitions
    );
    Ok(())
}

fn reject<M: Model>(mutation: Mutation, expected: &str) -> Result<(), String> {
    let result = explore::<M>(mutation)?;
    let (reason, trace) = result
        .counterexample
        .ok_or_else(|| format!("mutation {mutation:?} survived"))?;
    if reason != expected {
        return Err(format!(
            "mutation {mutation:?} failed for unexpected reason {reason}"
        ));
    }
    println!("REVIEW MUTATION REJECTED {mutation:?}: {reason}");
    for (index, event) in trace.iter().enumerate() {
        println!("  {}. {event}", index + 1);
    }
    Ok(())
}

fn main() -> Result<(), String> {
    println!(
        "Review models: four independent finite seams; one operation/command/context in each."
    );
    println!("Assumptions: atomic authoritative transitions; correct native evidence; immutable payloads; authentic current authorization.");
    println!("Excluded: complete cross-store bridge, cryptography, provider deduplication, byte custody, clocks, fairness and production implementation.");
    baseline::<Admission>("Admission")?;
    baseline::<Knowledge>("Knowledge")?;
    baseline::<Replay>("Replay")?;
    baseline::<PartialEffect>("PartialEffect")?;
    reject::<Admission>(
        Mutation::CloseFromProjection,
        "missing projection closed a potentially effective native operation",
    )?;
    reject::<Admission>(
        Mutation::IgnoreAdmissionTombstone,
        "late submission reopened a closed admission intent",
    )?;
    reject::<Admission>(
        Mutation::IgnoreCancellation,
        "capture followed an earlier committed cancellation",
    )?;
    reject::<Knowledge>(
        Mutation::ReleaseWithoutJoin,
        "bytes escaped before native knowledge joined",
    )?;
    reject::<Knowledge>(
        Mutation::IgnoreKnowledgeFence,
        "stale public preparation captured after restricted observation",
    )?;
    reject::<Replay>(
        Mutation::RevisionBeforeReplay,
        "committed command replay incorrectly conflicted on its old revision",
    )?;
    reject::<Replay>(
        Mutation::CachedResponseAfterRevocation,
        "cached protected response escaped after read revocation",
    )?;
    reject::<PartialEffect>(
        Mutation::PartialFailureAsNoEffect,
        "partial failure caused a second external effect for the same step",
    )?;
    Ok(())
}
