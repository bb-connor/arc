//! Bounded architecture exploration, not an implementation security claim.
#![forbid(unsafe_code)]
#![deny(warnings)]

mod state;

use state::{Mutation, State};
use std::collections::{HashSet, VecDeque};

struct Exploration {
    states: usize,
    transitions: usize,
    counterexample: Option<(String, Vec<String>)>,
}

fn explore(mutation: Mutation) -> Result<Exploration, String> {
    let initial = State::initial();
    let mut visited = HashSet::from([initial]);
    let mut queue = VecDeque::from([(initial, Vec::<String>::new())]);
    let mut transitions = 0usize;
    while let Some((state, trace)) = queue.pop_front() {
        if let Err(reason) = state.invariant() {
            return Ok(Exploration {
                states: visited.len(),
                transitions,
                counterexample: Some((reason.to_owned(), trace)),
            });
        }
        for (event, next) in state.successors(mutation) {
            transitions += 1;
            if visited.insert(next) {
                if visited.len() > 1_000_000 {
                    return Err("state bound exceeded; exploration is incomplete".into());
                }
                let mut path = trace.clone();
                path.push(event);
                queue.push_back((next, path));
            }
        }
    }
    Ok(Exploration {
        states: visited.len(),
        transitions,
        counterexample: None,
    })
}

fn main() -> Result<(), String> {
    println!("Model: one effectful step, two continuations, two coordinators, at most two owner epochs per continuation.");
    println!("Assumptions: atomic authoritative transitions; authentic approvals/no-effect proofs; correct provider evidence; finite abstraction.");
    println!("Excluded: cryptography, actual storage, reservation bridge, artifact protocol, time, fairness and production implementation.");
    let baseline = explore(Mutation::None)?;
    if let Some((reason, path)) = baseline.counterexample {
        return Err(format!("baseline violated {reason}: {path:?}"));
    }
    println!(
        "BASELINE PASS: {} reachable states, {} transitions; exhaustive within the stated bounds.",
        baseline.states, baseline.transitions
    );
    for mutation in [
        Mutation::OverlappingSelection,
        Mutation::IgnoreOwnerEpoch,
        Mutation::ReplayUnknown,
        Mutation::UnknownMeansNoEffect,
    ] {
        let result = explore(mutation)?;
        let (reason, path) = result
            .counterexample
            .ok_or_else(|| format!("mutation {mutation:?} survived; no counterexample found"))?;
        let expected = match mutation {
            Mutation::OverlappingSelection => "more than one unresolved continuation owns the step",
            Mutation::IgnoreOwnerEpoch => "a stale coordinator epoch captured live ownership",
            Mutation::ReplayUnknown => "the one modeled effectful step executed more than once",
            Mutation::UnknownMeansNoEffect => {
                "an actual effect was classified as closed without effect"
            }
            Mutation::None => return Err("baseline is not a mutation".into()),
        };
        if reason != expected {
            return Err(format!(
                "mutation {mutation:?} failed for unexpected reason: {reason}"
            ));
        }
        println!("MUTATION REJECTED {mutation:?}: {reason}");
        println!(
            "  explored {} states, {} transitions before counterexample",
            result.states, result.transitions
        );
        for (index, event) in path.iter().enumerate() {
            println!("  {}. {event}", index + 1);
        }
    }
    Ok(())
}
