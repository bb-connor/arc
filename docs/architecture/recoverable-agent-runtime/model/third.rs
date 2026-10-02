//! Revision 3 binding/custody exploration and symbolic authority vectors.
#![forbid(unsafe_code)]
#![deny(warnings)]

mod third_contracts;
mod third_nonce;

use std::collections::{HashSet, VecDeque};
use third_contracts::CoverageFault;
use third_nonce::{Fault, State};

struct Exploration {
    states: usize,
    transitions: usize,
    useful_restart: bool,
    counterexample: Option<(&'static str, Vec<&'static str>)>,
}

fn explore(fault: Fault) -> Result<Exploration, String> {
    let first = State::default();
    let mut seen = HashSet::from([first]);
    let mut queue = VecDeque::from([(first, Vec::new())]);
    let mut result = Exploration {
        states: 1,
        transitions: 0,
        useful_restart: false,
        counterexample: None,
    };
    while let Some((state, path)) = queue.pop_front() {
        if let Err(reason) = state.invariant() {
            result.counterexample = Some((reason, path));
            return Ok(result);
        }
        if !state.settlement_enabled(fault) {
            result.counterexample = Some((
                "expired initiator blocked authorized historical settlement",
                path,
            ));
            return Ok(result);
        }
        result.useful_restart |= state.useful_restart();
        for (event, next) in state.successors(fault) {
            result.transitions = result
                .transitions
                .checked_add(1)
                .ok_or("transition overflow")?;
            if seen.insert(next) {
                result.states = seen.len();
                if result.states > 100_000 {
                    return Err("state ceiling exceeded; exploration incomplete".into());
                }
                let mut trace = path.clone();
                trace.push(event);
                queue.push_back((next, trace));
            }
        }
    }
    Ok(result)
}

fn expected_rejection(
    name: &str,
    result: Result<usize, &'static str>,
    expected: &str,
) -> Result<(), String> {
    match result {
        Err(reason) if reason == expected => {
            println!("THIRD MUTATION REJECTED {name}: {reason}");
            Ok(())
        }
        other => Err(format!("{name} expected {expected}, observed {other:?}")),
    }
}

fn main() -> Result<(), String> {
    println!("Scope: one frozen process envelope, one native nonce operation, one crash, expiry/cancellation and exact attachment.");
    println!("Assumptions: atomic durable steps, authentic native issuance/effect evidence, complete closure, current serving ownership.");
    println!("Authority vectors use four symbolic obligation classes and four context bindings, not real signatures or label arithmetic.");
    println!("Excluded: complete native participant composition, SQL, cryptography, provider correctness, timing and fairness.");
    let baseline = explore(Fault::None)?;
    if baseline.counterexample.is_some() || !baseline.useful_restart {
        return Err("nonce baseline failed safety or useful restart reachability".into());
    }
    println!(
        "THIRD BASELINE PASS Nonce: {} reachable states, {} transitions; useful restart reachable.",
        baseline.states, baseline.transitions
    );
    for (fault, expected) in [
        (
            Fault::FinalizeWithoutCustody,
            "process finalized without durable exact request custody",
        ),
        (
            Fault::PreflightBeforeIntent,
            "native preflight preceded durable admission intent",
        ),
        (
            Fault::RenewMissingNonce,
            "missing process acknowledgement minted another native nonce",
        ),
        (
            Fault::RewriteProcessEnvelope,
            "native attachment rewrote the frozen process envelope",
        ),
        (
            Fault::RequireLiveInitiator,
            "expired initiator blocked authorized historical settlement",
        ),
    ] {
        let result = explore(fault)?;
        let (reason, trace) = result
            .counterexample
            .ok_or_else(|| format!("fault survived: {fault:?}"))?;
        if reason != expected {
            return Err(format!("{fault:?} failed for unexpected reason: {reason}"));
        }
        println!("THIRD MUTATION REJECTED {fault:?}: {reason}");
        for (index, event) in trace.iter().enumerate() {
            println!("  {}. {event}", index + 1);
        }
    }
    println!(
        "THIRD CONTRACT PASS Coverage: {} bounded cases.",
        third_contracts::coverage(CoverageFault::None)?
    );
    for (fault, expected) in [
        (
            CoverageFault::AnyOwnerSuffices,
            "partial owner or power coverage authorized the complete release",
        ),
        (
            CoverageFault::IgnoreApprovalContext,
            "approval from another action target challenge or source satisfied coverage",
        ),
        (
            CoverageFault::CountSignatureAliases,
            "two aliases of one principal satisfied a two-principal obligation",
        ),
    ] {
        expected_rejection(
            &format!("{fault:?}"),
            third_contracts::coverage(fault),
            expected,
        )?;
    }
    Ok(())
}
