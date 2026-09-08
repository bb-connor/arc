use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::super::state::error;
use super::journal::Snapshot;
use super::plan::Worker;
use crate::CliError;

pub(super) struct Completion {
    pub complete: bool,
    pub handled_failures: Vec<HandledFailure>,
    pub unhandled_failures: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct HandledFailure {
    process: String,
    supervisor: String,
    settled_child: String,
    settlement_request_id: String,
}

pub(super) fn evaluate(
    snapshots: &[Snapshot],
    declared: &[Worker],
    parents: &BTreeMap<String, String>,
    settlements: &[(String, String, String)],
) -> Result<Completion, CliError> {
    let states: BTreeMap<_, _> = snapshots
        .iter()
        .map(|s| (s.process.as_str(), s.state.as_str()))
        .collect();
    let declared: BTreeSet<_> = declared.iter().map(|w| w.process.as_str()).collect();
    if states.len() != snapshots.len()
        || states.len() != declared.len() + parents.len()
        || declared
            .iter()
            .any(|id| !states.contains_key(id) || parents.contains_key(*id))
    {
        return Err(error("supervised worker journal does not match its plan"));
    }
    for id in parents.keys() {
        let mut current = id.as_str();
        let mut seen = BTreeSet::new();
        while let Some(parent) = parents.get(current) {
            if !states.contains_key(current) || !seen.insert(current) {
                return Err(error("invalid supervised child ancestry"));
            }
            current = parent;
        }
        if !declared.contains(current) {
            return Err(error("supervised child has no declared ancestor"));
        }
    }
    let mut observed = BTreeMap::new();
    for (parent, child, request) in settlements {
        if parents.get(child) != Some(parent)
            || states.get(child.as_str()) != Some(&"failed")
            || !states.contains_key(parent.as_str())
            || request.is_empty()
            || observed
                .insert((parent.as_str(), child.as_str()), request.as_str())
                .is_some()
        {
            return Err(error("invalid recorded child failure settlement"));
        }
    }
    let mut handled_failures = Vec::new();
    let mut unhandled_failures = Vec::new();
    for snapshot in snapshots.iter().filter(|s| s.state == "failed") {
        let mut current = snapshot.process.as_str();
        let mut handled = None;
        while let Some(parent) = parents.get(current) {
            if states.get(parent.as_str()) == Some(&"completed") {
                if let Some(request) = observed.get(&(parent.as_str(), current)) {
                    handled = Some(HandledFailure {
                        process: snapshot.process.clone(),
                        supervisor: parent.clone(),
                        settled_child: current.to_owned(),
                        settlement_request_id: (*request).to_owned(),
                    });
                    break;
                }
            }
            current = parent;
        }
        if let Some(handled) = handled {
            handled_failures.push(handled);
        } else {
            unhandled_failures.push(snapshot.process.clone());
        }
    }
    Ok(Completion {
        complete: unhandled_failures.is_empty()
            && snapshots
                .iter()
                .all(|s| matches!(s.state.as_str(), "completed" | "failed"))
            && declared
                .iter()
                .all(|id| states.get(id) == Some(&"completed")),
        handled_failures,
        unhandled_failures,
    })
}
