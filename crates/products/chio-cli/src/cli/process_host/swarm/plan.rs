//! Bounded independent graphs sharing one existing process family.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use super::{error, identifier, read_json, CliError};

pub(crate) struct Plan {
    pub(super) profile_id: String,
    pub(super) graphs: Vec<Graph>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Graph {
    pub(super) graph_id: String,
    pub(super) calls: Vec<Call>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Call {
    pub(super) process: String,
    pub(super) operation_key: String,
    pub(super) server_id: String,
    pub(super) tool_name: String,
    pub(super) arguments: Value,
}

#[derive(Deserialize)]
#[serde(tag = "schema", deny_unknown_fields)]
enum Document {
    #[serde(rename = "chio.process.swarm-plan.v1")]
    Single { graph_id: String, calls: Vec<Call> },
    #[serde(rename = "chio.process.swarm-plan.v2")]
    SharedFamily {
        profile_id: String,
        graphs: Vec<Graph>,
    },
}

pub(super) fn load(path: &Path) -> Result<Plan, CliError> {
    let plan = match read_json(path)? {
        Document::Single { graph_id, calls } => Plan {
            profile_id: graph_id.clone(),
            graphs: vec![Graph { graph_id, calls }],
        },
        Document::SharedFamily { profile_id, graphs } => {
            if !(2..=8).contains(&graphs.len()) {
                return Err(error("a shared-family plan requires 2-8 independent graphs"));
            }
            Plan { profile_id, graphs }
        }
    };
    identifier(&plan.profile_id)?;
    let mut graph_ids = BTreeSet::new();
    let mut processes = BTreeSet::new();
    for graph in &plan.graphs {
        identifier(&graph.graph_id)?;
        if !graph_ids.insert(&graph.graph_id) {
            return Err(error("a shared-family plan repeats a graph identity"));
        }
        if !(2..=32).contains(&graph.calls.len()) {
            return Err(error("a bounded fan-out graph requires 2-32 calls"));
        }
        for call in &graph.calls {
            identifier(&call.process)?;
            identifier(&call.operation_key)?;
            if !call.arguments.is_object() {
                return Err(error("planned arguments must be an object"));
            }
            if call.process == "root" || !processes.insert(&call.process) {
                return Err(error("a bounded fan-out plan needs one call per distinct child"));
            }
            if processes.len() > 32 {
                return Err(error("a shared-family plan exceeds 32 total planned calls"));
            }
        }
    }
    Ok(plan)
}
