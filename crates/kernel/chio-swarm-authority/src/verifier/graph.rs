//! Structural and temporal validation of the signed task graph.
use std::collections::{BTreeMap, BTreeSet};

use crate::error::SwarmAuthorityError;
use crate::types::{SwarmGraphEdge, SwarmGraphNode, SwarmTaskGraph, CHIO_SWARM_TASK_GRAPH_SCHEMA};

use super::util::{rejected, require_non_empty, require_sha256, require_unique_strings};

pub(super) fn validate_task_graph(
    graph: &SwarmTaskGraph,
    now_unix_ms: u64,
) -> Result<(), SwarmAuthorityError> {
    if graph.schema != CHIO_SWARM_TASK_GRAPH_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm task graph schema: {}",
            graph.schema
        )));
    }
    require_non_empty(&graph.graph_id, "swarm graph id")?;
    require_non_empty(&graph.root_transaction_ref, "swarm root transaction ref")?;
    require_non_empty(&graph.planner_subject, "swarm planner subject")?;
    require_non_empty(&graph.issuer, "swarm issuer")?;
    require_non_empty(&graph.signature, "swarm task graph signature")?;
    require_non_empty(&graph.budget_pool_ref, "swarm budget pool ref")?;
    require_non_empty(&graph.revocation_epoch_ref, "swarm revocation epoch ref")?;
    if graph.created_at_unix_ms > now_unix_ms {
        return Err(rejected("swarm task graph is from the future"));
    }
    if graph.expires_at_unix_ms <= now_unix_ms {
        return Err(rejected("swarm task graph is expired"));
    }
    if graph.nodes.is_empty() {
        return Err(rejected("swarm task graph requires at least one task"));
    }
    if graph.max_fanout == 0 {
        return Err(rejected("swarm task graph max_fanout must be positive"));
    }

    let task_by_id = task_index(graph)?;
    let edge_set = edge_set(&graph.edges);
    validate_roots(graph)?;
    validate_edges(graph, &task_by_id, &edge_set)?;
    validate_joins(graph, &task_by_id)?;
    validate_route_refs(graph)?;
    validate_acyclic(graph, &task_by_id)?;
    validate_edge_depths(graph, &task_by_id)?;
    validate_graph_limits(graph)?;
    Ok(())
}

pub(super) fn task_index(
    graph: &SwarmTaskGraph,
) -> Result<BTreeMap<&str, &SwarmGraphNode>, SwarmAuthorityError> {
    let mut tasks = BTreeMap::new();
    for node in &graph.nodes {
        require_non_empty(&node.task_id, "swarm task id")?;
        require_non_empty(&node.scope_hash, "swarm task scope hash")?;
        require_sha256(&node.scope_hash, "swarm task scope hash")?;
        if tasks.insert(node.task_id.as_str(), node).is_some() {
            return Err(rejected(format!(
                "duplicate swarm task id: {}",
                node.task_id
            )));
        }
    }
    Ok(tasks)
}

pub(super) fn edge_set(edges: &[SwarmGraphEdge]) -> BTreeSet<(&str, &str)> {
    edges
        .iter()
        .map(|edge| (edge.from_task_id.as_str(), edge.to_task_id.as_str()))
        .collect()
}

fn validate_roots(graph: &SwarmTaskGraph) -> Result<(), SwarmAuthorityError> {
    let root_count = graph
        .nodes
        .iter()
        .filter(|node| node.parent_task_id.is_none() && node.depth == 0)
        .count();
    if root_count != 1 {
        return Err(rejected("swarm task graph requires exactly one root task"));
    }
    for node in &graph.nodes {
        if node.depth == 0 && node.parent_task_id.is_some() {
            return Err(rejected(format!(
                "swarm root-depth task has parent: {}",
                node.task_id
            )));
        }
        if node.depth > 0 && node.parent_task_id.is_none() {
            return Err(rejected(format!(
                "swarm non-root task missing parent: {}",
                node.task_id
            )));
        }
    }
    Ok(())
}

fn validate_edges(
    graph: &SwarmTaskGraph,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    edge_set: &BTreeSet<(&str, &str)>,
) -> Result<(), SwarmAuthorityError> {
    for edge in &graph.edges {
        require_non_empty(&edge.from_task_id, "swarm edge source")?;
        require_non_empty(&edge.to_task_id, "swarm edge target")?;
        require_non_empty(&edge.edge_type, "swarm edge type")?;
        if !task_by_id.contains_key(edge.from_task_id.as_str()) {
            return Err(rejected(format!(
                "unknown swarm edge source: {}",
                edge.from_task_id
            )));
        }
        if !task_by_id.contains_key(edge.to_task_id.as_str()) {
            return Err(rejected(format!(
                "unknown swarm edge target: {}",
                edge.to_task_id
            )));
        }
    }
    if edge_set.len() != graph.edges.len() {
        return Err(rejected("duplicate swarm task graph edge"));
    }
    for node in &graph.nodes {
        if let Some(parent_task_id) = &node.parent_task_id {
            if !edge_set.contains(&(parent_task_id.as_str(), node.task_id.as_str())) {
                return Err(rejected(format!(
                    "swarm task parent edge missing: {} -> {}",
                    parent_task_id, node.task_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_edge_depths(
    graph: &SwarmTaskGraph,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<(), SwarmAuthorityError> {
    for edge in &graph.edges {
        let Some(parent) = task_by_id.get(edge.from_task_id.as_str()) else {
            return Err(rejected(format!(
                "unknown swarm edge source: {}",
                edge.from_task_id
            )));
        };
        let Some(child) = task_by_id.get(edge.to_task_id.as_str()) else {
            return Err(rejected(format!(
                "unknown swarm edge target: {}",
                edge.to_task_id
            )));
        };
        let expected_child_depth = parent
            .depth
            .checked_add(1)
            .ok_or_else(|| rejected("swarm task depth overflow"))?;
        if child.depth != expected_child_depth {
            return Err(rejected(format!(
                "swarm task depth mismatch: {} -> {}",
                edge.from_task_id, edge.to_task_id
            )));
        }
    }
    Ok(())
}

fn validate_graph_limits(graph: &SwarmTaskGraph) -> Result<(), SwarmAuthorityError> {
    let mut fanout: BTreeMap<&str, u32> = BTreeMap::new();
    for node in &graph.nodes {
        if node.depth > graph.max_depth {
            return Err(rejected(format!(
                "swarm task exceeds max depth: {}",
                node.task_id
            )));
        }
    }
    for edge in &graph.edges {
        let count = fanout.entry(edge.from_task_id.as_str()).or_default();
        *count += 1;
        if *count > graph.max_fanout {
            return Err(rejected(format!(
                "swarm task exceeds max fanout: {}",
                edge.from_task_id
            )));
        }
    }
    Ok(())
}

fn validate_joins(
    graph: &SwarmTaskGraph,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<(), SwarmAuthorityError> {
    let mut join_ids = BTreeSet::new();
    for join in &graph.joins {
        require_non_empty(&join.join_id, "swarm join id")?;
        require_non_empty(&join.next_task_id, "swarm join next task id")?;
        if !join_ids.insert(join.join_id.as_str()) {
            return Err(rejected(format!(
                "duplicate swarm join id: {}",
                join.join_id
            )));
        }
        if join.parent_task_ids.is_empty() {
            return Err(rejected(format!(
                "swarm join requires parents: {}",
                join.join_id
            )));
        }
        if join.parent_task_ids.len() < 2 {
            return Err(rejected(format!(
                "swarm join requires at least two parents: {}",
                join.join_id
            )));
        }
        if !task_by_id.contains_key(join.next_task_id.as_str()) {
            return Err(rejected(format!(
                "swarm join next task is unknown: {}",
                join.next_task_id
            )));
        }
        require_unique_strings(&join.parent_task_ids, "swarm join parent task")?;
        for parent_task_id in &join.parent_task_ids {
            if parent_task_id == &join.next_task_id {
                return Err(rejected(format!(
                    "swarm join next task is a parent: {}",
                    join.join_id
                )));
            }
            if !task_by_id.contains_key(parent_task_id.as_str()) {
                return Err(rejected(format!(
                    "swarm join parent task is unknown: {parent_task_id}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_route_refs(graph: &SwarmTaskGraph) -> Result<(), SwarmAuthorityError> {
    require_unique_strings(&graph.route_plan_refs, "swarm route plan ref")?;
    for route_plan_ref in &graph.route_plan_refs {
        require_non_empty(route_plan_ref, "swarm route plan ref")?;
    }
    Ok(())
}

fn validate_acyclic(
    graph: &SwarmTaskGraph,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<(), SwarmAuthorityError> {
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &graph.edges {
        adjacency
            .entry(edge.from_task_id.as_str())
            .or_default()
            .push(edge.to_task_id.as_str());
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for task_id in task_by_id.keys() {
        visit_task(task_id, &adjacency, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit_task<'a>(
    task_id: &'a str,
    adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
    visiting: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), SwarmAuthorityError> {
    if visited.contains(task_id) {
        return Ok(());
    }
    if !visiting.insert(task_id) {
        return Err(rejected(format!("swarm task graph cycle at {task_id}")));
    }
    if let Some(children) = adjacency.get(task_id) {
        for child in children {
            visit_task(child, adjacency, visiting, visited)?;
        }
    }
    visiting.remove(task_id);
    visited.insert(task_id);
    Ok(())
}
