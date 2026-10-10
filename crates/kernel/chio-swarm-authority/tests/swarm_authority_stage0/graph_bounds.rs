use super::*;
use chio_swarm_authority::MAX_SWARM_GRAPH_TASKS;

#[test]
fn swarm_authority_stage0_rejects_an_oversized_graph_before_walking_it(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    let tasks = MAX_SWARM_GRAPH_TASKS + 1;
    let scope_hash = bundle.task_graph.nodes[0].scope_hash.clone();
    bundle.task_graph.max_depth = u32::try_from(tasks)?;
    bundle.task_graph.nodes = (0..tasks)
        .map(|index| SwarmGraphNode {
            task_id: format!("task-{index}"),
            parent_task_id: index.checked_sub(1).map(|parent| format!("task-{parent}")),
            route_plan_ref: None,
            continuation_token_ref: None,
            budget_allocation_ref: None,
            scope_hash: scope_hash.clone(),
            depth: u32::try_from(index).unwrap_or(u32::MAX),
        })
        .collect();
    bundle.task_graph.edges = (1..tasks)
        .map(|index| SwarmGraphEdge {
            from_task_id: format!("task-{}", index - 1),
            to_task_id: format!("task-{index}"),
            edge_type: "delegates".to_string(),
        })
        .collect();
    bundle.task_graph.joins.clear();

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("oversized swarm task graph verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm task graph exceeds its task ceiling"));
    Ok(())
}
