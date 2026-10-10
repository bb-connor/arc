//! Original graph artifacts with schema, digest, and collection bounds.
use super::*;

pub(super) fn parse_graph_artifact_paths(
    evidence_graph_bytes: &[u8],
) -> Result<GraphArtifactPaths, CliError> {
    let graph: GraphArtifactPaths = crate::input::json(evidence_graph_bytes)?;
    if graph.nodes.len() > crate::input::collection::MAX_ENTRIES {
        return Err(CliError::cli_other_error("proof graph node limit exceeded"));
    }
    Ok(graph)
}

pub(super) fn select_required_graph_node<'a>(
    nodes: &'a [GraphArtifactNode],
    role: &str,
    label: &str,
) -> Result<&'a GraphArtifactNode, CliError> {
    let matches = graph_nodes_by_role(nodes, role);
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact role: {role}",
        ))),
        _ => Err(CliError::cli_other_error(format!(
            "proof verify: multiple {label} artifact roles: {role}",
        ))),
    }
}

pub(super) fn graph_nodes_by_role<'a>(
    nodes: &'a [GraphArtifactNode],
    role: &str,
) -> Vec<&'a GraphArtifactNode> {
    nodes.iter().filter(|node| node.role == role).collect()
}

pub(super) fn select_required_graph_node_by_path<'a>(
    nodes: &'a [GraphArtifactNode],
    path: &str,
    label: &str,
) -> Result<&'a GraphArtifactNode, CliError> {
    let matches: Vec<&GraphArtifactNode> = nodes.iter().filter(|node| node.path == path).collect();
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact path: {path}",
        ))),
        _ => Err(CliError::cli_other_error(format!(
            "proof verify: multiple {label} artifact paths: {path}",
        ))),
    }
}

pub(super) fn load_required_graph_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<T, CliError> {
    let bytes =
        load_required_graph_bytes_artifact(bundle_dir, nodes, role, expected_schema, label)?;
    crate::input::json(&bytes).map_err(CliError::from)
}

pub(super) fn load_required_graph_bytes_artifact(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let node = select_required_graph_node(nodes, role, label)?;
    load_graph_bytes_artifact(bundle_dir, node, expected_schema, label)
}

pub(super) fn load_required_graph_bytes_artifact_by_path(
    bundle_dir: &Path,
    budget: &mut crate::input::collection::Budget,
    nodes: &[GraphArtifactNode],
    path: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let node = select_required_graph_node_by_path(nodes, path, label)?;
    load_graph_bytes_artifact_bounded(bundle_dir, node, expected_schema, label, budget)
}

pub(super) fn load_optional_graph_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Option<T>, CliError> {
    let matches = graph_nodes_by_role(nodes, role);
    match matches.as_slice() {
        [node] => load_graph_json_artifact(bundle_dir, node, expected_schema, label).map(Some),
        [] => Ok(None),
        _ => Err(CliError::cli_other_error(format!(
            "proof verify: multiple {label} artifact roles: {role}",
        ))),
    }
}

pub(super) fn load_optional_graph_json_artifacts<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    budget: &mut crate::input::collection::Budget,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<T>, CliError> {
    let mut artifacts = Vec::new();
    for node in graph_nodes_by_role(nodes, role) {
        let bytes =
            load_graph_bytes_artifact_bounded(bundle_dir, node, expected_schema, label, budget)?;
        artifacts.push(crate::input::json(&bytes)?);
    }
    Ok(artifacts)
}

pub(super) fn load_graph_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    node: &GraphArtifactNode,
    expected_schema: &str,
    label: &str,
) -> Result<T, CliError> {
    let bytes = load_graph_bytes_artifact(bundle_dir, node, expected_schema, label)?;
    crate::input::json(&bytes).map_err(CliError::from)
}

pub(super) fn load_graph_bytes_artifact(
    bundle_dir: &Path,
    node: &GraphArtifactNode,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    load_graph_bytes_artifact_bounded(
        bundle_dir,
        node,
        expected_schema,
        label,
        &mut crate::input::collection::Budget::default(),
    )
}

pub(super) fn load_graph_bytes_artifact_bounded(
    bundle_dir: &Path,
    node: &GraphArtifactNode,
    expected_schema: &str,
    label: &str,
    budget: &mut crate::input::collection::Budget,
) -> Result<Vec<u8>, CliError> {
    let schema = graph_node_schema(node, label)?;
    if schema != expected_schema {
        return Err(CliError::cli_other_error(format!(
            "proof verify: unsupported {label} artifact schema for {}: {schema}",
            node.path,
        )));
    }
    budget.enter(0)?;
    let path = resolve_bundle_artifact_path(bundle_dir, &node.path)?;
    let bytes = budget.read(&path)?;
    let actual_digest = chio_core::sha256_hex(&bytes);
    let expected_digest = graph_node_sha256(node, label)?;
    if actual_digest != expected_digest {
        return Err(CliError::cli_other_error(format!(
            "proof verify: {label} artifact digest mismatch for {}: expected {}, got {}",
            node.path, expected_digest, actual_digest,
        )));
    }
    Ok(bytes)
}

pub(super) fn graph_node_schema<'a>(
    node: &'a GraphArtifactNode,
    label: &str,
) -> Result<&'a str, CliError> {
    node.schema.as_deref().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact schema for {}",
            node.path,
        ))
    })
}

pub(super) fn graph_node_sha256<'a>(
    node: &'a GraphArtifactNode,
    label: &str,
) -> Result<&'a str, CliError> {
    node.sha256.as_deref().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact digest for {}",
            node.path,
        ))
    })
}

pub(super) fn load_graph_artifacts_matching(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    include_node: impl Fn(&GraphArtifactNode) -> bool,
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let mut budget = crate::input::collection::Budget::default();
    budget.charge(evidence_graph_bytes.len())?;
    let mut artifacts = BTreeMap::new();
    for node in graph.nodes.iter().filter(|node| include_node(node)) {
        budget.enter(0)?;
        let path = resolve_bundle_artifact_path(bundle_dir, &node.path)?;
        artifacts.insert(node.path.clone(), budget.read(&path)?);
    }
    Ok(artifacts)
}

pub(super) fn load_required_graph_json_artifact_bounded<T: serde::de::DeserializeOwned>(
    bundle_dir: &Path,
    budget: &mut crate::input::collection::Budget,
    nodes: &[GraphArtifactNode],
    role: &str,
    schema: &str,
    label: &str,
) -> Result<T, CliError> {
    let node = select_required_graph_node(nodes, role, label)?;
    let bytes = load_graph_bytes_artifact_bounded(bundle_dir, node, schema, label, budget)?;
    Ok(crate::input::json(&bytes)?)
}
