//! `chio lineage {query,diff,roots}` CLI surface.
//!
//! - `query` runs a forward or reverse query starting from a seed node id
//!   on a fixture lineage JSON dump. The dump is the same format the
//!   static viewer reads; this lets the CLI exercise the same query
//!   layer the tests use without inventing a new wire format.
//! - `diff` computes the symmetric edge diff between two lineage dumps
//!   (typically guard `v1` vs `v2`).
//! - `roots` reads pinned-frontier artifacts from a directory and lists
//!   their digests plus signing state.
//!
//! All outputs are deterministic. JSON output carries the schema tag
//! `chio.lineage.cli/v1`.

#[cfg(test)]
use std::fs;
use std::path::Path;

use chio_lineage::anchor::AnchoredFrontier;
use chio_lineage::diff::{diff as compute_diff, render_text, LineageDiff};
use chio_lineage::query::{forward, reverse, QueryBounds, QueryResult};
use chio_lineage::schema::LineageGraph;
use serde::{Deserialize, Serialize};

pub const LINEAGE_CLI_SCHEMA: &str = "chio.lineage.cli/v1";

#[derive(Debug, thiserror::Error)]
pub enum LineageCliError {
    #[error("lineage input rejected")]
    Input(#[source] crate::CliError),
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Forward,
    Reverse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CliQueryReport {
    pub schema: String,
    pub seeds: Vec<String>,
    pub direction: String,
    pub graph: LineageGraph,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CliDiffReport {
    pub schema: String,
    pub diff: LineageDiff,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CliRootsReport {
    pub schema: String,
    pub roots: Vec<AnchoredFrontier>,
}

fn read_graph(path: &Path) -> Result<LineageGraph, LineageCliError> {
    let bytes = crate::input::read(path).map_err(|e| LineageCliError::Input(e.into()))?;
    crate::input::json(&bytes).map_err(|e| LineageCliError::Input(e.into()))
}

pub fn cmd_query(
    graph_path: &Path,
    seeds: &[String],
    direction: Direction,
    bounds: QueryBounds,
) -> Result<CliQueryReport, LineageCliError> {
    let graph = read_graph(graph_path)?;
    let seed_refs: Vec<&str> = seeds.iter().map(String::as_str).collect();
    let QueryResult { graph, .. } = match direction {
        Direction::Forward => forward(&graph, &seed_refs, bounds),
        Direction::Reverse => reverse(&graph, &seed_refs, bounds),
    };
    Ok(CliQueryReport {
        schema: LINEAGE_CLI_SCHEMA.to_string(),
        seeds: seeds.to_vec(),
        direction: match direction {
            Direction::Forward => "forward".to_string(),
            Direction::Reverse => "reverse".to_string(),
        },
        graph,
    })
}

pub fn cmd_diff(
    left_label: &str,
    left_path: &Path,
    right_label: &str,
    right_path: &Path,
) -> Result<CliDiffReport, LineageCliError> {
    let left = read_graph(left_path)?;
    let right = read_graph(right_path)?;
    let d = compute_diff(left_label, &left, right_label, &right);
    Ok(CliDiffReport {
        schema: LINEAGE_CLI_SCHEMA.to_string(),
        diff: d,
    })
}

/// Render a diff as a stable text summary (used by the TTY output path).
pub fn render_diff_text(report: &CliDiffReport) -> String {
    render_text(&report.diff)
}

pub fn cmd_roots(roots_dir: &Path) -> Result<CliRootsReport, LineageCliError> {
    let mut budget = crate::input::collection::Budget::default();
    let paths = crate::input::collection::directory(roots_dir, &mut budget)
        .map_err(LineageCliError::Input)?;
    let mut artifacts = Vec::new();
    for path in paths {
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = budget.read(&path).map_err(LineageCliError::Input)?;
        artifacts.push(
            crate::input::json::<AnchoredFrontier>(&bytes)
                .map_err(|error| LineageCliError::Input(error.into()))?,
        );
    }
    artifacts.sort_by(|a, b| a.digest.hex.cmp(&b.digest.hex));
    Ok(CliRootsReport {
        schema: LINEAGE_CLI_SCHEMA.to_string(),
        roots: artifacts,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_lineage::ingest_replay_corpus::{ingest_corpus, CorpusIngestError, CorpusReceiptRow};

    fn fixture_graph() -> Result<LineageGraph, CorpusIngestError> {
        ingest_corpus(&[CorpusReceiptRow {
            receipt_id: "r1".into(),
            parent_receipt_id: None,
            capability_id: Some("cap.x".into()),
            parent_capability_id: None,
            tool_name: Some("fs.read".into()),
            tenant_id: None,
            recorded_at: Some(1),
            signed_lineage_statement: None,
        }])
    }

    #[test]
    fn query_forward_finds_receipts_from_capability() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.json");
        let g = fixture_graph()?;
        fs::write(&path, serde_json::to_vec(&g).unwrap()).unwrap();
        let report = cmd_query(
            &path,
            &["cap:cap.x".to_string()],
            Direction::Forward,
            QueryBounds::default(),
        )
        .unwrap();
        assert_eq!(report.direction, "forward");
        assert_eq!(report.schema, LINEAGE_CLI_SCHEMA);
        assert!(!report.graph.nodes.is_empty());
        Ok(())
    }

    #[test]
    fn diff_emits_stable_schema() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir().unwrap();
        let lp = dir.path().join("l.json");
        let rp = dir.path().join("r.json");
        let g = fixture_graph()?;
        fs::write(&lp, serde_json::to_vec(&g).unwrap()).unwrap();
        fs::write(&rp, serde_json::to_vec(&g).unwrap()).unwrap();
        let report = cmd_diff("v1", &lp, "v2", &rp).unwrap();
        assert_eq!(report.schema, LINEAGE_CLI_SCHEMA);
        assert!(report.diff.only_left.is_empty());
        assert!(report.diff.only_right.is_empty());
        Ok(())
    }

    #[test]
    fn roots_handles_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let report = cmd_roots(dir.path()).unwrap();
        assert!(report.roots.is_empty());
    }
}
