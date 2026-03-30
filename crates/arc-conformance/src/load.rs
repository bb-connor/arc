use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::{ScenarioDescriptor, ScenarioResult};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error in {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

pub fn load_scenarios_from_dir(
    path: impl AsRef<Path>,
) -> Result<Vec<ScenarioDescriptor>, LoadError> {
    let mut scenarios = read_json_files::<ScenarioDescriptor>(path.as_ref())?;
    scenarios.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(scenarios)
}

pub fn load_results_from_dir(path: impl AsRef<Path>) -> Result<Vec<ScenarioResult>, LoadError> {
    let mut results = Vec::new();
    for file_path in collect_json_files(path.as_ref())? {
        let content = fs::read_to_string(&file_path)?;
        match serde_json::from_str::<Vec<ScenarioResult>>(&content) {
            Ok(mut batch) => results.append(&mut batch),
            Err(_) => {
                let record = deserialize::<ScenarioResult>(&file_path, &content)?;
                results.push(record);
            }
        }
    }
    results.sort_by(|left, right| {
        left.scenario_id
            .cmp(&right.scenario_id)
            .then_with(|| left.peer.cmp(&right.peer))
            .then_with(|| left.deployment_mode.cmp(&right.deployment_mode))
            .then_with(|| left.transport.cmp(&right.transport))
    });
    Ok(results)
}

fn read_json_files<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, LoadError> {
    let mut items = Vec::new();
    for file_path in collect_json_files(path)? {
        let content = fs::read_to_string(&file_path)?;
        items.push(deserialize::<T>(&file_path, &content)?);
    }
    Ok(items)
}

fn deserialize<T: DeserializeOwned>(path: &Path, content: &str) -> Result<T, LoadError> {
    serde_json::from_str(content).map_err(|source| LoadError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn collect_json_files(path: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let mut files = Vec::new();
    walk_json_files(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_json_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), LoadError> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            walk_json_files(&entry_path, files)?;
        } else if entry_path.extension().and_then(|value| value.to_str()) == Some("json") {
            files.push(entry_path);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn unique_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}"))
    }

    #[test]
    fn loads_scenarios_and_results_from_json_directories() {
        let dir = unique_dir("arc-conformance-load");
        fs::create_dir_all(dir.join("scenarios")).expect("create scenarios dir");
        fs::create_dir_all(dir.join("results")).expect("create results dir");

        fs::write(
            dir.join("scenarios/initialize.json"),
            r#"{
              "id": "initialize",
              "title": "Initialize",
              "area": "lifecycle",
              "category": "mcp-core",
              "specVersions": ["2025-11-25"],
              "transport": ["stdio"],
              "peerRoles": ["client_to_arc_server"],
              "deploymentModes": ["wrapped_stdio"],
              "requiredCapabilities": {"server": [], "client": []},
              "tags": ["wave1"],
              "expected": "pass"
            }"#,
        )
        .expect("write scenario");
        fs::write(
            dir.join("results/results.json"),
            r#"[{
              "scenarioId": "initialize",
              "peer": "js",
              "peerRole": "client_to_arc_server",
              "deploymentMode": "wrapped_stdio",
              "transport": "stdio",
              "specVersion": "2025-11-25",
              "category": "mcp-core",
              "status": "pass",
              "durationMs": 12,
              "assertions": [{"name": "initialize_succeeds", "status": "pass"}]
            }]"#,
        )
        .expect("write results");

        let scenarios = load_scenarios_from_dir(dir.join("scenarios")).expect("load scenarios");
        let results = load_results_from_dir(dir.join("results")).expect("load results");

        assert_eq!(scenarios.len(), 1);
        assert_eq!(results.len(), 1);
        assert_eq!(scenarios[0].id, "initialize");
        assert_eq!(results[0].peer, "js");
    }
}
