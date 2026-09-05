use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::state::{error, identifier, Host};
use crate::CliError;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub schema: String,
    pub max_parallel: usize,
    pub workers: Vec<Worker>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Worker {
    pub process: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub max_attempts: u32,
    pub timeout_seconds: u64,
}

impl Plan {
    pub fn validate(&self, host: &Host) -> Result<(), CliError> {
        if self.schema != "chio.process.run.v1"
            || self.workers.is_empty()
            || self.workers.len() > 128
            || self.max_parallel == 0
            || self.max_parallel > 32
        {
            return Err(error(
                "run plan requires chio.process.run.v1, 1-128 workers and 1-32 parallel workers",
            ));
        }
        let mut ids = BTreeSet::new();
        for worker in &self.workers {
            identifier(&worker.process)?;
            if !ids.insert(worker.process.as_str())
                || worker.command.is_empty()
                || worker.command.len() > 128
                || !std::path::Path::new(&worker.command[0]).is_absolute()
                || !worker.cwd.is_absolute()
                || worker
                    .command
                    .iter()
                    .any(|s| s.contains('\0') || s.len() > 16_384)
                || worker.max_attempts == 0
                || worker.max_attempts > 16
                || worker.timeout_seconds == 0
                || worker.timeout_seconds > 3600
                || worker.depends_on.len() > 128
            {
                return Err(error(
                    "invalid worker command, paths, identity or restart limits",
                ));
            }
            let process = host.runtime.process(&worker.process).map_err(error)?;
            if process.state != chio_process::ProcessState::Running {
                return Err(error("run plan includes a cancelled process"));
            }
        }
        let mut dependencies = BTreeMap::new();
        for worker in &self.workers {
            let deps: BTreeSet<_> = worker.depends_on.iter().map(String::as_str).collect();
            if deps.len() != worker.depends_on.len()
                || !deps.is_subset(&ids)
                || deps.contains(worker.process.as_str())
            {
                return Err(error(
                    "worker dependencies must be unique, existing, other workers",
                ));
            }
            dependencies.insert(worker.process.as_str(), deps);
        }
        while !dependencies.is_empty() {
            let ready: BTreeSet<_> = dependencies
                .iter()
                .filter(|(_, deps)| deps.is_empty())
                .map(|(id, _)| *id)
                .collect();
            if ready.is_empty() {
                return Err(error("worker dependency cycle"));
            }
            dependencies.retain(|id, _| !ready.contains(id));
            for deps in dependencies.values_mut() {
                deps.retain(|id| !ready.contains(id));
            }
        }
        Ok(())
    }
}
