use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::state::{error, identifier, Host};
use crate::CliError;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub schema: String,
    pub max_parallel: usize,
    pub workers: Vec<Worker>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<Template>,
}

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Template {
    pub id: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    #[serde(default)]
    pub input: Value,
    pub max_attempts: u32,
    pub timeout_seconds: u64,
}

impl Template {
    pub fn worker(&self, process: String, task: Value) -> Worker {
        Worker {
            process,
            command: self.command.clone(),
            cwd: self.cwd.clone(),
            input: serde_json::json!({"configuration": self.input, "task": task}),
            depends_on: Vec::new(),
            max_attempts: self.max_attempts,
            timeout_seconds: self.timeout_seconds,
        }
    }
}

impl Worker {
    fn validate(&self) -> Result<(), CliError> {
        identifier(&self.process)?;
        if self.command.is_empty()
            || self.command.len() > 128
            || !std::path::Path::new(&self.command[0]).is_absolute()
            || !self.cwd.is_absolute()
            || self
                .command
                .iter()
                .any(|s| s.contains('\0') || s.len() > 16_384)
            || self.max_attempts == 0
            || self.max_attempts > 16
            || self.timeout_seconds == 0
            || self.timeout_seconds > 3600
            || self.depends_on.len() > 128
        {
            return Err(error(
                "invalid worker command, paths, identity or restart limits",
            ));
        }
        Ok(())
    }
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
        let expected: BTreeSet<_> = host
            .record
            .config
            .spawn_templates
            .iter()
            .map(|t| t.id.as_str())
            .collect();
        let mut templates = BTreeSet::new();
        for template in &self.templates {
            template
                .worker(template.id.clone(), Value::Null)
                .validate()?;
            if !templates.insert(template.id.as_str()) {
                return Err(error("duplicate runnable template"));
            }
        }
        if templates != expected {
            return Err(error(
                "run templates must exactly match the host's spawn templates",
            ));
        }
        for worker in &self.workers {
            worker.validate()?;
            if !ids.insert(worker.process.as_str())
                || (!templates.is_empty() && worker.process.starts_with("dyn_"))
            {
                return Err(error("duplicate or reserved worker identity"));
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
