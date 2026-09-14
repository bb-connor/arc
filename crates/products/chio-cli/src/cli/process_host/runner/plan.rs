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
    #[serde(default, skip_serializing_if = "FailurePolicy::is_stop")]
    pub failure_policy: FailurePolicy,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FailurePolicy {
    #[default]
    Stop,
    ContinueIndependent,
    Supervised,
}

impl FailurePolicy {
    fn is_stop(&self) -> bool {
        *self == Self::Stop
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_suspensions: Option<u32>,
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_suspensions: Option<u32>,
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,
}

/// The fixed local Docker worker profile. Commands and cwd refer to the image.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Container {
    pub image: String,
}

/// Cooperative suspensions a worker may take when its plan sets no ceiling.
/// Suspensions are bounded separately from failures so a fork/join round does
/// not spend the restart budget, and a worker that suspends without ever
/// completing still stops.
pub(super) const DEFAULT_MAX_SUSPENSIONS: u32 = 64;

/// Per-attempt ceilings. The OS ceilings are hard limits applied to the
/// worker process before exec; exceeding CPU time terminates the attempt.
/// The resident-memory ceiling is enforced by the runner from the worker's
/// sampled peak resident set.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Resources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_open_files: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_address_space_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_resident_bytes: Option<u64>,
}

impl Resources {
    fn validate(&self) -> Result<(), CliError> {
        let within = |value: Option<u64>, low: u64, high: u64| {
            value.is_none_or(|v| (low..=high).contains(&v))
        };
        if self.max_cpu_seconds.is_none()
            && self.max_open_files.is_none()
            && self.max_file_bytes.is_none()
            && self.max_address_space_bytes.is_none()
            && self.max_resident_bytes.is_none()
        {
            return Err(error("worker resources must set at least one ceiling"));
        }
        if !within(self.max_cpu_seconds, 1, 86_400)
            || !within(self.max_open_files, 16, 1_048_576)
            || !within(self.max_file_bytes, 1, 1 << 40)
            || !within(self.max_address_space_bytes, 64 << 20, 1 << 48)
            || !within(self.max_resident_bytes, 16 << 20, 1 << 48)
        {
            return Err(error(
                "worker resource ceilings are outside their supported ranges",
            ));
        }
        Ok(())
    }

    /// OS ceilings and hard values in the order they are applied.
    pub fn ceilings(&self) -> Vec<(Ceiling, u64)> {
        [
            (Ceiling::CpuSeconds, self.max_cpu_seconds),
            (Ceiling::OpenFiles, self.max_open_files),
            (Ceiling::FileBytes, self.max_file_bytes),
            (Ceiling::AddressSpaceBytes, self.max_address_space_bytes),
        ]
        .into_iter()
        .filter_map(|(ceiling, value)| value.map(|value| (ceiling, value)))
        .collect()
    }
}

#[derive(Clone, Copy)]
pub(super) enum Ceiling {
    CpuSeconds,
    OpenFiles,
    FileBytes,
    AddressSpaceBytes,
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
            max_suspensions: self.max_suspensions,
            timeout_seconds: self.timeout_seconds,
            resources: self.resources,
            container: self.container.clone(),
        }
    }
}

impl Worker {
    /// Cooperative suspensions this worker may take before it is failed.
    pub fn max_suspensions(&self) -> u32 {
        self.max_suspensions.unwrap_or(DEFAULT_MAX_SUSPENSIONS)
    }

    fn validate(&self) -> Result<(), CliError> {
        identifier(&self.process)?;
        if let Some(container) = &self.container {
            let digest = container.image.strip_prefix("sha256:").unwrap_or("");
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                || self.resources.is_some()
                || self.cwd != std::path::Path::new("/work")
            {
                return Err(error("container workers require an immutable local sha256 image, cwd /work and the fixed container resource profile"));
            }
        }
        if let Some(resources) = &self.resources {
            resources.validate()?;
        }
        if !self
            .max_suspensions
            .is_none_or(|limit| (1..=1024).contains(&limit))
        {
            return Err(error("worker suspension ceiling must be 1-1024"));
        }
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
        if (self.failure_policy == FailurePolicy::Supervised)
            != host.record.config.supervised_children
        {
            return Err(error(
                "supervised failure policy and host supervised_children must be enabled together",
            ));
        }
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
            // Existence is required here. Cancellation is checked after stale
            // container cleanup so a cancelled worker can still be reconciled.
            host.runtime.process(&worker.process).map_err(error)?;
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
