mod load;
mod model;
mod report;
mod runner;

pub use load::{load_results_from_dir, load_scenarios_from_dir, LoadError};
pub use model::{
    AssertionOutcome, AssertionResult, CompatibilityReport, DeploymentMode, PeerRole,
    RequiredCapabilities, ResultStatus, ScenarioCategory, ScenarioDescriptor, ScenarioResult,
    Transport,
};
pub use report::generate_markdown_report;
pub use runner::{
    default_repo_root, default_run_options, run_conformance_harness, unique_run_dir,
    ConformanceAuthMode, ConformanceRunOptions, ConformanceRunSummary, PeerTarget, RunnerError,
};
