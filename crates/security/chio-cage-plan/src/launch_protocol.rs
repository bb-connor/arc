use super::{CageEnforcementFailure, CageInitPlan, Deserialize, EnforcementPrepared, Serialize};

pub const LAUNCH_ENVELOPE_SCHEMA: &str = "chio.cage.launch-envelope.v1";
pub const STATUS_RECORD_SCHEMA: &str = "chio.cage.status-record.v1";
pub const CONTROL_FD_ENV: &str = "CHIO_CAGE_CONTROL_FD";
#[cfg(feature = "enforcement-mutants")]
pub const ENFORCEMENT_MUTATION_ENV: &str = "CHIO_CAGE_TEST_ENFORCEMENT_MUTATION";
pub const CONTROL_FD: i32 = 0;
pub const PLAN_FD: i32 = 3;
pub const STATUS_FD: i32 = 4;
pub const TARGET_FD: i32 = 255;
pub const TEMP_FD_START: i32 = TARGET_FD + 1;
pub const MAX_TRANSFER_FDS: usize = 192;
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STATUS_BYTES: usize = 64 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "linux")]
pub const REQUIRED_MEMFD_SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchEnvelope {
    pub schema: String,
    pub parent_process_id: u32,
    pub trace_session_digest: String,
    pub plan_digest: String,
    pub fd_table_digest: String,
    pub helper_binding_digest: String,
    pub target_binding_digest: String,
    pub plan: CageInitPlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StatusRecord {
    Prepared {
        schema: String,
        evidence: Box<EnforcementPrepared>,
    },
    Failure {
        schema: String,
        failure: CageEnforcementFailure,
    },
}
