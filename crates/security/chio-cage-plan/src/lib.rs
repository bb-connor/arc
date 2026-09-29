#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions
    )
)]
//! Shared confinement plan, descriptor, and enforcement-evidence contracts.
#[cfg(all(feature = "enforcement-mutants", not(debug_assertions)))]
compile_error!("enforcement-mutants is test-only and cannot be built for release");
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
mod enforcement;
mod environment;
mod error;
mod execution_identity;
#[cfg(target_os = "linux")]
pub mod linux;
mod model;
mod seccomp_plan;
pub use chio_core_types::{canonical_json_bytes, sha256_hex};
pub use enforcement::{
    CageEnforcementFailure, CageEnforcementFailureCode, CageEnforcementRecord,
    CageEnforcementState, EnforcementEvidenceError, EnforcementPrepared, ExecTransitionObserved,
    FullyEnforcedEvidence, ObservedRulesetStatus, ProcessExitEvidence, SeccompEnforcementStatus,
    CAGE_ENFORCEMENT_RECORD_SCHEMA, ENFORCEMENT_PREPARED_SCHEMA, EXEC_TRANSITION_OBSERVED_SCHEMA,
    MINIMUM_LANDLOCK_ABI, NONO_PATCH_VERSION, PINNED_NONO_VERSION, PINNED_SECCOMPILER_VERSION,
};
pub use environment::is_credential_or_injection_name;
pub use error::CageError;
pub use execution_identity::{
    validate_cage_execution_identity_binding, ExecutionIdentity, MAX_SUPPLEMENTARY_GIDS,
};
pub use model::{
    validate_cage_target_fd_binding, validate_sha256_hex, validate_target_argv, BrokerPeerIdentity,
    CageInitPlan, FdPurpose, FdTableEntry, FileIdentity, FilesystemGrant, FilesystemGrantAccess,
    ForbiddenResourceBinding, LandlockPolicyPlan, NativeSyscallProfile, NetworkMode,
    RequiredEnforcement, ResourceKind, ResourceLimitPlan, SandboxArchitecture,
    SeccompArgumentComparison, SeccompDefaultAction, SyscallArgumentConstraint, AT_EMPTY_PATH,
    BROKER_IPC_FD_SLOT, CAGE_COMPILER_VERSION, CAGE_INIT_PLAN_SCHEMA, CHILD_NOFILE_LIMIT,
    HELPER_FD_SLOT, MAX_TARGET_ARGV_BYTES, MAX_TARGET_ARG_BYTES, MAX_TARGET_ARG_COUNT,
    PLAN_FD_SLOT, READ_GRANT_FD_SLOT_START, RUNTIME_FD_SLOT_START, STATUS_FD_SLOT, TARGET_FD_SLOT,
    WORKING_DIRECTORY_FD_SLOT, WRITE_GRANT_FD_SLOT_START,
};
#[cfg(target_os = "linux")]
pub use model::{TARGET_STDERR_FD_SLOT, TARGET_STDIN_FD_SLOT, TARGET_STDOUT_FD_SLOT};
pub use seccomp_plan::{SeccompPlanError, SeccompProfilePlan, Syscall};

mod launch_protocol;
#[cfg(feature = "enforcement-mutants")]
pub use launch_protocol::ENFORCEMENT_MUTATION_ENV;
#[cfg(target_os = "linux")]
pub use launch_protocol::REQUIRED_MEMFD_SEALS;
pub use launch_protocol::{
    LaunchEnvelope, StatusRecord, CONTROL_FD, CONTROL_FD_ENV, LAUNCH_ENVELOPE_SCHEMA,
    MAX_ARTIFACT_BYTES, MAX_ENVELOPE_BYTES, MAX_STATUS_BYTES, MAX_TRANSFER_FDS, PLAN_FD, STATUS_FD,
    STATUS_RECORD_SCHEMA, TARGET_FD, TEMP_FD_START,
};
