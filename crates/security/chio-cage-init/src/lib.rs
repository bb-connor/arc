#![cfg(target_os = "linux")]
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
//! Single-threaded confinement bootstrap and shared launch-boundary validation.
#[cfg(all(feature = "enforcement-mutants", not(debug_assertions)))]
compile_error!("enforcement-mutants is test-only and cannot be built for release");
#[cfg(feature = "enforcement-mutants")]
use chio_cage_plan::ENFORCEMENT_MUTATION_ENV;
use chio_cage_plan::{
    is_credential_or_injection_name, validate_cage_target_fd_binding, validate_target_argv,
    CageEnforcementFailure, CageEnforcementFailureCode, CageInitPlan, EnforcementPrepared,
    ExecutionIdentity, FdPurpose, FdTableEntry, FileIdentity, FilesystemGrantAccess,
    LaunchEnvelope, NativeSyscallProfile, NetworkMode, ObservedRulesetStatus, ResourceKind,
    SandboxArchitecture, SeccompArgumentComparison, SeccompDefaultAction, SeccompEnforcementStatus,
    SeccompProfilePlan, StatusRecord, SyscallArgumentConstraint, BROKER_IPC_FD_SLOT,
    CAGE_COMPILER_VERSION, CAGE_INIT_PLAN_SCHEMA, CONTROL_FD, CONTROL_FD_ENV,
    ENFORCEMENT_PREPARED_SCHEMA, LAUNCH_ENVELOPE_SCHEMA, MAX_ARTIFACT_BYTES, MAX_ENVELOPE_BYTES,
    MAX_SUPPLEMENTARY_GIDS, MAX_TRANSFER_FDS, MINIMUM_LANDLOCK_ABI, NONO_PATCH_VERSION,
    PINNED_NONO_VERSION, PINNED_SECCOMPILER_VERSION, PLAN_FD, STATUS_FD, STATUS_RECORD_SCHEMA,
    TARGET_FD, TEMP_FD_START,
};
#[cfg(target_os = "linux")]
use chio_cage_plan::{
    REQUIRED_MEMFD_SEALS, TARGET_STDERR_FD_SLOT, TARGET_STDIN_FD_SLOT, TARGET_STDOUT_FD_SLOT,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::{SystemTime, UNIX_EPOCH};
mod descriptor_transfer;

#[derive(Debug)]
pub struct BootstrapFault {
    pub code: CageEnforcementFailureCode,
    pub stage: &'static str,
}

impl BootstrapFault {
    pub const fn new(code: CageEnforcementFailureCode, stage: &'static str) -> Self {
        Self { code, stage }
    }
}

mod bootstrap;

mod validation;
use validation::{
    target_entry, validate_envelope, verify_helper_self, verify_memfd_seals, verify_single_threaded,
};

mod descriptors;
use descriptors::{
    checked_slot_fd, is_status_socket, peer_credentials, remap_descriptors, write_packet,
};

mod identity;
use identity::{apply_execution_identity, arm_parent_death};

mod sandbox;
use sandbox::{
    apply_landlock, apply_resource_limits, install_seccomp, reset_signal_state, LandlockEnforcement,
};

mod seccomp;

mod exec;
use exec::build_exec_vectors;

mod status;
pub use bootstrap::run_cage_init;
pub use descriptor_transfer::{receive_descriptors, send_descriptors};
pub use seccomp::{compile_seccomp_filter, filter_digest, syscall_number};
pub use status::unix_time_ms;
use status::write_failure_record;
pub use validation::{
    hash_file, helper_identity_and_binding_match, read_bounded_file,
    seccomp_profile_is_fail_closed, validate_digest, validate_fd_table_shape,
    verify_descriptor_table, verify_received_descriptor_identity,
};
