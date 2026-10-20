//! Committed-disclosure audit of the `cage_receipt` receipt-metadata block.
//!
//! The block is the cage receipt's content preimage. Its members carry no
//! process argument, path, environment value or tenant identifier as such,
//! but `bindings.plan_digest` (and `enforcement_record.fully_enforced.prepared
//! .plan_digest`) is an unsalted SHA-256 over the canonical cage-init plan,
//! whose preimage holds the target argv, the target environment and the
//! descriptor paths, and `fd_table_digest` is an unsalted SHA-256 over the
//! descriptor table with its paths. Each confirms a guessed argument, path
//! or environment value, so the block is not committed-safe and stays
//! unregistered until a cage projection replaces it.

use chio_cage::{CageReceiptBindings, CageReceiptBody};
use chio_cage_plan::{
    CageEnforcementFailure, CageEnforcementFailureCode, CageEnforcementRecord, CageInitPlan,
    EnforcementPrepared, ExecTransitionObserved, FullyEnforcedEvidence, ProcessExitEvidence,
};
use chio_core::receipt::metadata::metadata_key_spec;
use chio_test_support::prelude::*;

const NATIVE_PLAN: &str = include_str!(
    "../../../../tests/bindings/vectors/security/cage/positive/cage-init-plan-native-v1.json"
);

const ARGUMENT_MARKER: &str = "marker-argument-7f3a";
const ENVIRONMENT_MARKER: &str = "marker-environment-7f3a";
const PATH_MARKER: &str = "/marker-path-7f3a/mcp-server";

fn plan_digest(plan: &CageInitPlan) -> String {
    chio_core::sha256_hex(&chio_core::canonical_json_bytes(plan).test_unwrap())
}

fn fd_table_digest(plan: &CageInitPlan) -> String {
    chio_core::sha256_hex(&chio_core::canonical_json_bytes(&plan.fd_table).test_unwrap())
}

fn marked_plan() -> CageInitPlan {
    let mut plan: CageInitPlan = serde_json::from_str(NATIVE_PLAN).test_unwrap();
    plan.target_argv = vec![PATH_MARKER.to_string(), ARGUMENT_MARKER.to_string()];
    plan.environment
        .insert("CHIO_ENV".to_string(), ENVIRONMENT_MARKER.to_string());
    for entry in &mut plan.fd_table {
        if entry.path.is_some() {
            entry.path = Some(PATH_MARKER.to_string());
        }
    }
    plan
}

#[test]
fn cage_plan_digest_preimages_carry_arguments_environment_and_paths() {
    let plan = marked_plan();
    let preimage =
        String::from_utf8(chio_core::canonical_json_bytes(&plan).test_unwrap()).test_unwrap();
    for marker in [ARGUMENT_MARKER, ENVIRONMENT_MARKER, PATH_MARKER] {
        assert!(preimage.contains(marker), "plan preimage lacks {marker}");
    }
    let table = String::from_utf8(chio_core::canonical_json_bytes(&plan.fd_table).test_unwrap())
        .test_unwrap();
    assert!(table.contains(PATH_MARKER));

    let mut other_argument = plan.clone();
    other_argument.target_argv[1] = "other-argument".to_string();
    assert_ne!(plan_digest(&plan), plan_digest(&other_argument));

    let mut other_environment = plan.clone();
    other_environment
        .environment
        .insert("CHIO_ENV".to_string(), "other-environment".to_string());
    assert_ne!(plan_digest(&plan), plan_digest(&other_environment));

    let mut other_path = plan.clone();
    for entry in &mut other_path.fd_table {
        if entry.path.is_some() {
            entry.path = Some("/other/mcp-server".to_string());
        }
    }
    assert_ne!(fd_table_digest(&plan), fd_table_digest(&other_path));
    assert_ne!(plan_digest(&plan), plan_digest(&other_path));
}

/// Names every member of the block. A new member fails to compile here until
/// it is audited.
fn audited_members(body: &CageReceiptBody) -> usize {
    let CageReceiptBody {
        schema: _,
        attempt_id: _,
        stage: _,
        bindings,
        admitted_policy_digest: _,
        enforcement_record,
        started_at_unix_ms: _,
        recorded_at_unix_ms: _,
    } = body;
    let mut digest_members = 0;
    if let Some(CageReceiptBindings {
        manifest_digest: _,
        profile_digest: _,
        plan_digest: _,
        fd_table_digest: _,
        helper_binding_digest: _,
        target_binding_digest: _,
        target_identity: _,
    }) = bindings
    {
        digest_members += 2;
    }
    let CageEnforcementRecord {
        schema: _,
        state: _,
        fully_enforced,
        failure,
        exit,
    } = enforcement_record;
    if let Some(FullyEnforcedEvidence {
        prepared:
            EnforcementPrepared {
                schema: _,
                process_id: _,
                manifest_digest: _,
                profile_digest: _,
                plan_digest: _,
                fd_table_digest: _,
                helper_binding_digest: _,
                target_binding_digest: _,
                target_identity: _,
                applied_execution_identity: _,
                nono_version: _,
                nono_patch_version: _,
                landlock_abi: _,
                landlock_filesystem_status: _,
                landlock_network_status: _,
                seccompiler_version: _,
                seccomp_status: _,
                seccomp_architecture: _,
                seccomp_filter_digest: _,
                trace_session_digest: _,
                prepared_at_unix_ms: _,
            },
        exec_transition:
            ExecTransitionObserved {
                schema: _,
                process_id: _,
                trace_session_digest: _,
                target_binding_digest: _,
                target_identity: _,
                observed_at_unix_ms: _,
            },
        status_eof_observed: _,
    }) = fully_enforced
    {
        digest_members += 2;
    }
    if let Some(CageEnforcementFailure { code: _, stage: _ }) = failure {}
    if let Some(ProcessExitEvidence {
        process_id: _,
        exit_code: _,
        signal: _,
        exited_at_unix_ms: _,
    }) = exit
    {}
    digest_members
}

#[test]
fn cage_receipt_block_is_not_committed_safe() {
    let failure = CageEnforcementFailure::new(CageEnforcementFailureCode::InvalidPlan, "admission")
        .test_unwrap();
    let record = CageEnforcementRecord::rejected(failure).test_unwrap();
    let body = CageReceiptBody::new("attempt-1", None, record, 1_000, 2_000).test_unwrap();
    assert_eq!(audited_members(&body), 0);

    assert!(metadata_key_spec("cage_receipt").is_none());
    assert!(metadata_key_spec("schema").is_none());
}
