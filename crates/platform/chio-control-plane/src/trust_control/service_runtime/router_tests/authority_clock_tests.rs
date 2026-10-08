//! Trust-service capability issuance reads time from the service's authority
//! clock for both the signing authority and its policy wrapper.
use super::*;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::CapabilityAuthority;
use chio_security_types::clock::FixedClock;

use crate::trust_control::report_validation::{
    load_capability_authority, load_capability_authority_with_deferred_lineage,
};

const SERVICE_NOW_SECS: u64 = 1_900_000_000;

fn read_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Read],
            constraints: Vec::new(),
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

fn fixed_service_state(
    configure: impl FnOnce(&mut TrustServiceConfig, &std::path::Path),
    directory: &std::path::Path,
) -> TrustServiceState {
    let mut state = metrics_state("authority-clock-token");
    state.finding_challenge_clock = Arc::new(FixedClock::from_millis(SERVICE_NOW_SECS * 1_000));
    configure(&mut state.config, directory);
    state
}

fn issued_at(authority: Result<Box<dyn CapabilityAuthority>, axum::response::Response>) -> u64 {
    let authority = authority.unwrap_or_else(|response| {
        panic!("capability authority unavailable: {}", response.status())
    });
    let subject = Keypair::generate().public_key();
    authority
        .issue_capability(&subject, read_scope(), 60)
        .unwrap_or_else(|error| panic!("issue capability: {error}"))
        .issued_at
}

#[test]
fn seed_backed_issuance_uses_the_service_authority_clock() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let state = fixed_service_state(
        |config, directory| config.authority_seed_path = Some(directory.join("authority.seed")),
        directory.path(),
    );

    assert_eq!(
        issued_at(load_capability_authority(&state)),
        SERVICE_NOW_SECS
    );
    assert_eq!(
        issued_at(load_capability_authority_with_deferred_lineage(&state)),
        SERVICE_NOW_SECS
    );
}

#[test]
fn database_backed_issuance_uses_the_service_authority_clock() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let state = fixed_service_state(
        |config, directory| config.authority_db_path = Some(directory.join("authority.sqlite3")),
        directory.path(),
    );

    assert_eq!(
        issued_at(load_capability_authority(&state)),
        SERVICE_NOW_SECS
    );
    assert_eq!(
        issued_at(load_capability_authority_with_deferred_lineage(&state)),
        SERVICE_NOW_SECS
    );
}
