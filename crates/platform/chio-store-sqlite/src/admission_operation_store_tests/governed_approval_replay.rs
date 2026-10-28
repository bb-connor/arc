use super::*;

use std::sync::Arc;

use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;

#[path = "governed_approval_replay/authority.rs"]
mod authority;
#[path = "governed_approval_replay/claims.rs"]
mod claims;

const AUTHORITY_ID: &str = "approval-authority";
const GENERATION_ID: &str = "approval-generation";
const CAPACITY: u64 = 8;

fn binding() -> GovernedApprovalAuthorityBindingV1 {
    GovernedApprovalAuthorityBindingV1::new(
        identifier("authority", AUTHORITY_ID),
        identifier("expectation", GENERATION_ID),
    )
}

fn install(fixture: &Fixture) -> AnchoredTestResult<GovernedApprovalAuthorityBindingV1> {
    install_with_capacity(fixture, CAPACITY)
}

fn install_with_capacity(
    fixture: &Fixture,
    capacity: u64,
) -> AnchoredTestResult<GovernedApprovalAuthorityBindingV1> {
    let binding = binding();
    let installed = fixture.store.install_governed_approval_authority(
        &binding,
        capacity,
        &fixture.fence,
        now_ms(),
    )?;
    assert_eq!(installed.binding(), &binding);
    Ok(binding)
}

fn global_count(fixture: &Fixture) -> i64 {
    fixture
        .store
        .connection()
        .expect("connection")
        .query_row("SELECT COUNT(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })
        .expect("global count")
}
