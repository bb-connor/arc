#[path = "delegation_freeze_public/support.rs"]
mod support;

use chio_kernel::{KernelError, ReceiptStore};
use chio_security_types::ports::CapabilityIssuanceOperation;
use support::*;

#[test]
fn frozen_bound_delegation_cannot_subscribe_a_live_session() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-frozen-subscription", Some(FROZEN))?;
    let session = fixture.open_for(&token)?;
    let authority = fixture.install()?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI);
    assert!(
        matches!(result, Err(KernelError::CapabilityIssuanceDenied(_))),
        "an active frozen lineage must refuse the public subscription: {result:?}"
    );
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    let queries = authority.queries()?;
    let query = queries.last().ok_or("no delegation freeze query")?;
    assert_eq!(query.operation, CapabilityIssuanceOperation::Delegate);
    assert_eq!(query.tenant_id.as_str(), TENANT);
    assert_eq!(query.lineage_id.as_str(), FROZEN);
    assert_eq!(
        query.parent_capability_id.as_ref().map(|id| id.as_str()),
        Some(fixture.root.id.as_str())
    );
    Ok(())
}

#[test]
fn sibling_lineage_can_subscribe_the_registered_resource() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-sibling-subscription", Some(SIBLING))?;
    let session = fixture.open_for(&token)?;
    fixture.install()?;
    fixture
        .kernel
        .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI)?;
    assert!(fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn bound_delegation_without_a_freeze_authority_cannot_subscribe() -> TestResult {
    let fixture = Fixture::new()?;
    let token = fixture.delegated("child-no-authority-subscription", Some(SIBLING))?;
    let session = fixture.open_for(&token)?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI);
    assert!(
        matches!(result, Err(KernelError::CapabilityIssuanceDenied(_))),
        "bound delegation requires its authority on the public subscription: {result:?}"
    );
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn configured_freeze_authority_refuses_delegation_without_signed_binding() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-unbound-configured", None)?;
    let session = fixture.open_for(&token)?;
    fixture.install()?;
    let result =
        fixture
            .kernel
            .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI);
    assert!(
        matches!(result, Err(KernelError::CapabilityIssuanceDenied(_))),
        "configured authority cannot classify an unbound delegation as standalone: {result:?}"
    );
    assert!(!fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn standalone_unbound_delegation_can_subscribe_without_an_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let token = fixture.delegated("child-unbound-standalone", None)?;
    let session = fixture.open_for(&token)?;
    fixture
        .kernel
        .subscribe_session_resource(&session, &token, &token.subject.to_hex(), URI)?;
    assert!(fixture
        .kernel
        .session_has_resource_subscription(&session, URI)?);
    Ok(())
}

#[test]
fn already_issued_roots_are_unchanged_by_a_delegation_freeze() -> TestResult {
    for bound in [false, true] {
        let mut fixture = Fixture::new()?;
        let token = if bound {
            fixture.bound_root()?
        } else {
            fixture.root.clone()
        };
        let session = fixture.open_for(&token)?;
        let authority = fixture.install()?;
        fixture.kernel.subscribe_session_resource(
            &session,
            &token,
            &token.subject.to_hex(),
            URI,
        )?;
        assert!(fixture
            .kernel
            .session_has_resource_subscription(&session, URI)?);
        fixture.kernel.register_delegation_parent(&token)?;
        assert!(
            authority.queries()?.is_empty(),
            "an already issued root is not a Delegate operation"
        );
    }
    Ok(())
}

#[test]
fn frozen_bound_delegation_cannot_be_registered_as_a_parent() -> TestResult {
    let mut fixture = Fixture::new()?;
    let token = fixture.delegated("child-frozen-parent-registration", Some(FROZEN))?;
    assert!(fixture.store.get_capability_snapshot(&token.id)?.is_none());
    let authority = fixture.install()?;
    let result = fixture.kernel.register_delegation_parent(&token);
    assert!(
        matches!(result, Err(KernelError::CapabilityIssuanceDenied(_))),
        "public parent registration must reject the frozen delegation: {result:?}"
    );
    assert!(
        fixture.store.get_capability_snapshot(&token.id)?.is_none(),
        "denied registration cannot retain an accepted child snapshot"
    );
    let queries = authority.queries()?;
    let query = queries
        .last()
        .ok_or("no parent-registration freeze query")?;
    assert_eq!(query.operation, CapabilityIssuanceOperation::Delegate);
    assert_eq!(
        query.parent_capability_id.as_ref().map(|id| id.as_str()),
        Some(fixture.root.id.as_str())
    );
    Ok(())
}
