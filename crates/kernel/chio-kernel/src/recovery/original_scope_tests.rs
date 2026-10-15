use super::*;
use crate::admission_operation::AdmissionOperationError;
use crate::recovery::vector_test_fixture::{action_scope, seed_request, TestResult};
use chio_security_types::recovery::{AuthorityDomainId, ProcessId, RecoveryTenantId};

fn refused(result: Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError>) -> bool {
    matches!(result, Err(RecoveryOriginalRequestError::Refused))
}

#[test]
fn original_scope_requires_the_installed_all_mode_authority() -> TestResult {
    let scope = action_scope()?;
    let seed = seed_request()?;
    let authority = scope.authority_domain.as_str().to_owned();
    assert!(refused(original_request_scope(
        None,
        DurableAdmissionMode::All,
        &scope,
        &seed
    )));
    for mode in [
        DurableAdmissionMode::Off,
        DurableAdmissionMode::Monetary,
        DurableAdmissionMode::SideEffecting,
    ] {
        assert!(
            refused(original_request_scope(
                Some(&authority),
                mode,
                &scope,
                &seed
            )),
            "{mode:?}"
        );
    }
    let mut foreign = scope.clone();
    foreign.authority_domain = AuthorityDomainId::new("authority:foreign")?;
    assert!(refused(original_request_scope(
        Some(&authority),
        DurableAdmissionMode::All,
        &foreign,
        &seed
    )));
    assert!(refused(original_request_scope(
        Some("authority:foreign"),
        DurableAdmissionMode::All,
        &scope,
        &seed
    )));
    let derived =
        original_request_scope(Some(&authority), DurableAdmissionMode::All, &scope, &seed)?;
    assert!(derived.matches(&scope, &seed));
    Ok(())
}

#[test]
fn original_scope_binds_the_installed_local_system_namespace() -> TestResult {
    let scope = action_scope()?;
    let seed = seed_request()?;
    let authority = scope.authority_domain.as_str().to_owned();
    let derived =
        original_request_scope(Some(&authority), DurableAdmissionMode::All, &scope, &seed)?;
    let coordinator = AdmissionIdentifier::try_new("coordinator_authority_id", authority.clone())?;
    let local = AuthenticatedRequestNamespace::for_local_system(coordinator.clone())?;
    assert_eq!(derived.namespace(), local.digest());
    assert_eq!(derived.request_id().as_str(), seed.request_id);
    let tenant = AuthenticatedRequestNamespace::from_authentication_context(
        coordinator,
        scope.tenant_id.as_str(),
    )?;
    assert_ne!(derived.namespace(), tenant.digest());

    let mut retargeted_scope = scope.clone();
    retargeted_scope.tenant_id = RecoveryTenantId::new("tenant:other")?;
    let retargeted = original_request_scope(
        Some(&authority),
        DurableAdmissionMode::All,
        &retargeted_scope,
        &seed,
    )?;
    assert_eq!(retargeted.namespace(), derived.namespace());
    assert!(retargeted.matches(&retargeted_scope, &seed));
    assert!(!retargeted.matches(&scope, &seed));
    Ok(())
}

#[test]
fn original_scope_matches_only_its_exact_scope_request_and_seed() -> TestResult {
    let scope = action_scope()?;
    let seed = seed_request()?;
    let authority = scope.authority_domain.as_str().to_owned();
    let derived =
        original_request_scope(Some(&authority), DurableAdmissionMode::All, &scope, &seed)?;
    assert!(derived.matches(&scope, &seed));

    let mut changed_scopes = Vec::new();
    let mut changed = scope.clone();
    changed.authority_domain = AuthorityDomainId::new("authority:foreign")?;
    changed_scopes.push(changed);
    let mut changed = scope.clone();
    changed.tenant_id = RecoveryTenantId::new("tenant:other")?;
    changed_scopes.push(changed);
    let mut changed = scope.clone();
    changed.process_id = ProcessId::new("process:other")?;
    changed_scopes.push(changed);
    for changed in &changed_scopes {
        assert!(!derived.matches(changed, &seed));
    }

    let mut changed_seeds = Vec::new();
    let mut changed = seed.clone();
    changed.request_id = format!("{}-changed", seed.request_id);
    changed_seeds.push(changed);
    let mut changed = seed.clone();
    changed.arguments = serde_json::json!({"body": "private-canary", "title": "changed"});
    changed_seeds.push(changed);
    let mut changed = seed.clone();
    changed.tool_name = format!("{}-changed", seed.tool_name);
    changed_seeds.push(changed);
    for changed in &changed_seeds {
        assert!(!derived.matches(&scope, changed));
        let rederived =
            original_request_scope(Some(&authority), DurableAdmissionMode::All, &scope, changed)?;
        assert!(rederived.matches(&scope, changed));
        assert!(!rederived.matches(&scope, &seed));
    }

    let mut unnamed = seed.clone();
    unnamed.request_id = String::new();
    assert!(matches!(
        original_request_scope(
            Some(&authority),
            DurableAdmissionMode::All,
            &scope,
            &unnamed
        ),
        Err(RecoveryOriginalRequestError::Store(
            AdmissionOperationStoreError::Operation(AdmissionOperationError::Empty {
                field: "request_id"
            })
        ))
    ));
    Ok(())
}
