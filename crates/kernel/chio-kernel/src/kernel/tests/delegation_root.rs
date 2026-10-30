use super::*;
use crate::kernel::validation::lineage::DelegationRootError;

struct DelegatedFixture {
    kernel: ChioKernel,
    store: Arc<SqliteReceiptStore>,
    parent: CapabilityToken,
    delegated: CapabilityToken,
}

fn delegated_fixture(label: &str) -> Result<DelegatedFixture, Box<dyn std::error::Error>> {
    let now = current_unix_timestamp();
    let issuer = make_keypair();
    let root_subject = make_keypair();
    let child = make_keypair();
    let mut config = make_config();
    config.keypair = issuer.clone();
    let mut kernel = make_kernel(config);
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let parent = CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("{label}-parent"),
            issuer: issuer.public_key(),
            subject: root_subject.public_key(),
            scope: scope.clone(),
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(300),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent.id.clone(),
            delegator: root_subject.public_key(),
            delegatee: child.public_key(),
            attenuations: Vec::new(),
            timestamp: now,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &root_subject,
    )?;
    let delegated = CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("{label}-child"),
            issuer: issuer.public_key(),
            subject: child.public_key(),
            scope,
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(300),
            delegation_chain: vec![link],
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    let path = unique_receipt_db_path(label);
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    kernel.set_receipt_store_handle(store.clone())?;
    Ok(DelegatedFixture {
        kernel,
        store,
        parent,
        delegated,
    })
}

#[test]
fn a_root_capability_has_no_delegation_root() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = delegated_fixture("chio-root-none")?;
    assert!(matches!(
        fixture.kernel.delegation_root_subject(&fixture.parent),
        Ok(None)
    ));
    Ok(())
}

#[test]
fn the_delegation_root_is_the_retained_parent_subject() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = delegated_fixture("chio-root-ok")?;
    fixture
        .store
        .record_capability_snapshot(&fixture.parent, None)?;
    let root = fixture.kernel.delegation_root_subject(&fixture.delegated);
    assert!(
        matches!(&root, Ok(Some(subject)) if *subject == fixture.parent.subject),
        "{root:?}"
    );
    Ok(())
}

#[test]
fn a_missing_delegation_root_snapshot_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = delegated_fixture("chio-root-missing")?;
    let error = fixture
        .kernel
        .delegation_root_subject(&fixture.delegated)
        .err();
    assert!(
        matches!(
            &error,
            Some(DelegationRootError::Missing { capability_id }) if *capability_id == fixture.parent.id
        ),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn a_failed_delegation_root_lookup_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = delegated_fixture("chio-root-lookup")?;
    fixture
        .store
        .connection()?
        .execute("DROP TABLE capability_lineage", [])?;
    let error = fixture
        .kernel
        .delegation_root_subject(&fixture.delegated)
        .err();
    assert!(
        matches!(&error, Some(DelegationRootError::LookupFailed(_))),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn an_invalid_delegation_root_subject_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = delegated_fixture("chio-root-invalid")?;
    fixture
        .store
        .record_capability_snapshot(&fixture.parent, None)?;
    fixture
        .store
        .connection()?
        .execute("UPDATE capability_lineage SET subject_key = 'substituted'", [])?;
    let error = fixture
        .kernel
        .delegation_root_subject(&fixture.delegated)
        .err();
    assert!(
        matches!(&error, Some(DelegationRootError::InvalidSubject(_))),
        "{error:?}"
    );
    Ok(())
}
