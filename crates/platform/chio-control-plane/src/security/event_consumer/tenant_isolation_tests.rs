use super::tests::{authoritative_finding, publish_recovery_batch};
use chio_security_types::ports::{
    AttestedFindingBatchKey, AttestedFindingBatchStore, AttestedFindingResponseOutboxStore,
    TenantId,
};
use chio_store_sqlite::SqliteSecurityStateStore;

#[test]
fn signed_ingress_cannot_be_relabelled_to_a_foreign_tenant_after_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    use super::tests::{signed_event, verifier};
    use super::*;
    use chio_security_types::ports::{CorrelationIngressStore, EventAppend};

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("tenant-ingress.sqlite");
    let key = chio_core::Keypair::from_seed(&[77; 32]);
    let event = signed_event(&key);
    let mut foreign = event.clone();
    foreign.tenant_id = TenantId::new("foreign-tenant")?;
    for pass in 0..2 {
        let store = Arc::new(SqliteSecurityStateStore::open(&path)?);
        let ingress =
            VerifiedSecurityEventIngress::new(Arc::new(verifier(&key)), Arc::clone(&store))?;
        assert_eq!(
            ingress.verify_and_append(&event)?,
            if pass == 0 {
                EventAppend::Inserted
            } else {
                EventAppend::Duplicate
            }
        );
        assert_eq!(
            ingress.verify_and_append(&foreign),
            Err(PortError::integrity_failure())
        );
        assert_eq!(
            store.load_pending_correlation_events(10)?.as_slice(),
            std::slice::from_ref(&event)
        );
        assert_eq!(
            store.acknowledge_correlated_event(&foreign),
            Err(PortError::integrity_failure())
        );
        assert_eq!(store.count_pending_correlation_events()?, 1);
    }
    Ok(())
}

#[test]
fn exact_attested_batch_and_outbox_ids_are_tenant_bound_after_restart() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("tenant-attested-batch.sqlite");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("store: {error}"));
    let finding = authoritative_finding();
    let publication = publish_recovery_batch(&store, &[finding]);
    let check = |store: &SqliteSecurityStateStore| {
        let mut key = AttestedFindingBatchKey {
            tenant_id: publication.body.tenant_id.clone(),
            batch_id: publication.body.batch_id.clone(),
        };
        assert_eq!(
            store
                .load_attested_finding_batch(&key)
                .unwrap_or_else(|error| panic!("owned batch: {error}")),
            Some(publication.clone())
        );
        key.tenant_id =
            TenantId::new("foreign-tenant").unwrap_or_else(|error| panic!("tenant: {error}"));
        assert_eq!(
            store
                .load_attested_finding_batch(&key)
                .unwrap_or_else(|error| panic!("foreign batch: {error}")),
            None
        );
        for binding in publication.body.bindings.as_slice() {
            let mut key = chio_security_types::ports::AttestedFindingResponseOutboxKey {
                tenant_id: publication.body.tenant_id.clone(),
                action_id: binding.action_id.clone(),
            };
            assert!(store
                .load_attested_finding_response_outbox(&key)
                .unwrap_or_else(|error| panic!("owned outbox: {error}"))
                .is_some());
            key.tenant_id =
                TenantId::new("foreign-tenant").unwrap_or_else(|error| panic!("tenant: {error}"));
            assert_eq!(
                store
                    .load_attested_finding_response_outbox(&key)
                    .unwrap_or_else(|error| panic!("foreign outbox: {error}")),
                None
            );
        }
    };
    check(&store);
    drop(store);
    check(&SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("reopen: {error}")));
}
