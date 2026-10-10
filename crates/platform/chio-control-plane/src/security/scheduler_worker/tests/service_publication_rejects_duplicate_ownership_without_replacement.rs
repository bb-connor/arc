use super::*;

#[test]
fn service_publication_rejects_duplicate_ownership_without_replacement() {
    let registry = ActiveDefenseServiceRegistry::default();
    let first: Arc<dyn ActiveDefenseServices> = Arc::new(TestServices {
        ready: Mutex::new(true),
    });
    registry
        .publish(Arc::clone(&first))
        .unwrap_or_else(|error| panic!("publish first: {error}"));
    let duplicate: Arc<dyn ActiveDefenseServices> = Arc::new(TestServices {
        ready: Mutex::new(true),
    });

    assert!(matches!(
        registry.publish(duplicate),
        Err(ResponseWorkerTickError::ServicesAlreadyPublished)
    ));
    let installed = registry
        .snapshot()
        .unwrap_or_else(|| panic!("installed services missing"));
    assert!(Arc::ptr_eq(&installed, &first));
}
