use super::*;


#[test]
fn service_publication_is_atomic_when_replacement_readiness_fails() {
    let registry = ActiveDefenseServiceRegistry::default();
    let first = Arc::new(TestServices {
        ready: Mutex::new(true),
    });
    let first_services: Arc<dyn ActiveDefenseServices> = first.clone();
    registry
        .publish(Arc::clone(&first_services))
        .unwrap_or_else(|error| panic!("publish first: {error}"));
    let replacement = Arc::new(TestServices {
        ready: Mutex::new(false),
    });
    assert!(registry.publish(replacement).is_err());
    let installed = registry
        .snapshot()
        .unwrap_or_else(|| panic!("installed services missing"));
    assert!(Arc::ptr_eq(&installed, &first_services));
}
