use super::*;


#[test]
fn service_publication_can_precede_operational_kernel_binding() {
    let registry = ActiveDefenseServiceRegistry::default();
    let services: Arc<dyn ActiveDefenseServices> = Arc::new(BootstrapOnlyServices);
    registry
        .publish(Arc::clone(&services))
        .unwrap_or_else(|error| panic!("publish bootstrap-ready services: {error}"));
    let installed = registry
        .snapshot()
        .unwrap_or_else(|| panic!("bootstrap-ready services are missing"));
    assert!(Arc::ptr_eq(&installed, &services));
    assert!(installed.ensure_ready().is_err());
}
