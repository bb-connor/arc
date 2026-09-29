use super::*;

#[test]
fn service_publication_rechecks_readiness_at_commit_time() {
    let registry = ActiveDefenseServiceRegistry::default();
    let services = Arc::new(SequencedServices {
        readiness: Mutex::new(VecDeque::from([true, true, false])),
    });
    assert!(registry.publish(services).is_err());
    assert!(registry.snapshot().is_none());
}
