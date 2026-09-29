use super::*;


#[test]
fn alert_and_throttle_are_probed_but_cannot_make_an_incomplete_router_ready() {
    let alerts = Arc::new(RecordingAlertStore::default());
    let alert_store: Arc<dyn EscalateAlertStore> = alerts.clone();
    let alert_backend: Arc<dyn ResponseEffectBackend> =
        Arc::new(EscalateAlertBackend::new(alert_store));
    let overlays = Arc::new(RecordingOverlayStore::default());
    let suspension_backend: Arc<dyn ResponseEffectBackend> =
        Arc::new(SessionSuspensionOverlayBackend::new(overlays.clone()));
    let throttles = Arc::new(RecordingThrottleStore::default());
    let throttle_store: Arc<dyn SessionThrottleStore> = throttles.clone();
    let throttle_backend: Arc<dyn ResponseEffectBackend> =
        Arc::new(SessionThrottleBackend::new(throttle_store));
    let router = ActiveResponseEffectPort::from_backends(vec![
        alert_backend,
        throttle_backend,
        suspension_backend,
    ])
    .unwrap_or_else(|error| panic!("partial alert router: {error}"));
    assert_eq!(
        require_error(router.ensure_effects_ready()).kind(),
        PortErrorKind::Unavailable
    );
    assert!(alerts.counts().2 > 0, "alert backend was not probed");
    assert!(throttles.counts().2 > 0, "throttle backend was not probed");
    assert!(overlays.counts().2 > 0, "overlay backend was not probed");
}
