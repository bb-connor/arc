use super::*;

#[test]
fn global_readiness_probes_installed_backend_but_rejects_incomplete_matrix() {
    let store = Arc::new(RecordingOverlayStore::default());
    let port = port(Arc::clone(&store));
    let error = require_error(port.ensure_effects_ready());
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert!(store.counts().2 > 0, "installed backend was not probed");

    store.fail_reads();
    let unavailable = require_error(port.ensure_effects_ready());
    assert_eq!(unavailable.kind(), PortErrorKind::Unavailable);
}
