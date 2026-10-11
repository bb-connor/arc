use super::*;
use crate::security::{
    ProductionActiveDefenseBuildError, ProductionActiveDefenseHostError, ResponseWorkerTickError,
};

const OUTAGE_RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);

struct ToggleablePolicyPlanner {
    ready: AtomicBool,
}

impl ToggleablePolicyPlanner {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(true),
        }
    }

    fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }
}

impl AttestedFindingResponsePolicyPlanner for ToggleablePolicyPlanner {
    fn ensure_ready(&self) -> PortResult<()> {
        if self.ready.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(PortError::unavailable())
        }
    }
}

fn fixture_with_planner() -> (HostFixture, Arc<ToggleablePolicyPlanner>) {
    let mut fixture = HostFixture::new();
    let planner = Arc::new(ToggleablePolicyPlanner::new());
    fixture.config.response_policy_planner = planner.clone();
    (fixture, planner)
}

#[tokio::test]
async fn teardown_recovery_worker_lifts_an_expired_overlay_while_planning_is_unavailable() {
    let (fixture, planner) = fixture_with_planner();
    let expires_at_unix_ms = fixture.install_ttl_containment_plan();
    let host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    assert!(fixture.has_active_overlay_contributions());
    let primary = Arc::clone(host.orchestrator().worker());
    fixture.clock.panic_on_next_worker_read();
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while primary.health().lifecycle != ResponseWorkerLifecycle::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("primary worker did not crash"));

    planner.set_ready(false);
    let outage = ActiveDefenseServices::ensure_bootstrap_ready(host.orchestrator().as_ref());
    assert!(
        matches!(
            &outage,
            Err(ResponseWorkerTickError::Port(error)) if error.kind() == PortErrorKind::Unavailable
        ),
        "planning outage is not in effect when teardown starts: {outage:?}"
    );
    fixture.clock.set(expires_at_unix_ms.saturating_add(1));
    drop(host);
    let lifted = tokio::time::timeout(OUTAGE_RECOVERY_TIMEOUT, async {
        while fixture.has_active_overlay_contributions() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    let vacant = tokio::time::timeout(
        OUTAGE_RECOVERY_TIMEOUT,
        fixture.registry.wait_until_vacant(),
    )
    .await
    .is_ok_and(|vacancy| vacancy.is_ok());
    // Restore planning even when the regression fails so the retained
    // teardown finishes and does not hold the shared teardown supervisor.
    planner.set_ready(true);
    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        fixture.registry.wait_until_vacant(),
    )
    .await
    .unwrap_or_else(|_| panic!("teardown did not finish after planning recovered"))
    .unwrap_or_else(|error| panic!("wait for registry reclamation: {error}"));

    assert!(
        lifted,
        "no recovery worker started while planning was unavailable; the expired overlay outlived its TTL"
    );
    assert!(
        vacant,
        "teardown did not finish while planning was unavailable"
    );
    assert!(!fixture.has_active_overlay_contributions());
}

#[tokio::test]
async fn planning_outage_keeps_runtime_admission_and_host_start_closed() {
    let (fixture, planner) = fixture_with_planner();
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    planner.set_ready(false);

    let readiness = host.ensure_ready();
    let before = fixture.security_event_count();
    let consumed = host.consume(&unverified_event("planning-outage-event"));
    let after = fixture.security_event_count();
    planner.set_ready(true);
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));
    drop(host);
    planner.set_ready(false);
    let restarted =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await;
    planner.set_ready(true);

    assert!(
        matches!(
            readiness,
            Err(ProductionActiveDefenseHostError::Worker(
                ResponseWorkerTickError::RuntimeAdmissionClosed
            ))
        ),
        "planning outage must close runtime admission: {readiness:?}"
    );
    let consume_error = match consumed {
        Ok(report) => panic!("planning outage admitted event consumption: {report:?}"),
        Err(error) => error,
    };
    assert_eq!(consume_error.kind(), PortErrorKind::Unavailable);
    assert_eq!(after, before);
    match restarted {
        Ok(_) => panic!("host started while planning was unavailable"),
        Err(ProductionActiveDefenseHostError::Build(ProductionActiveDefenseBuildError::Port(
            error,
        ))) => assert_eq!(error.kind(), PortErrorKind::Unavailable),
        Err(error) => panic!("host start failed for the wrong reason: {error}"),
    }
    assert!(fixture.registry.snapshot().is_none());
}
