use chio_security_types::ports::EffectPort;

use super::*;

struct ObservedBlast {
    inner: Arc<dyn BlastRadiusPort>,
    external_calls: AtomicU64,
}

impl ObservedBlast {
    fn call(&self) {
        self.external_calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl BlastRadiusPort for ObservedBlast {
    fn ensure_blast_radius_ready(&self) -> PortResult<()> {
        self.inner.ensure_blast_radius_ready()
    }
    fn resolve(&self, request: &BlastRadiusRequest) -> PortResult<BlastRadiusResult> {
        self.call();
        self.inner.resolve(request)
    }
    fn acquire_fence(
        &self,
        acquisition: &BlastRadiusFenceAcquisition,
        expected: &LineageFenceRequest,
    ) -> PortResult<LineageFence> {
        self.call();
        self.inner.acquire_fence(acquisition, expected)
    }
    fn query_fence(&self, expected: &LineageFenceRequest) -> PortResult<Option<LineageFence>> {
        self.call();
        self.inner.query_fence(expected)
    }
    fn renew_fence(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
        self.call();
        self.inner.renew_fence(renewal)
    }
    fn takeover_fence(&self, takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        self.call();
        self.inner.takeover_fence(takeover)
    }
    fn release_fence(&self, release: &LineageFenceRelease) -> PortResult<()> {
        self.call();
        self.inner.release_fence(release)
    }
}

fn exercise_preflight(corrupt: bool) {
    let harness = FenceLapseHarness::new();
    let observed = Arc::new(ObservedBlast {
        inner: Arc::clone(&harness.blast),
        external_calls: AtomicU64::new(0),
    });
    let blast: Arc<dyn BlastRadiusPort> = observed.clone();
    let freezes: Arc<dyn IssuanceFreezeStore> = harness.store.clone();
    let authority: Arc<dyn ResponseSchedulerStore> = harness.store.clone();
    let clock: Arc<dyn Clock> = harness.clock.clone();
    let backend = IssuanceFreezeBackend::new_with_scheduler(freezes, blast, Arc::clone(&authority))
        .with_clock(clock);
    let effects = ActiveResponseEffectPort::from_backends(vec![
        Arc::new(backend) as Arc<dyn ResponseEffectBackend>
    ])
    .unwrap_or_else(|error| panic!("observed real router: {error}"))
    .with_plan_authority(authority);
    let planned = &harness.plan.effects.as_slice()[0];
    let apply = EffectRequest {
        tenant_id: tenant(),
        action_id: action(),
        plan_hash: harness.plan.plan_hash,
        effect_id: planned.effect_id.clone(),
        effect_kind: planned.kind,
        target: planned.target.clone(),
        plan_expires_at_unix_ms: harness.plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record("response_effect_command:preflight-original-apply"),
        expected_version_hash: planned.observed_base_version_hash,
        scheduler_lease_owner_id: harness.initial_work.lease_owner_id.clone(),
        scheduler_fencing_token: harness.initial_work.fencing_token,
        canonical_contribution: planned.canonical_contribution.clone(),
        contribution_hash: planned.contribution_hash,
    };
    let applied = effects
        .execute(&apply)
        .unwrap_or_else(|error| panic!("real original Apply: {error}"));
    assert!(applied.applied);
    assert!(
        observed.external_calls.load(Ordering::SeqCst) > 0,
        "the observer delegated real acquisition"
    );
    let mut remove = apply.clone();
    remove.operation = EffectOperation::Remove;
    remove.expected_version_hash = applied.resulting_version_hash;
    remove.idempotency_key = record("response_effect_command:preflight-original-remove");
    assert!(
        !effects
            .execute(&remove)
            .unwrap_or_else(|error| panic!("real completed Remove: {error}"))
            .applied
    );
    assert!(harness.local_contributions().is_empty());
    assert_eq!(harness.external_fence(), None);
    if corrupt {
        let connection =
            rusqlite::Connection::open(harness._directory.path().join("fence-lapse.db"))
                .unwrap_or_else(|error| panic!("open witness corruption fixture: {error}"));
        assert_eq!(connection.execute(
            "UPDATE security_issuance_freeze_commands SET result_body_hash = ?1 WHERE tenant_id = ?2 AND idempotency_key = ?3",
            rusqlite::params![vec![0xA5_u8;32], remove.tenant_id.as_str(), remove.idempotency_key.as_str()],
        ).unwrap_or_else(|error| panic!("corrupt only the genuine Remove evidence: {error}")), 1);
    }
    let before = raw_freeze_state(&harness);
    observed.external_calls.store(0, Ordering::SeqCst);
    let mut fresh = apply;
    fresh.idempotency_key = record("response_effect_command:preflight-fresh-apply");
    let error = effects
        .execute(&fresh)
        .err()
        .unwrap_or_else(|| panic!("fresh Apply ignored removal evidence"));
    let expected = if corrupt {
        PortErrorKind::IntegrityFailure
    } else {
        PortErrorKind::Conflict
    };
    let code = if corrupt {
        "store.integrity_failure"
    } else {
        "store.conflict"
    };
    assert_eq!(error.kind(), expected);
    assert_eq!(error.code().as_str(), code);
    assert_eq!(
        observed.external_calls.load(Ordering::SeqCst),
        0,
        "completed-removal classification must precede every external query/acquire/release"
    );
    assert_eq!(raw_freeze_state(&harness), before);
    assert!(harness.local_contributions().is_empty());
    assert_eq!(harness.external_fence(), None);
}

#[test]
fn completed_removal_refuses_fresh_apply_before_any_external_fence_call() {
    exercise_preflight(false);
}

#[test]
fn corrupt_completed_removal_refuses_before_any_external_fence_call() {
    exercise_preflight(true);
}
