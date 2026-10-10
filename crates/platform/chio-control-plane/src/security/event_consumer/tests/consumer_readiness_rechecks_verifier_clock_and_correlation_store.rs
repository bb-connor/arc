use super::*;

#[test]
fn consumer_readiness_rechecks_verifier_clock_and_correlation_store() {
    let keypair = Keypair::from_seed(&[82_u8; 32]);
    let clock = Arc::new(ToggleClock {
        ready: AtomicBool::new(true),
        now_unix_ms: 10_000,
    });
    let verifier = Arc::new(
        NativeSecurityEventVerifier::new(
            Arc::clone(&clock) as Arc<dyn Clock>,
            vec![TrustedSecurityEventProducer {
                tenant_id: tenant(),
                producer_id: producer(),
                producer_key_id: record("detector-key-v1"),
                policy_version: record("policy-v1"),
                producer_key: keypair.public_key(),
            }],
            Vec::new(),
            60_000,
            1_000,
        )
        .unwrap_or_else(|error| panic!("verifier: {error}")),
    );
    let correlation_ready = Arc::new(AtomicBool::new(true));
    let consumer = ProductionCorrelationConsumer::from_parts(
        verifier,
        Arc::new(ToggleCorrelation {
            ready: Arc::clone(&correlation_ready),
        }),
        Arc::new(FailSecondAttestation {
            calls: Mutex::new(0),
        }),
        Arc::new(RecordingPlanner::default()),
    )
    .unwrap_or_else(|error| panic!("consumer: {error}"));

    clock.ready.store(false, Ordering::Release);
    assert!(consumer.ensure_ready().is_err());
    clock.ready.store(true, Ordering::Release);
    correlation_ready.store(false, Ordering::Release);
    assert!(consumer.ensure_ready().is_err());
}
