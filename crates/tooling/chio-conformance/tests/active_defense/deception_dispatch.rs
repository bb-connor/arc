#[test]
fn canary_pre_dispatch_denial() {
    let mut kernel = ChioKernel::new(kernel_config());
    let subject = Keypair::from_seed(&[65; 32]);
    let capability = kernel
        .issue_capability(&subject.public_key(), scope(), 300)
        .test_expect("issue canary capability");
    let mut invocation = request();
    invocation.agent_id = capability.subject.to_hex();
    invocation.capability = capability;

    let directory = tempdir().test_expect("temporary directory");
    let decoy_store = Arc::new(
        SqliteSealedDecoyRegistryStore::open(directory.path().join("decoys.db"))
            .test_expect("open decoy store"),
    );
    let registry = Arc::new(PrivateDecoyRegistry::new(
        decoy_store,
        Arc::new(DecoyKeys),
        Arc::new(NoDecoyExports),
    ));
    create_and_arm_canary(&registry, invocation.capability.id.as_bytes());
    let detector = Arc::new(DecoyTripwireDetectorPort::decoy_only(
        Arc::new(DecoyDetector::new(registry)),
        Arc::new(FixedClock(1_000)),
    ));
    let events = Arc::new(FailingEvents(AtomicUsize::new(0)));
    let publisher = Arc::new(
        TripwireEventPublisher::new(
            events.clone(),
            Arc::new(FixedClock(1_000)),
            Arc::new(Ed25519Backend::new(tripwire_keypair())),
            ProducerId::new("active-defense-conformance").test_expect("producer id"),
            record("active-defense-conformance-key-v1"),
            record("active-defense-conformance-policy-v1"),
        )
        .test_expect("tripwire event publisher")
        .with_receipt_evidence(Arc::new(ValidatingReceipts), digest(b"tripwire-policy"))
        .test_expect("tripwire receipt evidence"),
    );
    kernel.add_guard(Box::new(TripwireGuard::new(
        detector,
        publisher,
        MissingContextPolicy::Deny,
    )));
    let dispatches = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingServer(dispatches.clone())));

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &invocation,
            &security_context(&invocation),
        )
        .test_expect("kernel canary decision");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(events.0.load(Ordering::SeqCst), 1);
    let evidence = response.receipt.evidence.first().test_expect("tripwire evidence");
    let details = evidence.details.as_deref().test_expect("tripwire details");
    assert!(details.contains("\"event_persistence\":\"failed\""));
}

#[test]
fn honey_tool_pre_dispatch_denial() {
    const FIXTURE_SECRET: &str = "active-defense-fixture-secret-must-not-enter-receipts";

    let mut kernel = ChioKernel::new(kernel_config());
    let subject = Keypair::from_seed(&[66; 32]);
    let capability = kernel
        .issue_capability(&subject.public_key(), scope(), 300)
        .test_expect("issue ordinary capability");
    let mut invocation = request();
    invocation.agent_id = capability.subject.to_hex();
    invocation.capability = capability;
    invocation.arguments = serde_json::json!({
        "batch": 1,
        "fixture_secret": FIXTURE_SECRET,
    });

    let honey_tool_marker = canonical_json_bytes(&serde_json::json!({
        "server_id": invocation.server_id.as_str(),
        "tool_name": invocation.tool_name.as_str(),
    }))
    .test_expect("canonical honey-tool marker");
    assert_eq!(
        honey_tool_marker.as_slice(),
        br#"{"server_id":"server-active-defense","tool_name":"export_records"}"#
    );

    let directory = tempdir().test_expect("temporary directory");
    let decoy_store = Arc::new(
        SqliteSealedDecoyRegistryStore::open(directory.path().join("decoys.db"))
            .test_expect("open decoy store"),
    );
    let registry = Arc::new(PrivateDecoyRegistry::new(
        decoy_store,
        Arc::new(DecoyKeys),
        Arc::new(NoDecoyExports),
    ));
    create_and_arm_decoy(
        &registry,
        "honey-tool-export-records",
        DecoySurface::HoneyTool,
        "active-defense-honey-tool",
        &honey_tool_marker,
    );

    let lookups = Arc::new(Mutex::new(Vec::new()));
    let detector = Arc::new(RecordingTripwireDetector {
        inner: DecoyTripwireDetectorPort::decoy_only(
            Arc::new(DecoyDetector::new(registry)),
            Arc::new(FixedClock(1_000)),
        ),
        lookups: lookups.clone(),
    });
    let events = Arc::new(RecordingEvents(AtomicUsize::new(0)));
    let receipts = Arc::new(SecretScanningReceipts::new(vec![
        honey_tool_marker.clone(),
        FIXTURE_SECRET.as_bytes().to_vec(),
    ]));
    let publisher = Arc::new(
        TripwireEventPublisher::new(
            events.clone(),
            Arc::new(FixedClock(1_000)),
            Arc::new(Ed25519Backend::new(tripwire_keypair())),
            ProducerId::new("active-defense-conformance").test_expect("producer id"),
            record("active-defense-conformance-key-v1"),
            record("active-defense-conformance-policy-v1"),
        )
        .test_expect("tripwire event publisher")
        .with_receipt_evidence(receipts.clone(), digest(b"tripwire-policy"))
        .test_expect("tripwire receipt evidence"),
    );
    kernel.add_guard(Box::new(TripwireGuard::new(
        detector,
        publisher,
        MissingContextPolicy::Deny,
    )));
    let dispatches = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingServer(dispatches.clone())));

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &invocation,
            &security_context(&invocation),
        )
        .test_expect("kernel honey-tool decision");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(
        lookups
            .lock()
            .test_expect("tripwire lookup record")
            .as_slice(),
        &[
            (TripwireKind::CanaryCapability, false),
            (TripwireKind::HoneyTool, true),
        ]
    );
    assert_eq!(events.0.load(Ordering::SeqCst), 1);
    assert_eq!(receipts.appends.load(Ordering::SeqCst), 1);
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
}
