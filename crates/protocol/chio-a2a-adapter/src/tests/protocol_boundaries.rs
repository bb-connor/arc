use super::*;

struct ProtocolClock(
    std::sync::Mutex<
        Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>,
    >,
);
impl ProtocolClock {
    fn new() -> Self {
        Self(std::sync::Mutex::new(Ok(Self::at(0))))
    }
    fn at(elapsed: u64) -> chio_security_types::clock::ClockReading {
        use chio_security_types::clock::*;
        ClockReading::new(
            UnixMillis::new(1_700_000_000_000 + elapsed),
            MonotonicInstant::from_nanos(elapsed * 1_000_000),
        )
    }
    fn advance(&self, elapsed: u64) {
        *self.0.lock().unwrap() = Ok(Self::at(elapsed));
    }
    fn fail(&self) {
        *self.0.lock().unwrap() = Err(chio_security_types::clock::ClockError::Unavailable);
    }
}
impl chio_security_types::clock::Clock for ProtocolClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        *self.0.lock().unwrap()
    }
}

#[test]
fn protocol_boundary_oauth_deadlines_are_finite_checked_and_fault_sensitive() {
    let server = FakeA2aServer::spawn_http_json().expect("local test server");
    let clock = Arc::new(ProtocolClock::new());
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), Keypair::generate().public_key().to_hex())
            .with_clock(clock.clone()),
    )
    .expect("discover");
    let started = clock.read().unwrap();
    adapter
        .store_cached_bearer_token("key".into(), "secret".into(), Some(31), started)
        .unwrap();
    assert_eq!(
        adapter
            .lookup_cached_bearer_token("key")
            .unwrap()
            .as_deref(),
        Some("secret")
    );
    clock.fail();
    assert!(matches!(
        adapter.lookup_cached_bearer_token("key"),
        Err(AdapterError::Clock(ClockError::Unavailable))
    ));
    clock.advance(1_000);
    assert_eq!(adapter.lookup_cached_bearer_token("key").unwrap(), None);
    assert!(matches!(
        adapter.store_cached_bearer_token("key".into(), "secret".into(), Some(u64::MAX), started),
        Err(AdapterError::Clock(ClockError::Overflow))
    ));
    assert!(adapter.token_cache.lock().unwrap().is_empty());
    // A delayed response may not start a fresh full lifetime at insertion.
    adapter
        .store_cached_bearer_token("key".into(), "secret".into(), Some(31), started)
        .unwrap();
    assert!(adapter.token_cache.lock().unwrap().is_empty());
}

#[test]
fn protocol_boundary_registry_refuses_ambiguous_and_substituted_records() {
    let path = unique_path("protocol-registry", ".json");
    fs::write(
        &path,
        br#"{"version":"chio.a2a-task-registry.v1","tasks":{},"tasks":{}}"#,
    )
    .unwrap();
    assert!(matches!(
        A2aTaskRegistry::open(&path),
        Err(AdapterError::UntrustedInput(
            chio_core::canonical::UntrustedJsonError::SignedInput(_)
        ))
    ));
    let record = json!({"taskId":"other", "toolName":"read", "serverId":"server", "interfaceUrl":"https://example.com", "protocolBinding":"JSONRPC", "partner":"peer", "firstSeenAt":10, "lastSeenAt":11, "lastSource":"stream"});
    fs::write(
        &path,
        serde_json::to_vec(&json!({"version":TASK_REGISTRY_VERSION,"tasks":{"task":record}}))
            .unwrap(),
    )
    .unwrap();
    assert!(
        matches!(A2aTaskRegistry::open(&path), Err(AdapterError::Lifecycle(reason)) if reason == "task registry identity or time mismatch")
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn protocol_boundary_sse_duplicate_fields_never_reach_decoder() {
    let mut chunks = Vec::new();
    let mut terminal = false;
    let mut lines = vec![r#"{"task":{"id":"one","id":"two"}}"#.into()];
    let error = process_sse_event(&mut chunks, &mut terminal, &mut lines, &mut 0, &|_| {
        panic!("untrusted event reached decoder")
    })
    .unwrap_err();
    assert!(matches!(
        error,
        AdapterError::UntrustedInput(chio_core::canonical::UntrustedJsonError::SignedInput(_))
    ));
    assert!(chunks.is_empty());
}
