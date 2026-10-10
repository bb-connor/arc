use super::*;

async fn invoke_raw_peer(
    binding: A2aProtocolBinding,
    payload: &str,
    registry_path: Option<&std::path::Path>,
) -> Result<Value, AdapterError> {
    ensure_rustls_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let mut card = local_test_adapter(A2aAgentCapabilities::default(), binding, None).agent_card;
    card.supported_interfaces = vec![A2aAgentInterface {
        url: base_url.clone(),
        protocol_binding: match binding {
            A2aProtocolBinding::JsonRpc => "JSONRPC",
            A2aProtocolBinding::HttpJson => "HTTP+JSON",
        }
        .into(),
        protocol_version: "1.0".into(),
        tenant: None,
    }];
    let payload = match binding {
        A2aProtocolBinding::JsonRpc => format!(r#"{{"jsonrpc":"2.0","result":{payload}}}"#),
        A2aProtocolBinding::HttpJson => payload.to_owned(),
    };
    let handle = thread::spawn(move || {
        for body in [serde_json::to_string(&card).unwrap(), payload] {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "peer request not received"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("peer listener: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _request = read_http_request(&mut socket);
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        }
    });
    let mut config = test_adapter_config(&base_url, Keypair::generate().public_key().to_hex());
    if let Some(path) = registry_path {
        config = config.with_task_registry_file(path);
    }
    let adapter = A2aAdapter::discover(config).unwrap();
    let result = adapter.invoke_skill(
        "research",
        &adapter.agent_card.skills[0],
        json!({"message":"numbers"}),
        None,
    );
    handle.join().unwrap();
    result
}

#[tokio::test]
async fn unsigned_http_peer_numbers_survive_both_bindings() {
    let payload = r#"{"message":{"messageId":"reply","role":"ROLE_AGENT","parts":[{"data":{"ratio":0.50,"whole":21.0,"small":1e-05,"wide":18446744073709551615}}]}}"#;
    for binding in [A2aProtocolBinding::JsonRpc, A2aProtocolBinding::HttpJson] {
        let result = invoke_raw_peer(binding, payload, None).await.unwrap();
        let data = &result["message"]["parts"][0]["data"];
        assert_eq!(data["ratio"].as_f64(), Some(0.5));
        assert_eq!(data["whole"].as_f64(), Some(21.0));
        assert_eq!(data["small"].as_f64(), Some(0.00001));
        assert_eq!(data["wide"].as_u64(), Some(u64::MAX));
    }
}

#[tokio::test]
async fn unsigned_http_peer_nested_duplicates_still_reject() {
    let payload = r#"{"message":{"messageId":"reply","role":"ROLE_AGENT","parts":[{"data":{"ratio":1,"ratio":2}}]}}"#;
    for binding in [A2aProtocolBinding::JsonRpc, A2aProtocolBinding::HttpJson] {
        assert!(matches!(
            invoke_raw_peer(binding, payload, None).await,
            Err(AdapterError::UntrustedInput(
                chio_core::canonical::UntrustedJsonError::SignedInput(_)
            ))
        ));
    }
}

#[tokio::test]
async fn unsigned_http_task_numbers_preserve_registry_reopen() {
    let payload = r#"{"task":{"id":"task-numbers","status":{"state":"TASK_STATE_COMPLETED"},"artifacts":[{"artifactId":"artifact","parts":[{"data":{"ratio":0.50,"whole":1.0,"small":1e-05}}]}]}}"#;
    for binding in [A2aProtocolBinding::JsonRpc, A2aProtocolBinding::HttpJson] {
        let path = unique_path("a2a-unsigned-task-reopen", ".json");
        let output = invoke_raw_peer(binding, payload, Some(&path))
            .await
            .unwrap();
        assert_eq!(
            output["task"]["artifacts"][0]["parts"][0]["data"]["ratio"].as_f64(),
            Some(0.5)
        );
        let restored = A2aTaskRegistry::open(&path).unwrap().load().unwrap();
        assert_eq!(restored.tasks.len(), 1);
        let task = &restored.tasks["task-numbers"];
        assert_eq!(task.task_id, "task-numbers");
        assert_eq!(task.last_state.as_deref(), Some("TASK_STATE_COMPLETED"));
        assert!(task.first_seen_at <= task.last_seen_at);
        fs::remove_file(path).unwrap();
    }
}
