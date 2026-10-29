use super::*;

fn default_request_auth() -> A2aResolvedRequestAuth {
    A2aResolvedRequestAuth {
        headers: Vec::new(),
        query_params: Vec::new(),
        cookies: Vec::new(),
        tls_mode: A2aTlsMode::Default,
    }
}

#[test]
fn config_debug_output_redacts_credentials_and_private_keys() {
    let materials = generate_mtls_test_materials();
    let config = A2aAdapterConfig::new("https://agent.example", "public-key-hex")
        .with_bearer_token("bearer-secret-value")
        .with_api_key_header("X-Api-Key", "header-secret-value")
        .with_api_key_query_param("api_key", "query-secret-value")
        .with_api_key_cookie("session", "cookie-secret-value")
        .with_oauth_client_credentials("client-id", "client-secret-value")
        .with_mtls_client_auth_pem(
            materials.client_cert_chain_pem.clone(),
            materials.client_private_key_pem.clone(),
        );
    let cached = A2aCachedBearerToken {
        cache_key: "cache-key".to_string(),
        access_token: "access-token-secret-value".to_string(),
        deadline: AuthorityDeadline::for_timeout_ms(
            ClockReading::new(
                chio_security_types::clock::UnixMillis::new(1_700_000_000_000),
                chio_security_types::clock::MonotonicInstant::from_nanos(0),
            ),
            60_000,
        )
        .expect("deadline"),
    };
    let rendered = format!("{config:?} {cached:?}");
    let key_body = materials
        .client_private_key_pem
        .lines()
        .find(|line| !line.starts_with("-----") && !line.is_empty())
        .expect("key body line");
    for secret in [
        "bearer-secret-value",
        "header-secret-value",
        "query-secret-value",
        "cookie-secret-value",
        "client-secret-value",
        "access-token-secret-value",
        "PRIVATE KEY",
        key_body,
    ] {
        assert!(!rendered.contains(secret), "Debug output exposes {secret}");
    }
    assert!(rendered.contains("client-id"));
    assert!(rendered.contains("X-Api-Key"));
}

#[test]
fn error_statuses_report_only_the_status() {
    let Some(listener) = bind_fake_a2a_listener("error status listener") else {
        return;
    };
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let _ = read_http_request(&mut stream);
        let body = "upstream-detail-that-must-not-surface";
        write!(
            stream,
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("write 400");
    });
    let transport_config = A2aTransportConfig {
        default_tls_config: None,
        mutual_tls_config: None,
        egress_contract: Some(test_egress_contract(&base_url)),
    };
    let url = Url::parse(&format!("{base_url}/card")).expect("url");
    let error = fetch_json::<Value>(
        &url,
        &default_request_auth(),
        Duration::from_secs(2),
        &transport_config,
    )
    .expect_err("400 is an error");
    handle.join().expect("join status server");
    assert!(
        matches!(&error, AdapterError::Remote(message) if message == "HTTP 400"),
        "{error:?}"
    );
}

#[test]
fn a_mutual_tls_request_refuses_a_cross_origin_redirect() {
    let Some(target) = bind_fake_a2a_listener("cross-origin target listener") else {
        return;
    };
    target.set_nonblocking(true).expect("nonblocking target");
    let target_base_url = format!("http://{}", target.local_addr().expect("target address"));
    let Some(initial) = bind_fake_a2a_listener("cross-origin initial listener") else {
        return;
    };
    let initial_base_url = format!("http://{}", initial.local_addr().expect("initial address"));
    let location = format!("{target_base_url}/card");
    let handle = thread::spawn(move || {
        let (mut stream, _) = initial.accept().expect("accept request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let _ = read_http_request(&mut stream);
        write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write redirect");
    });

    let materials = generate_mtls_test_materials();
    let identity = ClientIdentityPem {
        cert_chain_pem: &materials.client_cert_chain_pem,
        private_key_pem: &materials.client_private_key_pem,
    };
    let mutual_tls_config =
        BlockingContractTls::from_pem(std::slice::from_ref(&materials.root_ca_pem), Some(identity))
            .expect("mutual TLS config");
    let mut contract = test_egress_contract(&initial_base_url);
    insert_test_egress_authority(&mut contract, &target_base_url);
    let transport_config = A2aTransportConfig {
        default_tls_config: None,
        mutual_tls_config: Some(mutual_tls_config),
        egress_contract: Some(contract),
    };
    let request_auth = A2aResolvedRequestAuth {
        tls_mode: A2aTlsMode::MutualTls,
        ..default_request_auth()
    };
    let url = Url::parse(&format!("{initial_base_url}/card")).expect("url");
    let error = fetch_json::<Value>(
        &url,
        &request_auth,
        Duration::from_secs(2),
        &transport_config,
    )
    .expect_err("a client identity is not carried to another authority");
    handle.join().expect("join redirect server");
    assert!(
        matches!(target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "the redirect target was dialed: {error:?}"
    );
}

fn plain_transport(base_url: &str) -> A2aTransportConfig {
    A2aTransportConfig {
        default_tls_config: None,
        mutual_tls_config: None,
        egress_contract: Some(test_egress_contract(base_url)),
    }
}

/// Answers one request with `head` and then writes `chunk` until the client
/// goes away, reporting how many body bytes it managed to write.
fn serve_endless_body(
    listener: TcpListener,
    head: &'static str,
    chunk: Vec<u8>,
) -> thread::JoinHandle<u64> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("set write timeout");
        let _ = read_http_request(&mut stream);
        if stream.write_all(head.as_bytes()).is_err() {
            return 0;
        }
        let mut written = 0_u64;
        while stream.write_all(&chunk).is_ok() {
            written += chunk.len() as u64;
        }
        written
    })
}

#[test]
fn a_held_open_event_stream_completes_at_its_terminal_event() {
    let Some(listener) = bind_fake_a2a_listener("held-open SSE listener") else {
        return;
    };
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let (release, released) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let _ = read_http_request(&mut stream);
        let body = http_stream_body(TestScenario::StreamingComplete);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n",
            body.len()
        )
        .expect("write terminal event");
        stream.flush().expect("flush terminal event");
        let _ = released.recv_timeout(Duration::from_secs(20));
    });
    let url = Url::parse(&format!("{base_url}/tasks/task-1:subscribe")).expect("url");
    let outcome = get_sse(
        &url,
        &default_request_auth(),
        Duration::from_secs(3),
        &plain_transport(&base_url),
        Ok,
    );
    let _ = release.send(());
    handle.join().expect("join held-open server");
    match outcome {
        Ok(ToolServerStreamResult::Complete(stream)) => assert_eq!(stream.chunks.len(), 3),
        other => panic!("expected completion at the terminal event, got {other:?}"),
    }
}

#[test]
fn an_endless_event_stream_is_cut_off_at_the_protocol_ceiling() {
    let Some(listener) = bind_fake_a2a_listener("endless SSE listener") else {
        return;
    };
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let mut line = b": ".to_vec();
    line.resize(1023, b'a');
    line.push(b'\n');
    let server = serve_endless_body(
        listener,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
        line.repeat(64),
    );
    let url = Url::parse(&format!("{base_url}/tasks/task-1:subscribe")).expect("url");
    let outcome = get_sse(
        &url,
        &default_request_auth(),
        Duration::from_secs(10),
        &plain_transport(&base_url),
        Ok,
    );
    let written = server.join().expect("join endless server");
    assert!(outcome.is_err(), "{outcome:?}");
    assert!(
        written < 16 * 1024 * 1024,
        "the client read {written} bytes past a 1 MiB stream ceiling"
    );
}

#[test]
fn an_endless_json_body_is_cut_off_at_the_protocol_ceiling() {
    let Some(listener) = bind_fake_a2a_listener("endless JSON listener") else {
        return;
    };
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let server = serve_endless_body(
        listener,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n[",
        b"0,".repeat(32 * 1024),
    );
    let url = Url::parse(&format!("{base_url}/card")).expect("url");
    let outcome = fetch_json::<Value>(
        &url,
        &default_request_auth(),
        Duration::from_secs(10),
        &plain_transport(&base_url),
    );
    let written = server.join().expect("join endless server");
    assert!(outcome.is_err(), "{outcome:?}");
    assert!(
        written < 40 * 1024 * 1024,
        "the client read {written} bytes past a 16 MiB JSON ceiling"
    );
}
