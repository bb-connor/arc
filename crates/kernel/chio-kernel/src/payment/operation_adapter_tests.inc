fn operation_authorize_request(
    operation_id: &str,
    request_binding_hash: &str,
) -> PaymentAuthorizeRequest {
    PaymentAuthorizeRequest {
        operation_id: Some(operation_id.to_string()),
        request_binding_hash: Some(request_binding_hash.to_string()),
        amount_units: 125,
        currency: "USD".to_string(),
        payer: "agent-operation".to_string(),
        payee: "tool-operation".to_string(),
        reference: "request-operation".to_string(),
        governed: None,
        commerce: None,
    }
}

#[test]
fn x402_operation_authorize_posts_and_attests_exact_binding() {
    let operation_id = "x402-operation";
    let request_binding_hash = "ab".repeat(32);
    let (url, request_rx, handle) = spawn_once_json_server(
        200,
        serde_json::json!({
            "authorizationId": "x402-operation-authorization",
            "operationId": operation_id,
            "requestBindingHash": request_binding_hash,
            "settled": true,
            "metadata": { "network": "base" }
        }),
    );
    let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

    let authorization = adapter
        .authorize_for_operation(
            operation_id,
            &request_binding_hash,
            &operation_authorize_request(operation_id, &request_binding_hash),
        )
        .expect("operation-owned x402 authorization");

    let request = request_rx.recv().expect("operation request");
    assert!(request.contains(&format!("\"operationId\":\"{operation_id}\"")));
    assert!(request.contains(&format!(
        "\"requestBindingHash\":\"{request_binding_hash}\""
    )));
    assert_eq!(authorization.metadata["operationId"], operation_id);
    assert_eq!(
        authorization.metadata["requestBindingHash"],
        request_binding_hash
    );
    handle.join().expect("x402 operation server");
}

#[test]
fn acp_operation_lookup_uses_exact_binding_and_null_proves_absence() {
    let operation_id = "acp-operation";
    let request_binding_hash = "cd".repeat(32);
    let (url, request_rx, handle) = spawn_once_json_server(
        200,
        serde_json::json!({
            "authorizationId": "acp-operation-authorization",
            "operationId": operation_id,
            "requestBindingHash": request_binding_hash,
            "settled": false,
            "metadata": { "provider": "stripe" }
        }),
    );
    let adapter = AcpPaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

    let authorization = adapter
        .lookup_authorization_for_operation(operation_id, &request_binding_hash)
        .expect("operation-owned ACP lookup")
        .expect("existing ACP authorization");
    let request = request_rx.recv().expect("operation lookup request");
    assert!(request.starts_with("POST /authorize/lookup HTTP/1.1"));
    assert!(request.contains(&format!("\"operationId\":\"{operation_id}\"")));
    assert_eq!(authorization.metadata["operationId"], operation_id);
    assert_eq!(
        authorization.metadata["requestBindingHash"],
        request_binding_hash
    );
    handle.join().expect("ACP lookup server");

    let (url, _request_rx, handle) = spawn_once_json_server(200, serde_json::Value::Null);
    let adapter = AcpPaymentAdapter::new(url).with_timeout(Duration::from_secs(2));
    assert!(adapter
        .lookup_authorization_for_operation(operation_id, &request_binding_hash)
        .expect("authoritative absence")
        .is_none());
    handle.join().expect("ACP absent lookup server");

    let (url, _request_rx, handle) = spawn_once_json_server(
        404,
        serde_json::json!({ "error": "lookup endpoint unavailable" }),
    );
    let adapter = AcpPaymentAdapter::new(url).with_timeout(Duration::from_secs(2));
    assert!(adapter
        .lookup_authorization_for_operation(operation_id, &request_binding_hash)
        .is_err());
    handle.join().expect("ACP unavailable lookup server");
}

#[test]
fn operation_lookup_rejects_rebound_rail_metadata() {
    let operation_id = "x402-rebound-operation";
    let request_binding_hash = "ef".repeat(32);
    let (url, _request_rx, handle) = spawn_once_json_server(
        200,
        serde_json::json!({
            "authorizationId": "x402-rebound-authorization",
            "operationId": operation_id,
            "requestBindingHash": request_binding_hash,
            "settled": true,
            "metadata": {
                "operationId": "different-operation",
                "requestBindingHash": request_binding_hash
            }
        }),
    );
    let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

    let error = adapter
        .lookup_authorization_for_operation(operation_id, &request_binding_hash)
        .expect_err("rebound rail metadata must fail closed");
    assert!(error.to_string().contains("mismatched operation metadata"));
    handle.join().expect("x402 rebound lookup server");
}

#[test]
fn operation_settlement_state_is_derived_from_authoritative_lookup() {
    let operation_id = "x402-settlement-operation";
    let request_binding_hash = "12".repeat(32);
    let (url, request_rx, handle) = spawn_once_json_server(
        200,
        serde_json::json!({
            "authorizationId": "x402-settlement-authorization",
            "operationId": operation_id,
            "requestBindingHash": request_binding_hash,
            "settled": true,
            "metadata": {}
        }),
    );
    let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

    let state = adapter
        .settlement_state_for_operation(
            operation_id,
            &request_binding_hash,
            "x402-settlement-reference",
            Some("x402-settlement-authorization"),
        )
        .expect("operation settlement lookup");
    let request = request_rx.recv().expect("operation settlement request");
    assert!(request.starts_with("POST /authorize/lookup HTTP/1.1"));
    match state {
        RailSettlementState::Settled {
            authorization_id,
            result,
        } => {
            assert_eq!(authorization_id, "x402-settlement-authorization");
            assert_eq!(result.transaction_id, authorization_id);
            assert_eq!(result.metadata["operationId"], operation_id);
            assert_eq!(
                result.metadata["requestBindingHash"],
                request_binding_hash
            );
        }
        other => panic!("expected settled operation state, got {other:?}"),
    }
    handle.join().expect("x402 settlement lookup server");

    let (url, _request_rx, handle) = spawn_once_json_server(
        200,
        serde_json::json!({
            "authorizationId": "acp-held-authorization",
            "operationId": "acp-held-operation",
            "requestBindingHash": "34".repeat(32),
            "settled": false,
            "metadata": {}
        }),
    );
    let adapter = AcpPaymentAdapter::new(url).with_timeout(Duration::from_secs(2));
    assert!(matches!(
        adapter
            .settlement_state_for_operation(
                "acp-held-operation",
                &"34".repeat(32),
                "acp-held-reference",
                Some("acp-held-authorization"),
            )
            .expect("held operation lookup"),
        RailSettlementState::Held { authorization_id }
            if authorization_id == "acp-held-authorization"
    ));
    handle.join().expect("ACP held lookup server");
}

#[test]
fn operation_authorize_lost_ack_recovers_through_exact_lookup() {
    let operation_id = "x402-lost-ack-operation";
    let request_binding_hash = "56".repeat(32);
    let (url, request_rx, handle) = spawn_json_sequence_server(vec![
        None,
        Some((
            200,
            serde_json::json!({
                "authorizationId": "x402-lost-ack-authorization",
                "operationId": operation_id,
                "requestBindingHash": request_binding_hash,
                "settled": true,
                "metadata": {}
            }),
        )),
    ]);
    let adapter = X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2));
    let authorize_request = operation_authorize_request(operation_id, &request_binding_hash);

    assert!(matches!(
        adapter.authorize_for_operation(
            operation_id,
            &request_binding_hash,
            &authorize_request,
        ),
        Err(PaymentError::Unavailable(_))
    ));
    let recovered = adapter
        .lookup_authorization_for_operation(operation_id, &request_binding_hash)
        .expect("authoritative recovery lookup")
        .expect("committed authorization");
    assert_eq!(
        recovered.authorization_id,
        "x402-lost-ack-authorization"
    );

    let authorize_http = request_rx.recv().expect("authorize request");
    let lookup_http = request_rx.recv().expect("lookup request");
    assert!(authorize_http.starts_with("POST /authorize HTTP/1.1"));
    assert!(authorize_http.contains(&format!("\"operationId\":\"{operation_id}\"")));
    assert!(authorize_http.contains(&format!(
        "\"requestBindingHash\":\"{request_binding_hash}\""
    )));
    assert!(lookup_http.starts_with("POST /authorize/lookup HTTP/1.1"));
    assert!(lookup_http.contains(&format!("\"operationId\":\"{operation_id}\"")));
    assert!(lookup_http.contains(&format!(
        "\"requestBindingHash\":\"{request_binding_hash}\""
    )));
    handle.join().expect("lost-ack recovery server");
}

#[test]
fn operation_authorize_rejects_mismatched_rail_echo() {
    let operation_id = "acp-echo-operation";
    let request_binding_hash = "78".repeat(32);
    let (url, _request_rx, handle) = spawn_once_json_server(
        200,
        serde_json::json!({
            "authorizationId": "acp-echo-authorization",
            "operationId": "different-operation",
            "requestBindingHash": request_binding_hash,
            "settled": false,
            "metadata": {}
        }),
    );
    let adapter = AcpPaymentAdapter::new(url).with_timeout(Duration::from_secs(2));

    let error = adapter
        .authorize_for_operation(
            operation_id,
            &request_binding_hash,
            &operation_authorize_request(operation_id, &request_binding_hash),
        )
        .expect_err("mismatched rail echo must fail closed");
    assert!(error.to_string().contains("did not attest"));
    handle.join().expect("mismatched echo server");
}

#[test]
fn http_authorize_bridges_do_not_claim_synthetic_operation_mutations() {
    fn assert_authorize_only(adapter: &dyn PaymentAdapter) {
        let operation_id = "authorize-only-operation";
        let request_binding_hash = "90".repeat(32);
        assert!(adapter.supports_operation_authorization_recovery());
        assert!(!adapter.supports_operation_payment_mutations());
        assert!(matches!(
            adapter.capture_for_operation(OperationPaymentCaptureRequest {
                operation_id,
                request_binding_hash: &request_binding_hash,
                authorization_id: "authorize-only-authorization",
                amount_units: 25,
                currency: "USD",
                reference: "authorize-only-reference",
            }),
            Err(PaymentError::OperationIdempotencyUnsupported("capture"))
        ));
        assert!(matches!(
            adapter.release_for_operation(
                operation_id,
                &request_binding_hash,
                "authorize-only-authorization",
                "authorize-only-reference",
            ),
            Err(PaymentError::OperationIdempotencyUnsupported("release"))
        ));
        assert!(matches!(
            adapter.refund_for_operation(OperationPaymentRefundRequest {
                operation_id,
                request_binding_hash: &request_binding_hash,
                transaction_id: "authorize-only-transaction",
                amount_units: 25,
                currency: "USD",
                reference: "authorize-only-reference",
            }),
            Err(PaymentError::OperationIdempotencyUnsupported("refund"))
        ));
    }

    assert_authorize_only(&X402PaymentAdapter::new("http://127.0.0.1:1"));
    assert_authorize_only(&AcpPaymentAdapter::new("http://127.0.0.1:1"));
}

fn spawn_json_sequence_server(
    responses: Vec<Option<(u16, serde_json::Value)>>,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let address = listener
        .local_addr()
        .expect("listener should expose local address");
    let (request_tx, request_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("server should accept request");
            let request = read_operation_adapter_request(&mut stream);
            request_tx
                .send(request)
                .expect("request should be sent to test");
            let Some((status_code, body)) = response else {
                continue;
            };
            let body_text = body.to_string();
            let response = format!(
                "HTTP/1.1 {status_code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_text(status_code),
                body_text.len(),
                body_text
            );
            stream
                .write_all(response.as_bytes())
                .expect("server should write response");
        }
    });
    (format!("http://{address}"), request_rx, handle)
}

fn read_operation_adapter_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = 0_usize;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("server should configure read timeout");
    loop {
        let read = stream
            .read(&mut chunk)
            .expect("server should read request bytes");
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if header_end.is_none() {
            header_end = find_header_end(&request);
            if let Some(end) = header_end {
                content_length = parse_content_length(&request[..end]);
            }
        }
        if let Some(end) = header_end {
            if request.len() >= end + content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}
