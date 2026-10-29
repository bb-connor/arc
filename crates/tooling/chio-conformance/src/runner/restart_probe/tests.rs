use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chio_egress_contract::{BlockingContractAgent, HttpEgressContract};
use chio_test_support::plain::TestResultOk;
use serde_json::json;
use tiny_http::{Header, Response, Server};

use super::{parse_sse, Probe, SseEvent, MAX_RESPONSE_BYTES};

fn fixture_agent(address: &impl std::fmt::Display) -> BlockingContractAgent {
    let url = format!("http://{address}/mcp");
    let contract = HttpEgressContract::for_configured_url(
        "restart-probe-fixture",
        &url,
        MAX_RESPONSE_BYTES as u64,
    )
    .test_expect("fixture contract");
    BlockingContractAgent::new(&contract, Duration::from_secs(3), Duration::from_secs(3))
        .test_expect("fixture agent")
}

const RESPONSE_LIMIT: usize = 8 * 1024 * 1024;

fn rpc_response(body: Vec<u8>) -> Result<Vec<SseEvent>, String> {
    let server = Server::http("127.0.0.1:0").test_expect("bind response fixture");
    let address = server
        .server_addr()
        .to_ip()
        .test_expect("IP fixture address");
    let worker = thread::spawn(move || {
        let request = server
            .recv_timeout(Duration::from_secs(5))
            .test_expect("receive request")
            .test_expect("request before fixture deadline");
        let response = Response::from_data(body).with_header(
            Header::from_bytes("Content-Type", "text/event-stream").test_expect("content type"),
        );
        request.respond(response)
    });
    let probe = Probe {
        agent: fixture_agent(&address),
        endpoint: format!("http://{address}/mcp"),
        token: "restart-probe-fixture".to_owned(),
        timeout: Duration::from_secs(3),
    };
    let result = probe.rpc("session", &json!({"id":2,"method":"resources/subscribe"}));
    let sent = worker.join().test_expect("fixture worker");
    match (&result, sent) {
        (_, Ok(())) => {}
        (Err(_), Err(error)) => assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        )),
        (Ok(_), Err(error)) => panic!("fixture response failed: {error}"),
    }
    result
}

#[test]
fn sse_frames_keep_their_ids_and_skip_priming_events() {
    let events = parse_sse(
        "id: s-1\nretry: 1000\ndata:\n\nid: s-2\ndata: {\"method\":\"notifications/resources/updated\"}\n\ndata: {\"id\":3,\"result\":{}}\n\n",
    )
    .test_expect("valid priming and event frames");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].id.as_deref(), Some("s-2"));
    assert_eq!(
        events[0].message["method"],
        "notifications/resources/updated"
    );
    assert_eq!(events[1].id, None);
    assert_eq!(events[1].message["id"], 3);
}

#[test]
fn rpc_refuses_duplicate_response_fields() {
    let result = rpc_response(b"data: {\"id\":999,\"id\":2,\"result\":{}}\n\n".to_vec());
    assert_eq!(
        result.map(|events| events.len()),
        Err("urn:chio:error:attest:signed-json-invalid-input".to_owned())
    );
}

#[test]
fn rpc_refuses_nested_duplicate_notification_fields() {
    let result = rpc_response(
        b"data: {\"method\":\"notifications/resources/updated\",\"params\":{\"uri\":\"wrong\",\"uri\":\"fixture://docs/alpha\"}}\n\n".to_vec(),
    );
    assert_eq!(
        result.map(|events| events.len()),
        Err("urn:chio:error:attest:signed-json-invalid-input".to_owned())
    );
}

#[test]
fn rpc_refuses_malformed_data_before_a_valid_response() {
    let result = rpc_response(b"data: {bad}\n\ndata: {\"id\":2,\"result\":{}}\n\n".to_vec());
    assert_eq!(
        result.map(|events| events.len()),
        Err("urn:chio:error:attest:signed-json-invalid-input".to_owned())
    );
}

#[test]
fn rpc_refuses_invalid_utf8() {
    let result = rpc_response(b"data: {\"id\":2,\"result\":{\"text\":\"\xff\"}}\n\n".to_vec());
    assert_eq!(
        result.map(|events| events.len()),
        Err("restart probe response is not UTF-8".to_owned())
    );
}

#[test]
fn rpc_refuses_response_above_byte_bound() {
    let result = rpc_response(vec![b' '; RESPONSE_LIMIT + 1]);
    assert_eq!(
        result.map(|events| events.len()),
        Err("restart probe response exceeds 8388608 bytes".to_owned())
    );
}

#[test]
fn rpc_accepts_response_at_byte_bound() {
    let suffix = b"\n\ndata: {\"id\":2,\"result\":{}}\n\n";
    let mut body = vec![b':'; RESPONSE_LIMIT - suffix.len()];
    body.extend_from_slice(suffix);
    let events = rpc_response(body).test_expect("bounded response");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].message["id"], 2);
}

#[test]
fn rpc_refuses_json_tokens_split_across_data_lines() {
    let result = rpc_response(b"data: {\"id\":1\ndata: 2,\"result\":{}}\n\n".to_vec());
    assert_eq!(
        result.map(|events| events.len()),
        Err("urn:chio:error:attest:signed-json-invalid-input".to_owned())
    );
}

#[test]
fn rpc_refuses_unterminated_data_frame() {
    let result = rpc_response(b"data: {\"id\":2,\"result\":{}}".to_vec());
    assert_eq!(
        result.map(|events| events.len()),
        Err("restart probe response ends inside an SSE event".to_owned())
    );
}

#[test]
fn rpc_refuses_whitespace_only_data() {
    let result = rpc_response(b"data:  \n\ndata: {\"id\":2,\"result\":{}}\n\n".to_vec());
    assert_eq!(
        result.map(|events| events.len()),
        Err("urn:chio:error:attest:signed-json-invalid-input".to_owned())
    );
}

#[test]
fn sse_accepts_line_endings_bom_and_multiline_json() {
    for ending in ["\n", "\r\n", "\r"] {
        let body = [
            "\u{feff}: keepalive",
            "id: priming",
            "retry: 1000",
            "data:",
            "",
            "id: event-2",
            "data: {",
            "data: \"id\":2,\"result\":{\"score\":0.10}",
            "data: }",
            "",
            "",
        ]
        .join(ending);
        let events = parse_sse(&body).test_expect("valid event stream");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id.as_deref(), Some("event-2"));
        assert_eq!(events[0].message["id"], 2);
        assert_eq!(events[0].message["result"]["score"], 0.1);
    }
}

#[test]
fn sse_preserves_id_spaces_and_ignores_nul_and_empty_ids() {
    let events = parse_sse(
        "id:  spaced \ndata: {\"id\":1}\n\nid: bad\0id\ndata: {\"id\":2}\n\nid:\ndata: {\"id\":3}\n\n",
    )
    .test_expect("valid id fields");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].id.as_deref(), Some(" spaced "));
    assert_eq!(events[1].id, None);
    assert_eq!(events[2].id, None);
}

#[test]
fn rpc_deadline_covers_a_trickling_response_body() {
    let server = Server::http("127.0.0.1:0").test_expect("bind trickle fixture");
    let address = server
        .server_addr()
        .to_ip()
        .test_expect("IP fixture address");
    let worker = thread::spawn(move || {
        let mut request = server
            .recv_timeout(Duration::from_secs(5))
            .test_expect("receive request")
            .test_expect("request before fixture deadline");
        let mut body = Vec::new();
        request
            .as_reader()
            .read_to_end(&mut body)
            .test_expect("request body");
        let mut wire = request.into_writer();
        wire.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
            .test_expect("response headers");
        wire.flush().test_expect("flush response headers");
        for _ in 0..40 {
            if let Err(error) = wire.write_all(b"1\r\n \r\n").and_then(|()| wire.flush()) {
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ));
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        wire.write_all(b"0\r\n\r\n")
            .and_then(|()| wire.flush())
            .test_expect("complete chunked response");
    });
    let probe = Probe {
        agent: fixture_agent(&address),
        endpoint: format!("http://{address}/mcp"),
        token: "restart-probe-fixture".to_owned(),
        timeout: Duration::from_secs(1),
    };
    let result = probe.rpc("session", &json!({"id":2,"method":"resources/subscribe"}));
    assert_eq!(
        result.map(|events| events.len()),
        Err("restart probe response timed out".to_owned())
    );
    worker.join().test_expect("trickle fixture worker");
}

#[test]
fn replay_deadline_refuses_a_stalled_response() {
    let server = Server::http("127.0.0.1:0").test_expect("bind stalled fixture");
    let address = server
        .server_addr()
        .to_ip()
        .test_expect("IP fixture address");
    let worker = thread::spawn(move || {
        let request = server
            .recv_timeout(Duration::from_secs(5))
            .test_expect("receive request")
            .test_expect("request before fixture deadline");
        thread::sleep(Duration::from_secs(2));
        let _ = request.respond(Response::empty(409));
    });
    let probe = Probe {
        agent: fixture_agent(&address),
        endpoint: format!("http://{address}/mcp"),
        token: "restart-probe-fixture".to_owned(),
        timeout: Duration::from_secs(1),
    };
    assert_eq!(
        probe.replay_status("session", "cursor"),
        Err("restart probe request timed out".to_owned())
    );
    worker.join().test_expect("stalled fixture worker");
}

#[test]
fn rpc_refuses_a_truncated_http_body_without_reporting_a_timeout() {
    let server = Server::http("127.0.0.1:0").test_expect("bind truncated fixture");
    let address = server
        .server_addr()
        .to_ip()
        .test_expect("IP fixture address");
    let worker = thread::spawn(move || {
        let mut request = server
            .recv_timeout(Duration::from_secs(5))
            .test_expect("receive request")
            .test_expect("request before fixture deadline");
        let mut body = Vec::new();
        request
            .as_reader()
            .read_to_end(&mut body)
            .test_expect("request body");
        let mut wire = request.into_writer();
        wire.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\ndata: {}\n\n",
        )
        .test_expect("truncated response");
        wire.flush().test_expect("flush truncated response");
    });
    let probe = Probe {
        agent: fixture_agent(&address),
        endpoint: format!("http://{address}/mcp"),
        token: "restart-probe-fixture".to_owned(),
        timeout: Duration::from_secs(3),
    };
    assert_eq!(
        probe
            .rpc("session", &json!({"id":2,"method":"resources/subscribe"}))
            .map(|events| events.len()),
        Err("restart probe response could not be read".to_owned())
    );
    worker.join().test_expect("truncated fixture worker");
}

const INITIALIZE_RESULT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}"#;

fn initialize_response(
    status: u16,
    content_type: &str,
    body: &str,
) -> (Result<String, String>, usize) {
    let server = Server::http("127.0.0.1:0").test_expect("bind initialize fixture");
    let address = server
        .server_addr()
        .to_ip()
        .test_expect("IP fixture address");
    let stopped = Arc::new(AtomicBool::new(false));
    let received = Arc::new(AtomicUsize::new(0));
    let stop = Arc::clone(&stopped);
    let requests = Arc::clone(&received);
    let initialize = Response::from_string(body)
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", content_type).test_expect("content type"))
        .with_header(Header::from_bytes("MCP-Session-Id", "session").test_expect("session header"));
    let worker = thread::spawn(move || {
        let responses = [
            initialize,
            Response::from_string("").with_status_code(202),
            Response::from_string("data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n")
                .with_header(
                    Header::from_bytes("Content-Type", "text/event-stream")
                        .test_expect("content type"),
                ),
        ];
        for response in responses {
            let request = loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                if let Some(request) = server
                    .recv_timeout(Duration::from_millis(20))
                    .test_expect("receive request")
                {
                    break request;
                }
            };
            requests.fetch_add(1, Ordering::SeqCst);
            request.respond(response).test_expect("fixture response");
        }
    });
    let probe = Probe {
        agent: fixture_agent(&address),
        endpoint: format!("http://{address}/mcp"),
        token: "restart-probe-fixture".to_owned(),
        timeout: Duration::from_secs(3),
    };
    let result = probe.open_subscribed_session();
    stopped.store(true, Ordering::SeqCst);
    worker.join().test_expect("initialize fixture worker");
    (result, received.load(Ordering::SeqCst))
}

fn assert_initialize_refused(status: u16, content_type: &str, body: &str, error: &str) {
    assert_eq!(
        initialize_response(status, content_type, body),
        (Err(error.to_owned()), 1)
    );
}

#[test]
fn initialize_accepts_json_response() {
    assert_eq!(
        initialize_response(200, "application/json; charset=utf-8", INITIALIZE_RESULT),
        (Ok("session".to_owned()), 3)
    );
}

#[test]
fn initialize_accepts_sse_response_with_priming() {
    let body = format!("id: priming\ndata:\n\nid: initialized\ndata: {INITIALIZE_RESULT}\n\n");
    assert_eq!(
        initialize_response(200, "text/event-stream", &body),
        (Ok("session".to_owned()), 3)
    );
}

#[test]
fn initialize_refuses_unsuccessful_http_status() {
    assert_initialize_refused(
        500,
        "application/json",
        INITIALIZE_RESULT,
        "initialize answered 500",
    );
}

#[test]
fn initialize_refuses_malformed_json() {
    assert_initialize_refused(
        200,
        "application/json",
        "{bad}",
        "urn:chio:error:attest:signed-json-invalid-input",
    );
}

#[test]
fn initialize_refuses_duplicate_json_fields() {
    let body = INITIALIZE_RESULT.replacen("\"id\":1", "\"id\":9,\"id\":1", 1);
    assert_initialize_refused(
        200,
        "application/json",
        &body,
        "urn:chio:error:attest:signed-json-invalid-input",
    );
}

#[test]
fn initialize_refuses_malformed_sse_before_result() {
    let body = format!("data: {{bad}}\n\ndata: {INITIALIZE_RESULT}\n\n");
    assert_initialize_refused(
        200,
        "text/event-stream",
        &body,
        "urn:chio:error:attest:signed-json-invalid-input",
    );
}

#[test]
fn initialize_refuses_duplicate_sse_fields() {
    let body = format!(
        "data: {}\n\n",
        INITIALIZE_RESULT.replacen("\"id\":1", "\"id\":9,\"id\":1", 1)
    );
    assert_initialize_refused(
        200,
        "text/event-stream",
        &body,
        "urn:chio:error:attest:signed-json-invalid-input",
    );
}

#[test]
fn initialize_refuses_priming_without_result() {
    assert_initialize_refused(
        200,
        "text/event-stream",
        "id: priming\ndata:\n\n",
        "initialize did not succeed",
    );
}

#[test]
fn initialize_refuses_error_response() {
    assert_initialize_refused(
        200,
        "application/json",
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"failed"}}"#,
        "initialize did not succeed",
    );
}

#[test]
fn initialize_refuses_mismatched_response_id() {
    let body = INITIALIZE_RESULT.replacen("\"id\":1", "\"id\":9", 1);
    assert_initialize_refused(200, "application/json", &body, "initialize did not succeed");
}

#[test]
fn initialize_refuses_unsupported_content_type() {
    assert_initialize_refused(
        200,
        "text/plain",
        INITIALIZE_RESULT,
        "initialize returned an unsupported content type",
    );
}

#[test]
fn initialize_refuses_a_different_protocol_version() {
    let body = INITIALIZE_RESULT.replace("2025-11-25", "unsupported");
    assert_initialize_refused(200, "application/json", &body, "initialize did not succeed");
}

#[test]
fn initialize_refuses_missing_result_fields() {
    assert_initialize_refused(
        200,
        "application/json",
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        "initialize did not succeed",
    );
}

#[test]
fn initialize_refuses_invalid_jsonrpc_version() {
    let body = INITIALIZE_RESULT.replace("2.0", "invalid");
    assert_initialize_refused(200, "application/json", &body, "initialize did not succeed");
}

#[test]
fn initialize_refuses_result_with_an_error_member() {
    let body = INITIALIZE_RESULT.replacen("\"id\":1", "\"id\":1,\"error\":null", 1);
    assert_initialize_refused(200, "application/json", &body, "initialize did not succeed");
}

#[test]
fn initialize_refuses_duplicate_terminal_responses() {
    let body = format!("data: {INITIALIZE_RESULT}\n\ndata: {INITIALIZE_RESULT}\n\n");
    assert_initialize_refused(
        200,
        "text/event-stream",
        &body,
        "initialize did not succeed",
    );
}

#[test]
fn initialize_refuses_invalid_capabilities_type() {
    let body = INITIALIZE_RESULT.replace("\"capabilities\":{}", "\"capabilities\":[]");
    assert_initialize_refused(200, "application/json", &body, "initialize did not succeed");
}

#[test]
fn initialize_refuses_invalid_server_information() {
    let body = INITIALIZE_RESULT.replace("\"version\":\"1\"", "\"version\":1");
    assert_initialize_refused(200, "application/json", &body, "initialize did not succeed");
}

#[test]
fn initialize_accepts_sse_notifications_before_result() {
    let body = format!("data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"level\":\"info\",\"data\":\"ready\"}}}}\n\ndata: {INITIALIZE_RESULT}\n\n");
    assert_eq!(
        initialize_response(200, "Text/Event-Stream; charset=utf-8", &body),
        (Ok("session".to_owned()), 3)
    );
}

#[test]
fn initialize_accepts_successful_json_status() {
    assert_eq!(
        initialize_response(201, "application/json", INITIALIZE_RESULT),
        (Ok("session".to_owned()), 3)
    );
}

#[test]
fn initialize_refuses_non_ok_sse_status() {
    let body = format!("data: {INITIALIZE_RESULT}\n\n");
    assert_initialize_refused(201, "text/event-stream", &body, "initialize answered 201");
}

#[test]
fn initialize_accepts_external_extension_fields() {
    let body = INITIALIZE_RESULT.replacen(
        "\"result\":{",
        "\"result\":{\"instructions\":\"Ready\",\"_meta\":{\"fixture\":true},",
        1,
    );
    assert_eq!(
        initialize_response(200, "application/json", &body),
        (Ok("session".to_owned()), 3)
    );
}

#[test]
fn initialize_distinguishes_a_server_ping_from_the_response() {
    let body = format!("data: {{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}}\n\ndata: {INITIALIZE_RESULT}\n\n");
    assert_eq!(
        initialize_response(200, "text/event-stream", &body),
        (Ok("session".to_owned()), 3)
    );
}

#[test]
fn initialize_refuses_malformed_sse_after_result() {
    let body = format!("data: {INITIALIZE_RESULT}\n\ndata: {{bad}}\n\n");
    assert_initialize_refused(
        200,
        "text/event-stream",
        &body,
        "urn:chio:error:attest:signed-json-invalid-input",
    );
}

use std::net::SocketAddr;

use super::{run, ConformanceRunOptions};
use crate::model::ResultStatus;
use crate::redirect_stub::{ok_empty, redirect_to, serve};

fn options() -> ConformanceRunOptions {
    let mut options = crate::default_run_options();
    options.auth_token = "restart-probe-secret".to_string();
    options
}

#[test]
fn a_redirect_to_another_authority_is_not_dialed_and_the_token_stays() {
    let target = serve(ok_empty());
    let origin = serve(redirect_to(&format!(
        "http://127.0.0.1:{}/mcp",
        target.port
    )));
    let listen: SocketAddr = format!("127.0.0.1:{}", origin.port).parse().unwrap();
    let _ = run(&options(), listen, || Ok(()));
    assert!(!origin.requests().is_empty());
    assert!(origin
        .requests()
        .iter()
        .all(|request| request.contains("restart-probe-secret")));
    assert!(target.requests().is_empty());
}

#[test]
fn a_link_local_listen_address_is_refused_without_dialing() {
    let listen: SocketAddr = "169.254.169.254:80".parse().unwrap();
    let results = run(&options(), listen, || Ok(())).expect("results");
    assert!(results.iter().all(|result| {
        result.status == ResultStatus::Fail
            && result
                .failure_message
                .as_deref()
                .is_some_and(|message| message.contains("link-local"))
    }));
}
