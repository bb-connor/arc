use super::super::super::*;
use chio_test_support::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub(super) const TEST_SERVER_ENDPOINT_MARKER: &str = "chio-test-server-endpoint";

#[derive(Clone)]
struct TestMutationEvent {
    event: BudgetMutationEventView,
    command_kind: Option<AdmissionCommandKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CapturedRequest {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) body: String,
}

pub(super) struct StaticResponseServer {
    pub(super) url: String,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

pub(super) struct ScriptedResponse {
    pub(super) status: u16,
    pub(super) body: String,
    pub(super) content_type: &'static str,
}

pub(super) struct ScriptedResponseServer {
    pub(super) url: String,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl ScriptedResponseServer {
    pub(super) fn spawn(responses: Vec<ScriptedResponse>) -> Self {
        Self::spawn_inner(responses, false)
    }

    pub(super) fn spawn_with_mutation_absence(responses: Vec<ScriptedResponse>) -> Self {
        Self::spawn_inner(responses, true)
    }

    fn spawn_inner(responses: Vec<ScriptedResponse>, mutation_absence: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind scripted server");
        listener
            .set_nonblocking(true)
            .test_expect("set scripted server nonblocking");
        let addr = listener.local_addr().test_expect("scripted server address");
        let endpoint = format!("http://{addr}");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&captured);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_endpoint = endpoint.clone();
        let join = thread::spawn(move || {
            let mut responses = std::collections::VecDeque::from(responses);
            let mut mutation_events = HashMap::new();
            loop {
                let Some(mut stream) = accept_until_shutdown(&listener, &worker_shutdown) else {
                    return;
                };
                let request = read_http_request(&mut stream);
                let response = if mutation_absence {
                    mutation_event_response(&request, &worker_endpoint, &mutation_events)
                } else {
                    None
                }
                .unwrap_or_else(|| {
                    materialize_response(
                        responses
                            .pop_front()
                            .test_expect("scripted response remains"),
                        &worker_endpoint,
                    )
                });
                if mutation_absence {
                    remember_mutation_event(
                        &request,
                        &response.body,
                        &worker_endpoint,
                        &mut mutation_events,
                    );
                }
                captured_requests
                    .lock()
                    .test_expect("capture scripted request")
                    .push(request);
                write_scripted_response(&mut stream, &response);
                stream.flush().test_expect("flush scripted response");
            }
        });
        Self {
            url: endpoint,
            captured,
            shutdown,
            join: Some(join),
        }
    }

    pub(super) fn spawn_dynamic<F>(expected_requests: usize, handler: F) -> Self
    where
        F: Fn(&CapturedRequest) -> ScriptedResponse + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind scripted server");
        listener
            .set_nonblocking(true)
            .test_expect("set dynamic scripted server nonblocking");
        let addr = listener.local_addr().test_expect("scripted server address");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&captured);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let join = thread::spawn(move || {
            for _ in 0..expected_requests {
                let Some(mut stream) = accept_until_shutdown(&listener, &worker_shutdown) else {
                    return;
                };
                let request = read_http_request(&mut stream);
                let response = handler(&request);
                captured_requests
                    .lock()
                    .test_expect("capture scripted request")
                    .push(request);
                write!(
                    stream,
                    "HTTP/1.1 {} test\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.content_type,
                    response.body
                )
                .test_expect("write scripted response");
                stream.flush().test_expect("flush scripted response");
            }
        });
        Self {
            url: format!("http://{addr}"),
            captured,
            shutdown,
            join: Some(join),
        }
    }

    pub(super) fn requests(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .test_expect("scripted requests")
            .clone()
    }
}

impl Drop for ScriptedResponseServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let result = join.join();
            if !thread::panicking() {
                result.test_expect("join scripted server");
            }
        }
    }
}

impl StaticResponseServer {
    pub(super) fn spawn(
        status: u16,
        body: &str,
        content_type: &str,
        expected_requests: usize,
    ) -> Self {
        Self::spawn_inner(status, body, content_type, expected_requests, false)
    }

    pub(super) fn spawn_with_mutation_absence(
        status: u16,
        body: &str,
        content_type: &str,
        expected_requests: usize,
    ) -> Self {
        Self::spawn_inner(status, body, content_type, expected_requests, true)
    }

    fn spawn_inner(
        status: u16,
        body: &str,
        content_type: &str,
        expected_requests: usize,
        mutation_absence: bool,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind static response server");
        listener
            .set_nonblocking(true)
            .test_expect("set static response server nonblocking");
        let addr = listener.local_addr().test_expect("server local addr");
        let endpoint = format!("http://{addr}");
        let body = body.to_string();
        let content_type = content_type.to_string();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&captured);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_endpoint = endpoint.clone();
        let join = thread::spawn(move || {
            let mut served = 0;
            let body = body.replace(TEST_SERVER_ENDPOINT_MARKER, &worker_endpoint);
            let mut mutation_events = HashMap::new();
            loop {
                let Some(mut stream) = accept_until_shutdown(&listener, &worker_shutdown) else {
                    return;
                };
                let request = read_http_request(&mut stream);
                let mutation_response = mutation_absence
                    .then(|| mutation_event_response(&request, &worker_endpoint, &mutation_events))
                    .flatten();
                if let Some(response) = mutation_response {
                    write_scripted_response(&mut stream, &response);
                } else {
                    assert!(
                        served < expected_requests,
                        "static response server received an unexpected non-query request"
                    );
                    write!(
                        stream,
                        "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .test_expect("write response");
                    served += 1;
                    if mutation_absence {
                        remember_mutation_event(
                            &request,
                            &body,
                            &worker_endpoint,
                            &mut mutation_events,
                        );
                    }
                }
                captured_requests
                    .lock()
                    .test_expect("capture request")
                    .push(request);
                stream.flush().test_expect("flush response");
            }
        });
        Self {
            url: endpoint,
            captured,
            shutdown,
            join: Some(join),
        }
    }

    pub(super) fn requests(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .test_expect("captured requests")
            .clone()
    }
}

fn write_scripted_response(stream: &mut TcpStream, response: &ScriptedResponse) {
    write!(
        stream,
        "HTTP/1.1 {} test\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n{}",
        response.status,
        response.body.len(),
        response.content_type,
        response.body
    )
    .test_expect("write scripted response");
}

fn materialize_response(mut response: ScriptedResponse, endpoint: &str) -> ScriptedResponse {
    response.body = response.body.replace(TEST_SERVER_ENDPOINT_MARKER, endpoint);
    response
}

fn mutation_event_response(
    request: &CapturedRequest,
    endpoint: &str,
    mutation_events: &HashMap<String, TestMutationEvent>,
) -> Option<ScriptedResponse> {
    if request.target != BUDGET_MUTATION_EVENT_QUERY_PATH {
        return None;
    }
    let query_request: BudgetMutationEventQueryRequest =
        serde_json::from_str(&request.body).test_expect("decode mutation-event query request");
    let canonical_members =
        canonical_json_bytes(&vec![endpoint.to_string()]).test_expect("canonicalize membership");
    let mut membership_preimage = b"chio.admission-membership.v1\0".to_vec();
    membership_preimage.extend_from_slice(&canonical_members);
    let membership_digest = sha256_hex(&membership_preimage);
    let stored = mutation_events.get(&query_request.event_id);
    let index = stored.map_or(1, |stored| stored.event.event_seq);
    let term = stored
        .and_then(|stored| stored.command_kind)
        .map_or(1, |_| 7);
    let proof = AdmissionCommitProof {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership_digest.clone(),
        index,
        leader_epoch: term,
        current_term_commit_index: index,
        leader_id: endpoint.to_string(),
        quorum_size: 1,
        witness_urls: vec![endpoint.to_string()],
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("mutation query test clock")
        .as_secs();
    let (command_kind, entry, result_commit_proof, result_commit_target, result, authority, commit) =
        stored
            .and_then(|stored| {
                stored
                    .command_kind
                    .map(|kind| operation_mutation_proof(kind, &stored.event, endpoint, &proof))
            })
            .map(|(kind, entry, commit_proof, result, authority, commit)| {
                (
                    Some(kind),
                    Some(entry.clone()),
                    Some(commit_proof),
                    Some(entry),
                    Some(result),
                    Some(authority),
                    Some(commit),
                )
            })
            .unwrap_or((None, None, None, None, None, None, None));
    let body = BudgetMutationEventReplicaResponseBody {
        protocol_version: BUDGET_MUTATION_EVENT_QUERY_PROTOCOL_VERSION.to_string(),
        consensus_protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        service: BUDGET_MUTATION_EVENT_QUERY_SERVICE.to_string(),
        membership_digest,
        node_id: endpoint.to_string(),
        request_nonce: query_request.request_nonce.clone(),
        issued_at: now,
        expires_at: now + BUDGET_MUTATION_EVENT_QUERY_MAX_TTL_SECS,
        query: BudgetMutationEventQueryView {
            service_namespace: BUDGET_MUTATION_EVENT_QUERY_NAMESPACE.to_string(),
            request_digest: budget_mutation_event_query_request_digest(&query_request)
                .test_expect("digest mutation query request"),
            event_id: query_request.event_id.clone(),
            current_term: term,
            leader_id: endpoint.to_string(),
            last_log_index: index,
            last_log_term: term,
            commit_index: index,
            last_applied: index,
            applied_state_digest: "00".repeat(32),
            read_barrier: proof,
            command_kind,
            entry,
            result_commit_proof,
            result_commit_target,
            result,
            rejection: None,
            mutation_event: stored.map(|stored| stored.event.clone()),
            budget_authority: authority,
            budget_commit: commit,
        },
    };
    let response = BudgetMutationEventReplicaResponse::sign(body, &Keypair::generate())
        .test_expect("sign mutation absence response");
    Some(ScriptedResponse {
        status: 200,
        body: serde_json::to_string(&response).test_expect("encode mutation absence response"),
        content_type: "application/json",
    })
}

fn remember_mutation_event(
    request: &CapturedRequest,
    response_body: &str,
    endpoint: &str,
    mutation_events: &mut HashMap<String, TestMutationEvent>,
) {
    if remember_capture_query_event(request, response_body, endpoint, mutation_events) {
        return;
    }
    let Some(kind) = ordinary_mutation_kind(request) else {
        return;
    };
    let request_body: serde_json::Value =
        serde_json::from_str(&request.body).test_expect("decode mutation request");
    let response: serde_json::Value =
        serde_json::from_str(response_body).test_expect("decode mutation response");
    let event_id = request_body["eventId"]
        .as_str()
        .test_expect("mutation request event id")
        .to_string();
    let Some(event_seq) = response["budgetCommit"]["commitIndex"]
        .as_u64()
        .or_else(|| response["budgetAuthority"]["budgetCommitIndex"].as_u64())
    else {
        return;
    };
    let total_cost_exposed_after = response["totalExposureCharged"]
        .as_u64()
        .test_expect("mutation response total exposure");
    let total_cost_realized_spend_after = response["totalRealizedSpend"]
        .as_u64()
        .test_expect("mutation response total realized spend");
    let exposure_units = match kind {
        BudgetMutationKind::ReconcileSpend | BudgetMutationKind::CaptureExposure => request_body
            ["authorizedExposureUnits"]
            .as_u64()
            .test_expect("settlement request exposure"),
        BudgetMutationKind::ReverseExposure => request_body["exposureUnits"]
            .as_u64()
            .test_expect("mutation request cost"),
        _ => request_body["reductionUnits"]
            .as_u64()
            .test_expect("mutation request reduction"),
    };
    let realized_spend_units = request_body["realizedSpendUnits"].as_u64().unwrap_or(0);
    let monetary_state = match kind {
        BudgetMutationKind::ReverseExposure => BudgetMonetaryHoldStateView::Reversed,
        BudgetMutationKind::ReleaseExposure => BudgetMonetaryHoldStateView::Released,
        BudgetMutationKind::ReconcileSpend => BudgetMonetaryHoldStateView::Reconciled,
        BudgetMutationKind::CaptureExposure => BudgetMonetaryHoldStateView::Captured,
        _ => panic!("unsupported ordinary mutation kind"),
    };
    let operation_id = request_body["operationId"].as_str().map(str::to_string);
    let request_binding_hash = request_body["requestBindingHash"]
        .as_str()
        .map(str::to_string);
    let operation_owned = operation_id.is_some();
    let kind = if operation_owned && kind == BudgetMutationKind::ReverseExposure {
        BudgetMutationKind::ReverseInvocations
    } else {
        kind
    };
    let event = BudgetMutationEventView {
        event_id: event_id.clone(),
        hold_id: request_body["holdId"].as_str().map(str::to_string),
        operation_id,
        request_binding_hash,
        capability_id: request_body["capabilityId"]
            .as_str()
            .test_expect("mutation request capability")
            .to_string(),
        grant_index: u32::try_from(
            request_body["grantIndex"]
                .as_u64()
                .test_expect("mutation request grant index"),
        )
        .test_expect("mutation request grant index fits u32"),
        kind: kind.as_str().to_string(),
        allowed: None,
        recorded_at: i64::try_from(event_seq).test_expect("event sequence fits i64"),
        event_seq,
        usage_seq: Some(event_seq),
        exposure_units,
        realized_spend_units,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: u32::try_from(
            response["invocationCount"]
                .as_u64()
                .test_expect("mutation response invocation count"),
        )
        .test_expect("mutation response invocation count fits u32"),
        invocation_counts_after: response["testInvocationCountsAfter"]
            .as_array()
            .map(|value| {
                serde_json::from_value(serde_json::Value::Array(value.clone()))
                    .test_expect("decode test invocation counts")
            })
            .unwrap_or_default(),
        invocation_state: if matches!(
            kind,
            BudgetMutationKind::ReverseExposure | BudgetMutationKind::ReverseInvocations
        ) {
            BudgetInvocationReservationStateView::Reversed
        } else {
            BudgetInvocationReservationStateView::Absent
        },
        monetary_state,
        revocation_set: response
            .get("testRevocationSet")
            .filter(|value| !value.is_null())
            .map(|value| {
                serde_json::from_value(value.clone()).test_expect("decode test revocation set")
            }),
        total_cost_exposed_after,
        total_cost_realized_spend_after,
        authority: Some(BudgetMutationAuthorityView {
            authority_id: endpoint.to_string(),
            lease_id: if operation_owned {
                format!("{endpoint}#admission-term-7")
            } else {
                format!("{endpoint}#term-7")
            },
            lease_epoch: 7,
        }),
    };
    mutation_events.insert(
        event_id,
        TestMutationEvent {
            event,
            command_kind: operation_owned.then_some(AdmissionCommandKind::ReverseExposure),
        },
    );
}

fn remember_capture_query_event(
    request: &CapturedRequest,
    response_body: &str,
    endpoint: &str,
    mutation_events: &mut HashMap<String, TestMutationEvent>,
) -> bool {
    let (capture, command_kind) = match request.target.as_str() {
        BUDGET_CAPTURE_INVOCATIONS_QUERY_PATH => {
            let response: CaptureInvocationPointQueryResponse =
                serde_json::from_str(response_body).test_expect("decode invocation capture query");
            (response.capture, AdmissionCommandKind::CaptureInvocations)
        }
        ADMISSION_CAPTURE_QUERY_PATH => {
            let response: AdmissionCapturePointQueryResponse =
                serde_json::from_str(response_body).test_expect("decode admission capture query");
            (
                response.capture.and_then(|capture| capture.budget),
                AdmissionCommandKind::CombinedCapture,
            )
        }
        _ => return false,
    };
    let Some(capture) = capture else {
        return true;
    };
    let event_seq = capture
        .budget_commit
        .as_ref()
        .map(|commit| commit.commit_index)
        .test_expect("capture query commit");
    let authority = BudgetMutationAuthorityView {
        authority_id: endpoint.to_string(),
        lease_id: format!("{endpoint}#admission-term-7"),
        lease_epoch: 7,
    };
    let event = BudgetMutationEventView {
        event_id: capture.event_id.clone(),
        hold_id: Some(capture.hold_id.clone()),
        operation_id: Some(capture.operation_id.clone()),
        request_binding_hash: Some(capture.request_binding_hash.clone()),
        capability_id: capture.capability_id.clone(),
        grant_index: u32::try_from(capture.grant_index)
            .test_expect("capture query grant index fits u32"),
        kind: BudgetMutationKind::CaptureInvocations.as_str().to_string(),
        allowed: None,
        recorded_at: i64::try_from(event_seq).test_expect("capture event sequence fits i64"),
        event_seq,
        usage_seq: Some(event_seq),
        exposure_units: capture.exposure_units,
        realized_spend_units: capture.realized_spend_units,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: capture.invocation_count_after,
        invocation_counts_after: capture.invocation_counts_after,
        invocation_state: capture.invocation_state,
        monetary_state: capture.monetary_state,
        revocation_set: Some(capture.revocation_set),
        total_cost_exposed_after: capture.committed_cost_units_after,
        total_cost_realized_spend_after: 0,
        authority: Some(authority),
    };
    mutation_events.insert(
        event.event_id.clone(),
        TestMutationEvent {
            event,
            command_kind: Some(command_kind),
        },
    );
    true
}

fn operation_mutation_proof(
    command_kind: AdmissionCommandKind,
    event: &BudgetMutationEventView,
    endpoint: &str,
    proof: &AdmissionCommitProof,
) -> (
    AdmissionCommandKind,
    AdmissionLogEntry,
    AdmissionCommitProof,
    AdmissionConsensusResult,
    BudgetAuthorityMetadataView,
    BudgetWriteCommitView,
) {
    let authority = serde_json::json!({
        "authorityId": endpoint,
        "leaseId": format!("{endpoint}#admission-term-7"),
        "leaseEpoch": 7
    });
    let command = if command_kind == AdmissionCommandKind::CombinedCapture {
        serde_json::json!({"request": {"budgetAuthority": authority}})
    } else {
        serde_json::json!({"budgetAuthority": authority})
    };
    let canonical_command =
        String::from_utf8(canonical_json_bytes(&command).test_expect("canonicalize test command"))
            .test_expect("canonical test command is UTF-8");
    let operation_id = scoped_test_operation_id(command_kind, &event.event_id);
    let entry = AdmissionLogEntry {
        index: event.event_seq,
        leader_epoch: 7,
        operation_id: operation_id.clone(),
        command_kind,
        command_digest: sha256_hex(canonical_command.as_bytes()),
        canonical_command,
    };
    let response_json = "{}".to_string();
    let result = AdmissionConsensusResult {
        operation_id,
        log_index: event.event_seq,
        response_digest: sha256_hex(response_json.as_bytes()),
        response_json,
        security_projection_digest: "00".repeat(32),
    };
    let lease_id = format!("{endpoint}#admission-term-7");
    let authority = BudgetAuthorityMetadataView {
        authority_id: endpoint.to_string(),
        leader_url: endpoint.to_string(),
        budget_term: 7,
        lease_id: lease_id.clone(),
        lease_epoch: 7,
        lease_expires_at: 5_000,
        lease_ttl_ms: 750,
        guarantee_level: "ha_linearizable".to_string(),
        budget_commit_index: Some(event.event_seq),
        partition_escrow_evidence: None,
    };
    let commit = BudgetWriteCommitView {
        budget_seq: event.event_seq,
        commit_index: event.event_seq,
        quorum_committed: true,
        quorum_size: 1,
        committed_nodes: 1,
        witness_urls: vec![endpoint.to_string()],
        authority_id: endpoint.to_string(),
        budget_term: 7,
        lease_id,
        lease_epoch: 7,
    };
    (
        command_kind,
        entry,
        proof.clone(),
        result,
        authority,
        commit,
    )
}

fn scoped_test_operation_id(command_kind: AdmissionCommandKind, event_id: &str) -> String {
    let label = match command_kind {
        AdmissionCommandKind::CaptureInvocations => "capture_invocations",
        AdmissionCommandKind::ReverseExposure => "reverse_exposure",
        AdmissionCommandKind::CombinedCapture => "combined_capture",
        _ => panic!("unsupported test operation kind"),
    };
    let canonical = canonical_json_bytes(&serde_json::json!({
        "commandKind": label,
        "operationId": event_id,
    }))
    .test_expect("canonicalize test operation scope");
    let mut preimage = b"chio.admission-consensus-operation.v1\0".to_vec();
    preimage.extend_from_slice(&canonical);
    sha256_hex(&preimage)
}

fn ordinary_mutation_kind(request: &CapturedRequest) -> Option<BudgetMutationKind> {
    match request.target.as_str() {
        BUDGET_RELEASE_EXPOSURE_PATH => Some(BudgetMutationKind::ReverseExposure),
        BUDGET_RECONCILE_SPEND_PATH => {
            let body: serde_json::Value =
                serde_json::from_str(&request.body).test_expect("decode reconcile request");
            if body["authorizedExposureUnits"].is_u64() {
                Some(BudgetMutationKind::ReconcileSpend)
            } else {
                Some(BudgetMutationKind::ReleaseExposure)
            }
        }
        BUDGET_CAPTURE_EXPOSURE_PATH => Some(BudgetMutationKind::CaptureExposure),
        _ => None,
    }
}

impl Drop for StaticResponseServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let result = join.join();
            if !thread::panicking() {
                result.test_expect("join response server");
            }
        }
    }
}

fn accept_until_shutdown(listener: &TcpListener, shutdown: &AtomicBool) -> Option<TcpStream> {
    loop {
        if shutdown.load(Ordering::Acquire) {
            return None;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .test_expect("set accepted test stream blocking");
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept test HTTP request failed: {error}"),
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut headers_end = None;
    let mut content_length = 0usize;
    loop {
        let read = stream.read(&mut chunk).test_expect("read HTTP request");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if headers_end.is_none() {
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                headers_end = Some(position + 4);
                content_length =
                    parse_content_length(&String::from_utf8_lossy(&buffer[..position + 4]));
            }
        }
        if let Some(headers_end) = headers_end {
            if buffer.len() >= headers_end + content_length {
                break;
            }
        }
    }

    let headers_end = headers_end.test_expect("HTTP request headers terminator");
    let header_text = String::from_utf8_lossy(&buffer[..headers_end]);
    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines.next().test_expect("request line");
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .test_expect("request method")
        .to_string();
    let target = request_line_parts
        .next()
        .test_expect("request target")
        .to_string();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    let body = String::from_utf8_lossy(&buffer[headers_end..]).to_string();

    CapturedRequest {
        method,
        target,
        headers,
        body,
    }
}

fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

pub(super) fn assert_bearer_request(
    request: &CapturedRequest,
    method: &str,
    path_prefix: &str,
    fragments: &[&str],
) {
    assert_eq!(request.method, method);
    assert!(
        request.target.starts_with(path_prefix),
        "unexpected target: {}",
        request.target
    );
    for fragment in fragments {
        assert!(
            request.target.contains(fragment),
            "expected `{}` in target `{}`",
            fragment,
            request.target
        );
    }
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer secret")
    );
}

pub(super) fn assert_json_post(request: &CapturedRequest, path: &str, body_fragments: &[&str]) {
    assert_bearer_request(request, "POST", path, &[]);
    let content_type = request
        .headers
        .get("content-type")
        .test_expect("content-type header");
    assert!(content_type.starts_with("application/json"));
    for fragment in body_fragments {
        assert!(
            request.body.contains(fragment),
            "expected `{}` in body `{}`",
            fragment,
            request.body
        );
    }
}
