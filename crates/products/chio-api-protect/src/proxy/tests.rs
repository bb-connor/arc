use super::*;
use axum::body::to_bytes;
use chio_core_types::capability::{
    attenuation::{DelegationLink, DelegationLinkBody},
    governance::{GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody},
    scope::ChioScope,
    threshold_approval::{
        ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequest,
        ThresholdApprovalRequirement,
    },
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_http_core::{
    http_status_scope, AppendThresholdApprovalVoteRequest, AuthMethod,
    AuthenticatedThresholdApprovalRequestContext, CreateThresholdApprovalProposalRequest,
    DeliverThresholdApprovalResponseRequest, RespondResponse, CHIO_HTTP_STATUS_SCOPE_DECISION,
    CHIO_HTTP_STATUS_SCOPE_FINAL,
};
use chio_kernel::{
    ApprovalOutcome, ApprovalRequest, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalCreationParameters,
};
use chio_openapi::PolicyDecision;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use tower::ServiceExt;

use chio_test_support::prelude::*;

const PETSTORE_YAML: &str = r#"
openapi: "3.0.0"
info:
  title: Petstore
  version: "1.0.0"
paths:
  /pets:
    get:
      operationId: listPets
      summary: List all pets
      responses:
        "200":
          description: A list of pets
    post:
      operationId: createPet
      summary: Create a pet
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        "201":
          description: Created
  /pets/{petId}:
    get:
      operationId: showPetById
      summary: Info for a specific pet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: A pet
    delete:
      operationId: deletePet
      summary: Delete a pet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "204":
          description: Deleted
"#;

fn signed_capability_token_json(issuer: &Keypair, id: &str) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: issuer.public_key(),
            scope: ChioScope {
                grants: vec![chio_http_core::http_authority_tool_grant()],
                ..ChioScope::default()
            },
            issued_at: now.saturating_sub(60),
            expires_at: now + 3600,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .test_unwrap();
    serde_json::to_string(&token).test_unwrap()
}

struct MockUpstreamServer {
    base_url: String,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    handle: thread::JoinHandle<()>,
}

impl MockUpstreamServer {
    fn bind_mock_upstream_listener() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(error) => match error.kind() {
                std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::Unsupported => {
                    eprintln!(
                            "skipping proxy mock-upstream test because loopback bind is unavailable: {error}"
                        );
                    None
                }
                _ => panic!("bind mock upstream listener: {error}"),
            },
        }
    }

    fn spawn(status: u16, headers: Vec<(&str, &str)>, body: &str) -> Option<Self> {
        let listener = Self::bind_mock_upstream_listener()?;
        let address = listener.local_addr().test_unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        let body = body.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().test_unwrap();
            let request = read_http_request(&mut stream);
            request_log.lock().test_unwrap().push(request);
            write_http_response(&mut stream, status, &headers, &body);
        });
        Some(Self {
            base_url: format!("http://{}", address),
            requests,
            handle,
        })
    }

    /// Accept one connection and read the request, then hold the socket open
    /// without responding so a client with a request timeout must give up on its
    /// own. Stands in for an upstream that received the request but stalls.
    fn spawn_unresponsive() -> Option<Self> {
        let listener = Self::bind_mock_upstream_listener()?;
        let address = listener.local_addr().test_unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let request = read_http_request(&mut stream);
                request_log.lock().test_unwrap().push(request);
                // Never write a response. Block reading until the client gives up
                // and closes the connection, modeling an upstream that stalls
                // indefinitely rather than sleeping a fixed interval: the caller's
                // request timeout must be what ends the hop.
                let mut sink = [0_u8; 256];
                while let Ok(read) = stream.read(&mut sink) {
                    if read == 0 {
                        break;
                    }
                }
            }
        });
        Some(Self {
            base_url: format!("http://{}", address),
            requests,
            handle,
        })
    }

    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().test_unwrap().clone()
    }

    fn join(self) {
        self.handle.join().test_unwrap();
    }
}

fn test_state(routes: Vec<RouteEntry>, upstream: String) -> Arc<ProxyState> {
    make_test_state(routes, upstream, None, false)
}

fn test_state_with_receipt_db(
    routes: Vec<RouteEntry>,
    upstream: String,
    receipt_db: Option<&str>,
) -> Arc<ProxyState> {
    make_test_state(routes, upstream, receipt_db, false)
}

fn make_test_state(
    routes: Vec<RouteEntry>,
    upstream: String,
    receipt_db: Option<&str>,
    allow_advisory: bool,
) -> Arc<ProxyState> {
    make_test_state_with_revocation_store(routes, upstream, receipt_db, allow_advisory, None)
}

fn make_test_state_with_revocation_store(
    routes: Vec<RouteEntry>,
    upstream: String,
    receipt_db: Option<&str>,
    allow_advisory: bool,
    revocation_store_override: Option<Arc<dyn chio_kernel::RevocationStore>>,
) -> Arc<ProxyState> {
    let keypair = Keypair::generate();
    let approval_store: Arc<dyn ApprovalStore> = if let Some(path) = receipt_db {
        Arc::new(SqliteApprovalStore::open(path).test_unwrap())
    } else {
        Arc::new(InMemoryApprovalStore::new())
    };
    let (receipt_store, receipts, tool_receipts, revoked_capability_ids) =
        if let Some(path) = receipt_db {
            let store = SqliteReceiptStore::open(path).test_unwrap();
            let trusted_signers = [keypair.public_key()];
            let receipts = store.load_receipts(&trusted_signers).test_unwrap();
            let tool_receipts = store.load_tool_receipts(&trusted_signers).test_unwrap();
            let revoked_capability_ids = store.load_revoked_capability_ids().test_unwrap();
            (
                Some(Mutex::new(store)),
                receipts,
                tool_receipts,
                revoked_capability_ids,
            )
        } else {
            (None, Vec::new(), Vec::new(), HashSet::new())
        };
    // Mirror the proxy's serving modes: a durable sibling store when a receipt
    // database is configured, an in-memory store shared with the release path
    // otherwise, so a release is honored in-process even without a receipt db.
    let revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>> = revocation_store_override
        .or_else(|| {
            Some(match receipt_db {
                Some(path) => Arc::new(
                    chio_store_sqlite::SqliteRevocationStore::open(format!("{path}.revocations"))
                        .test_unwrap(),
                ) as Arc<dyn chio_kernel::RevocationStore>,
                None => Arc::new(chio_kernel::InMemoryRevocationStore::new()),
            })
        });
    let signer_public_key = keypair.public_key();
    let trusted_capability_issuers = vec![signer_public_key.clone()];
    let trusted_receipt_signers = vec![signer_public_key];
    let evaluator_receipt_store: Option<Arc<dyn chio_kernel::ReceiptStore>> =
        receipt_db.map(|path| {
            Arc::new(chio_store_sqlite::SqliteReceiptStore::open(path).test_unwrap())
                as Arc<dyn chio_kernel::ReceiptStore>
        });
    let evaluator = RequestEvaluator::new_with_durable_stores(
        routes,
        keypair.clone(),
        "test-policy".to_string(),
        Arc::clone(&approval_store),
        Vec::new(),
        evaluator_receipt_store,
        revocation_store.clone(),
        true,
    )
    .test_unwrap()
    .with_verified_manifest_registry(crate::evaluator::compatibility_manifest_registry_for_tests());
    let egress_contract = default_upstream_egress_contract(&upstream).test_unwrap();
    let http_client = client_builder_with_contract(&egress_contract)
        .build()
        .test_unwrap();
    Arc::new(ProxyState {
        evaluator,
        signer_keypair: keypair,
        upstream,
        http_client,
        egress_contract,
        approval_admin: ApprovalAdmin::new(approval_store),
        receipt_log: Mutex::new(ReceiptLog { receipts }),
        tool_receipt_log: Mutex::new(ToolReceiptLog {
            receipts: tool_receipts,
        }),
        receipt_store,
        revocation_store,
        revoked_capability_ids: Mutex::new(revoked_capability_ids),
        trusted_capability_issuers,
        trusted_receipt_signers,
        sidecar_control_token: None,
        budget_store: None,
        mediation_hold_capable: false,
        mediation_kernel: None,
        reaper_handle: Mutex::new(None),
        allow_advisory,
        receipt_backend: "ephemeral",
        revocation_backend: "ephemeral",
    })
}

#[derive(Default)]
struct ObservedRevocationStore {
    queried_ids: std::sync::Mutex<Vec<String>>,
    revoked_ids: std::sync::Mutex<HashSet<String>>,
    fail_query_id: Option<String>,
}

impl ObservedRevocationStore {
    fn with_revoked(ids: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            queried_ids: std::sync::Mutex::new(Vec::new()),
            revoked_ids: std::sync::Mutex::new(ids.into_iter().map(str::to_string).collect()),
            fail_query_id: None,
        }
    }

    fn failing(capability_id: &str) -> Self {
        Self {
            fail_query_id: Some(capability_id.to_string()),
            ..Self::default()
        }
    }

    fn queried_ids(&self) -> Vec<String> {
        self.queried_ids.lock().test_unwrap().clone()
    }

    fn clear_queries(&self) {
        self.queried_ids.lock().test_unwrap().clear();
    }
}

impl chio_kernel::RevocationStore for ObservedRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, chio_kernel::RevocationStoreError> {
        self.queried_ids
            .lock()
            .test_unwrap()
            .push(capability_id.to_string());
        if self.fail_query_id.as_deref() == Some(capability_id) {
            return Err(chio_kernel::RevocationStoreError::Sync(
                "sensitive revocation backend /var/lib/chio/revocations.db".to_string(),
            ));
        }
        Ok(self
            .revoked_ids
            .lock()
            .test_unwrap()
            .contains(capability_id))
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, chio_kernel::RevocationStoreError> {
        Ok(self
            .revoked_ids
            .lock()
            .test_unwrap()
            .insert(capability_id.to_string()))
    }
}

/// Build proxy state whose upstream client aborts a hop after `timeout`, so a
/// stalled upstream surfaces inside the handler instead of hanging.
fn test_state_with_client_timeout(
    routes: Vec<RouteEntry>,
    upstream: String,
    timeout: std::time::Duration,
) -> Arc<ProxyState> {
    let keypair = Keypair::generate();
    let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
    let signer_public_key = keypair.public_key();
    let trusted_capability_issuers = vec![signer_public_key.clone()];
    let trusted_receipt_signers = vec![signer_public_key];
    let evaluator = RequestEvaluator::new_ephemeral_with_approval_store(
        routes,
        keypair.clone(),
        "test-policy".to_string(),
        Arc::clone(&approval_store),
    )
    .with_verified_manifest_registry(crate::evaluator::compatibility_manifest_registry_for_tests());
    let egress_contract = default_upstream_egress_contract(&upstream).test_unwrap();
    let http_client = client_builder_with_contract(&egress_contract)
        .timeout(timeout)
        .build()
        .test_unwrap();
    Arc::new(ProxyState {
        evaluator,
        signer_keypair: keypair,
        upstream,
        http_client,
        egress_contract,
        approval_admin: ApprovalAdmin::new(approval_store),
        receipt_log: Mutex::new(ReceiptLog {
            receipts: Vec::new(),
        }),
        tool_receipt_log: Mutex::new(ToolReceiptLog {
            receipts: Vec::new(),
        }),
        receipt_store: None,
        revocation_store: None,
        revoked_capability_ids: Mutex::new(HashSet::new()),
        trusted_capability_issuers,
        trusted_receipt_signers,
        sidecar_control_token: None,
        budget_store: None,
        mediation_hold_capable: false,
        mediation_kernel: None,
        reaper_handle: Mutex::new(None),
        allow_advisory: false,
        receipt_backend: "ephemeral",
        revocation_backend: "ephemeral",
    })
}

fn pending_approval_request(approval_id: &str) -> (ApprovalRequest, Keypair, Keypair) {
    let request_subject = Keypair::generate();
    let approver = Keypair::generate();
    let approval = ApprovalRequest {
        approval_id: approval_id.to_string(),
        policy_id: "policy-hitl".to_string(),
        subject_id: "agent-1".to_string(),
        capability_id: "cap-1".to_string(),
        subject_public_key: Some(request_subject.public_key()),
        tool_server: "srv".to_string(),
        tool_name: "tool".to_string(),
        action: "invoke".to_string(),
        parameter_hash: "hash-1".to_string(),
        expires_at: 4_000_000_000,
        callback_hint: None,
        created_at: 123,
        summary: "pending approval".to_string(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec!["force_approval".to_string()],
    };
    (approval, request_subject, approver)
}

fn signed_approval_response_token(
    approval_id: &str,
    subject: &Keypair,
    approver: &Keypair,
    decision: GovernedApprovalDecision,
) -> GovernedApprovalToken {
    let now = chrono::Utc::now().timestamp() as u64;
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("tok-{approval_id}"),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "hash-1".to_string(),
            threshold_proposal_hash: None,
            request_id: approval_id.to_string(),
            issued_at: now.saturating_sub(10),
            expires_at: now + 600,
            decision,
        },
        approver,
    )
    .test_unwrap()
}

fn temp_receipt_db_path() -> String {
    chio_test_support::private_fs::unique_sqlite_path("chio-api-protect-test")
        .to_string_lossy()
        .into_owned()
}

fn with_peer_addr(mut request: Request<Body>, peer: SocketAddr) -> Request<Body> {
    // The capped serve listener exposes the peer address as `CappedPeerAddr`, so
    // the sidecar-control checks read `ConnectInfo<CappedPeerAddr>`; mirror that
    // extension type here rather than the bare `SocketAddr`.
    request
        .extensions_mut()
        .insert(ConnectInfo(CappedPeerAddr(peer)));
    request
}

fn with_loopback_peer(request: Request<Body>) -> Request<Body> {
    with_peer_addr(request, SocketAddr::from(([127, 0, 0, 1], 4100)))
}

fn read_http_request<R: Read>(stream: &mut R) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = 0_usize;

    loop {
        let read = stream.read(&mut chunk).test_unwrap();
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

    String::from_utf8(request).test_unwrap()
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn write_http_response<W: Write>(
    stream: &mut W,
    status: u16,
    headers: &[(String, String)],
    body: &str,
) {
    let mut response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        http_status_text(status),
        body.len(),
    );
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    stream.write_all(response.as_bytes()).test_unwrap();
}

fn http_status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        502 => "Bad Gateway",
        _ => "Unknown",
    }
}

include!("tests/routes_and_proxy.rs");
include!("tests/revocation_and_control.rs");
include!("tests/sdk_and_readiness.rs");
