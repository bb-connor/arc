//! Broker execution selects its own dispatch-committed original. A request ID
//! is unique only within one authenticated tenant namespace of the store.
use super::*;

mod selector_controls;
use crate::authority_ipc::{AuthorityOperation, AuthorityResult, BrokerAuthorityHandler};
use crate::budget::{ExecutionHoldState, QueryExecutionHoldRequest};
use crate::ipc_client::{BrokerIpcClientConfig, BrokerPeerIdentity};
use crate::store::AttemptRegistration;
use chio_control_plane::security::adapters::{FlowResolverConfig, NativeFlowResolver};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::session::{
    EnterpriseIdentityContext, OAuthBearerFederatedClaims, OAuthBearerSessionAuthInput,
    OperationContext, RequestId, SessionAuthContext, SessionOperation, ToolCallOperation,
};
use chio_flow::CategoryLabelMap;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationId, AdmissionOperationState, AdmissionOperationStore,
    AdmissionOperationV1, DurableAdmissionMode, NativeSecurityAuthorityBindingV1,
    LOCAL_SYSTEM_TENANT_ID,
};
use chio_kernel::supplemental_admission::{
    SupplementalAdmissionParticipant, SupplementalAdmissionRegistrationContext,
};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, SecurityInvocationContext,
    SecurityInvocationContextV1, SecurityPreDispatchPolicy, SessionOperationResponse,
    ToolCallRequest, ToolCallResponse, ToolDispatchContext, ToolServerConnection, Verdict,
};
use chio_manifest::{
    sign_manifest, AuthoritativeToolPolicy, RuntimeToolTopology, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_security_kernel::SystemClock as SecurityClock;
use chio_security_types::clock::Clock as _;
use chio_security_types::ports::{
    BoundedVec, ClassificationPort, ClassificationRequest, ClassificationResult, ClassifierId,
    ClassifierVersion, IsolationEpochId, LineageId, PortError, PortResult, SessionId, TenantId,
};
use chio_security_types::{InformationLabel, PrincipalId};
use chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore;
use chio_store_sqlite::security_state::SqliteSecurityParticipantSource;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore, SqliteSecurityStateStore};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, Weak};

const REQUEST_ID: &str = "request-1";
const OTHER_TENANT: &str = "tenant-b";
const BROKER_SERVER: &str = "broker-tools";
const BROKER_TOOL: &str = "execute";
const TENANT_SERVER: &str = "tenant-tools";
const TENANT_TOOL: &str = "echo";
const INSTALLED_AUTHORITY_REFUSAL: &str = "broker request differs from installed kernel authority";

#[test]
fn broker_prepares_its_dispatch_committed_original_after_another_tenant_reuses_the_request_id(
) -> TestResult {
    let store = DurableStore::provision()?;
    store.admit_other_tenant(REQUEST_ID)?;
    let broker = store.native_broker(REQUEST_ID)?;
    let response = broker.evaluate(&broker.execute)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let dispatch = broker.only_dispatch()?;
    assert_eq!(dispatch.execute, broker.execute);
    assert_eq!(
        dispatch.stored.len(),
        2,
        "both tenants retain the request ID"
    );
    let original = dispatch
        .stored
        .iter()
        .find(|operation| operation.binding().operation_id().as_str() == dispatch.operation_id)
        .ok_or("the dispatching original is not stored under its request ID")?;
    let other = dispatch
        .stored
        .iter()
        .find(|operation| operation.binding().operation_id().as_str() != dispatch.operation_id)
        .ok_or("the other tenant's operation is not stored under the request ID")?;
    assert_eq!(original.state(), AdmissionOperationState::DispatchCommitted);
    assert_eq!(tenant(original), LOCAL_SYSTEM_TENANT_ID);
    assert_eq!(other.state(), AdmissionOperationState::Completed);
    assert_eq!(tenant(other), OTHER_TENANT);
    assert_eq!(
        other.binding().request_id(),
        original.binding().request_id()
    );
    assert_ne!(
        other.binding().replay_key(),
        original.binding().replay_key()
    );
    let (registration, registered) = dispatch
        .registration
        .clone()
        .ok_or("the original broker registration is not readable")?;
    assert_eq!(registration.ids.operation_id, dispatch.operation_id);
    assert_eq!(registration.invocation_id, REQUEST_ID);
    assert_eq!(registered, broker.execute);
    assert!(
        matches!(
            &dispatch.hold,
            Some(Ok(AuthorityResult::Hold(ExecutionHoldState::Captured(_))))
        ),
        "{:?}",
        dispatch.hold
    );
    assert_prepared(&dispatch.prepared, &registration, &broker.execute)?;
    assert_installed_authority_refusal(&dispatch.substituted);
    Ok(())
}

#[test]
fn broker_prepares_a_unique_original_and_refuses_unknown_or_reused_requests() -> TestResult {
    let store = DurableStore::provision()?;
    let broker = store.native_broker(REQUEST_ID)?;
    let response = broker.evaluate(&broker.execute)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let dispatch = broker.only_dispatch()?;
    assert_eq!(dispatch.execute, broker.execute);
    let [original] = dispatch.stored.as_slice() else {
        return Err(format!(
            "expected one stored request, found {}",
            dispatch.stored.len()
        )
        .into());
    };
    assert_eq!(
        original.binding().operation_id().as_str(),
        dispatch.operation_id
    );
    assert_eq!(original.state(), AdmissionOperationState::DispatchCommitted);
    assert_eq!(tenant(original), LOCAL_SYSTEM_TENANT_ID);
    let (registration, registered) = dispatch
        .registration
        .clone()
        .ok_or("the original broker registration is not readable")?;
    assert_eq!(registration.ids.operation_id, dispatch.operation_id);
    assert_eq!(registered, broker.execute);
    assert_prepared(&dispatch.prepared, &registration, &broker.execute)?;
    assert_installed_authority_refusal(&dispatch.substituted);

    let unknown = broker.reissued("request-unknown", "3".repeat(32))?;
    assert_installed_authority_refusal(
        &broker
            .handler
            .handle(&AuthorityOperation::PrepareExecution(Box::new(unknown))),
    );

    // The tenant namespace and request ID form a unique replay key, so the
    // same tenant cannot retain a second operation under this request ID.
    let reused = broker.reissued(REQUEST_ID, "4".repeat(32))?;
    let denied = broker.evaluate(&reused)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    let reason = denied.reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains(&format!(
            "request id conflicts with retained operation {}",
            dispatch.operation_id
        )),
        "{reason}"
    );
    assert_eq!(
        request_operations(&store.database, REQUEST_ID)?,
        [dispatch.operation_id.clone()]
    );
    assert_eq!(broker.pending_dispatches()?, 0);
    Ok(())
}

fn assert_prepared(
    result: &crate::Result<AuthorityResult>,
    registration: &AttemptRegistration,
    execute: &BrokerExecuteRequest,
) -> TestResult {
    let Ok(AuthorityResult::Prepared(context)) = result else {
        return Err(format!("broker refused its dispatch-committed original: {result:?}").into());
    };
    context.validate_for(execute)?;
    assert_eq!(
        context.admission_operation_id,
        registration.ids.operation_id
    );
    assert_eq!(context.quotas, registration.quotas);
    assert_eq!(
        context.authority_metadata_digest,
        registration.authority_metadata_digest
    );
    assert_eq!(
        context.revocation_authority_domain,
        registration.revocation_authority_domain
    );
    assert_eq!(
        context.prepared_dispatch_id,
        crate::registration::prepared_dispatch_id(registration, execute)?
    );
    assert!(context.source_receipt_ids.is_empty());
    Ok(())
}

fn assert_installed_authority_refusal(result: &crate::Result<AuthorityResult>) {
    assert!(
        matches!(
            result,
            Err(BrokerError::AuthorizationDenied(message)) if message == INSTALLED_AUTHORITY_REFUSAL
        ),
        "{result:?}"
    );
}

fn tenant(operation: &AdmissionOperationV1) -> String {
    operation
        .binding()
        .to_persisted()
        .authenticated_tenant_id
        .as_str()
        .to_owned()
}

fn request_operations(database: &Path, request_id: &str) -> TestResult<Vec<String>> {
    let connection = rusqlite::Connection::open(database)?;
    let mut statement = connection.prepare(
        "SELECT operation_id FROM admission_operations WHERE request_id = ?1 ORDER BY operation_id",
    )?;
    let identifiers = statement
        .query_map([request_id], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(identifiers)
}

fn scope(server: &str, tool: &str) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: server.into(),
            tool_name: tool.into(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(4),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    }
}

/// One provisioned authority database reopened by successive serving owners.
struct DurableStore {
    database: PathBuf,
    locks: PathBuf,
    // Dropped last so every store handle closes before the files are removed.
    directory: tempfile::TempDir,
}

impl DurableStore {
    fn provision() -> TestResult<Self> {
        use std::os::unix::fs::PermissionsExt;
        let directory = crate::private_tempdir()?;
        let locks = directory.path().join("locks");
        std::fs::create_dir(&locks)?;
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("authority.db");
        SqliteAuthorityStore::provision(&database, &locks)?;
        Ok(Self {
            database,
            locks,
            directory,
        })
    }

    fn kernel(&self, authority: &SqliteAuthorityStore) -> TestResult<ChioKernel> {
        let signer = Keypair::generate();
        let mut kernel = ChioKernel::new(KernelConfig {
            ca_public_keys: vec![signer.public_key()],
            keypair: signer,
            max_delegation_depth: 5,
            policy_hash: "a".repeat(64),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: 30,
            max_stream_total_bytes: 1_048_576,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            allow_ephemeral_revocation_store: false,
            checkpoint_batch_size: 0,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: Default::default(),
        });
        let receipts = SqliteReceiptStore::open(self.directory.path().join("receipts.db"))?;
        receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
        kernel.set_receipt_store_handle(Arc::new(receipts))?;
        kernel.set_revocation_store(Box::new(authority.revocation_store()));
        kernel.set_budget_store(Box::new(authority.budget_store()));
        kernel.set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
        Ok(kernel)
    }

    /// A tenant-authenticated session operation retained by an earlier owner.
    fn admit_other_tenant(&self, request_id: &str) -> TestResult {
        let authority = SqliteAuthorityStore::open_serving(&self.database, &self.locks)?;
        let mut kernel = self.kernel(&authority)?;
        kernel.register_tool_server(Box::new(TenantTool));
        kernel.reconcile_durable_admission_startup()?;
        let agent = Keypair::generate();
        let capability =
            kernel.issue_capability(&agent.public_key(), scope(TENANT_SERVER, TENANT_TOOL), 300)?;
        let session = kernel.open_session(agent.public_key().to_hex(), vec![capability.clone()])?;
        kernel.set_session_auth_context(
            &session,
            SessionAuthContext::streamable_http_oauth_bearer_with_claims(
                OAuthBearerSessionAuthInput {
                    principal: Some("oidc:https://issuer.example#sub:tenant-b".into()),
                    issuer: Some("https://issuer.example".into()),
                    subject: Some(OTHER_TENANT.into()),
                    audience: Some("chio-mcp".into()),
                    scopes: vec!["mcp:invoke".into()],
                    federated_claims: OAuthBearerFederatedClaims::default(),
                    enterprise_identity: Some(EnterpriseIdentityContext {
                        provider_id: "broker-selection-tenant-provider".into(),
                        provider_kind: "oidc_jwks".into(),
                        principal: "oidc:https://issuer.example#sub:tenant-b".into(),
                        subject_key: "tenant-b-subject".into(),
                        tenant_id: Some(OTHER_TENANT.into()),
                        ..Default::default()
                    }),
                    token_fingerprint: Some("broker-selection-tenant-b".into()),
                    origin: None,
                },
            ),
        )?;
        kernel.activate_session(&session)?;
        let operation: ToolCallOperation = serde_json::from_value(json!({
            "capability": capability, "server_id": TENANT_SERVER, "tool_name": TENANT_TOOL,
            "arguments": {"tenant": OTHER_TENANT},
        }))?;
        let response = kernel.evaluate_session_operation(
            &OperationContext::new(
                session,
                RequestId::new(request_id),
                agent.public_key().to_hex(),
            ),
            &SessionOperation::ToolCall(Box::new(operation)),
        )?;
        let SessionOperationResponse::ToolCall(response) = response else {
            return Err("tenant operation omitted its tool response".into());
        };
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(response.receipt.tenant_id.as_deref(), Some(OTHER_TENANT));
        drop(kernel);
        drop(authority);
        Ok(())
    }

    /// The current owner's native broker route, served by the production
    /// authority handler installed behind the authority RPC server.
    fn native_broker(&self, request_id: &str) -> TestResult<NativeBroker> {
        self.native_broker_with_selector_probe(request_id, false)
    }

    fn native_broker_with_selector_probe(
        &self,
        request_id: &str,
        selector_probe: bool,
    ) -> TestResult<NativeBroker> {
        let authority = SqliteAuthorityStore::open_serving(&self.database, &self.locks)?;
        let mut kernel = self.kernel(&authority)?;
        let native = initialize_native(&authority, self.directory.path())?;
        let resolver = NativeFlowResolver::new(
            native.clone(),
            manifests()?,
            Arc::new(EmptyClassifier),
            Arc::new(SecurityClock),
            FlowResolverConfig::new(
                InformationLabel::bottom(),
                CategoryLabelMap::new(
                    ClassifierId::new("classifier.empty")?,
                    ClassifierVersion::new("1")?,
                    BTreeMap::new(),
                )?,
                BTreeMap::new(),
                // The egress fence is wall-clock custody. It must outlive
                // durable SQLite writes under a loaded parallel debug run.
                60_000,
            )?,
        )?
        .with_captured_lifecycle();
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(resolver));
        let (fixture_verifier, mut execute, _) = fixture()?;
        let verifier = BrokerQuotaVerifier::new(
            fixture_verifier.config,
            Arc::new(crate::daemon::SystemClock),
        )?;
        let participant = Arc::new(BrokerAdmissionParticipant::new(
            BrokerIpcClientConfig {
                socket_path: self.directory.path().join("broker.sock"),
                tenant_scope: "broker-original-selection".into(),
                timeout_ms: 1000,
                expected_peer: BrokerPeerIdentity {
                    process_id: 100,
                    user_id: 1000,
                    group_id: 1000,
                },
                trusted_receipt_signer: Keypair::from_seed(&[35; 32]).public_key(),
            },
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[34; 32]))),
            "broker-revocation-domain".into(),
            &verifier,
        )?);
        let selector_controls = if selector_probe {
            Some(selector_controls::LiveControls::new(
                &authority,
                &native,
                &participant,
                &verifier,
                self.directory.path(),
            )?)
        } else {
            None
        };
        let selected = verifier.binding().clone();
        kernel.set_supplemental_quota_verifier(Arc::new(verifier), selected)?;
        kernel.set_supplemental_admission_participant(
            Arc::new(AcceptRegistration),
            participant.binding().clone(),
        )?;
        let probe = Arc::new(BrokerProbe {
            handler: OnceLock::new(),
            selector_controls,
            reader: BrokerNativeCaptureReader::new(
                &authority,
                native.clone(),
                participant.binding().clone(),
            )?,
            participant: participant.clone(),
            store: authority.admission_operation_store(),
            database: self.database.clone(),
            delivering: Mutex::new(None),
            dispatches: Mutex::new(Vec::new()),
        });
        kernel.register_tool_server(Box::new(ProbeConnection(probe.clone())));
        kernel.reconcile_durable_admission_startup()?;
        let caller = Keypair::from_seed(&[32; 32]);
        let parent = kernel.issue_capability(
            &caller.public_key(),
            scope(BROKER_SERVER, BROKER_TOOL),
            300,
        )?;
        kernel.register_delegation_parent(&parent)?;
        let now = crate::daemon::SystemClock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::as_secs)?;
        let mut body = execute.capability.body;
        body.parent_capability_id = parent.id.clone();
        body.issued_at_unix_seconds = now;
        body.not_before_unix_seconds = now;
        body.expires_at_unix_seconds = now + 300;
        body.proof.nonce_ttl_seconds = 300;
        execute.capability = issue_capability(
            body,
            &Ed25519Backend::new(Keypair::from_seed(&[31; 32])),
            true,
        )?;
        execute.invocation_id = request_id.into();
        execute.proof = issue_request_proof(
            &execute.capability,
            &execute.request,
            "1".repeat(32),
            now,
            &caller,
        )?;
        let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            TenantId::new("broker-selection-tenant")?,
            SessionId::new("broker-selection-session")?,
            PrincipalId::new(caller.public_key().to_hex())?,
            IsolationEpochId::new("broker-selection-epoch")?,
            LineageId::new(&parent.id)?,
            1,
        ));
        let kernel = Arc::new(kernel);
        let handler = Arc::new(BrokerKernelAuthorityHandler::new(
            &authority,
            native,
            participant,
            kernel.clone(),
        )?);
        probe
            .handler
            .set(Arc::downgrade(&handler))
            .map_err(|_| "broker authority handler was already installed")?;
        Ok(NativeBroker {
            handler,
            kernel,
            probe,
            context,
            caller,
            parent,
            execute,
            _authority: authority,
        })
    }
}

struct NativeBroker {
    handler: Arc<BrokerKernelAuthorityHandler>,
    kernel: Arc<ChioKernel>,
    probe: Arc<BrokerProbe>,
    context: SecurityInvocationContext,
    caller: Keypair,
    parent: CapabilityToken,
    execute: BrokerExecuteRequest,
    _authority: SqliteAuthorityStore,
}

impl NativeBroker {
    fn evaluate(&self, execute: &BrokerExecuteRequest) -> TestResult<ToolCallResponse> {
        let request: ToolCallRequest = serde_json::from_value(json!({
            "request_id": execute.invocation_id, "capability": self.parent,
            "tool_name": BROKER_TOOL, "server_id": BROKER_SERVER,
            "agent_id": self.caller.public_key().to_hex(), "arguments": execute,
            "supplemental_authorization": {
                "signed_extension": String::from_utf8(canonical_json_bytes(execute)?)?,
            },
        }))?;
        Ok(self
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&request, &self.context)?)
    }

    fn reissued(&self, invocation_id: &str, nonce: String) -> TestResult<BrokerExecuteRequest> {
        let mut execute = self.execute.clone();
        execute.invocation_id = invocation_id.into();
        execute.proof = issue_request_proof(
            &execute.capability,
            &execute.request,
            nonce,
            crate::daemon::SystemClock
                .unix_millis()
                .map(chio_security_types::clock::UnixMillis::as_secs)?,
            &self.caller,
        )?;
        Ok(execute)
    }

    fn only_dispatch(&self) -> TestResult<Dispatch> {
        let observed = std::mem::take(
            &mut *self
                .probe
                .dispatches
                .lock()
                .map_err(|_| "dispatch record lock")?,
        );
        let [dispatch]: [std::result::Result<Dispatch, String>; 1] =
            observed.try_into().map_err(|all: Vec<_>| {
                format!("expected one broker dispatch, observed {}", all.len())
            })?;
        Ok(dispatch?)
    }

    fn pending_dispatches(&self) -> TestResult<usize> {
        Ok(self
            .probe
            .dispatches
            .lock()
            .map_err(|_| "dispatch record lock")?
            .len())
    }
}

/// What the broker authority observed while the kernel dispatched.
struct Dispatch {
    operation_id: String,
    execute: BrokerExecuteRequest,
    stored: Vec<AdmissionOperationV1>,
    registration: Option<(AttemptRegistration, BrokerExecuteRequest)>,
    hold: Option<crate::Result<AuthorityResult>>,
    prepared: crate::Result<AuthorityResult>,
    substituted: crate::Result<AuthorityResult>,
    selector_report: Option<selector_controls::LiveReport>,
}

struct BrokerProbe {
    handler: OnceLock<Weak<BrokerKernelAuthorityHandler>>,
    selector_controls: Option<selector_controls::LiveControls>,
    reader: BrokerNativeCaptureReader,
    participant: Arc<BrokerAdmissionParticipant>,
    store: SqliteAdmissionOperationStore,
    database: PathBuf,
    delivering: Mutex<Option<String>>,
    dispatches: Mutex<Vec<std::result::Result<Dispatch, String>>>,
}

impl BrokerProbe {
    fn observe(&self, arguments: Value) -> TestResult<Dispatch> {
        let execute: BrokerExecuteRequest = serde_json::from_value(arguments)?;
        let operation_id = self
            .delivering
            .lock()
            .map_err(|_| "delivery record lock")?
            .take()
            .ok_or("dispatch arrived without its delivery context")?;
        let now = self.store.observed_authority_time()?.get();
        let mut stored = Vec::new();
        for identifier in request_operations(&self.database, &execute.invocation_id)? {
            stored.push(
                self.store
                    .load_by_operation_id(&AdmissionOperationId::from_persisted(identifier)?)?
                    .ok_or("a listed operation disappeared")?,
            );
        }
        let registration = self.reader.read_registration(
            self.participant.as_ref(),
            &AdmissionOperationId::from_persisted(operation_id.clone())?,
            now,
        )?;
        let handler = self
            .handler
            .get()
            .and_then(Weak::upgrade)
            .ok_or("broker authority handler is not installed")?;
        let hold = registration.as_ref().map(|(registration, _)| {
            handler.handle(&AuthorityOperation::QueryExecutionHold(
                QueryExecutionHoldRequest {
                    operation_id: registration.ids.operation_id.clone(),
                    invocation_id: registration.invocation_id.clone(),
                    parent_capability_id: registration.parent_capability_id.clone(),
                    broker_capability_id: registration.broker_capability_id.clone(),
                    hold_id: registration.ids.hold_id.clone(),
                    authorize_event_id: registration.ids.authorize_event_id.clone(),
                    reverse_event_id: registration.ids.reverse_event_id.clone(),
                    capture_event_id: registration.ids.capture_event_id.clone(),
                },
            ))
        });
        let prepared = handler.handle(&AuthorityOperation::PrepareExecution(Box::new(
            execute.clone(),
        )));
        let mut altered = execute.clone();
        altered.proof.body.nonce = "2".repeat(32);
        let substituted = handler.handle(&AuthorityOperation::PrepareExecution(Box::new(altered)));
        let selector_report = self
            .selector_controls
            .as_ref()
            .map(|controls| controls.observe(&execute));
        Ok(Dispatch {
            operation_id,
            execute,
            stored,
            registration,
            hold,
            prepared,
            substituted,
            selector_report,
        })
    }
}

struct ProbeConnection(Arc<BrokerProbe>);

#[async_trait::async_trait]
impl ToolServerConnection for ProbeConnection {
    fn server_id(&self) -> &str {
        BROKER_SERVER
    }
    fn tool_names(&self) -> Vec<String> {
        vec![BROKER_TOOL.into()]
    }
    async fn prepare_delivery(
        &self,
        context: &ToolDispatchContext,
    ) -> std::result::Result<(), KernelError> {
        *self
            .0
            .delivering
            .lock()
            .map_err(|_| KernelError::GuardDenied("delivery record lock".into()))? =
            Some(context.operation_id().to_owned());
        Ok(())
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let observed = self.0.observe(arguments).map_err(|error| error.to_string());
        self.0
            .dispatches
            .lock()
            .map_err(|_| KernelError::GuardDenied("dispatch record lock".into()))?
            .push(observed);
        Ok(json!({"completed": true}))
    }
}

struct TenantTool;

#[async_trait::async_trait]
impl ToolServerConnection for TenantTool {
    fn server_id(&self) -> &str {
        TENANT_SERVER
    }
    fn tool_names(&self) -> Vec<String> {
        vec![TENANT_TOOL.into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Ok(json!({"tenant": OTHER_TENANT}))
    }
}

/// The broker daemon is not part of this boundary. The original registration
/// is reconstructed from kernel custody by the installed reader.
struct AcceptRegistration;

impl SupplementalAdmissionParticipant for AcceptRegistration {
    fn register_original(
        &self,
        _: &SupplementalAdmissionRegistrationContext<'_>,
    ) -> std::result::Result<(), SupplementalQuotaVerifierError> {
        Ok(())
    }
}

fn initialize_native(
    authority: &SqliteAuthorityStore,
    directory: &Path,
) -> TestResult<NativeSecurityAuthorityBindingV1> {
    let source_path = directory.join("native-source.sqlite3");
    drop(SqliteSecurityStateStore::open(&source_path)?);
    let source = SqliteSecurityParticipantSource::open(source_path)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let selected = AdmissionIdentifier::try_new("authority", "broker-original-selection")?;
    let now: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let expected =
        store.expect_security_participant_source(&selected, &selected, &source, &fence, now)?;
    store.import_security_participant_source(
        &selected,
        expected.expectation_id(),
        &source,
        &fence,
        now,
    )?;
    Ok(store
        .hydrate_security_participant_state(&selected, expected.expectation_id(), &fence, now)?
        .admission_binding()?)
}

fn manifests() -> TestResult<Arc<VerifiedManifestRegistry>> {
    let signer = Keypair::from_seed(&[73; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.into(),
        server_id: BROKER_SERVER.into(),
        name: "Broker tools".into(),
        description: None,
        version: "1.0.0".into(),
        tools: vec![ToolDefinition {
            name: BROKER_TOOL.into(),
            description: "Execute through the credential broker".into(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations::default(),
            latency_hint: None,
            flow: Some(ToolFlowDeclaration::new(
                Some(InformationLabel::bottom()),
                Some(InformationLabel::bottom()),
                true,
                BTreeSet::new(),
            )?),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        InformationLabel::bottom(),
        BTreeSet::new(),
    )?;
    let mut registry = VerifiedManifestRegistry::default();
    registry.register(
        sign_manifest(&manifest, &signer)?,
        &signer.public_key(),
        &BTreeMap::from([(BROKER_TOOL.into(), policy)]),
        &BTreeMap::from([(BROKER_TOOL.into(), RuntimeToolTopology::remote())]),
    )?;
    Ok(Arc::new(registry))
}

struct EmptyClassifier;

impl ClassificationPort for EmptyClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        Ok(ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: request.payload_digest,
            classifier_id: ClassifierId::new("classifier.empty").map_err(PortError::from)?,
            classifier_version: ClassifierVersion::new("1").map_err(PortError::from)?,
            findings: BoundedVec::new(Vec::new()).map_err(|_| PortError::invalid_data())?,
        })
    }
}
