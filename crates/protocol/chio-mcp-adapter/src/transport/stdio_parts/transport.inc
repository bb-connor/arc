struct TransportInner {
    writer_tx: mpsc::SyncSender<WriterCommand>,
    next_id: u64,
}

#[derive(Clone, Copy, Debug)]
struct StdioRequestTimeouts {
    initialization: Duration,
    discovery: Duration,
    request: Duration,
}

impl Default for StdioRequestTimeouts {
    fn default() -> Self {
        Self {
            initialization: UPSTREAM_INITIALIZATION_TIMEOUT,
            discovery: UPSTREAM_DISCOVERY_TIMEOUT,
            request: UPSTREAM_REQUEST_TIMEOUT,
        }
    }
}

#[derive(Debug)]
enum ChildTerminalState {
    Running,
    Exited,
    Failed(String),
}

#[derive(Debug)]
struct ChildLifecycle {
    child: Option<ManagedChild>,
    terminal: ChildTerminalState,
}

enum NaturalExitPoll {
    Running,
    Stopped,
    Exited,
    Failed(AdapterError),
}

enum NaturalChildExit {
    Legacy,
    Caged(Box<chio_cage::CageEnforcementRecord>),
}

impl ChildLifecycle {
    fn new(child: ManagedChild) -> Self {
        Self {
            child: Some(child),
            terminal: ChildTerminalState::Running,
        }
    }
}

#[derive(Clone, Debug)]
struct ActiveCageReceiptPersistence {
    persistence: CageReceiptPersistence,
    bindings: chio_cage::CageReceiptBindings,
    started_at_unix_ms: u64,
}

impl ActiveCageReceiptPersistence {
    fn persist(&self, record: chio_cage::CageEnforcementRecord) -> Result<(), AdapterError> {
        self.persistence
            .persist(Some(self.bindings.clone()), record, self.started_at_unix_ms)
    }

    fn persist_failure(
        &self,
        state: chio_cage::CageEnforcementState,
        code: chio_cage::CageEnforcementFailureCode,
        stage: &str,
    ) -> Result<(), AdapterError> {
        let failure = chio_cage::CageEnforcementFailure::new(code, stage).map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "cage failure evidence construction failed: {error}"
            ))
        })?;
        let record = match state {
            chio_cage::CageEnforcementState::Unsupported => {
                chio_cage::CageEnforcementRecord::unsupported(failure)
            }
            chio_cage::CageEnforcementState::Rejected => {
                chio_cage::CageEnforcementRecord::rejected(failure)
            }
            chio_cage::CageEnforcementState::BootstrapFailed => {
                chio_cage::CageEnforcementRecord::bootstrap_failed(failure)
            }
            _ => {
                return Err(AdapterError::ConnectionFailed(
                    "cage failure receipt requested for a non-failure state".to_string(),
                ))
            }
        }
        .map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "cage failure record construction failed: {error}"
            ))
        })?;
        self.persist(record)
    }
}

#[derive(Debug)]
enum ManagedChild {
    Legacy(Child),
    Caged(Box<chio_cage::EnforcedChild>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeLaunchRequirement {
    LegacyAllowed,
    CageRequired,
}

fn dispatch_native_launch<T, E>(
    requirement: NativeLaunchRequirement,
    legacy: impl FnOnce() -> Result<T, E>,
    cage: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    match requirement {
        NativeLaunchRequirement::LegacyAllowed => legacy(),
        NativeLaunchRequirement::CageRequired => cage(),
    }
}

/// Verified inputs required to opt an MCP subprocess into cage enforcement.
#[derive(Clone)]
pub struct CageReceiptPersistence {
    attempt_id: String,
    context: chio_cage::CageReceiptSigningContext,
    signer: Arc<dyn SigningBackend>,
    trusted_signer: chio_core::PublicKey,
    receipt_store: Arc<dyn ReceiptStore>,
}

impl std::fmt::Debug for CageReceiptPersistence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CageReceiptPersistence")
            .field("attempt_id", &self.attempt_id)
            .field("context", &self.context)
            .field("signer", &"redacted")
            .field("trusted_signer", &self.trusted_signer)
            .field("receipt_store", &"configured")
            .finish()
    }
}

impl CageReceiptPersistence {
    pub fn new(
        attempt_id: impl Into<String>,
        context: chio_cage::CageReceiptSigningContext,
        signer: Arc<dyn SigningBackend>,
        trusted_signer: chio_core::PublicKey,
        receipt_store: Arc<dyn ReceiptStore>,
    ) -> Result<Self, AdapterError> {
        let attempt_id = attempt_id.into();
        if attempt_id.is_empty()
            || attempt_id.len() > 512
            || attempt_id.trim() != attempt_id
            || attempt_id
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return Err(AdapterError::ConnectionFailed(
                "cage receipt attempt identity is invalid".to_string(),
            ));
        }
        if !receipt_store.supports_native_security_receipts() {
            return Err(AdapterError::ConnectionFailed(
                "cage-required launch needs an authoritative native-security receipt store"
                    .to_string(),
            ));
        }
        if signer.public_key() != trusted_signer {
            return Err(AdapterError::ConnectionFailed(
                "cage receipt signer does not match the configured trusted kernel key".to_string(),
            ));
        }
        Ok(Self {
            attempt_id,
            context,
            signer,
            trusted_signer,
            receipt_store,
        })
    }

    fn persist(
        &self,
        bindings: Option<chio_cage::CageReceiptBindings>,
        record: chio_cage::CageEnforcementRecord,
        started_at_unix_ms: u64,
    ) -> Result<(), AdapterError> {
        let recorded_at_unix_ms = now_unix_ms()?;
        let body = chio_cage::CageReceiptBody::new(
            self.attempt_id.clone(),
            bindings,
            record,
            started_at_unix_ms,
            recorded_at_unix_ms,
        )
        .map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "cage release receipt construction failed: {error}"
            ))
        })?;
        let receipt = chio_cage::sign_cage_receipt(body, &self.context, self.signer.as_ref())
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "cage release receipt signing failed: {error}"
                ))
            })?;
        chio_cage::persist_signed_cage_receipt_with_trusted_key(
            &receipt,
            &self.trusted_signer,
            |receipt| self.receipt_store.append_chio_receipt(receipt),
        )
        .map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "cage release receipt persistence failed: {error:?}"
            ))
        })?;
        let loaded = self
            .receipt_store
            .load_chio_receipt(&receipt.id)
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "cage release receipt verification read failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                AdapterError::ConnectionFailed(
                    "cage release receipt was not queryable after persistence".to_string(),
                )
            })?;
        let expected = chio_core::canonical_json_bytes(&receipt).map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "cage release receipt verification encoding failed: {error}"
            ))
        })?;
        let observed = chio_core::canonical_json_bytes(&loaded).map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "persisted cage release receipt encoding failed: {error}"
            ))
        })?;
        if observed != expected {
            return Err(AdapterError::ConnectionFailed(
                "persisted cage release receipt differs from the signed envelope".to_string(),
            ));
        }
        Ok(())
    }
}

pub struct CageRequiredLaunch {
    manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    server_id: String,
    signed_manifest: chio_manifest::SignedManifest,
    compiled: chio_cage::CompiledCage,
    launch_options: chio_cage::CageLaunchOptions,
    receipt_persistence: CageReceiptPersistence,
    migration: chio_security_types::EnterpriseMigrationRuntimeBinding,
}

impl std::fmt::Debug for CageRequiredLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CageRequiredLaunch")
            .field("server_id", &self.server_id)
            .field("signed_manifest", &self.signed_manifest)
            .field("compiled", &self.compiled)
            .field("launch_options", &self.launch_options)
            .field("receipt_persistence", &self.receipt_persistence)
            .field("migration", &"durable")
            .finish()
    }
}

#[derive(Clone)]
pub struct LegacyNativeLaunchAuthorization {
    server_id: String,
    migration: chio_security_types::EnterpriseMigrationRuntimeBinding,
    manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
}

impl std::fmt::Debug for LegacyNativeLaunchAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LegacyNativeLaunchAuthorization")
            .field("server_id", &self.server_id)
            .field("migration", &"durable")
            .field("manifest_registry", &"verified")
            .finish()
    }
}

impl LegacyNativeLaunchAuthorization {
    pub fn new(
        server_id: impl Into<String>,
        migration: chio_security_types::EnterpriseMigrationRuntimeBinding,
        manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    ) -> Result<Self, AdapterError> {
        let server_id = server_id.into();
        validate_cage_migration_identity(&server_id, &migration)?;
        manifest_registry
            .authorize_cage_manifest(&server_id)
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "legacy MCP launch manifest authorization failed: {error}"
                ))
            })?;
        migration
            .require_legacy_fallback_permitted()
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "legacy MCP launch denied by enterprise migration state: {error}"
                ))
            })?;
        Ok(Self {
            server_id,
            migration,
            manifest_registry,
        })
    }

    fn revalidate(&self) -> Result<(), AdapterError> {
        validate_cage_migration_identity(&self.server_id, &self.migration)?;
        self.manifest_registry
            .authorize_cage_manifest(&self.server_id)
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "legacy MCP launch manifest authorization failed: {error}"
                ))
            })?;
        self.migration
            .require_legacy_fallback_permitted()
            .map_err(|error| {
                AdapterError::ConnectionFailed(format!(
                    "legacy MCP launch denied by enterprise migration state: {error}"
                ))
            })
    }

    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    #[must_use]
    pub fn requires_flow_runtime(&self) -> bool {
        self.manifest_registry.requires_flow_runtime()
    }
}

pub enum NativeMcpLaunch {
    LegacyAuthorized(Box<LegacyNativeLaunchAuthorization>),
    CageRequired(Box<CageRequiredLaunch>),
}

impl NativeMcpLaunch {
    #[must_use]
    pub fn server_id(&self) -> &str {
        match self {
            Self::LegacyAuthorized(authorization) => authorization.server_id(),
            Self::CageRequired(launch) => &launch.server_id,
        }
    }

    #[must_use]
    pub fn requires_flow_runtime(&self) -> bool {
        match self {
            Self::LegacyAuthorized(authorization) => authorization.requires_flow_runtime(),
            Self::CageRequired(launch) => launch.manifest_registry.requires_flow_runtime(),
        }
    }
}

pub trait NativeMcpLaunchFactory:
    Send + Sync + std::panic::RefUnwindSafe + std::panic::UnwindSafe
{
    /// Return a stable digest of the currently trusted launch-policy material.
    /// Resumable runtimes re-evaluate this value before accepting an old
    /// session so a policy replacement cannot inherit prior authorization.
    fn authorization_contract_digest(&self) -> Result<String, AdapterError>;

    fn prepare_launch(
        &self,
        command: &str,
        args: &[&str],
        expected_server_id: &str,
        admitted_manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    ) -> Result<NativeMcpLaunch, AdapterError>;
}

impl CageRequiredLaunch {
    /// Bind a compiled cage to the same live registry that authorized it.
    ///
    /// Construction and launch both re-derive the non-forgeable cage
    /// authorization. A different registry snapshot, signed envelope, server,
    /// tool topology, or native profile rejects before process dispatch.
    pub fn new(
        manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
        server_id: impl Into<String>,
        compiled: chio_cage::CompiledCage,
        receipt_persistence: CageReceiptPersistence,
        migration: chio_security_types::EnterpriseMigrationRuntimeBinding,
    ) -> Result<Self, AdapterError> {
        let server_id = server_id.into();
        validate_cage_migration_identity(&server_id, &migration)?;
        migration.require_enforced().map_err(|error| {
            AdapterError::ConnectionFailed(format!(
                "cage MCP launch denied by enterprise migration state: {error}"
            ))
        })?;
        let signed_manifest =
            validate_cage_registry_binding(manifest_registry.as_ref(), &server_id, &compiled)?
                .signed_manifest()
                .clone();
        if !receipt_persistence
            .receipt_store
            .supports_native_security_receipts()
        {
            return Err(AdapterError::ConnectionFailed(
                "cage-required launch receipt store is incapable of native-security persistence"
                    .to_string(),
            ));
        }
        Ok(Self {
            manifest_registry,
            server_id,
            signed_manifest,
            compiled,
            launch_options: chio_cage::CageLaunchOptions::default(),
            receipt_persistence,
            migration,
        })
    }

    #[must_use]
    pub fn with_launch_options(mut self, launch_options: chio_cage::CageLaunchOptions) -> Self {
        self.launch_options = launch_options;
        self
    }
}

fn validate_cage_migration_identity(
    server_id: &str,
    binding: &chio_security_types::EnterpriseMigrationRuntimeBinding,
) -> Result<(), AdapterError> {
    let state = binding.state();
    if state.key.scope_kind != chio_security_types::EnterpriseMigrationScopeKind::ToolServer
        || state.key.control != chio_security_types::EnterpriseMigrationControl::CageEnforcement
        || state.key.scope_id.as_str() != server_id
        || state.generation != state.stage.generation()
    {
        return Err(AdapterError::ConnectionFailed(
            "native MCP launch migration binding does not match the exact tool server and cage control"
                .to_string(),
        ));
    }
    Ok(())
}

struct ExpectedCageEvidence {
    manifest_digest: String,
    helper_binding_digest: String,
    target_binding_digest: String,
    target_identity: chio_cage::FileIdentity,
}

enum RequestMessage {
    Message(serde_json::Value),
    ReadError(String),
    Cancelled(String),
}

struct ActiveRequest {
    id: u64,
    sender: mpsc::SyncSender<RequestMessage>,
}

struct WriterCommand {
    bytes: Vec<u8>,
    completion: Option<mpsc::SyncSender<Result<(), String>>>,
}

struct BoundedStdioWriter {
    writer_tx: mpsc::SyncSender<WriterCommand>,
    shutdown_requested: Arc<AtomicBool>,
    buffer: Vec<u8>,
    deadline: Instant,
}

impl BoundedStdioWriter {
    fn new(
        writer_tx: mpsc::SyncSender<WriterCommand>,
        shutdown_requested: Arc<AtomicBool>,
        timeout: Duration,
    ) -> Self {
        Self {
            writer_tx,
            shutdown_requested,
            buffer: Vec::new(),
            deadline: Instant::now() + timeout,
        }
    }
}

impl Write for BoundedStdioWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.buffer.len().saturating_add(bytes.len()) > MAX_STDIO_MCP_FRAME_BYTES + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound MCP JSON-RPC frame exceeded the transport limit",
            ));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let command = WriterCommand {
            bytes: std::mem::take(&mut self.buffer),
            completion: Some(completion_tx),
        };
        self.writer_tx
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "MCP stdin writer queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "MCP stdin writer supervisor disconnected",
                ),
            })?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MCP stdin write exceeded its deadline",
            ));
        }
        loop {
            if self.shutdown_requested.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "MCP stdin write cancelled by shutdown",
                ));
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MCP stdin write exceeded its deadline",
                ));
            }
            let poll = std::cmp::min(UPSTREAM_REQUEST_POLL_INTERVAL, remaining);
            match completion_rx.recv_timeout(poll) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, error)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "MCP stdin writer completion disconnected",
                    ))
                }
            }
        }
    }
}

/// Spawns an MCP server as a subprocess and communicates via stdio.
///
/// MCP uses newline-delimited JSON-RPC over stdin/stdout. Each message is a
/// single JSON object terminated by `\n`. The transport handles the
/// `initialize` handshake automatically on construction.
///
/// The child process is killed on drop if it is still running.
pub struct StdioMcpTransport {
    inner: Mutex<TransportInner>,
    child_lifecycle: Arc<Mutex<ChildLifecycle>>,
    active_request: Arc<Mutex<Option<ActiveRequest>>>,
    notification_tx: mpsc::SyncSender<serde_json::Value>,
    notification_rx: Mutex<mpsc::Receiver<serde_json::Value>>,
    shutdown_requested: Arc<AtomicBool>,
    request_timeouts: StdioRequestTimeouts,
    capabilities: McpServerCapabilities,
    enforcement_evidence: Option<chio_cage::FullyEnforcedEvidence>,
    cage_receipts: Option<ActiveCageReceiptPersistence>,
}

impl StdioMcpTransport {
    /// Spawn an MCP subprocess under an exact durable migration decision.
    pub fn spawn(
        command: &str,
        args: &[&str],
        launch: NativeMcpLaunch,
    ) -> Result<Self, AdapterError> {
        match launch {
            NativeMcpLaunch::LegacyAuthorized(authorization) => {
                Self::spawn_legacy_authorized(command, args, *authorization)
            }
            NativeMcpLaunch::CageRequired(launch) => {
                Self::spawn_cage_required(command, args, *launch)
            }
        }
    }

    fn spawn_legacy_authorized(
        command: &str,
        args: &[&str],
        authorization: LegacyNativeLaunchAuthorization,
    ) -> Result<Self, AdapterError> {
        let admitted_manifest = authorization
            .manifest_registry
            .verified_manifest(&authorization.server_id)
            .ok_or_else(|| {
                AdapterError::ConnectionFailed(
                    "legacy MCP launch manifest disappeared from the verified registry".into(),
                )
            })?
            .manifest
            .clone();
        let transport = Self::spawn_legacy_with_gate(command, args, || authorization.revalidate())?;
        if let Err(error) = validate_signed_mcp_tool_surface(&transport, &admitted_manifest) {
            return Err(merge_cleanup_failures(
                error,
                [("legacy transport shutdown", transport.shutdown())],
            ));
        }
        Ok(transport)
    }

    #[cfg(test)]
    pub(crate) fn spawn_legacy_unchecked_for_test(
        command: &str,
        args: &[&str],
    ) -> Result<Self, AdapterError> {
        Self::spawn_legacy_with_gate(command, args, || Ok(()))
    }

    #[cfg(test)]
    fn spawn_legacy_unchecked_for_test_with_timeouts(
        command: &str,
        args: &[&str],
        request_timeouts: StdioRequestTimeouts,
    ) -> Result<Self, AdapterError> {
        Self::spawn_legacy_with_gate_and_timeouts(command, args, || Ok(()), request_timeouts)
    }

    fn spawn_legacy_with_gate(
        command: &str,
        args: &[&str],
        prelaunch: impl FnOnce() -> Result<(), AdapterError>,
    ) -> Result<Self, AdapterError> {
        Self::spawn_legacy_with_gate_and_timeouts(
            command,
            args,
            prelaunch,
            StdioRequestTimeouts::default(),
        )
    }

    fn spawn_legacy_with_gate_and_timeouts(
        command: &str,
        args: &[&str],
        prelaunch: impl FnOnce() -> Result<(), AdapterError>,
        request_timeouts: StdioRequestTimeouts,
    ) -> Result<Self, AdapterError> {
        let mut child_command = Command::new(command);
        child_command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        remove_chio_auth_env(&mut child_command);

        let mut child = dispatch_native_launch(
            NativeLaunchRequirement::LegacyAllowed,
            || {
                prelaunch()?;
                child_command.spawn().map_err(|e| {
                    AdapterError::ConnectionFailed(format!("failed to spawn {command}: {e}"))
                })
            },
            || {
                Err(AdapterError::ConnectionFailed(
                    "legacy MCP launch selected the cage backend".into(),
                ))
            },
        )?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AdapterError::ConnectionFailed("child stdout not captured".into()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AdapterError::ConnectionFailed("child stdin not captured".into()))?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| AdapterError::ConnectionFailed("child stderr not captured".into()))?;

        Self::from_launched_process(
            ManagedChild::Legacy(child),
            Box::new(stdin),
            Box::new(stdout),
            Box::new(stderr),
            None,
            None,
            request_timeouts,
        )
    }

    /// Launch an explicitly opted-in MCP server through the verified cage.
    ///
    /// Every cage admission, compilation, bootstrap, or evidence failure is
    /// terminal. This path never retries with the legacy direct spawn.
    pub fn spawn_cage_required(
        command: &str,
        args: &[&str],
        launch: CageRequiredLaunch,
    ) -> Result<Self, AdapterError> {
        let CageRequiredLaunch {
            manifest_registry,
            server_id,
            signed_manifest,
            compiled,
            launch_options,
            receipt_persistence,
            migration,
        } = launch;
        let started_at_unix_ms = now_unix_ms()?;
        let cage_receipts = ActiveCageReceiptPersistence {
            persistence: receipt_persistence,
            bindings: chio_cage::CageReceiptBindings::from_compiled(&compiled),
            started_at_unix_ms,
        };
        let expected = match validate_cage_required_inputs(
            command,
            args,
            manifest_registry.as_ref(),
            &server_id,
            &compiled,
        ) {
            Ok(expected) => expected,
            Err(error) => {
                let receipt_result = cage_receipts.persist_failure(
                    chio_cage::CageEnforcementState::Rejected,
                    chio_cage::CageEnforcementFailureCode::InvalidPlan,
                    "input_validation",
                );
                return Err(merge_cleanup_failures(
                    error,
                    [("failure receipt", receipt_result)],
                ));
            }
        };
        let prepared = match chio_cage::prepare_launch_with_options(compiled, launch_options) {
            Ok(prepared) => prepared,
            Err(error) => {
                let record = error.record().clone();
                let failure = record
                    .failure
                    .as_ref()
                    .map(|failure| format!("{:?} at {}", failure.code, failure.stage))
                    .unwrap_or_else(|| "missing fail-closed cage preparation evidence".to_string());
                let error = AdapterError::ConnectionFailed(format!(
                    "cage-required MCP launch preparation failed: {failure}"
                ));
                return Err(merge_cleanup_failures(
                    error,
                    [("preparation receipt", cage_receipts.persist(record))],
                ));
            }
        };
        if let Err(error) =
            validate_cage_migration_identity(&server_id, &migration).and_then(|()| {
                migration.require_enforced().map_err(|error| {
                    AdapterError::ConnectionFailed(format!(
                        "cage MCP launch denied by enterprise migration state: {error}"
                    ))
                })
            })
        {
            let receipt_result = cage_receipts.persist_failure(
                chio_cage::CageEnforcementState::Rejected,
                chio_cage::CageEnforcementFailureCode::InvalidPlan,
                "enterprise_migration",
            );
            return Err(merge_cleanup_failures(
                error,
                [("failure receipt", receipt_result)],
            ));
        }
        let launch_result = dispatch_native_launch(
            NativeLaunchRequirement::CageRequired,
            || {
                Err(AdapterError::ConnectionFailed(
                    "cage-required MCP launch selected the legacy backend".into(),
                ))
            },
            || Ok(chio_cage::launch_prepared(prepared, launch_options)),
        )?;
        let mut child = match launch_result {
            Ok(child) => child,
            Err(error) => {
                let record = error.record().clone();
                let failure = record
                    .failure
                    .as_ref()
                    .map(|failure| format!("{:?} at {}", failure.code, failure.stage))
                    .unwrap_or_else(|| "missing fail-closed cage failure evidence".to_string());
                let error = AdapterError::ConnectionFailed(format!(
                    "cage-required MCP launch failed: {failure}"
                ));
                return Err(merge_cleanup_failures(
                    error,
                    [("launch receipt", cage_receipts.persist(record))],
                ));
            }
        };
        if let Err(error) = validate_cage_evidence(child.evidence(), &expected) {
            return Err(fail_caged_child(
                error,
                child,
                &cage_receipts,
                Some((
                    chio_cage::CageEnforcementState::BootstrapFailed,
                    chio_cage::CageEnforcementFailureCode::ExecIdentityMismatch,
                    "evidence_validation",
                )),
            ));
        }
        let evidence = child.evidence().clone();
        let stdio = match child.take_stdio() {
            Some(stdio) => stdio,
            None => {
                return Err(fail_caged_child(
                    AdapterError::ConnectionFailed(
                        "cage-required launch returned no verified stdio handles".into(),
                    ),
                    child,
                    &cage_receipts,
                    Some((
                        chio_cage::CageEnforcementState::BootstrapFailed,
                        chio_cage::CageEnforcementFailureCode::DescriptorCountMismatch,
                        "stdio_release",
                    )),
                ));
            }
        };
        let fully_enforced =
            match chio_cage::CageEnforcementRecord::fully_enforced(evidence.clone()) {
                Ok(record) => record,
                Err(error) => {
                    return Err(fail_caged_child(
                        AdapterError::ConnectionFailed(format!(
                            "fully enforced cage record construction failed: {error}"
                        )),
                        child,
                        &cage_receipts,
                        Some((
                            chio_cage::CageEnforcementState::BootstrapFailed,
                            chio_cage::CageEnforcementFailureCode::StatusProtocolViolation,
                            "fully_enforced_record",
                        )),
                    ));
                }
            };
        if let Err(error) = cage_receipts.persist(fully_enforced) {
            return Err(fail_caged_child(error, child, &cage_receipts, None));
        }
        let (stdin, stdout, stderr) = stdio.into_parts();
        let transport = Self::from_launched_process(
            ManagedChild::Caged(Box::new(child)),
            Box::new(stdin),
            Box::new(stdout),
            Box::new(stderr),
            Some(evidence),
            Some(cage_receipts.clone()),
            StdioRequestTimeouts::default(),
        )?;
        if let Err(error) = validate_signed_mcp_tool_surface(&transport, &signed_manifest.manifest)
        {
            let shutdown_result = transport.shutdown();
            return Err(merge_cleanup_failures(
                error,
                [("terminal receipt", shutdown_result)],
            ));
        }
        Ok(transport)
    }

    fn from_launched_process(
        child: ManagedChild,
        stdin: Box<dyn Write + Send>,
        stdout: Box<dyn Read + Send>,
        stderr: Box<dyn Read + Send>,
        enforcement_evidence: Option<chio_cage::FullyEnforcedEvidence>,
        cage_receipts: Option<ActiveCageReceiptPersistence>,
        request_timeouts: StdioRequestTimeouts,
    ) -> Result<Self, AdapterError> {
        let child_lifecycle = Arc::new(Mutex::new(ChildLifecycle::new(child)));
        let shutdown_requested = Arc::new(AtomicBool::new(false));

        let (writer_tx, writer_rx) = mpsc::sync_channel(MAX_STDIO_MCP_BUFFERED_MESSAGES);
        if let Err(error) = std::thread::Builder::new()
            .name("chio-mcp-stdin".to_string())
            .spawn(move || run_stdio_writer(stdin, writer_rx))
        {
            shutdown_requested.store(true, Ordering::Release);
            let cleanup = finish_child_lifecycle(child_lifecycle.as_ref(), cage_receipts.as_ref());
            return Err(merge_cleanup_failures(
                AdapterError::ConnectionFailed(format!(
                    "failed to spawn MCP stdin supervisor: {error}"
                )),
                [("terminal receipt", cleanup)],
            ));
        }

        // Drain stderr so the child never blocks on a full channel.
        if let Err(error) = std::thread::Builder::new()
            .name("chio-mcp-stderr".to_string())
            .spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    match line {
                        Ok(text) => warn!(target: "chio_mcp_adapter::stderr", "{text}"),
                        Err(_) => break,
                    }
                }
            })
        {
            shutdown_requested.store(true, Ordering::Release);
            let cleanup = finish_child_lifecycle(child_lifecycle.as_ref(), cage_receipts.as_ref());
            return Err(merge_cleanup_failures(
                AdapterError::ConnectionFailed(format!(
                    "failed to spawn MCP stderr supervisor: {error}"
                )),
                [("terminal receipt", cleanup)],
            ));
        }

        let active_request = Arc::new(Mutex::new(None::<ActiveRequest>));
        let (notification_tx, notification_rx) =
            mpsc::sync_channel(MAX_STDIO_MCP_BUFFERED_MESSAGES);
        let reader_notification_tx = notification_tx.clone();
        let reader_active_request = Arc::clone(&active_request);
        let reader_child_lifecycle = Arc::clone(&child_lifecycle);
        let reader_cage_receipts = cage_receipts.clone();
        let reader_shutdown_requested = Arc::clone(&shutdown_requested);
        if let Err(error) = std::thread::Builder::new()
            .name("chio-mcp-stdout".to_string())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let message = match read_line(&mut reader) {
                        Ok(message) => message,
                        Err(error) => {
                            let terminal = finish_child_lifecycle(
                                reader_child_lifecycle.as_ref(),
                                reader_cage_receipts.as_ref(),
                            );
                            let terminal_error = merge_cleanup_failures(
                                error,
                                [("terminal receipt", terminal)],
                            )
                            .to_string();
                            if let Ok(mut active_request) = reader_active_request.lock() {
                                if let Some(active_request) = active_request.take() {
                                    let message = if reader_shutdown_requested
                                        .load(Ordering::Acquire)
                                    {
                                        RequestMessage::Cancelled(
                                            "upstream MCP request cancelled by shutdown"
                                                .to_string(),
                                        )
                                    } else {
                                        RequestMessage::ReadError(terminal_error)
                                    };
                                    let _ = active_request.sender.try_send(message);
                                }
                            }
                            break;
                        }
                    };

                    let active_sender = reader_active_request
                        .lock()
                        .ok()
                        .and_then(|active_request| {
                            active_request
                                .as_ref()
                                .map(|active_request| active_request.sender.clone())
                        });
                    if let Some(sender) = active_sender {
                        if sender
                            .try_send(RequestMessage::Message(message.clone()))
                            .is_ok()
                        {
                            continue;
                        }
                    }

                    if message.get("id").is_none() {
                        if reader_notification_tx.try_send(message).is_err() {
                            warn!(
                                target: "chio_mcp_adapter::transport",
                                "dropping upstream MCP notification because the bounded queue is full"
                            );
                        }
                    } else {
                        warn!(target: "chio_mcp_adapter::transport", "unexpected upstream message without an active request: {message}");
                    }
                }
            })
        {
            shutdown_requested.store(true, Ordering::Release);
            let cleanup = finish_child_lifecycle(
                child_lifecycle.as_ref(),
                cage_receipts.as_ref(),
            );
            return Err(merge_cleanup_failures(
                AdapterError::ConnectionFailed(format!(
                    "failed to spawn MCP stdout supervisor: {error}"
                )),
                [("terminal receipt", cleanup)],
            ));
        }

        let supervisor_child_lifecycle = Arc::clone(&child_lifecycle);
        let supervisor_cage_receipts = cage_receipts.clone();
        let supervisor_active_request = Arc::clone(&active_request);
        let supervisor_shutdown_requested = Arc::clone(&shutdown_requested);
        if let Err(error) = std::thread::Builder::new()
            .name("chio-mcp-child".to_string())
            .spawn(move || loop {
                match poll_natural_child_exit(
                    supervisor_child_lifecycle.as_ref(),
                    supervisor_cage_receipts.as_ref(),
                ) {
                    NaturalExitPoll::Running => {
                        std::thread::sleep(UPSTREAM_REQUEST_POLL_INTERVAL);
                    }
                    NaturalExitPoll::Stopped => break,
                    NaturalExitPoll::Exited => {
                        notify_active_request_after_terminal(
                            supervisor_active_request.as_ref(),
                            supervisor_shutdown_requested.load(Ordering::Acquire),
                            None,
                        );
                        break;
                    }
                    NaturalExitPoll::Failed(error) => {
                        notify_active_request_after_terminal(
                            supervisor_active_request.as_ref(),
                            supervisor_shutdown_requested.load(Ordering::Acquire),
                            Some(error.to_string()),
                        );
                        break;
                    }
                }
            })
        {
            shutdown_requested.store(true, Ordering::Release);
            let cleanup = finish_child_lifecycle(child_lifecycle.as_ref(), cage_receipts.as_ref());
            return Err(merge_cleanup_failures(
                AdapterError::ConnectionFailed(format!(
                    "failed to spawn MCP child supervisor: {error}"
                )),
                [("terminal receipt", cleanup)],
            ));
        }

        let mut transport = Self {
            inner: Mutex::new(TransportInner {
                writer_tx,
                next_id: 1,
            }),
            child_lifecycle,
            active_request,
            notification_tx,
            notification_rx: Mutex::new(notification_rx),
            shutdown_requested,
            request_timeouts,
            capabilities: McpServerCapabilities::default(),
            enforcement_evidence,
            cage_receipts,
        };

        let initialize_result = match transport.initialize() {
            Ok(result) => result,
            Err(error) => {
                let mut failures = vec![format!("MCP initialize failed: {error}")];
                if let Err(shutdown_error) = transport.shutdown() {
                    failures.push(format!(
                        "terminal receipt persistence failed: {shutdown_error}"
                    ));
                }
                return Err(AdapterError::ConnectionFailed(failures.join("; ")));
            }
        };
        transport.capabilities = McpServerCapabilities::from_initialize_result(&initialize_result);

        Ok(transport)
    }

    /// Verified cage evidence for cage-required transports. Legacy transports
    /// return `None` and never claim native confinement.
    #[must_use]
    pub fn enforcement_evidence(&self) -> Option<&chio_cage::FullyEnforcedEvidence> {
        self.enforcement_evidence.as_ref()
    }

    /// Send the MCP `initialize` handshake followed by the
    /// `notifications/initialized` notification.
    fn initialize(&self) -> Result<serde_json::Value, AdapterError> {
        let started = Instant::now();
        let params = json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": proxy_client_capabilities(),
            "clientInfo": {
                "name": "chio-mcp-adapter",
                "version": "0.1.0"
            }
        });

        let result = self.send_request("initialize", params)?;
        debug!("MCP initialize response: {result}");

        // Send the initialized notification (no id, no response expected).
        let remaining = self
            .request_timeouts
            .initialization
            .saturating_sub(started.elapsed());
        self.send_notification_with_timeout("notifications/initialized", json!({}), remaining)?;

        Ok(result)
    }

    /// Send a JSON-RPC request and wait for the matching response.
    ///
    /// Notifications (messages without an `id` field) received while waiting
    /// are either forwarded through the active nested-flow bridge or logged
    /// and skipped.
    fn send_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AdapterError> {
        self.send_request_with_nested_flow(method, params, None)
    }

    fn send_request_with_nested_flow(
        &self,
        method: &str,
        params: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, AdapterError> {
        self.ensure_request_can_start()?;
        let mut nested_flow_bridge = nested_flow_bridge;
        let (request_tx, request_rx) = mpsc::sync_channel(MAX_STDIO_MCP_BUFFERED_MESSAGES);

        let (id, request_id) = {
            let mut active_request = self
                .active_request
                .lock()
                .map_err(|e| AdapterError::ConnectionFailed(format!("lock poisoned: {e}")))?;
            if active_request.is_some() {
                return Err(AdapterError::ConnectionFailed(
                    "concurrent upstream MCP requests are not supported".into(),
                ));
            }
            if self.shutdown_requested.load(Ordering::Acquire) {
                return Err(AdapterError::ConnectionFailed(
                    "upstream MCP transport is shutting down".to_string(),
                ));
            }
            let mut inner = self
                .inner
                .lock()
                .map_err(|e| AdapterError::ConnectionFailed(format!("lock poisoned: {e}")))?;
            let id = inner.next_id;
            inner.next_id += 1;
            let request_id = json!(id);
            *active_request = Some(ActiveRequest {
                id,
                sender: request_tx,
            });
            (id, request_id)
        };

        let timeout = self.request_timeout_for(method);
        let started = Instant::now();
        let mut nested_task_runtime = NestedFlowTaskRuntime::default();

        let result = (|| {
            {
                let request = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": method,
                    "params": params,
                });
                let remaining = timeout.saturating_sub(started.elapsed());
                self.with_terminal_writer(remaining, |writer| send_line(writer, &request))?;
            }

            // Read routed messages until we get a response with a matching id.
            loop {
                if let Some(error) = self.request_interruption_error()? {
                    return Err(error);
                }
                let elapsed = started.elapsed();
                if elapsed >= timeout {
                    self.cancel_upstream_request(
                        &request_id,
                        &format!("MCP {method} request exceeded its {timeout:?} deadline"),
                    );
                    return Err(self.terminalize_connection_failure(
                        AdapterError::ConnectionFailed(format!(
                            "MCP {method} request timed out after {timeout:?}"
                        )),
                    ));
                }
                let poll_interval =
                    std::cmp::min(UPSTREAM_REQUEST_POLL_INTERVAL, timeout - elapsed);
                let response = match request_rx.recv_timeout(poll_interval) {
                    Ok(RequestMessage::Message(response)) => response,
                    Ok(RequestMessage::ReadError(error)) => {
                        return Err(AdapterError::ConnectionFailed(error));
                    }
                    Ok(RequestMessage::Cancelled(reason)) => {
                        return Err(AdapterError::ConnectionFailed(reason));
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if started.elapsed() >= timeout || nested_flow_bridge.is_none() {
                            continue;
                        }
                        let remaining = timeout.saturating_sub(started.elapsed());
                        self.with_terminal_writer(remaining, |writer| {
                            service_active_request_runtime(
                                &mut nested_flow_bridge,
                                &mut nested_task_runtime,
                                writer,
                                &request_id,
                            )
                        })?;
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(self.terminalize_connection_failure(
                            AdapterError::ConnectionFailed(
                                "upstream MCP reader disconnected".into(),
                            ),
                        ));
                    }
                };

                if self.shutdown_requested.load(Ordering::Acquire) {
                    continue;
                }

                if response.get("method").is_some() && response.get("id").is_some() {
                    let method = response
                        .get("method")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    if nested_flow_bridge.is_none() {
                        let remaining = timeout.saturating_sub(started.elapsed());
                        if self.with_terminal_writer(remaining, |writer| {
                            respond_to_upstream_roots_without_bridge(writer, &response)
                        })? {
                            continue;
                        }
                        return Err(AdapterError::NestedFlowDenied(format!(
                            "upstream server requested {method} without an active nested-flow bridge"
                        )));
                    }
                    let remaining = timeout.saturating_sub(started.elapsed());
                    self.with_terminal_writer(remaining, |writer| {
                        {
                            let bridge = nested_flow_bridge.as_deref_mut().ok_or_else(|| {
                                AdapterError::NestedFlowDenied(format!(
                                    "upstream server requested {method} without an active nested-flow bridge"
                                ))
                            })?;
                            respond_to_upstream_nested_flow(
                                writer,
                                &response,
                                bridge,
                                &mut nested_task_runtime,
                            )?;
                        }
                        service_active_request_runtime(
                            &mut nested_flow_bridge,
                            &mut nested_task_runtime,
                            writer,
                            &request_id,
                        )
                    })?;
                    continue;
                }

                if response.get("id").is_none() {
                    if is_nested_flow_notification(&response) {
                        let Some(bridge) = nested_flow_bridge.as_deref_mut() else {
                            self.queue_notification(response)?;
                            continue;
                        };
                        forward_upstream_notification(&response, bridge)?;
                    } else {
                        self.queue_notification(response)?;
                    }
                    if nested_flow_bridge.is_none() {
                        continue;
                    }
                    let remaining = timeout.saturating_sub(started.elapsed());
                    self.with_terminal_writer(remaining, |writer| {
                        service_active_request_runtime(
                            &mut nested_flow_bridge,
                            &mut nested_task_runtime,
                            writer,
                            &request_id,
                        )
                    })?;
                    continue;
                }

                if response["id"] != request_id {
                    debug!("MCP response id mismatch (expected {id}): {response}");
                    if nested_flow_bridge.is_none() {
                        continue;
                    }
                    let remaining = timeout.saturating_sub(started.elapsed());
                    self.with_terminal_writer(remaining, |writer| {
                        service_active_request_runtime(
                            &mut nested_flow_bridge,
                            &mut nested_task_runtime,
                            writer,
                            &request_id,
                        )
                    })?;
                    continue;
                }

                if let Some(err) = response.get("error") {
                    return Err(adapter_jsonrpc_error(err));
                }

                return response.get("result").cloned().ok_or_else(|| {
                    AdapterError::ParseError("response missing 'result' field".into())
                });
            }
        })();

        if let Ok(mut active_request) = self.active_request.lock() {
            if active_request
                .as_ref()
                .is_some_and(|active_request| active_request.id == id)
            {
                active_request.take();
            }
        }

        result
    }

    fn request_timeout_for(&self, method: &str) -> Duration {
        match method {
            "initialize" => self.request_timeouts.initialization,
            "tools/list" | "resources/list" | "resources/templates/list" | "prompts/list" => {
                self.request_timeouts.discovery
            }
            _ => self.request_timeouts.request,
        }
    }

    fn with_bounded_writer<T>(
        &self,
        timeout: Duration,
        action: impl FnOnce(&mut BoundedStdioWriter) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        if timeout.is_zero() {
            return Err(AdapterError::ConnectionFailed(
                "MCP stdin write deadline expired".to_string(),
            ));
        }
        let writer_tx = self
            .inner
            .lock()
            .map_err(|error| AdapterError::ConnectionFailed(format!("lock poisoned: {error}")))?
            .writer_tx
            .clone();
        let mut writer =
            BoundedStdioWriter::new(writer_tx, Arc::clone(&self.shutdown_requested), timeout);
        action(&mut writer)
    }

    fn with_terminal_writer<T>(
        &self,
        timeout: Duration,
        action: impl FnOnce(&mut BoundedStdioWriter) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        match self.with_bounded_writer(timeout, action) {
            Err(error @ AdapterError::ConnectionFailed(_)) => {
                Err(self.terminalize_connection_failure(error))
            }
            result => result,
        }
    }

    fn ensure_request_can_start(&self) -> Result<(), AdapterError> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(AdapterError::ConnectionFailed(
                "upstream MCP transport is shutting down".to_string(),
            ));
        }
        let lifecycle = self.child_lifecycle.lock().map_err(|error| {
            AdapterError::ConnectionFailed(format!("child lifecycle lock poisoned: {error}"))
        })?;
        match &lifecycle.terminal {
            ChildTerminalState::Running => Ok(()),
            ChildTerminalState::Exited => Err(AdapterError::ConnectionFailed(
                "upstream MCP process has exited".to_string(),
            )),
            ChildTerminalState::Failed(error) => Err(AdapterError::ConnectionFailed(format!(
                "upstream MCP terminal receipt persistence failed: {error}"
            ))),
        }
    }

    fn request_interruption_error(&self) -> Result<Option<AdapterError>, AdapterError> {
        let lifecycle = self.child_lifecycle.lock().map_err(|error| {
            AdapterError::ConnectionFailed(format!("child lifecycle lock poisoned: {error}"))
        })?;
        match &lifecycle.terminal {
            ChildTerminalState::Running => Ok(None),
            ChildTerminalState::Exited if self.shutdown_requested.load(Ordering::Acquire) => {
                Ok(Some(AdapterError::ConnectionFailed(
                    "upstream MCP request cancelled by shutdown".to_string(),
                )))
            }
            ChildTerminalState::Exited => Ok(Some(AdapterError::ConnectionFailed(
                "upstream MCP process exited before responding".to_string(),
            ))),
            ChildTerminalState::Failed(error) => Ok(Some(AdapterError::ConnectionFailed(format!(
                "upstream MCP terminal receipt persistence failed: {error}"
            )))),
        }
    }

    fn cancel_upstream_request(&self, request_id: &serde_json::Value, reason: &str) {
        let cancellation = json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": request_id,
                "reason": reason,
            }
        });
        let Ok(mut bytes) = serde_json::to_vec(&cancellation) else {
            return;
        };
        bytes.push(b'\n');
        if bytes.len() > MAX_STDIO_MCP_FRAME_BYTES + 1 {
            return;
        }
        let writer_tx = self.inner.lock().ok().map(|inner| inner.writer_tx.clone());
        if let Some(writer_tx) = writer_tx {
            let _ = writer_tx.try_send(WriterCommand {
                bytes,
                completion: None,
            });
        }
    }

    fn terminalize_connection_failure(&self, error: AdapterError) -> AdapterError {
        let terminal =
            finish_child_lifecycle(self.child_lifecycle.as_ref(), self.cage_receipts.as_ref());
        merge_cleanup_failures(error, [("terminal receipt", terminal)])
    }

    fn queue_notification(&self, message: serde_json::Value) -> Result<(), AdapterError> {
        self.notification_tx
            .try_send(message)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    AdapterError::ConnectionFailed("upstream notification queue is full".into())
                }
                mpsc::TrySendError::Disconnected(_) => AdapterError::ConnectionFailed(
                    "upstream notification queue disconnected".into(),
                ),
            })
    }

    fn send_notification_with_timeout(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<(), AdapterError> {
        self.ensure_request_can_start()?;
        let notification = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.with_terminal_writer(timeout, |writer| send_line(writer, &notification))
    }

    /// Gracefully shut down the MCP server by killing the child process.
    pub fn shutdown(&self) -> Result<(), AdapterError> {
        self.shutdown_requested.store(true, Ordering::Release);
        let active_request = self.active_request.lock().ok().and_then(|active_request| {
            active_request
                .as_ref()
                .map(|active_request| active_request.sender.clone())
        });
        let terminal =
            finish_child_lifecycle(self.child_lifecycle.as_ref(), self.cage_receipts.as_ref());
        if let Some(sender) = active_request {
            let message = match &terminal {
                Ok(()) => RequestMessage::Cancelled(
                    "upstream MCP request cancelled by shutdown".to_string(),
                ),
                Err(error) => RequestMessage::ReadError(format!(
                    "upstream MCP request cancelled by shutdown; terminal receipt persistence failed: {error}"
                )),
            };
            let _ = sender.try_send(message);
        }
        terminal
    }
}

impl McpTransport for StdioMcpTransport {
    fn capabilities(&self) -> McpServerCapabilities {
        self.capabilities.clone()
    }

    fn drain_notifications(&self) -> Vec<serde_json::Value> {
        let mut notifications = Vec::new();
        let Ok(notification_rx) = self.notification_rx.lock() else {
            return notifications;
        };

        while let Ok(notification) = notification_rx.try_recv() {
            notifications.push(notification);
        }

        notifications
    }

    fn shutdown(&self) -> Result<(), AdapterError> {
        StdioMcpTransport::shutdown(self)
    }

    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        let result = self.send_request("tools/list", json!({}))?;

        let tools_value = result.get("tools").ok_or_else(|| {
            AdapterError::ParseError("tools/list response missing 'tools'".into())
        })?;

        let tools: Vec<McpToolInfo> = serde_json::from_value(tools_value.clone())
            .map_err(|e| AdapterError::ParseError(format!("failed to parse tool list: {e}")))?;

        Ok(tools)
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<McpToolResult, AdapterError> {
        self.call_tool_with_nested_flow(tool_name, arguments, None)
    }

    fn call_tool_with_nested_flow(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<McpToolResult, AdapterError> {
        let params = json!({
            "name": tool_name,
            "arguments": arguments,
        });

        let result =
            self.send_request_with_nested_flow("tools/call", params, nested_flow_bridge)?;

        let tool_result: McpToolResult = serde_json::from_value(result)
            .map_err(|e| AdapterError::ParseError(format!("failed to parse tool result: {e}")))?;

        Ok(tool_result)
    }

    fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        let result = self.send_request("resources/list", json!({}))?;
        let resources_value = result.get("resources").ok_or_else(|| {
            AdapterError::ParseError("resources/list response missing 'resources'".into())
        })?;
        serde_json::from_value(resources_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse resources: {error}"))
        })
    }

    fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
        let result = self.send_request("resources/templates/list", json!({}))?;
        let templates_value = result.get("resourceTemplates").ok_or_else(|| {
            AdapterError::ParseError(
                "resources/templates/list response missing 'resourceTemplates'".into(),
            )
        })?;
        serde_json::from_value(templates_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse resource templates: {error}"))
        })
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
        let result = self.send_request("resources/read", json!({ "uri": uri }))?;
        let contents_value = result.get("contents").ok_or_else(|| {
            AdapterError::ParseError("resources/read response missing 'contents'".into())
        })?;
        let contents = serde_json::from_value(contents_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse resource contents: {error}"))
        })?;
        Ok(Some(contents))
    }

    fn list_prompts(&self) -> Result<Vec<PromptDefinition>, AdapterError> {
        let result = self.send_request("prompts/list", json!({}))?;
        let prompts_value = result.get("prompts").ok_or_else(|| {
            AdapterError::ParseError("prompts/list response missing 'prompts'".into())
        })?;
        serde_json::from_value(prompts_value.clone())
            .map_err(|error| AdapterError::ParseError(format!("failed to parse prompts: {error}")))
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, AdapterError> {
        let result = self.send_request(
            "prompts/get",
            json!({
                "name": name,
                "arguments": arguments,
            }),
        )?;
        let prompt = serde_json::from_value(result).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse prompt result: {error}"))
        })?;
        Ok(Some(prompt))
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        let result = self.send_request(
            "completion/complete",
            json!({
                "ref": {
                    "type": "ref/prompt",
                    "name": name,
                },
                "argument": {
                    "name": argument_name,
                    "value": value,
                },
                "context": {
                    "arguments": context,
                }
            }),
        )?;
        let completion_value = result.get("completion").ok_or_else(|| {
            AdapterError::ParseError("completion/complete response missing 'completion'".into())
        })?;
        let completion = serde_json::from_value(completion_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse prompt completion: {error}"))
        })?;
        Ok(Some(completion))
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        let result = self.send_request(
            "completion/complete",
            json!({
                "ref": {
                    "type": "ref/resource",
                    "uri": uri,
                },
                "argument": {
                    "name": argument_name,
                    "value": value,
                },
                "context": {
                    "arguments": context,
                }
            }),
        )?;
        let completion_value = result.get("completion").ok_or_else(|| {
            AdapterError::ParseError("completion/complete response missing 'completion'".into())
        })?;
        let completion = serde_json::from_value(completion_value.clone()).map_err(|error| {
            AdapterError::ParseError(format!("failed to parse resource completion: {error}"))
        })?;
        Ok(Some(completion))
    }
}

impl Drop for StdioMcpTransport {
    fn drop(&mut self) {
        self.shutdown_requested.store(true, Ordering::Release);
        if let Err(error) =
            finish_child_lifecycle(self.child_lifecycle.as_ref(), self.cage_receipts.as_ref())
        {
            warn!(
                target: "chio_mcp_adapter::transport",
                "cage terminal receipt persistence failed during drop: {error}"
            );
        }
    }
}
