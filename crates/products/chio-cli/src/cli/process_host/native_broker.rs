//! Brokered tools composed with the process host's original durable authority.

use std::collections::BTreeMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use chio_control_plane::security::adapters::NativeFlowResolver;
use chio_control_plane::security::adapters::{FlowResolverConfig, StructuredClassificationAdapter};
use chio_control_plane::DurableAdmissionRuntime;
use chio_core_types::{Ed25519Backend, PublicKey};
use chio_data_guards::{RegexClassificationRule, RegexStructuredClassifier};
use chio_kernel::admission_operation::{AdmissionIdentifier, NativeSecurityAuthorityBindingV1};
use chio_kernel::ChioKernel;
#[cfg(target_os = "linux")]
use chio_kernel::SecurityPreDispatchPolicy;
#[cfg(target_os = "linux")]
use chio_mcp_adapter::transport::StdioRequestTimeouts;
use chio_secret_broker::authority_ipc::AuthorityRpcServer;
use chio_secret_broker::ipc_client::{BrokerIpcClientConfig, BrokerPeerIdentity};
use chio_secret_broker::kernel_admission::{
    BrokerAdmissionParticipant, BrokerKernelAuthorityHandler, BrokerQuotaVerifier,
    BrokerQuotaVerifierConfig,
};
#[cfg(target_os = "linux")]
use chio_secret_broker::kernel_admission::{BrokerKernelConnection, BrokerNativeCaptureReader};
#[cfg(target_os = "linux")]
use chio_secret_broker::native_mcp::{NativeBrokerMcpRouter, NativeBrokerMcpTool};
use chio_security_types::ports::{ClassifierId, ClassifierVersion, RecordId};
use chio_security_types::InformationLabel;
use chio_store_sqlite::security_state::SqliteSecurityParticipantSource;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteSecurityStateStore};
use serde::{Deserialize, Serialize};

use super::state::{error, Config as HostConfig};
use crate::CliError;

#[path = "native_broker/classification.rs"]
mod classification;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub security: chio_process::ProcessSecurityProfile,
    pub quota: BrokerQuotaVerifierConfig,
    pub broker_identity: PublicKey,
    pub authority_seed_file: PathBuf,
    pub authority_public_key: PublicKey,
    pub revocation_authority_domain: String,
    pub ipc_timeout_ms: u64,
    pub classifier: ClassifierConfig,
    pub operator_input_floor: InformationLabel,
    pub fence_ttl_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClassifierConfig {
    pub id: String,
    pub version: String,
    pub rules: Vec<ClassifierRule>,
    pub category_labels: BTreeMap<String, InformationLabel>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClassifierRule {
    pub category: String,
    pub expression: String,
    pub confidence_basis_points: u16,
}

impl Config {
    pub fn validate_grant_quota(
        &self,
        scope: &chio_core_types::capability::scope::ChioScope,
    ) -> Result<(), CliError> {
        use chio_core_types::capability::scope::Operation;
        let mut matched = false;
        for grant in &scope.grants {
            if (grant.server_id == self.quota.server_id || grant.server_id == "*")
                && (grant.tool_name == self.quota.tool_name || grant.tool_name == "*")
                && grant.operations.contains(&Operation::Invoke)
            {
                matched = true;
                if grant.max_invocations.is_none_or(|limit| limit == 0) {
                    return Err(error(
                        "native broker tool grants require a positive max_invocations quota",
                    ));
                }
            }
        }
        if !matched {
            return Err(error("native broker route has no invocation grant"));
        }
        Ok(())
    }

    pub fn validate(&self, host: &HostConfig) -> Result<(), CliError> {
        self.security.validate().map_err(error)?;
        if !self.authority_seed_file.is_absolute() {
            return Err(error("broker authority seed path must be absolute"));
        }
        if !cfg!(target_os = "linux")
            || host.servers.len() != 1
            || !host.mailboxes.is_empty()
            || !host.spawn_templates.is_empty()
            || host.servers[0].id != self.quota.server_id
        {
            return Err(error(
                "native broker hosts require Linux and one explicitly selected broker server",
            ));
        }
        if self.ipc_timeout_ms == 0
            || self.ipc_timeout_ms > 30_000
            || self.fence_ttl_ms == 0
            || self.fence_ttl_ms > 30_000
        {
            return Err(error(
                "broker IPC and flow fence deadlines must be within 1..=30000 ms",
            ));
        }
        self.classification()?;
        BrokerQuotaVerifier::new(
            self.quota.clone(),
            Arc::new(chio_secret_broker::daemon::SystemDaemonClock),
        )
        .map_err(error)?;
        Ok(())
    }

    fn classification(
        &self,
    ) -> Result<(StructuredClassificationAdapter, FlowResolverConfig), CliError> {
        if self.classifier.rules.is_empty() {
            return Err(error(
                "native broker hosts require an explicit classifier rule set",
            ));
        }
        if self
            .classifier
            .rules
            .iter()
            .any(|rule| !self.classifier.category_labels.contains_key(&rule.category))
        {
            return Err(error(
                "native broker classifier rules require explicit category labels",
            ));
        }
        let rules = self
            .classifier
            .rules
            .iter()
            .map(|rule| {
                RegexClassificationRule::new(
                    &rule.category,
                    &rule.expression,
                    rule.confidence_basis_points,
                )
                .map_err(error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let classifier =
            RegexStructuredClassifier::new(&self.classifier.id, &self.classifier.version, rules)
                .map_err(error)?;
        let labels = self
            .classifier
            .category_labels
            .iter()
            .map(|(name, label)| Ok((RecordId::new(name).map_err(error)?, label.clone())))
            .collect::<Result<BTreeMap<_, _>, CliError>>()?;
        let mapping = chio_flow::CategoryLabelMap::new(
            ClassifierId::new(&self.classifier.id).map_err(error)?,
            ClassifierVersion::new(&self.classifier.version).map_err(error)?,
            labels,
        )
        .map_err(error)?;
        let config = FlowResolverConfig::new(
            self.operator_input_floor.clone(),
            mapping,
            BTreeMap::new(),
            self.fence_ttl_ms,
        )
        .map_err(error)?;
        Ok((
            StructuredClassificationAdapter::new(Arc::new(classification::BrokerBodyClassifier(
                classifier,
            ))),
            config,
        ))
    }

    fn authority_signer(&self) -> Result<Arc<Ed25519Backend>, CliError> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.authority_seed_file)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.uid()
                != chio_cage::BrokerPeerIdentity::current_process()
                    .map_err(error)?
                    .uid
        {
            return Err(error(
                "broker authority seed must be a private regular file owned by the host",
            ));
        }
        let mut seed = zeroize::Zeroizing::new(String::new());
        file.take(66).read_to_string(&mut seed)?;
        if metadata.len() > 65 {
            return Err(error("broker authority seed is oversized"));
        }
        let key = chio_core_types::Keypair::from_seed_hex(seed.trim()).map_err(error)?;
        if key.public_key() != self.authority_public_key {
            return Err(error(
                "broker authority seed differs from the operator's signing-key pin",
            ));
        }
        Ok(Arc::new(Ed25519Backend::new(key)))
    }
}

fn now_ms() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error)?
        .as_millis()
        .try_into()
        .map_err(error)
}

pub(super) fn prepare_call(
    state: &Path,
    process: &str,
    operation_key: &str,
    capability_path: &Path,
    request_path: &Path,
    output: &Path,
) -> Result<(), CliError> {
    use chio_secret_broker::protocol::{
        BrokerExecuteRequest, BrokerRequest, SignedBrokerCapability,
    };
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let host = super::state::Host::open(state, false)?;
    let config = host
        .record
        .config
        .native_broker
        .as_ref()
        .ok_or_else(|| error("host has no native broker route"))?;
    let capability: SignedBrokerCapability = super::state::read_json(capability_path)?;
    let request: BrokerRequest = super::state::read_json(request_path)?;
    let now = now_ms()? / 1000;
    chio_secret_broker::capability::verify_capability(
        &capability,
        &config.quota.issuer,
        &config.quota.audience,
        now,
        true,
    )
    .map_err(error)?;
    let invocation_id = host
        .runtime
        .request_id(process, operation_key)
        .map_err(error)?;
    let execute = host
        .runtime
        .registry()
        .with_process_signer(process, |parent, signer| {
            if capability.body.parent_capability_id != parent.id
                || capability.body.subject != parent.subject
                || now < parent.issued_at
                || now >= parent.expires_at
            {
                return Err(error(
                    "broker capability differs from the live process authority",
                ));
            }
            let proof = chio_secret_broker::proof::issue_request_proof(
                &capability,
                &request,
                uuid::Uuid::new_v4().to_string(),
                now,
                signer,
            )
            .map_err(error)?;
            Ok(BrokerExecuteRequest {
                schema: chio_secret_broker::protocol::BROKER_EXECUTE_SCHEMA.into(),
                capability,
                request,
                proof,
                invocation_id,
            })
        })
        .map_err(error)??;
    let bytes = chio_core_types::canonical_json_bytes(&execute).map_err(error)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn native_binding(
    config: &Config,
    directory: &Path,
    authority: &SqliteAuthorityStore,
    initializing: bool,
) -> Result<NativeSecurityAuthorityBindingV1, CliError> {
    // Changing the classifier or isolation policy cannot silently reset the
    // flow state of an existing host. Only initialization imports a source.
    let digest =
        chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(config).map_err(error)?);
    let selected =
        AdmissionIdentifier::try_new("security authority", format!("process-broker-{digest}"))
            .map_err(error)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    if initializing {
        let path = directory.join("native-source.db");
        drop(SqliteSecurityStateStore::open(&path).map_err(error)?);
        let source = SqliteSecurityParticipantSource::open(path).map_err(error)?;
        let expected = store
            .expect_security_participant_source(&selected, &selected, &source, &fence, now_ms()?)
            .map_err(error)?;
        store
            .import_security_participant_source(
                &selected,
                expected.expectation_id(),
                &source,
                &fence,
                now_ms()?,
            )
            .map_err(error)?;
        store
            .hydrate_security_participant_state(
                &selected,
                expected.expectation_id(),
                &fence,
                now_ms()?,
            )
            .map_err(error)?;
    }
    store
        .load_security_participant_state(&selected, &fence, now_ms()?)
        .map_err(error)?
        .ok_or_else(|| {
            error("process broker flow authority is absent or differs from initialization")
        })?
        .admission_binding()
        .map_err(error)
}

struct Components {
    #[cfg(target_os = "linux")]
    registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    #[cfg(target_os = "linux")]
    factory: Arc<crate::mcp_cli::SignedCagePolicyLaunchFactory>,
    #[cfg(target_os = "linux")]
    verifier: BrokerQuotaVerifier,
    participant: Arc<BrokerAdmissionParticipant>,
}

fn components(host: &HostConfig) -> Result<Components, CliError> {
    let config = host
        .native_broker
        .as_ref()
        .ok_or_else(|| error("missing broker host configuration"))?;
    config.validate(host)?;
    let server = &host.servers[0];
    let factory = Arc::new(crate::mcp_cli::SignedCagePolicyLaunchFactory::new(
        server
            .launch_policy
            .clone()
            .ok_or_else(|| error("missing broker launch policy"))?,
        server
            .launch_policy_signer
            .clone()
            .ok_or_else(|| error("missing broker launch trust root"))?,
    )?);
    let (registry, socket_path, peer) = factory.broker_admission_policy(&server.id)?;
    let admitted = registry
        .verified_manifest(&server.id)
        .ok_or_else(|| error("missing broker manifest"))?;
    if admitted.manifest.tools.len() != 1
        || admitted.manifest.tools[0].name != config.quota.tool_name
    {
        return Err(error("broker quota route differs from the signed manifest"));
    }
    let verifier = BrokerQuotaVerifier::new(
        config.quota.clone(),
        Arc::new(chio_secret_broker::daemon::SystemDaemonClock),
    )
    .map_err(error)?;
    let participant = Arc::new(
        BrokerAdmissionParticipant::new(
            BrokerIpcClientConfig {
                socket_path,
                tenant_scope: config.security.tenant_id.clone(),
                timeout_ms: config.ipc_timeout_ms,
                expected_peer: BrokerPeerIdentity {
                    process_id: peer.pid,
                    user_id: peer.uid,
                    group_id: peer.gid,
                },
                trusted_receipt_signer: config.broker_identity.clone(),
            },
            config.authority_signer()?,
            config.revocation_authority_domain.clone(),
            &verifier,
        )
        .map_err(error)?,
    );
    Ok(Components {
        #[cfg(target_os = "linux")]
        registry,
        #[cfg(target_os = "linux")]
        factory,
        #[cfg(target_os = "linux")]
        verifier,
        participant,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn completion_evidence(
    host: &super::state::Host,
    operation: &chio_kernel::admission_operation::AdmissionOperationId,
    response: &chio_secret_broker::protocol::BrokerExecuteResponse,
    observed_at: u64,
) -> Result<chio_secret_broker::kernel_admission::NativeBrokerCompletionEvidence, CliError> {
    let config = host
        .record
        .config
        .native_broker
        .as_ref()
        .ok_or_else(|| error("host has no broker route"))?;
    let selected = components(&host.record.config)?;
    let store = host
        .authority
        .local_authority_store()
        .ok_or_else(|| error("missing local broker custody"))?;
    let native = native_binding(config, host.lease.directory.path(), &store, false)?;
    let reader =
        BrokerNativeCaptureReader::new(&store, native, selected.participant.binding().clone())
            .map_err(error)?;
    reader
        .completed_evidence(&selected.participant, operation, response, observed_at)
        .map_err(error)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn connect(
    _: &HostConfig,
    _: &mut ChioKernel,
    _: &Path,
    _: &DurableAdmissionRuntime,
    _: bool,
) -> Result<super::serving::ConnectedServers, CliError> {
    Err(error("native broker hosts require Linux cage enforcement"))
}

#[cfg(target_os = "linux")]
pub(super) fn connect(
    host: &HostConfig,
    kernel: &mut ChioKernel,
    directory: &Path,
    authority: &DurableAdmissionRuntime,
    initializing: bool,
) -> Result<super::serving::ConnectedServers, CliError> {
    let config = host
        .native_broker
        .as_ref()
        .ok_or_else(|| error("missing broker host configuration"))?;
    let selected = components(host)?;
    let store = authority
        .local_authority_store()
        .ok_or_else(|| error("native broker requires the host's local authority"))?;
    let native = native_binding(config, directory, &store, initializing)?;
    let (classifier, flow_config) = config.classification()?;
    let resolver = NativeFlowResolver::new(
        native.clone(),
        selected.registry.clone(),
        Arc::new(classifier),
        Arc::new(chio_security_kernel::SystemSecurityClock),
        flow_config,
    )
    .map_err(error)?
    .with_captured_lifecycle();
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(resolver));
    let quota_binding = selected.verifier.binding().clone();
    kernel
        .set_supplemental_quota_verifier(Arc::new(selected.verifier), quota_binding)
        .map_err(error)?;
    kernel
        .set_supplemental_admission_participant(
            selected.participant.clone(),
            selected.participant.binding().clone(),
        )
        .map_err(error)?;
    let reader =
        BrokerNativeCaptureReader::new(&store, native, selected.participant.binding().clone())
            .map_err(error)?;
    let connection =
        Arc::new(BrokerKernelConnection::new(reader, selected.participant).map_err(error)?);
    let server = &host.servers[0];
    let manifest = selected
        .registry
        .verified_manifest(&server.id)
        .ok_or_else(|| error("missing broker manifest"))?
        .manifest
        .clone();
    let template = NativeBrokerMcpTool::new(
        server.command[0].clone(),
        server.command[1..].to_vec(),
        &server.id,
        selected.registry,
        selected.factory,
    )
    .map_err(error)?
    .with_request_timeouts(
        StdioRequestTimeouts::with_request_timeout_seconds(server.request_timeout_seconds)
            .map_err(error)?,
    );
    let router = NativeBrokerMcpRouter::new(connection, template).map_err(error)?;
    Ok((vec![Box::new(router)], vec![manifest], BTreeMap::new()))
}

/// Keeps the authenticated authority RPC live for the same host lifetime.
/// It reads original custody; it is not another admission or quota writer.
pub(super) struct AuthorityService {
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    socket: PathBuf,
    identity: (u64, u64),
}

impl AuthorityService {
    pub fn start(
        host: &HostConfig,
        directory: &Path,
        authority: &DurableAdmissionRuntime,
        kernel: Arc<ChioKernel>,
    ) -> Result<Self, CliError> {
        let config = host
            .native_broker
            .as_ref()
            .ok_or_else(|| error("missing broker host configuration"))?;
        let selected = components(host)?;
        let store = authority
            .local_authority_store()
            .ok_or_else(|| error("native broker requires the host's local authority"))?;
        let native = native_binding(config, directory, &store, false)?;
        let handler = Arc::new(
            BrokerKernelAuthorityHandler::new(&store, native, selected.participant, kernel.clone())
                .map_err(error)?,
        );
        let socket = directory.join("broker-authority.sock");
        // The host lease excludes another owner. Refuse live or substituted
        // paths; only a dead socket in this private directory can be removed.
        if let Ok(metadata) = std::fs::symlink_metadata(&socket) {
            if !metadata.file_type().is_socket()
                || metadata.uid() != std::fs::metadata(directory)?.uid()
            {
                return Err(error(
                    "broker authority socket path has another owner or type",
                ));
            }
            match std::os::unix::net::UnixStream::connect(&socket) {
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(&socket)?
                }
                _ => {
                    return Err(error(
                        "broker authority socket is live or cannot be safely recovered",
                    ))
                }
            }
        }
        let server = AuthorityRpcServer::bind(
            &socket,
            config.broker_identity.clone(),
            config.authority_signer()?,
            handler,
            30,
        )
        .map_err(error)?;
        server.set_nonblocking(true).map_err(error)?;
        let metadata = std::fs::symlink_metadata(&socket)?;
        let identity = (metadata.dev(), metadata.ino());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = std::thread::Builder::new()
            .name("chio-broker-authority".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    match server.try_serve_one() {
                        Ok(true) => {}
                        Ok(false) => std::thread::park_timeout(Duration::from_millis(10)),
                        Err(error) => {
                            tracing::error!(error = %error, "broker authority service failed");
                            let _ = kernel.emergency_stop("broker authority service failed");
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            socket,
            identity,
        })
    }
}

impl Drop for AuthorityService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
        if std::fs::symlink_metadata(&self.socket).is_ok_and(|metadata| {
            metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == self.identity
        }) {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}
