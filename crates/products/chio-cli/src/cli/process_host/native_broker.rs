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
    BrokerKernelAuthorityHandler, BrokerQuotaVerifier, BrokerQuotaVerifierConfig,
    BrokerRouteConfig, BrokerRouteSet,
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

#[path = "native_broker/config.rs"]
mod config;
pub(super) use config::Config;
use config::RouteConfig;
#[path = "native_broker/payload.rs"]
mod payload;
#[path = "native_broker/preparation.rs"]
pub(super) mod preparation;

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
    let route = config
        .routes
        .iter()
        .find(|route| route.quota.audience == capability.body.audience)
        .ok_or_else(|| error("broker capability audience is not an installed route"))?;
    let now = now_ms()? / 1000;
    chio_secret_broker::capability::verify_capability(
        &capability,
        &route.quota.issuer,
        &route.quota.audience,
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

#[cfg(target_os = "linux")]
struct RouteLaunch {
    registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    factory: Arc<crate::mcp_cli::SignedCagePolicyLaunchFactory>,
}

struct Components {
    #[cfg(target_os = "linux")]
    registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    #[cfg(target_os = "linux")]
    launches: BTreeMap<String, RouteLaunch>,
    routes: Arc<BrokerRouteSet>,
}

fn components(host: &HostConfig) -> Result<Components, CliError> {
    let config = host
        .native_broker
        .as_ref()
        .ok_or_else(|| error("missing broker host configuration"))?;
    config.validate(host)?;
    let signer = config.authority_signer()?;
    let mut route_configs = Vec::with_capacity(config.routes.len());
    #[cfg(target_os = "linux")]
    let mut merged = chio_manifest::VerifiedManifestRegistry::default();
    #[cfg(target_os = "linux")]
    let mut launches = BTreeMap::new();
    for route in &config.routes {
        let server = host
            .servers
            .iter()
            .find(|server| server.id == route.quota.server_id)
            .ok_or_else(|| error("missing broker server"))?;
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
            || admitted.manifest.tools[0].name != route.quota.tool_name
        {
            return Err(error("broker quota route differs from the signed manifest"));
        }
        route_configs.push(BrokerRouteConfig {
            quota: route.quota.clone(),
            ipc: BrokerIpcClientConfig {
                socket_path,
                tenant_scope: config.security.tenant_id.clone(),
                timeout_ms: route.ipc_timeout_ms,
                expected_peer: BrokerPeerIdentity {
                    process_id: peer.pid,
                    user_id: peer.uid,
                    group_id: peer.gid,
                },
                trusted_receipt_signer: route.broker_identity.clone(),
            },
            authority_signer: signer.clone(),
            revocation_authority_domain: route.revocation_authority_domain.clone(),
        });
        #[cfg(target_os = "linux")]
        {
            merged.merge_verified(&registry).map_err(error)?;
            launches.insert(server.id.clone(), RouteLaunch { registry, factory });
        }
    }
    let routes = Arc::new(
        BrokerRouteSet::new(
            route_configs,
            Arc::new(chio_secret_broker::daemon::SystemClock),
        )
        .map_err(error)?,
    );
    Ok(Components {
        #[cfg(target_os = "linux")]
        registry: Arc::new(merged),
        #[cfg(target_os = "linux")]
        launches,
        routes,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn completion_evidence(
    host: &super::state::Host,
    server: &str,
    tool: &str,
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
    let participant = selected.routes.participant(server, tool).map_err(error)?;
    let reader = BrokerNativeCaptureReader::new(
        &store,
        native,
        selected.routes.participant_binding().clone(),
    )
    .map_err(error)?;
    reader
        .completed_evidence(&participant, operation, response, observed_at)
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
        Arc::new(chio_security_kernel::SystemClock),
        flow_config,
    )
    .map_err(error)?
    .with_captured_lifecycle();
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(resolver));
    kernel
        .set_supplemental_quota_verifier(
            selected.routes.clone(),
            selected.routes.verifier_binding().clone(),
        )
        .map_err(error)?;
    kernel
        .set_supplemental_admission_participant(
            selected.routes.clone(),
            selected.routes.participant_binding().clone(),
        )
        .map_err(error)?;
    let mut connections: Vec<Box<dyn chio_kernel::ToolServerConnection>> = Vec::new();
    let mut manifests = Vec::new();
    for server in &host.servers {
        let launch = selected
            .launches
            .get(&server.id)
            .ok_or_else(|| error("missing broker launch"))?;
        let manifest = launch
            .registry
            .verified_manifest(&server.id)
            .ok_or_else(|| error("missing broker manifest"))?
            .manifest
            .clone();
        let [tool] = manifest.tools.as_slice() else {
            return Err(error("broker manifest must select one tool"));
        };
        let participant = selected
            .routes
            .participant(&server.id, &tool.name)
            .map_err(error)?;
        let reader = BrokerNativeCaptureReader::new(
            &store,
            native.clone(),
            selected.routes.participant_binding().clone(),
        )
        .map_err(error)?;
        let connection = Arc::new(BrokerKernelConnection::new(reader, participant).map_err(error)?);
        let template = NativeBrokerMcpTool::new(
            server.command[0].clone(),
            server.command[1..].to_vec(),
            &server.id,
            launch.registry.clone(),
            launch.factory.clone(),
        )
        .map_err(error)?
        .with_request_timeouts(
            StdioRequestTimeouts::with_request_timeout_seconds(server.request_timeout_seconds)
                .map_err(error)?,
        );
        connections.push(Box::new(
            NativeBrokerMcpRouter::new(connection, template).map_err(error)?,
        ));
        manifests.push(manifest);
    }
    Ok((connections, manifests, BTreeMap::new()))
}

#[path = "native_broker/authority.rs"]
mod authority;
pub(super) use authority::AuthorityService;
