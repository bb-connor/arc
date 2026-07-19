use std::collections::BTreeSet;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(unix)]
use std::thread::{self, JoinHandle};
#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, PublicKey, SigningBackend};
#[cfg(test)]
use chio_core::crypto::{Ed25519Backend, Keypair};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::receipt::signing::ReceiptSigningHandle;
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::{
    BlockingToolServerAdapter, BlockingToolServerConnection, CapabilitySnapshot, ChioKernel,
    KernelError, ReceiptStore,
};
use chio_secret_broker::authority_ipc::AuthorityRpcServer;
use chio_secret_broker::capability::capability_digest;
use chio_secret_broker::ipc_client::{
    BrokerIpcClient, BrokerIpcClientConfig, BrokerIpcExecutionOutcome,
};
use chio_secret_broker::protocol::{
    BrokerExecuteFailure, BrokerExecuteRequest, BrokerExecuteResponse,
};
use chio_secret_broker::revocation::{
    BrokerRevocationRequest, BrokerRevocationSnapshot, BrokerRevocations, CapabilityLiveness,
    CapabilityLivenessRequest, LiveParentCapability,
};
use chio_secret_broker::service::broker_request_digest;
use chio_secret_broker::{BrokerError, Result as BrokerResult};
use chio_store_sqlite::SqliteAdmissionCaptureAuthority;

use super::broker::{
    BrokerAuthorityRpcHandler, BrokerControlAuthority, BrokerIntegrationError,
    BrokerIntegrationRuntime, BrokerMigrationEnforcer,
};

const CAPABILITY_LIVENESS_SNAPSHOT_DOMAIN: &[u8] = b"chio.broker-parent-liveness-snapshot.v1\0";
const BROKER_RELEASE_RECEIPT_METADATA_SCHEMA: &str = "chio.broker.release-receipt-metadata.v1";

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum BrokerReleaseEvidence {
    Success {
        receipt_reference: String,
        receipt: Box<chio_secret_broker::receipt::SignedBrokerReceipt>,
    },
    Failure {
        diagnostic_code: String,
        receipt_reference: String,
        receipt: Box<chio_secret_broker::receipt::SignedBrokerFailureReceipt>,
    },
    TransportFailure {
        diagnostic_code: String,
        request_digest: String,
        capability_digest: String,
    },
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerReleaseReceiptMetadata {
    schema: String,
    evidence: BrokerReleaseEvidence,
}

pub struct BrokerReleaseReceiptPersistence {
    receipt_store: Arc<dyn ReceiptStore>,
    signer: Arc<dyn SigningBackend>,
    trusted_signer: PublicKey,
    server_id: String,
    tool_name: String,
    tenant_id: Option<String>,
}

impl BrokerReleaseReceiptPersistence {
    pub fn new(
        receipt_store: Arc<dyn ReceiptStore>,
        signer: Arc<dyn SigningBackend>,
        trusted_signer: PublicKey,
        server_id: String,
        tool_name: String,
        tenant_id: Option<String>,
    ) -> Result<Self, BrokerIntegrationError> {
        validate_identifier(&server_id, "broker receipt server id")?;
        validate_identifier(&tool_name, "broker receipt tool name")?;
        if let Some(tenant_id) = &tenant_id {
            validate_identifier(tenant_id, "broker receipt tenant id")?;
        }
        if !receipt_store.supports_native_security_receipts() {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker route requires an authoritative native-security receipt store".to_string(),
            ));
        }
        if signer.public_key() != trusted_signer {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker release receipt signer does not match its configured trust root"
                    .to_string(),
            ));
        }
        Ok(Self {
            receipt_store,
            signer,
            trusted_signer,
            server_id,
            tool_name,
            tenant_id,
        })
    }

    pub fn persist_success(
        &self,
        request: &BrokerExecuteRequest,
        response: &BrokerExecuteResponse,
    ) -> Result<ChioReceipt, BrokerIntegrationError> {
        self.persist(
            request,
            response.receipt.body.issued_at_unix_seconds,
            Some(Decision::Allow),
            BrokerReleaseEvidence::Success {
                receipt_reference: response.receipt_reference.clone(),
                receipt: Box::new(response.receipt.clone()),
            },
        )
    }

    pub fn persist_failure(
        &self,
        request: &BrokerExecuteRequest,
        failure: &BrokerExecuteFailure,
    ) -> Result<ChioReceipt, BrokerIntegrationError> {
        self.persist(
            request,
            failure.receipt.body.issued_at_unix_seconds,
            Some(Decision::Deny {
                reason: failure.diagnostic_code.clone(),
                guard: "broker-release-evidence".to_string(),
            }),
            BrokerReleaseEvidence::Failure {
                diagnostic_code: failure.diagnostic_code.clone(),
                receipt_reference: failure.receipt_reference.clone(),
                receipt: Box::new(failure.receipt.clone()),
            },
        )
    }

    pub fn persist_transport_failure(
        &self,
        request: &BrokerExecuteRequest,
        diagnostic_code: String,
    ) -> Result<ChioReceipt, BrokerIntegrationError> {
        let request_digest = broker_request_digest(request).map_err(integration_from_broker)?;
        let capability_digest =
            capability_digest(&request.capability).map_err(integration_from_broker)?;
        self.persist(
            request,
            now_unix_seconds()?,
            Some(Decision::Deny {
                reason: diagnostic_code.clone(),
                guard: "broker-transport".to_string(),
            }),
            BrokerReleaseEvidence::TransportFailure {
                diagnostic_code,
                request_digest,
                capability_digest,
            },
        )
    }

    fn persist(
        &self,
        request: &BrokerExecuteRequest,
        timestamp: u64,
        decision: Option<Decision>,
        evidence: BrokerReleaseEvidence,
    ) -> Result<ChioReceipt, BrokerIntegrationError> {
        let metadata = BrokerReleaseReceiptMetadata {
            schema: BROKER_RELEASE_RECEIPT_METADATA_SCHEMA.to_string(),
            evidence,
        };
        let handle = ReceiptSigningHandle::from_content(&metadata).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker release receipt handle failed: {error}"
            ))
        })?;
        let parameters = serde_json::json!({
            "brokerCapabilityId": request.capability.body.capability_id.clone(),
            "invocationId": request.invocation_id.clone(),
            "outcome": if matches!(&decision, Some(Decision::Allow)) { "success" } else { "failure" },
        });
        let body = ChioReceiptBody {
            id: String::new(),
            timestamp,
            capability_id: request.capability.body.capability_id.clone(),
            tool_server: self.server_id.clone(),
            tool_name: self.tool_name.clone(),
            action: ToolCallAction::from_parameters(parameters).map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker release receipt action failed: {error}"
                ))
            })?,
            decision,
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::Summary,
            actor_chain: Vec::new(),
            content_hash: handle.content_hash().to_string(),
            policy_hash: capability_digest(&request.capability).map_err(integration_from_broker)?,
            evidence: Vec::new(),
            metadata: Some(serde_json::to_value(metadata).map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker release receipt metadata failed: {error}"
                ))
            })?),
            trust_level: TrustLevel::Mediated,
            tenant_id: self.tenant_id.clone(),
            kernel_key: self.trusted_signer.clone(),
            bbs_projection_version: None,
        };
        let receipt =
            ChioReceipt::sign_with_backend_using_handle(body, self.signer.as_ref(), handle)
                .map_err(|error| {
                    BrokerIntegrationError::InvalidConfiguration(format!(
                        "broker release receipt signing failed: {error}"
                    ))
                })?;
        if receipt.kernel_key != self.trusted_signer
            || !receipt.verify_signature().map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker release receipt trusted-key verification failed: {error}"
                ))
            })?
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker release receipt signer is not trusted".to_string(),
            ));
        }
        self.receipt_store
            .append_chio_receipt(&receipt)
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker release receipt persistence failed: {error}"
                ))
            })?;
        let loaded = self
            .receipt_store
            .load_chio_receipt(&receipt.id)
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker release receipt verification read failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                BrokerIntegrationError::InvalidConfiguration(
                    "broker release receipt was not queryable after persistence".to_string(),
                )
            })?;
        if canonical_json_bytes(&loaded).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "persisted broker release receipt encoding failed: {error}"
            ))
        })? != canonical_json_bytes(&receipt).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker release receipt encoding failed: {error}"
            ))
        })? {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "persisted broker release receipt differs from the signed envelope".to_string(),
            ));
        }
        Ok(loaded)
    }
}

pub struct ReceiptStoreCapabilityLiveness {
    receipts: Arc<dyn ReceiptStore>,
    parent_audience: String,
}

impl ReceiptStoreCapabilityLiveness {
    pub fn new(
        receipts: Arc<dyn ReceiptStore>,
        parent_audience: String,
    ) -> Result<Self, BrokerIntegrationError> {
        validate_identifier(&parent_audience, "broker parent audience")?;
        Ok(Self {
            receipts,
            parent_audience,
        })
    }
}

impl CapabilityLiveness for ReceiptStoreCapabilityLiveness {
    fn verify_live_parent(
        &self,
        request: &CapabilityLivenessRequest,
    ) -> BrokerResult<LiveParentCapability> {
        validate_identifier(&request.parent_capability_id, "parent capability id")
            .map_err(integration_as_broker)?;
        if request.expected_audience != self.parent_audience {
            return Err(BrokerError::AuthorizationDenied(
                "parent capability audience is not configured for broker execution".to_string(),
            ));
        }
        let parent = self
            .receipts
            .get_capability_snapshot(&request.parent_capability_id)
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!(
                    "parent capability snapshot lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                BrokerError::AuthorizationDenied(
                    "parent capability has no authoritative issuance snapshot".to_string(),
                )
            })?;
        let subject = PublicKey::from_hex(&parent.subject_key).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "stored parent capability subject is invalid: {error}"
            ))
        })?;
        if parent.capability_id != request.parent_capability_id
            || subject != request.expected_subject
            || request.now_unix_seconds >= parent.expires_at
        {
            return Err(BrokerError::AuthorizationDenied(
                "parent capability issuance snapshot is expired or misbound".to_string(),
            ));
        }
        let chain = self
            .receipts
            .get_capability_delegation_chain(&request.parent_capability_id)
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!(
                    "parent capability delegation snapshot failed: {error}"
                ))
            })?;
        validate_lineage(&chain, &parent)?;
        let mut delegation_ancestor_ids = chain
            .iter()
            .filter(|snapshot| snapshot.capability_id != parent.capability_id)
            .map(|snapshot| snapshot.capability_id.clone())
            .collect::<Vec<_>>();
        delegation_ancestor_ids
            .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if delegation_ancestor_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(BrokerError::AuthorityUnavailable(
                "stored parent delegation lineage contains duplicate identities".to_string(),
            ));
        }
        let canonical = canonical_json_bytes(&chain).map_err(|error| {
            BrokerError::AuthorityUnavailable(format!(
                "parent capability snapshot encoding failed: {error}"
            ))
        })?;
        let mut snapshot_input =
            Vec::with_capacity(CAPABILITY_LIVENESS_SNAPSHOT_DOMAIN.len() + canonical.len());
        snapshot_input.extend_from_slice(CAPABILITY_LIVENESS_SNAPSHOT_DOMAIN);
        snapshot_input.extend_from_slice(&canonical);
        Ok(LiveParentCapability {
            capability_id: parent.capability_id,
            subject,
            audience: self.parent_audience.clone(),
            delegation_ancestor_ids,
            expires_at_unix_seconds: parent.expires_at,
            verified_at_unix_seconds: request.now_unix_seconds,
            authority_snapshot_digest: sha256_hex(&snapshot_input),
        })
    }
}

fn validate_lineage(chain: &[CapabilitySnapshot], parent: &CapabilitySnapshot) -> BrokerResult<()> {
    if chain.is_empty() || chain.len() > 64 || chain.last() != Some(parent) {
        return Err(BrokerError::AuthorityUnavailable(
            "stored parent delegation lineage is empty, oversized, or incomplete".to_string(),
        ));
    }
    for pair in chain.windows(2) {
        if pair[1].parent_capability_id.as_deref() != Some(pair[0].capability_id.as_str())
            || pair[1].delegation_depth != pair[0].delegation_depth.saturating_add(1)
        {
            return Err(BrokerError::AuthorityUnavailable(
                "stored parent delegation lineage is discontinuous".to_string(),
            ));
        }
    }
    Ok(())
}

pub struct CombinedAuthorityBrokerRevocations {
    authority: Arc<SqliteAdmissionCaptureAuthority>,
    authority_domain: String,
}

impl CombinedAuthorityBrokerRevocations {
    pub fn new(
        authority: Arc<SqliteAdmissionCaptureAuthority>,
        authority_domain: String,
    ) -> Result<Self, BrokerIntegrationError> {
        validate_identifier(&authority_domain, "broker revocation authority domain")?;
        Ok(Self {
            authority,
            authority_domain,
        })
    }
}

impl BrokerRevocations for CombinedAuthorityBrokerRevocations {
    fn check_broker_revocation(
        &self,
        request: &BrokerRevocationRequest,
    ) -> BrokerResult<BrokerRevocationSnapshot> {
        if request.broker_capability_id == request.revocation_id {
            return Err(BrokerError::InvalidRequest(
                "broker capability and revocation identities must be distinct".to_string(),
            ));
        }
        let snapshot = self
            .authority
            .broker_revocation_snapshot(&[
                request.broker_capability_id.clone(),
                request.revocation_id.clone(),
            ])
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!(
                    "combined broker revocation snapshot failed: {error}"
                ))
            })?;
        Ok(BrokerRevocationSnapshot {
            revoked: !snapshot.revoked_ids().is_empty(),
            observed_at_unix_seconds: request.now_unix_seconds,
            commit_index: snapshot.revocation_commit_index(),
            authority_domain: self.authority_domain.clone(),
        })
    }
}

pub struct BrokerOnlyToolRoute {
    client: Arc<BrokerIpcClient>,
    receipt_persistence: Arc<BrokerReleaseReceiptPersistence>,
    server_id: String,
    tool_name: String,
    selected_provider_adapter_ids: BTreeSet<String>,
    migration: Arc<dyn BrokerMigrationEnforcer>,
}

impl BrokerOnlyToolRoute {
    pub(super) fn new(
        client: Arc<BrokerIpcClient>,
        receipt_persistence: Arc<BrokerReleaseReceiptPersistence>,
        server_id: String,
        tool_name: String,
        selected_provider_adapter_ids: BTreeSet<String>,
        migration: Arc<dyn BrokerMigrationEnforcer>,
    ) -> Result<Self, BrokerIntegrationError> {
        validate_identifier(&server_id, "broker route server id")?;
        validate_identifier(&tool_name, "broker route tool name")?;
        if selected_provider_adapter_ids.is_empty() || selected_provider_adapter_ids.len() > 64 {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "selected broker provider set is empty or oversized".to_string(),
            ));
        }
        for provider in &selected_provider_adapter_ids {
            validate_identifier(provider, "selected broker provider adapter id")?;
        }
        Ok(Self {
            client,
            receipt_persistence,
            server_id,
            tool_name,
            selected_provider_adapter_ids,
            migration,
        })
    }
}

impl BlockingToolServerConnection for BrokerOnlyToolRoute {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool_name.clone()]
    }

    fn invoke_blocking(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        if tool_name != self.tool_name {
            return Err(KernelError::ToolServerError(
                "broker-only route rejected an unregistered tool".to_string(),
            ));
        }
        let request: BrokerExecuteRequest = serde_json::from_value(arguments).map_err(|error| {
            KernelError::ToolServerError(format!("broker execution request is invalid: {error}"))
        })?;
        if !self
            .selected_provider_adapter_ids
            .contains(&request.capability.body.provider_adapter_id)
        {
            return Err(KernelError::ToolServerError(
                "provider is not selected for this broker-only route".to_string(),
            ));
        }
        self.migration
            .require_provider_enforced(&request.capability.body.credential.provider)
            .map_err(|error| {
                KernelError::ToolServerError(format!(
                    "enterprise migration enforcement denied broker dispatch: {error}"
                ))
            })?;
        match self.client.execute_evidenced(&request) {
            Ok(BrokerIpcExecutionOutcome::Success(response)) => {
                let response = *response;
                self.receipt_persistence
                    .persist_success(&request, &response)
                    .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                serde_json::to_value(response).map_err(|error| {
                    KernelError::ToolServerError(format!(
                        "broker execution response encoding failed: {error}"
                    ))
                })
            }
            Ok(BrokerIpcExecutionOutcome::Failure(failure)) => {
                let failure = *failure;
                self.receipt_persistence
                    .persist_failure(&request, &failure)
                    .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                Err(KernelError::ToolServerError(format!(
                    "broker-only execution denied with {}",
                    failure.diagnostic_code
                )))
            }
            Err(error) => {
                let diagnostic_code = format!("chio.broker.{}", error.diagnostic_code());
                self.receipt_persistence
                    .persist_transport_failure(&request, diagnostic_code.clone())
                    .map_err(|persistence_error| {
                        KernelError::ToolServerError(persistence_error.to_string())
                    })?;
                Err(KernelError::ToolServerError(format!(
                    "broker-only transport denied with {diagnostic_code}"
                )))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ProductionBrokerRuntimeConfig {
    pub authority_socket_path: PathBuf,
    pub authority_maximum_clock_skew_seconds: u64,
    pub broker_client: BrokerIpcClientConfig,
    pub broker_server_id: String,
    pub broker_tool_name: String,
    pub selected_provider_adapter_ids: BTreeSet<String>,
}

#[cfg(unix)]
pub(super) struct ProductionBrokerRuntime {
    runtime: Arc<BrokerIntegrationRuntime>,
    authority_server: Arc<AuthorityRpcServer>,
    authority_started: Arc<AtomicBool>,
    broker_client: Arc<BrokerIpcClient>,
    route: Arc<BrokerOnlyToolRoute>,
}

#[cfg(unix)]
pub(super) struct ProductionBrokerAuthorityHandle {
    shutdown: Arc<AtomicBool>,
    started: Arc<AtomicBool>,
    worker: Option<JoinHandle<BrokerResult<()>>>,
}

#[cfg(unix)]
impl ProductionBrokerAuthorityHandle {
    pub(super) fn shutdown(mut self) -> BrokerResult<()> {
        self.stop();
        self.join()
    }

    fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = &self.worker {
            worker.thread().unpark();
        }
    }

    fn join(&mut self) -> BrokerResult<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        match worker.join() {
            Ok(result) => result,
            Err(_) => {
                self.started.store(false, Ordering::Release);
                Err(BrokerError::AuthorityUnavailable(
                    "broker authority server terminated unexpectedly".to_string(),
                ))
            }
        }
    }
}

#[cfg(unix)]
impl Drop for ProductionBrokerAuthorityHandle {
    fn drop(&mut self) {
        self.stop();
        let _ = self.join();
    }
}

#[cfg(unix)]
pub(super) struct ProductionBrokerAuthorityBinding {
    pub(super) runtime: Arc<BrokerIntegrationRuntime>,
    pub(super) trusted_broker: PublicKey,
    pub(super) authority_signer: Arc<dyn SigningBackend>,
    pub(super) broker_client: Arc<BrokerIpcClient>,
    pub(super) liveness: Arc<dyn CapabilityLiveness>,
    pub(super) revocations: Arc<dyn BrokerRevocations>,
    pub(super) control: Arc<dyn BrokerControlAuthority>,
    pub(super) migration: Arc<dyn BrokerMigrationEnforcer>,
}

#[cfg(unix)]
pub(super) struct ProductionBrokerReceiptBinding {
    pub(super) store: Arc<dyn ReceiptStore>,
    pub(super) signer: Arc<dyn SigningBackend>,
    pub(super) trusted_signer: PublicKey,
    pub(super) tenant_id: Option<String>,
}

#[cfg(unix)]
impl ProductionBrokerRuntime {
    pub(super) fn bind_with_client(
        config: ProductionBrokerRuntimeConfig,
        authority: ProductionBrokerAuthorityBinding,
        receipts: ProductionBrokerReceiptBinding,
    ) -> Result<Self, BrokerIntegrationError> {
        let ProductionBrokerAuthorityBinding {
            runtime,
            trusted_broker,
            authority_signer,
            broker_client,
            liveness,
            revocations,
            control,
            migration,
        } = authority;
        let ProductionBrokerReceiptBinding {
            store: receipt_store,
            signer: release_receipt_signer,
            trusted_signer: trusted_release_receipt_signer,
            tenant_id: receipt_tenant_id,
        } = receipts;
        validate_runtime_config(&config, runtime.as_ref())?;
        let receipt_persistence = Arc::new(BrokerReleaseReceiptPersistence::new(
            receipt_store,
            release_receipt_signer,
            trusted_release_receipt_signer,
            config.broker_server_id.clone(),
            config.broker_tool_name.clone(),
            receipt_tenant_id,
        )?);
        let route = Arc::new(BrokerOnlyToolRoute::new(
            Arc::clone(&broker_client),
            receipt_persistence,
            config.broker_server_id,
            config.broker_tool_name,
            config.selected_provider_adapter_ids,
            migration,
        )?);
        let handler = Arc::new(BrokerAuthorityRpcHandler::new(
            Arc::clone(&runtime),
            liveness,
            revocations,
            control,
        )?);
        let authority_server = Arc::new(AuthorityRpcServer::bind(
            &config.authority_socket_path,
            trusted_broker,
            authority_signer,
            handler,
            config.authority_maximum_clock_skew_seconds,
        )?);
        Ok(Self {
            runtime,
            authority_server,
            authority_started: Arc::new(AtomicBool::new(false)),
            broker_client,
            route,
        })
    }

    pub(super) fn start_authority(
        &self,
    ) -> Result<ProductionBrokerAuthorityHandle, BrokerIntegrationError> {
        spawn_authority_server(
            Arc::clone(&self.authority_server),
            Arc::clone(&self.authority_started),
        )
    }

    pub(super) fn budget_store(&self) -> Arc<dyn BudgetStore> {
        self.runtime.concrete_execution_authority().budget_store()
    }

    pub(super) fn install_kernel_authorities_before_security_publication(
        &self,
        kernel: &mut ChioKernel,
    ) -> Result<(), BrokerIntegrationError> {
        if !self.authority_started.load(Ordering::Acquire) {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker authority service must be running before kernel installation".to_string(),
            ));
        }
        authenticate_broker_for_execution_readiness(self.broker_client.as_ref())?;
        self.runtime
            .concrete_execution_authority()
            .drain_compensated_release_outbox()?;
        self.runtime.install_kernel_admission(kernel)?;
        Ok(())
    }

    pub(super) fn register_kernel_route_after_security_publication(
        &self,
        kernel: &mut ChioKernel,
    ) -> Result<(), BrokerIntegrationError> {
        if !self.authority_started.load(Ordering::Acquire) {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker authority service must be running before route registration".to_string(),
            ));
        }
        authenticate_broker_for_execution_readiness(self.broker_client.as_ref())?;
        self.runtime
            .concrete_execution_authority()
            .drain_compensated_release_outbox()?;
        let budget_store = self.budget_store();
        if !kernel.governed_runtime_uses_budget_authority(&budget_store) {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "governed security runtime did not retain the broker budget authority".to_string(),
            ));
        }
        let route: Arc<dyn BlockingToolServerConnection> = self.route.clone();
        let adapter = BlockingToolServerAdapter::new(route)?;
        kernel.register_tool_server(Box::new(adapter));
        Ok(())
    }
}

#[cfg(unix)]
fn authenticate_broker_for_execution_readiness(
    broker_client: &BrokerIpcClient,
) -> Result<(), BrokerIntegrationError> {
    // brokerd binds this endpoint only after it has authenticated the
    // authority and reconciled pending attempts. Requiring the pinned IPC
    // peer here keeps kernel admission and route publication fail closed.
    drop(broker_client.connect_authenticated()?);
    Ok(())
}

#[cfg(unix)]
fn spawn_authority_server(
    server: Arc<AuthorityRpcServer>,
    started: Arc<AtomicBool>,
) -> Result<ProductionBrokerAuthorityHandle, BrokerIntegrationError> {
    started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| {
            BrokerIntegrationError::InvalidConfiguration(
                "broker authority service is already running".to_string(),
            )
        })?;
    if let Err(error) = server.set_nonblocking(true) {
        started.store(false, Ordering::Release);
        return Err(error.into());
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let worker_started = Arc::clone(&started);
    let worker = thread::Builder::new()
        .name("chio-broker-authority".to_string())
        .spawn(move || {
            let result = (|| {
                while !worker_shutdown.load(Ordering::Acquire) {
                    if !server.try_serve_one()? {
                        thread::park_timeout(Duration::from_millis(10));
                    }
                }
                Ok(())
            })();
            worker_started.store(false, Ordering::Release);
            result
        })
        .map_err(|error| {
            started.store(false, Ordering::Release);
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker authority service thread failed: {error}"
            ))
        })?;

    Ok(ProductionBrokerAuthorityHandle {
        shutdown,
        started,
        worker: Some(worker),
    })
}

fn validate_runtime_config(
    config: &ProductionBrokerRuntimeConfig,
    runtime: &BrokerIntegrationRuntime,
) -> Result<(), BrokerIntegrationError> {
    if !config.authority_socket_path.is_absolute()
        || config.authority_socket_path == config.broker_client.socket_path
        || config.authority_maximum_clock_skew_seconds == 0
        || config.authority_maximum_clock_skew_seconds > 30
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "production broker authority socket or clock skew is invalid".to_string(),
        ));
    }
    if runtime.broker_destination().server_id() != config.broker_server_id
        || runtime.broker_destination().tool_name() != config.broker_tool_name
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "broker verifier destination differs from the installed broker-only route".to_string(),
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), BrokerIntegrationError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} is empty, oversized, padded, or contains a control byte"
        )));
    }
    Ok(())
}

fn integration_as_broker(error: BrokerIntegrationError) -> BrokerError {
    BrokerError::AuthorityUnavailable(error.to_string())
}

fn integration_from_broker(error: BrokerError) -> BrokerIntegrationError {
    BrokerIntegrationError::InvalidConfiguration(format!(
        "broker release receipt binding failed with {}",
        error.diagnostic_code()
    ))
}

fn now_unix_seconds() -> Result<u64, BrokerIntegrationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().max(1))
        .map_err(|_| {
            BrokerIntegrationError::InvalidConfiguration(
                "system clock is before the Unix epoch".to_string(),
            )
        })
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use chio_secret_broker::authority_ipc::{
        AuthorityOperation, AuthorityResult, BrokerAuthorityHandler,
    };

    use super::*;

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }

    struct CapabilitiesOnlyHandler;

    impl BrokerAuthorityHandler for CapabilitiesOnlyHandler {
        fn handle(&self, operation: &AuthorityOperation) -> BrokerResult<AuthorityResult> {
            match operation {
                AuthorityOperation::Capabilities => Ok(AuthorityResult::Capabilities(
                    chio_secret_broker::budget::ExecutionAuthorityCapabilities {
                        profile: chio_secret_broker::budget::ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                        atomic_multi_key_holds: true,
                        combined_capture_and_revocation: true,
                        query_by_id: true,
                        shared_revocation_write_domain: true,
                    },
                )),
                _ => Err(BrokerError::InvalidRequest(
                    "unsupported authority test operation".to_string(),
                )),
            }
        }
    }

    #[test]
    fn authority_supervisor_has_single_owner_and_stops_cleanly() {
        let directory = must(tempfile::tempdir(), "tempdir");
        let server = Arc::new(must(
            AuthorityRpcServer::bind(
                directory.path().join("authority.sock"),
                Keypair::from_seed(&[91; 32]).public_key(),
                Arc::new(Ed25519Backend::new(Keypair::from_seed(&[92; 32]))),
                Arc::new(CapabilitiesOnlyHandler),
                30,
            ),
            "bind authority",
        ));
        let started = Arc::new(AtomicBool::new(false));

        let handle = must(
            spawn_authority_server(Arc::clone(&server), Arc::clone(&started)),
            "start authority",
        );
        assert!(started.load(Ordering::Acquire));
        assert!(spawn_authority_server(server, Arc::clone(&started)).is_err());

        must(handle.shutdown(), "stop authority");
        assert!(!started.load(Ordering::Acquire));
    }

    #[test]
    fn execution_readiness_rejects_an_unavailable_broker_peer() {
        let directory = must(tempfile::tempdir(), "tempdir");
        let authority_signer = Keypair::from_seed(&[93; 32]);
        let broker_client = must(
            BrokerIpcClient::new(
                BrokerIpcClientConfig {
                    socket_path: directory.path().join("missing-broker.sock"),
                    tenant_scope: "tenant-production".to_string(),
                    timeout_ms: 100,
                    expected_peer: chio_secret_broker::ipc_client::BrokerPeerIdentity {
                        process_id: std::process::id(),
                        user_id: 0,
                        group_id: 0,
                    },
                    trusted_receipt_signer: Keypair::from_seed(&[94; 32]).public_key(),
                },
                Arc::new(Ed25519Backend::new(authority_signer)),
            ),
            "broker client",
        );

        assert!(matches!(
            authenticate_broker_for_execution_readiness(&broker_client),
            Err(BrokerIntegrationError::Broker(_))
        ));
    }
}
