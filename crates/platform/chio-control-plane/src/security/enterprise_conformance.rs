use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chio_cage::{
    persist_signed_cage_receipt_with_trusted_key, sign_cage_receipt,
    verify_signed_cage_receipt_with_trusted_key, CageEnforcementFailure,
    CageEnforcementFailureCode, CageEnforcementRecord, CageReceiptBody, CageReceiptSigningContext,
    FullyEnforcedEvidence,
};
use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{PublicKey, SigningBackend};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::lineage::ChildRequestReceipt;
use chio_kernel::{BlockingToolServerConnection, KernelError, ReceiptStore, ReceiptStoreError};
use chio_secret_broker::conformance::prepare_enterprise_broker_composition;
use chio_secret_broker::service::BrokerExecuteOutcome;

use super::broker_runtime::BrokerReleaseReceiptPersistence;

const CAGE_EVIDENCE: &str = include_str!(
    "../../../../../tests/bindings/vectors/security/cage/positive/cage-fully-enforced-evidence-v1.json"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseCompositionMutation {
    None,
    CapabilityValidation,
    BrokerExecution,
    CageEnforcement,
    ReceiptPersistence,
}

#[derive(Clone, Debug, Default)]
pub struct EnterpriseCompositionObservation {
    pub invocation_count: u64,
    pub broker_dispatch_count: u64,
    pub broker_terminal_receipt_id: Option<String>,
    pub broker_terminal_was_reloaded: bool,
    pub broker_terminal_replay_equal: bool,
    pub native_receipt_ids: Vec<String>,
    pub unpersisted_signed_receipt: Option<ChioReceipt>,
    pub cage_failure_code: Option<CageEnforcementFailureCode>,
}

struct UnavailableNativeReceiptStore;

impl ReceiptStore for UnavailableNativeReceiptStore {
    fn append_chio_receipt(&self, _: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "injected native-security receipt persistence outage".to_string(),
        ))
    }

    fn supports_native_security_receipts(&self) -> bool {
        true
    }

    fn load_chio_receipt(&self, _: &str) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "injected native-security receipt persistence outage".to_string(),
        ))
    }

    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "injected native-security receipt persistence outage".to_string(),
        ))
    }
}

pub struct EnterpriseCompositionCoordinator {
    broker_directory: PathBuf,
    capability_id: String,
    mutation: EnterpriseCompositionMutation,
    authoritative_receipts: Arc<dyn ReceiptStore>,
    receipt_signer: Arc<dyn SigningBackend>,
    trusted_receipt_signer: PublicKey,
    observation: Mutex<EnterpriseCompositionObservation>,
    invocation_count: AtomicU64,
}

impl EnterpriseCompositionCoordinator {
    pub fn new(
        broker_directory: impl AsRef<Path>,
        capability_id: String,
        mutation: EnterpriseCompositionMutation,
        authoritative_receipts: Arc<dyn ReceiptStore>,
        receipt_signer: Arc<dyn SigningBackend>,
        trusted_receipt_signer: PublicKey,
    ) -> Result<Self, KernelError> {
        if capability_id.is_empty() || capability_id.trim() != capability_id {
            return Err(KernelError::ToolServerError(
                "enterprise composition capability id is invalid".to_string(),
            ));
        }
        if !authoritative_receipts.supports_native_security_receipts() {
            return Err(KernelError::ToolServerError(
                "enterprise composition requires an authoritative native receipt store".to_string(),
            ));
        }
        if receipt_signer.public_key() != trusted_receipt_signer {
            return Err(KernelError::ToolServerError(
                "enterprise composition receipt signer is not trusted".to_string(),
            ));
        }
        Ok(Self {
            broker_directory: broker_directory.as_ref().to_path_buf(),
            capability_id,
            mutation,
            authoritative_receipts,
            receipt_signer,
            trusted_receipt_signer,
            observation: Mutex::new(EnterpriseCompositionObservation::default()),
            invocation_count: AtomicU64::new(0),
        })
    }

    pub fn observation(&self) -> Result<EnterpriseCompositionObservation, KernelError> {
        let mut observation = self.observation.lock().map_err(|_| {
            KernelError::ToolServerError(
                "enterprise composition observation lock is poisoned".to_string(),
            )
        })?;
        observation.invocation_count = self.invocation_count.load(Ordering::SeqCst);
        Ok(observation.clone())
    }

    fn record(&self, mut observation: EnterpriseCompositionObservation) -> Result<(), KernelError> {
        observation.invocation_count = self.invocation_count.load(Ordering::SeqCst);
        *self.observation.lock().map_err(|_| {
            KernelError::ToolServerError(
                "enterprise composition observation lock is poisoned".to_string(),
            )
        })? = observation;
        Ok(())
    }

    fn native_receipt_store(&self) -> Arc<dyn ReceiptStore> {
        if self.mutation == EnterpriseCompositionMutation::ReceiptPersistence {
            Arc::new(UnavailableNativeReceiptStore)
        } else {
            Arc::clone(&self.authoritative_receipts)
        }
    }

    fn cage_receipt(&self, enforced: bool, attempt_id: &str) -> Result<ChioReceipt, KernelError> {
        let evidence: FullyEnforcedEvidence =
            serde_json::from_str(CAGE_EVIDENCE).map_err(|error| {
                KernelError::ToolServerError(format!("cage evidence decoding failed: {error}"))
            })?;
        let started_at = evidence.prepared.prepared_at_unix_ms;
        let recorded_at = evidence.exec_transition.observed_at_unix_ms;
        let record = if enforced {
            CageEnforcementRecord::fully_enforced(evidence)
        } else {
            CageEnforcementRecord::unsupported(
                CageEnforcementFailure::new(
                    CageEnforcementFailureCode::UnsupportedKernel,
                    "cage_enforcement",
                )
                .map_err(cage_error)?,
            )
        }
        .map_err(cage_error)?;
        let body = CageReceiptBody::new(attempt_id, None, record, started_at, recorded_at)
            .map_err(cage_error)?;
        let context = CageReceiptSigningContext::new(
            self.capability_id.clone(),
            "enterprise-provider-server",
            "enterprise-provider-invoke",
            "b".repeat(64),
            Some("enterprise-tenant".to_string()),
        )
        .map_err(cage_error)?;
        sign_cage_receipt(body, &context, self.receipt_signer.as_ref()).map_err(cage_error)
    }

    fn persist_cage_receipt(
        &self,
        store: &dyn ReceiptStore,
        receipt: &ChioReceipt,
    ) -> Result<ChioReceipt, KernelError> {
        persist_signed_cage_receipt_with_trusted_key(
            receipt,
            &self.trusted_receipt_signer,
            |verified| store.append_chio_receipt(verified),
        )
        .map_err(|error| {
            KernelError::ToolServerError(format!("cage receipt persistence failed: {error:?}"))
        })?;
        let loaded = store
            .load_chio_receipt(&receipt.id)
            .map_err(receipt_error)?
            .ok_or_else(|| {
                KernelError::ToolServerError("persisted cage receipt was not queryable".to_string())
            })?;
        verify_signed_cage_receipt_with_trusted_key(&loaded, &self.trusted_receipt_signer)
            .map_err(cage_error)?;
        if canonical_json_bytes(&loaded).map_err(cage_error)?
            != canonical_json_bytes(receipt).map_err(cage_error)?
        {
            return Err(KernelError::ToolServerError(
                "persisted cage receipt differs from its signed envelope".to_string(),
            ));
        }
        Ok(loaded)
    }
}

impl BlockingToolServerConnection for EnterpriseCompositionCoordinator {
    fn server_id(&self) -> &str {
        "enterprise-composition"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["invoke".to_string()]
    }

    fn invoke_blocking(
        &self,
        tool_name: &str,
        _: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        if tool_name != "invoke" {
            return Err(KernelError::ToolServerError(
                "enterprise composition rejected an unknown tool".to_string(),
            ));
        }
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        if self.mutation == EnterpriseCompositionMutation::CapabilityValidation {
            return Err(KernelError::ToolServerError(
                "capability mutation crossed the kernel validation boundary".to_string(),
            ));
        }
        std::fs::create_dir_all(&self.broker_directory).map_err(|error| {
            KernelError::ToolServerError(format!(
                "enterprise broker directory creation failed: {error}"
            ))
        })?;
        let prepared =
            prepare_enterprise_broker_composition(&self.broker_directory).map_err(broker_error)?;
        let native_store = self.native_receipt_store();
        let receipt_persistence = BrokerReleaseReceiptPersistence::new(
            Arc::clone(&native_store),
            Arc::clone(&self.receipt_signer),
            self.trusted_receipt_signer.clone(),
            "enterprise-provider-server".to_string(),
            "enterprise-provider-invoke".to_string(),
            Some("enterprise-tenant".to_string()),
        )
        .map_err(|error| KernelError::ToolServerError(error.to_string()))?;

        if self.mutation == EnterpriseCompositionMutation::BrokerExecution {
            prepared.reverse_admission().map_err(broker_error)?;
            let execution = prepared.execute_evidenced(21).map_err(broker_error)?;
            let replay = prepared.execute_evidenced(22).map_err(broker_error)?;
            if replay.outcome != execution.outcome || replay.dispatch_count != 0 {
                return Err(KernelError::ToolServerError(
                    "broker denial did not replay its exact terminal failure".to_string(),
                ));
            }
            let BrokerExecuteOutcome::Failure(failure) = &execution.outcome else {
                return Err(KernelError::ToolServerError(
                    "reversed broker admission unexpectedly dispatched".to_string(),
                ));
            };
            let failure = failure.as_ref();
            let projected = receipt_persistence
                .persist_failure(&execution.request, failure)
                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
            self.record(EnterpriseCompositionObservation {
                broker_dispatch_count: execution.dispatch_count,
                broker_terminal_receipt_id: Some(failure.receipt.body.receipt_id.clone()),
                broker_terminal_was_reloaded: true,
                broker_terminal_replay_equal: true,
                native_receipt_ids: vec![projected.id],
                ..EnterpriseCompositionObservation::default()
            })?;
            return Err(KernelError::ToolServerError(
                "enterprise broker execution denied".to_string(),
            ));
        }

        let attempt_id = prepared.attempt_id().to_string();
        if self.mutation == EnterpriseCompositionMutation::CageEnforcement {
            prepared.reverse_admission().map_err(broker_error)?;
            let terminal = prepared.execute_evidenced(21).map_err(broker_error)?;
            let terminal_replay = prepared.execute_evidenced(22).map_err(broker_error)?;
            if terminal_replay.outcome != terminal.outcome || terminal_replay.dispatch_count != 0 {
                return Err(KernelError::ToolServerError(
                    "cage denial left a nonterminal broker attempt".to_string(),
                ));
            }
            let BrokerExecuteOutcome::Failure(failure) = &terminal.outcome else {
                return Err(KernelError::ToolServerError(
                    "cage rejection failed to terminalize the prepared broker attempt".to_string(),
                ));
            };
            let failure = failure.as_ref();
            let broker_projection = receipt_persistence
                .persist_failure(&terminal.request, failure)
                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
            let rejection = self.cage_receipt(false, &attempt_id)?;
            let persisted = self.persist_cage_receipt(native_store.as_ref(), &rejection)?;
            self.record(EnterpriseCompositionObservation {
                broker_dispatch_count: terminal.dispatch_count,
                broker_terminal_receipt_id: Some(failure.receipt.body.receipt_id.clone()),
                broker_terminal_was_reloaded: true,
                broker_terminal_replay_equal: true,
                native_receipt_ids: vec![broker_projection.id, persisted.id],
                cage_failure_code: Some(CageEnforcementFailureCode::UnsupportedKernel),
                ..EnterpriseCompositionObservation::default()
            })?;
            return Err(KernelError::ToolServerError(
                "enterprise cage enforcement denied".to_string(),
            ));
        }

        let cage_receipt = self.cage_receipt(true, &attempt_id)?;
        verify_signed_cage_receipt_with_trusted_key(&cage_receipt, &self.trusted_receipt_signer)
            .map_err(cage_error)?;
        let execution = prepared.execute_evidenced(21).map_err(broker_error)?;
        let replay = prepared.execute_evidenced(22).map_err(broker_error)?;
        if replay.outcome != execution.outcome || replay.dispatch_count != execution.dispatch_count
        {
            return Err(KernelError::ToolServerError(
                "broker success did not replay its exact terminal outcome".to_string(),
            ));
        }
        let BrokerExecuteOutcome::Success(response) = &execution.outcome else {
            return Err(KernelError::ToolServerError(
                "enterprise broker execution denied after cage enforcement".to_string(),
            ));
        };
        let response = response.as_ref();
        if self.mutation == EnterpriseCompositionMutation::ReceiptPersistence {
            if self
                .persist_cage_receipt(native_store.as_ref(), &cage_receipt)
                .is_ok()
            {
                return Err(KernelError::ToolServerError(
                    "injected receipt outage unexpectedly persisted cage evidence".to_string(),
                ));
            }
            self.record(EnterpriseCompositionObservation {
                broker_dispatch_count: execution.dispatch_count,
                broker_terminal_receipt_id: Some(response.receipt.body.receipt_id.clone()),
                broker_terminal_was_reloaded: true,
                broker_terminal_replay_equal: true,
                unpersisted_signed_receipt: Some(cage_receipt),
                ..EnterpriseCompositionObservation::default()
            })?;
            return Err(KernelError::ToolServerError(
                "enterprise receipt persistence denied".to_string(),
            ));
        }
        let projected = match receipt_persistence.persist_success(&execution.request, response) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.record(EnterpriseCompositionObservation {
                    broker_dispatch_count: execution.dispatch_count,
                    broker_terminal_receipt_id: Some(response.receipt.body.receipt_id.clone()),
                    broker_terminal_was_reloaded: true,
                    broker_terminal_replay_equal: true,
                    ..EnterpriseCompositionObservation::default()
                })?;
                return Err(KernelError::ToolServerError(format!(
                    "enterprise receipt persistence denied: {error}"
                )));
            }
        };
        let persisted_cage = self.persist_cage_receipt(native_store.as_ref(), &cage_receipt)?;
        self.record(EnterpriseCompositionObservation {
            broker_dispatch_count: execution.dispatch_count,
            broker_terminal_receipt_id: Some(response.receipt.body.receipt_id.clone()),
            broker_terminal_was_reloaded: true,
            broker_terminal_replay_equal: true,
            native_receipt_ids: vec![projected.id, persisted_cage.id],
            ..EnterpriseCompositionObservation::default()
        })?;
        Ok(serde_json::json!({
            "broker_receipt_reference": response.receipt_reference,
            "cage_receipt_id": cage_receipt.id,
        }))
    }
}

fn broker_error(error: chio_secret_broker::BrokerError) -> KernelError {
    KernelError::ToolServerError(format!("enterprise broker composition failed: {error}"))
}

fn cage_error(error: impl std::fmt::Display) -> KernelError {
    KernelError::ToolServerError(format!("enterprise cage composition failed: {error}"))
}

fn receipt_error(error: ReceiptStoreError) -> KernelError {
    KernelError::ToolServerError(format!("enterprise receipt store failed: {error}"))
}
