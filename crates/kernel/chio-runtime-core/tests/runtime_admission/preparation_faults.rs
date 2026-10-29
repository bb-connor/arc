use super::*;

#[path = "preparation.rs"]
mod preparation;

#[derive(Clone)]
struct PreparationStore {
    inner: InMemoryRuntimeAdmissionStore,
    bundle_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    panic_bundle_on_call: Option<u64>,
    bundle_snapshots: Option<(RuntimeAdmissionBundle, RuntimeAdmissionBundle)>,
    artifact_tamper_kind: Option<&'static str>,
    panic_trust_floor: bool,
    reject_trust_floor: bool,
    trust_floor_writes: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl PreparationStore {
    fn new(inner: InMemoryRuntimeAdmissionStore) -> Self {
        Self {
            inner,
            bundle_calls: Default::default(),
            panic_bundle_on_call: None,
            bundle_snapshots: None,
            artifact_tamper_kind: None,
            panic_trust_floor: false,
            reject_trust_floor: false,
            trust_floor_writes: Default::default(),
        }
    }

    fn trust_floor_writes(&self) -> u64 {
        self.trust_floor_writes
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl RuntimeAdmissionStore for PreparationStore {
    fn commit_runtime_admission_authority(
        &self,
        _: &chio_runtime_core::RuntimeAdmissionAuthorityCommit,
    ) -> Result<(), ChioRuntimeError> {
        Err(ChioRuntimeError::Rejected {
            code: "treaty_epoch_unavailable",
            detail: "runtime backend does not support atomic treaty authority".into(),
        })
    }

    fn verify_retained_runtime_treaty_authorization(
        &self,
        _: &chio_runtime_core::RuntimeTreatyAuthorizationBinding,
    ) -> Result<(), ChioRuntimeError> {
        Err(ChioRuntimeError::Rejected {
            code: "treaty_epoch_unavailable",
            detail: "runtime backend does not support retained treaty authorization".into(),
        })
    }

    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        let call = self
            .bundle_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.panic_bundle_on_call == Some(call) {
            panic!("injected admission bundle callback panic on call {call}");
        }
        if let Some((first, subsequent)) = self.bundle_snapshots.as_ref() {
            return Ok(Some(if call == 0 { first } else { subsequent }.clone()));
        }
        self.inner.bundle(admission_id)
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        let mut record = self
            .inner
            .treaty_runtime_artifact(evidence_kind, evidence_id)?;
        if self.artifact_tamper_kind == Some(evidence_kind) {
            if let Some(record) = record.as_mut() {
                record.raw_json["uncommitted_fixture_field"] = serde_json::json!(true);
            }
        }
        Ok(record)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.inner.runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.trust_floor_writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.record_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        self.trust_floor_writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.panic_trust_floor {
            self.inner
                .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)?;
            panic!("runtime trust floor callback panicked after recording");
        }
        if self.reject_trust_floor {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_trust_rollback",
                detail: "injected runtime trust floor rejection".to_string(),
            });
        }
        self.inner
            .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
    }
}

fn preparation_request(
    store: &InMemoryRuntimeAdmissionStore,
    include_swarm: bool,
) -> Result<(ToolCallRequest, Option<serde_json::Value>), Box<dyn std::error::Error>> {
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let treaty_fixture = treaty_runtime_fixture()?;
    insert_in_memory_treaty_runtime_fixture(store, &treaty_fixture)?;

    if !include_swarm {
        return Ok((
            treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&treaty_fixture))?,
            None,
        ));
    }

    let swarm_bundle = runtime_swarm_bundle(false)?;
    let mut request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    request.federated_origin_kernel_id = Some("kernel.buyer".to_string());
    let context = request
        .governed_intent
        .as_mut()
        .and_then(|intent| intent.context.as_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| io::Error::other("governed runtime context missing"))?;
    context.insert(
        "chioTreaty".to_string(),
        treaty_runtime_context(&treaty_fixture),
    );
    Ok((request, Some(swarm_route_metadata())))
}
