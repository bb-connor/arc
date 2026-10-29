use super::traits::RuntimeAdmissionStore;
use crate::validation::{validate_non_empty, validate_state_label};
use crate::*;

/// Process-local state shared by clones, with mutex-linearized trust-floor transitions.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRuntimeAdmissionStore {
    bundles: Arc<Mutex<BTreeMap<String, RuntimeAdmissionBundle>>>,
    treaty_artifacts: Arc<Mutex<BTreeMap<(String, String), TreatyRuntimeArtifactRecord>>>,
    trust_floors: Arc<Mutex<BTreeMap<String, RuntimeTrustFloorEntry>>>,
}

impl InMemoryRuntimeAdmissionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        let mut bundles = self.bundles.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission bundle store is poisoned".to_string())
        })?;
        if let Some(existing) = bundles.get(&bundle.admission_id) {
            if existing == &bundle {
                return Ok(());
            }
            return Err(ChioRuntimeError::DuplicateAdmissionBundle);
        }
        bundles.insert(bundle.admission_id.clone(), bundle);
        Ok(())
    }

    pub fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChioRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let artifact_sha256 = canonical_sha256(artifact)?;
        let raw_json = serde_json::to_value(artifact).map_err(ChioRuntimeError::Json)?;
        let mut treaty_artifacts = self.treaty_artifacts.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime treaty artifact store is poisoned".to_string())
        })?;
        let key = (evidence_kind.to_string(), evidence_id.to_string());
        if let Some(existing) = treaty_artifacts.get(&key) {
            if existing.artifact_sha256 == artifact_sha256 {
                return Ok(());
            }
            return Err(ChioRuntimeError::Rejected {
                code: "duplicate_treaty_runtime_artifact_mismatch",
                detail: "runtime treaty artifact id already exists with a different hash"
                    .to_string(),
            });
        }
        treaty_artifacts.insert(
            key,
            TreatyRuntimeArtifactRecord {
                evidence_kind: evidence_kind.to_string(),
                evidence_id: evidence_id.to_string(),
                artifact_sha256,
                raw_json,
            },
        );
        Ok(())
    }
}

impl RuntimeAdmissionStore for InMemoryRuntimeAdmissionStore {
    fn commit_runtime_admission_authority(
        &self,
        _: &crate::RuntimeAdmissionAuthorityCommit,
    ) -> Result<(), ChioRuntimeError> {
        Err(ChioRuntimeError::Rejected {
            code: "treaty_epoch_unavailable",
            detail: "runtime backend does not support atomic treaty authority".into(),
        })
    }

    fn verify_retained_runtime_treaty_authorization(
        &self,
        _: &crate::RuntimeTreatyAuthorizationBinding,
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
        let bundles = self.bundles.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission bundle store is poisoned".to_string())
        })?;
        Ok(bundles.get(admission_id).cloned())
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        let treaty_artifacts = self.treaty_artifacts.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime treaty artifact store is poisoned".to_string())
        })?;
        Ok(treaty_artifacts
            .get(&(evidence_kind.to_string(), evidence_id.to_string()))
            .cloned())
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        let floors = self.trust_floors.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission trust floor store is poisoned".to_string())
        })?;
        Ok(floors
            .get(&trust_floor_identity(verifier_id, key_id))
            .cloned())
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        let mut floors = self.trust_floors.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission trust floor store is poisoned".to_string())
        })?;
        floors.insert(
            trust_floor_identity(&entry.verifier_id, &entry.key_id),
            entry,
        );
        Ok(())
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        let mut floors = self.trust_floors.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission trust floor store is poisoned".to_string())
        })?;
        let identity = trust_floor_identity(&entry.verifier_id, &entry.key_id);
        validate_runtime_trust_floor_transition(
            floors.get(&identity).cloned(),
            &entry,
            previous_hash_sha256,
        )?;
        floors.insert(identity, entry);
        Ok(())
    }
}
