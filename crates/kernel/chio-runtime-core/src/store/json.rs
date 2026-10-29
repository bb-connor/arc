use super::json_file::{read_json_store, write_json_store};
use super::traits::RuntimeAdmissionStore;
use crate::*;

/// JSON-backed state with trust-floor transitions serialized across clones of one instance.
/// Independently opened handles and other processes are not coordinated. Use the SQLite
/// runtime store when transitions must be serialized across independent database connections.
#[derive(Debug, Clone)]
pub struct JsonRuntimeAdmissionStore {
    path: PathBuf,
    state: Arc<Mutex<JsonRuntimeAdmissionStoreState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JsonRuntimeAdmissionStoreState {
    schema: String,
    bundles: Vec<RuntimeAdmissionBundle>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    trust_floors: Vec<RuntimeTrustFloorEntry>,
}

impl Default for JsonRuntimeAdmissionStoreState {
    fn default() -> Self {
        Self {
            schema: CHIO_RUNTIME_ADMISSION_STORE_SCHEMA.to_string(),
            bundles: Vec::new(),
            trust_floors: Vec::new(),
        }
    }
}

impl JsonRuntimeAdmissionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChioRuntimeError> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            let state: JsonRuntimeAdmissionStoreState = read_json_store(&path)?;
            if !is_runtime_admission_store_schema(&state.schema) {
                return Err(ChioRuntimeError::Rejected {
                    code: "unsupported_runtime_store_schema",
                    detail: format!(
                        "runtime admission store {} declared unsupported schema {}",
                        path.display(),
                        state.schema
                    ),
                });
            }
            let mut state = state;
            state.schema = CHIO_RUNTIME_ADMISSION_STORE_SCHEMA.to_string();
            state
        } else {
            JsonRuntimeAdmissionStoreState::default()
        };
        let store = Self {
            path,
            state: Arc::new(Mutex::new(state)),
        };
        store.validate_locked_state()?;
        Ok(store)
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state
            .bundles
            .iter()
            .find(|existing| existing.admission_id == bundle.admission_id)
        {
            if existing == &bundle {
                return Ok(());
            }
            return Err(ChioRuntimeError::DuplicateAdmissionBundle);
        }
        let mut candidate = state.clone();
        candidate.bundles.push(bundle);
        self.commit(&mut state, candidate)
    }

    fn validate_locked_state(&self) -> Result<(), ChioRuntimeError> {
        let state = self.lock_state()?;
        Self::validate_state(&state)
    }

    fn validate_state(state: &JsonRuntimeAdmissionStoreState) -> Result<(), ChioRuntimeError> {
        let mut admission_ids = BTreeSet::new();
        for bundle in &state.bundles {
            if !admission_ids.insert(bundle.admission_id.as_str()) {
                return Err(ChioRuntimeError::DuplicateAdmissionBundle);
            }
        }
        let mut trust_floor_ids = BTreeSet::new();
        for entry in &state.trust_floors {
            let identity = trust_floor_identity(&entry.verifier_id, &entry.key_id);
            if !trust_floor_ids.insert(identity.clone()) {
                return Err(ChioRuntimeError::Rejected {
                    code: "duplicate_runtime_trust_floor",
                    detail: format!("runtime admission store repeats trust floor {identity}"),
                });
            }
            if entry.highest_version == 0 {
                return Err(ChioRuntimeError::Rejected {
                    code: "runtime_trust_floor_version_zero",
                    detail: format!("runtime trust floor {identity} has version zero"),
                });
            }
        }
        Ok(())
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, JsonRuntimeAdmissionStoreState>, ChioRuntimeError> {
        self.state.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission JSON store is poisoned".to_string())
        })
    }

    /// Live state changes only after `candidate` is validated and persisted.
    fn commit(
        &self,
        live: &mut JsonRuntimeAdmissionStoreState,
        candidate: JsonRuntimeAdmissionStoreState,
    ) -> Result<(), ChioRuntimeError> {
        Self::validate_state(&candidate)?;
        write_json_store(&self.path, &candidate)?;
        *live = candidate;
        Ok(())
    }
}

fn is_runtime_admission_store_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_ADMISSION_STORE_SCHEMA)
}

impl RuntimeAdmissionStore for JsonRuntimeAdmissionStore {
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
        let state = self.lock_state()?;
        Ok(state
            .bundles
            .iter()
            .find(|bundle| bundle.admission_id == admission_id)
            .cloned())
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        let state = self.lock_state()?;
        Ok(state
            .trust_floors
            .iter()
            .find(|entry| entry.verifier_id == verifier_id && entry.key_id == key_id)
            .cloned())
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        let mut candidate = state.clone();
        if let Some(existing) = candidate.trust_floors.iter_mut().find(|existing| {
            existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
        }) {
            *existing = entry;
        } else {
            candidate.trust_floors.push(entry);
        }
        self.commit(&mut state, candidate)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        let existing = state
            .trust_floors
            .iter()
            .find(|existing| {
                existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
            })
            .cloned();
        validate_runtime_trust_floor_transition(existing, &entry, previous_hash_sha256)?;
        let mut candidate = state.clone();
        if let Some(existing) = candidate.trust_floors.iter_mut().find(|existing| {
            existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
        }) {
            *existing = entry;
        } else {
            candidate.trust_floors.push(entry);
        }
        self.commit(&mut state, candidate)
    }
}
