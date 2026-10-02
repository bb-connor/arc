use chio_swarm_authority::SwarmAuthorityBundle;

use crate::*;

fn unsupported_runtime_trust_floor_store() -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_trust_floor_store_unsupported",
        detail: "runtime trust-floor store must implement atomic validation and recording"
            .to_string(),
    }
}

fn unsupported_treaty_continuation_store(
    operation: &str,
    continuation_id: &str,
) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "chio_treaty_continuation_store_unsupported",
        detail: format!(
            "runtime admission store does not support {operation} for treaty continuation {continuation_id}"
        ),
    }
}

fn unsupported_swarm_continuation_store(
    operation: &str,
    continuation_id: &str,
) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "chio_swarm_continuation_store_unsupported",
        detail: format!(
            "runtime admission store does not support {operation} for swarm continuation {continuation_id}"
        ),
    }
}

pub trait RuntimeAdmissionStore: Send + Sync {
    /// Verify this actual artifact/trust-floor backend against the destination's
    /// activated source snapshot. Memory, JSON and unqualified layered stores
    /// cannot serve operation-owned replay by default.
    fn verify_operation_owned_replay_source(
        &self,
        _expected: &chio_kernel::admission_operation::RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), ChioRuntimeError> {
        Err(ChioRuntimeError::Rejected {
            code: "operation_owned_runtime_source_unsupported",
            detail: "runtime backend does not qualify sealed operation-owned replay".into(),
        })
    }

    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError>;

    fn treaty_runtime_artifact(
        &self,
        _evidence_kind: &str,
        _evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        Ok(None)
    }

    /// Resolve only receiver-provisioned lease state. A revocation tombstone
    /// dominates the immutable activation, including after a store reopens.
    fn treaty_capability_lease(
        &self,
        lease_id: &str,
    ) -> Result<Option<RuntimeTreatyLeaseRecord>, ChioRuntimeError> {
        load_active_presentation_record(self, "capability_lease", lease_id)
    }

    fn treaty_governance_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<RuntimeTreatyGovernanceRecord>, ChioRuntimeError> {
        load_active_presentation_record(self, "governance_receipt", receipt_id)
    }

    fn swarm_authority_bundle(
        &self,
        _task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        Ok(None)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError>;

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError>;

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_treaty_continuation_store(
            "consume",
            continuation_id,
        ))
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_treaty_continuation_store(
            "release",
            continuation_id,
        ))
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_swarm_continuation_store(
            "consume",
            continuation_id,
        ))
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_swarm_continuation_store(
            "release",
            continuation_id,
        ))
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError>;

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError>;

    /// Validates and records a transition while excluding concurrent floor writers.
    /// Backends without an explicit atomic implementation fail closed.
    fn validate_and_record_runtime_trust_floor(
        &self,
        _entry: RuntimeTrustFloorEntry,
        _previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_runtime_trust_floor_store())
    }
}

fn load_active_presentation_record<S, T>(
    store: &S,
    kind: &str,
    id: &str,
) -> Result<Option<T>, ChioRuntimeError>
where
    S: RuntimeAdmissionStore + ?Sized,
    T: serde::de::DeserializeOwned,
{
    let record = store.treaty_runtime_artifact(kind, id)?;
    // Read the tombstone after the activation. A subsequent dispatch
    // revalidation resolves it again; this is not a cross-store transaction.
    if store
        .treaty_runtime_artifact(&format!("{kind}_revocation"), id)?
        .is_some()
    {
        return Ok(None);
    }
    record
        .map(|record| {
            if record.evidence_kind != kind
                || record.evidence_id != id
                || record.artifact_sha256 != canonical_sha256(&record.raw_json)?
            {
                return rejected(
                    "chio_treaty_unverified_required_evidence",
                    "receiver presentation record identity or content hash does not match",
                );
            }
            serde_json::from_value(record.raw_json)
                .map_err(|error| ChioRuntimeError::Json(error.to_string()))
        })
        .transpose()
}

pub trait RuntimeTrustFloorStore: Send + Sync {
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError>;

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError>;

    /// Validates and records a transition while excluding concurrent floor writers.
    /// Backends without an explicit atomic implementation fail closed.
    fn validate_and_record_runtime_trust_floor(
        &self,
        _entry: RuntimeTrustFloorEntry,
        _previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_runtime_trust_floor_store())
    }
}

impl<T> RuntimeTrustFloorStore for T
where
    T: RuntimeAdmissionStore + ?Sized,
{
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        RuntimeAdmissionStore::runtime_trust_floor(self, verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        RuntimeAdmissionStore::record_runtime_trust_floor(self, entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(
            self,
            entry,
            previous_hash_sha256,
        )
    }
}

pub struct LayeredRuntimeAdmissionStore<'a> {
    admission_store: &'a dyn RuntimeAdmissionStore,
    trust_floor_store: &'a dyn RuntimeTrustFloorStore,
}

impl<'a> LayeredRuntimeAdmissionStore<'a> {
    #[must_use]
    pub fn new(
        admission_store: &'a dyn RuntimeAdmissionStore,
        trust_floor_store: &'a dyn RuntimeTrustFloorStore,
    ) -> Self {
        Self {
            admission_store,
            trust_floor_store,
        }
    }
}

impl RuntimeAdmissionStore for LayeredRuntimeAdmissionStore<'_> {
    fn treaty_capability_lease(
        &self,
        lease_id: &str,
    ) -> Result<Option<RuntimeTreatyLeaseRecord>, ChioRuntimeError> {
        self.admission_store.treaty_capability_lease(lease_id)
    }

    fn treaty_governance_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<RuntimeTreatyGovernanceRecord>, ChioRuntimeError> {
        self.admission_store.treaty_governance_receipt(receipt_id)
    }

    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        self.admission_store.bundle(admission_id)
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        self.admission_store
            .treaty_runtime_artifact(evidence_kind, evidence_id)
    }

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        self.admission_store.swarm_authority_bundle(task_graph_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .consume_destructive_lease(lease_id, admission_id)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .release_destructive_lease(lease_id, admission_id)
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .consume_treaty_continuation(continuation_id, admission_id)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .release_treaty_continuation(continuation_id, admission_id)
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .consume_swarm_continuation(continuation_id, admission_id)
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .release_swarm_continuation(continuation_id, admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.trust_floor_store
            .runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.trust_floor_store.record_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        self.trust_floor_store
            .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
    }
}
