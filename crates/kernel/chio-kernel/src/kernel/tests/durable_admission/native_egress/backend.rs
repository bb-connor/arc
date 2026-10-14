use super::*;
use chio_core::receipt::security::ActiveDefenseReceiptBody;
use chio_security_types::ports::{
    CanonicalBody, DeclassificationConsumptionEvidenceCommit, DeclassificationTransitionBinding,
    Digest32,
};

#[derive(Default)]
struct State {
    enabled: bool,
    generation: u64,
    fault: Fault,
    commit_fault: bool,
    wrote: bool,
    reads: u64,
    lease_cap_ms: Option<u64>,
    committed_readback_delay_ms: Option<u64>,
    history: Option<NativeSecurityEgressHistoryV1>,
}

#[derive(Default)]
pub(in crate::kernel::tests) struct TestEgress(Mutex<State>);

impl TestEgress {
    pub(in crate::kernel::tests) fn require_enabled(
        &self,
        command: &str,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.0.lock().map_err(poison)?.enabled {
            return Ok(());
        }
        Err(AdmissionOperationStoreError::Unavailable(format!(
            "operation-owned native egress {command} is unsupported"
        )))
    }

    pub(super) fn enable(&self, generation: u64) -> TestResult {
        let mut state = self.0.lock().map_err(poison)?;
        state.enabled = true;
        state.generation = generation;
        Ok(())
    }

    pub(super) fn arm(&self, fault: Fault) -> TestResult {
        let mut state = self.0.lock().map_err(poison)?;
        state.fault = fault;
        state.commit_fault = false;
        state.wrote = false;
        Ok(())
    }

    pub(super) fn arm_commit(&self, fault: Fault) -> TestResult {
        self.arm(fault)?;
        self.0.lock().map_err(poison)?.commit_fault = true;
        Ok(())
    }

    /// Bound every later recovery claim to a short lifetime. Validation stays
    /// the test store's own `revalidate_recovery_claim`.
    pub(super) fn cap_lease(&self, lifetime_ms: u64) -> TestResult {
        self.0.lock().map_err(poison)?.lease_cap_ms = Some(lifetime_ms);
        Ok(())
    }

    pub(in crate::kernel::tests) fn capped_lease_expiry(
        &self,
        trusted_now_unix_ms: u64,
        requested_unix_ms: u64,
    ) -> Result<u64, AdmissionOperationStoreError> {
        Ok(match self.0.lock().map_err(poison)?.lease_cap_ms {
            Some(lifetime) => requested_unix_ms.min(trusted_now_unix_ms.saturating_add(lifetime)),
            None => requested_unix_ms,
        })
    }

    /// Make every history read that already contains a commitment slow, as a
    /// busy physical verifier would be after the write.
    pub(super) fn delay_committed_readback(&self, delay_ms: u64) -> TestResult {
        self.0.lock().map_err(poison)?.committed_readback_delay_ms = Some(delay_ms);
        Ok(())
    }

    pub(super) fn reads(&self) -> TestResult<u64> {
        Ok(self.0.lock().map_err(poison)?.reads)
    }

    pub(super) fn acquisition(&self) -> TestResult<NativeSecurityEgressAcquisitionV1> {
        Ok(self
            .0
            .lock()
            .map_err(poison)?
            .history
            .as_ref()
            .ok_or("no acquisition")?
            .acquisition
            .clone())
    }

    pub(super) fn committed(&self) -> TestResult<bool> {
        Ok(self
            .0
            .lock()
            .map_err(poison)?
            .history
            .as_ref()
            .is_some_and(|history| history.commitment.is_some()))
    }

    pub(in crate::kernel::tests) fn observe(
        &self,
        binding: &NativeSecurityAuthorityBindingV1,
        key: &FlowStateKey,
        now: u64,
    ) -> Result<NativeSecurityFlowObservationV1, AdmissionOperationStoreError> {
        self.require_enabled("observation")?;
        let state = self.0.lock().map_err(poison)?;
        let generation = state.generation;
        let now = match state.fault {
            Fault::StaleObservationTime => now - 1,
            Fault::FutureObservationTime => now + 60_000,
            _ => now,
        };
        drop(state);
        NativeSecurityFlowObservationV1::new(
            binding.clone(),
            key.clone(),
            Some(FlowStateSnapshot {
                key: key.clone(),
                principal_label: InformationLabel::bottom(),
                lineage_label: InformationLabel::bottom(),
                session_label: InformationLabel::bottom(),
                context_generation: generation,
            }),
            Some(generation),
            now,
        )
    }

    pub(in crate::kernel::tests) fn acquire(
        &self,
        input: &NativeSecurityEgressContext<'_>,
        command: &EgressFenceRequest,
    ) -> Result<EgressFence, AdmissionOperationStoreError> {
        let mut state = self.0.lock().map_err(poison)?;
        state.wrote = true;
        let fault = state.fault;
        if matches!(fault, Fault::Deny) {
            return Err(denied());
        }
        let mut fence = EgressFence {
            fence_id: RecordId::new("kernel-acquired-fence").map_err(invalid)?,
            key: command.key.clone(),
            request_id: command.request_id.clone(),
            request_hash: command.request_hash,
            context_generation: command.expected_context_generation,
            expires_at_unix_ms: command.expires_at_unix_ms,
        };
        if !matches!(fault, Fault::NoWrite) {
            state.history = Some(NativeSecurityEgressHistoryV1 {
                binding: input.binding.clone(),
                operation_id: input.operation.binding().operation_id().clone(),
                live_request_hash: AdmissionDigest::try_new(
                    "request",
                    sha256_hex(&canonical_json_bytes(input.request).map_err(invalid)?),
                )?,
                acquisition: NativeSecurityEgressAcquisitionV1 {
                    fence: fence.clone(),
                    event_digest: digest(b"acquired")?,
                },
                commitment: None,
            });
        }
        if matches!(fault, Fault::ChangedObservation) {
            state.generation += 1;
        }
        drop(state);
        match fault {
            Fault::LostAck => Err(AdmissionOperationStoreError::OutcomeUnknown(
                "injected lost acknowledgement".into(),
            )),
            Fault::PanicWrite => panic!("injected acquisition panic after write"),
            Fault::WrongAck => {
                fence.expires_at_unix_ms += 1;
                Ok(fence)
            }
            _ => Ok(fence),
        }
    }

    pub(in crate::kernel::tests) fn commit(
        &self,
        command: &EgressFenceCommit,
    ) -> Result<CommittedEgressFence, AdmissionOperationStoreError> {
        self.commit_event(command, None)
    }

    /// Mirrors the physical writer: it authenticates the live signed grant
    /// against the fence and the evidence, then stamps both the commitment and
    /// the use evidence at its own clock before refusing an expired grant.
    pub(in crate::kernel::tests) fn commit_declassified(
        &self,
        request: &ToolCallRequest,
        command: &EgressFenceCommit,
        consumption: &DeclassificationConsumptionEvidenceCommit,
    ) -> Result<CommittedEgressFence, AdmissionOperationStoreError> {
        authenticate_declassification(request, command, consumption)?;
        self.commit_event(command, Some(consumption))
    }

    fn commit_event(
        &self,
        command: &EgressFenceCommit,
        consumption: Option<&DeclassificationConsumptionEvidenceCommit>,
    ) -> Result<CommittedEgressFence, AdmissionOperationStoreError> {
        let mut state = self.0.lock().map_err(poison)?;
        state.wrote = true;
        let fault = state.fault;
        if matches!(fault, Fault::Deny) {
            return Err(denied());
        }
        // The physical writer owns the first commitment event. Preparation
        // supplies only a lower bound for that clock.
        let committed_at_unix_ms = match fault {
            Fault::PhysicalEventClock | Fault::StaleConsumptionClock => {
                std::thread::sleep(std::time::Duration::from_millis(25));
                current_unix_timestamp_ms().max(command.committed_at_unix_ms + 1)
            }
            Fault::EarlyEventClock => command.committed_at_unix_ms - 1,
            Fault::FutureEventClock => command.committed_at_unix_ms + 60_000,
            _ => command.committed_at_unix_ms,
        };
        let declassification = match consumption {
            Some(consumption) => {
                if consumption.consumption.consumed_at_unix_ms != command.committed_at_unix_ms {
                    return Err(invalid(
                        "native use evidence differs from its prepared clock",
                    ));
                }
                if committed_at_unix_ms >= consumption.consumption.grant_expires_at_unix_ms {
                    return Err(invalid(
                        "native declassification grant is not currently valid",
                    ));
                }
                Some(if matches!(fault, Fault::StaleConsumptionClock) {
                    consumption.clone()
                } else {
                    stamp_consumption(consumption, committed_at_unix_ms)?
                })
            }
            None => None,
        };
        let mut commitment = CommittedEgressFence {
            fence_id: command.fence.fence_id.clone(),
            request_id: command.fence.request_id.clone(),
            request_hash: command.fence.request_hash,
            context_generation: command.fence.context_generation,
            dispatch_commitment_id: command.dispatch_commitment_id.clone(),
            committed_at_unix_ms,
        };
        if !matches!(fault, Fault::NoWrite) {
            let history = state
                .history
                .as_mut()
                .ok_or_else(|| invalid("acquisition absent"))?;
            history.commitment = Some(NativeSecurityEgressCommitmentV1 {
                commitment: commitment.clone(),
                event_digest: digest(b"committed")?,
                acquisition_digest: history.acquisition.event_digest.clone(),
                declassification,
            });
        }
        if matches!(fault, Fault::ChangedObservation) {
            state.generation += 1;
        }
        drop(state);
        match fault {
            Fault::LostAck => Err(AdmissionOperationStoreError::OutcomeUnknown(
                "injected lost acknowledgement".into(),
            )),
            Fault::PanicWrite => panic!("injected commitment panic after write"),
            Fault::WrongAck => {
                commitment.committed_at_unix_ms += 1;
                Ok(commitment)
            }
            _ => Ok(commitment),
        }
    }

    pub(in crate::kernel::tests) fn read(
        &self,
        operation: Option<AdmissionOperationV1>,
    ) -> Result<
        Option<(AdmissionOperationV1, Option<NativeSecurityEgressHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        let Some(mut operation) = operation else {
            return Ok(None);
        };
        let mut state = self.0.lock().map_err(poison)?;
        state.reads += 1;
        let fault = if state.commit_fault && !state.wrote {
            Fault::None
        } else {
            state.fault
        };
        let mut history = state.history.clone();
        let slow = state.committed_readback_delay_ms.filter(|_| {
            history
                .as_ref()
                .is_some_and(|history| history.commitment.is_some())
        });
        drop(state);
        if let Some(delay_ms) = slow {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        if matches!(fault, Fault::PanicRead) {
            panic!("injected native egress readback panic");
        }
        if matches!(fault, Fault::MissingHistory) {
            history = None;
        }
        if matches!(fault, Fault::WrongOperation) {
            let mut persisted = operation.to_persisted();
            persisted.version += 1;
            operation = AdmissionOperationV1::from_persisted(persisted)?;
        }
        if let Some(history) = &mut history {
            match fault {
                Fault::WrongBinding => {
                    history.binding = NativeSecurityAuthorityBindingV1::new(
                        AdmissionIdentifier::try_new("store", "other-store")?,
                        AdmissionIdentifier::try_new("authority", "other-authority")?,
                        digest(b"other-init")?,
                    )
                }
                Fault::WrongRequest => history.live_request_hash = digest(b"other-request")?,
                Fault::ChangedAcquisition => {
                    history.acquisition.event_digest = digest(b"other-acquisition")?
                }
                Fault::WrongPredecessor => {
                    if let Some(commitment) = &mut history.commitment {
                        commitment.acquisition_digest = digest(b"wrong-predecessor")?;
                    }
                }
                _ => {}
            }
        }
        Ok(Some((operation, history)))
    }
}

fn authenticate_declassification(
    request: &ToolCallRequest,
    command: &EgressFenceCommit,
    consumption: &DeclassificationConsumptionEvidenceCommit,
) -> Result<(), AdmissionOperationStoreError> {
    let grant = request
        .declassification_grant
        .as_ref()
        .ok_or_else(|| invalid("native declassification signed grant is absent"))?;
    if !grant
        .verify_signature()
        .map_err(|_| invalid("native declassification grant signature is invalid"))?
    {
        return Err(invalid(
            "native declassification grant signature is invalid",
        ));
    }
    let body = grant.body();
    let fence = &command.fence;
    let binding = DeclassificationTransitionBinding::Consumption {
        tenant_id: fence.key.tenant_id.clone(),
        grant_id: consumption.consumption.grant_id.clone(),
        request_id: fence.request_id.clone(),
        request_hash: fence.request_hash,
    };
    let receipt: ActiveDefenseReceiptBody =
        serde_json::from_slice(consumption.receipt.canonical_body.as_bytes())
            .map_err(|_| invalid("native use receipt is not typed canonical evidence"))?;
    let ActiveDefenseReceiptBody::DeclassificationConsumption(receipt) = receipt else {
        return Err(invalid("native use receipt has another evidence kind"));
    };
    let grant_bytes = canonical_json_bytes(grant).map_err(invalid)?;
    if body.tenant_id() != &fence.key.tenant_id
        || body.subject_id() != &fence.key.principal_id
        || body.session_id() != &fence.key.session_id
        || body.request_hash() != fence.request_hash
        || body.grant_id() != &consumption.consumption.grant_id
        || body.expires_at_unix_seconds().checked_mul(1000)
            != Some(consumption.consumption.grant_expires_at_unix_ms)
        || consumption.consumption.tenant_id != fence.key.tenant_id
        || consumption.consumption.request_hash != fence.request_hash
        || consumption.transition_binding != binding
        || receipt.grant_hash != Digest32::new(*chio_core::sha256(&grant_bytes).as_bytes())
    {
        return Err(invalid("native declassification differs from its fence"));
    }
    Ok(())
}

fn stamp_consumption(
    consumption: &DeclassificationConsumptionEvidenceCommit,
    now: u64,
) -> Result<DeclassificationConsumptionEvidenceCommit, AdmissionOperationStoreError> {
    let body: ActiveDefenseReceiptBody =
        serde_json::from_slice(consumption.receipt.canonical_body.as_bytes())
            .map_err(|_| invalid("native use receipt is not typed canonical evidence"))?;
    let ActiveDefenseReceiptBody::DeclassificationConsumption(mut body) = body else {
        return Err(invalid("native use receipt has another evidence kind"));
    };
    body.header.occurred_at_unix_ms = now;
    let body = ActiveDefenseReceiptBody::DeclassificationConsumption(body);
    body.validate()
        .map_err(|_| invalid("native physical use receipt is invalid"))?;
    let mut stamped = consumption.clone();
    stamped.consumption.consumed_at_unix_ms = now;
    stamped.receipt.occurred_at_unix_ms = now;
    stamped.receipt.canonical_body =
        CanonicalBody::new(canonical_json_bytes(&body).map_err(invalid)?)
            .map_err(|_| invalid("native physical use receipt exceeds bounds"))?;
    stamped.receipt.body_hash = body
        .body_digest()
        .map_err(|_| invalid("native physical use receipt is invalid"))?;
    stamped.receipt.evidence_id = body
        .evidence_id()
        .map_err(|_| invalid("native physical use receipt is invalid"))?;
    Ok(stamped)
}

fn digest(bytes: &[u8]) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    Ok(AdmissionDigest::try_new("test", sha256_hex(bytes))?)
}

fn denied() -> AdmissionOperationStoreError {
    invalid("injected write denial")
}

fn poison<T>(_: std::sync::PoisonError<T>) -> AdmissionOperationStoreError {
    invalid("test native egress state poisoned")
}

fn invalid(error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(error.to_string())
}
