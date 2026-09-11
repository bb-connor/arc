use super::*;

#[derive(Default)]
struct State {
    enabled: bool,
    generation: u64,
    fault: Fault,
    commit_fault: bool,
    wrote: bool,
    reads: u64,
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
        let mut state = self.0.lock().map_err(poison)?;
        state.wrote = true;
        let fault = state.fault;
        if matches!(fault, Fault::Deny) {
            return Err(denied());
        }
        let mut commitment = CommittedEgressFence {
            fence_id: command.fence.fence_id.clone(),
            request_id: command.fence.request_id.clone(),
            request_hash: command.fence.request_hash,
            context_generation: command.fence.context_generation,
            dispatch_commitment_id: command.dispatch_commitment_id.clone(),
            committed_at_unix_ms: command.committed_at_unix_ms,
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
        drop(state);
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
