//! Kernel wiring for evidence capacity and idle recovery.

use std::num::NonZeroUsize;
use std::sync::Arc;

use super::evidence::{EvidencePool, EvidenceSlot, PostEffectEvidenceBudget};
use super::recovery::{EvidenceRecovery, EvidenceRecoveryResources, PendingPostEffectRecord};
use crate::kernel::ChioKernel;
use crate::KernelError;

enum EvidenceReservation {
    NewDispatch,
    DispatchedChild,
}

impl ChioKernel {
    /// Install the host's shared budget before this kernel admits any effects.
    /// The default is shared across all kernels constructed by this process.
    pub fn set_post_effect_evidence_budget(
        &mut self,
        budget: Arc<PostEffectEvidenceBudget>,
    ) -> Result<(), KernelError> {
        self.invalidate_idle_post_effect_evidence_worker()?;
        self.post_effect_host_budget = budget;
        Ok(())
    }

    /// Block until this kernel's retained post-effect evidence is persisted.
    /// Returns the pending error as soon as a flush attempt fails; supervised
    /// recovery keeps retrying and new dispatch stays closed meanwhile.
    pub fn await_post_effect_evidence(&self) -> Result<(), KernelError> {
        let queue = self
            .post_effect_evidence
            .lock()
            .map_err(|_| KernelError::Internal("post-effect evidence owner poisoned".into()))?
            .as_ref()
            .map(EvidenceRecovery::queue);
        match queue {
            Some(queue) => queue.await_drained(),
            None => Ok(()),
        }
    }

    pub(in crate::kernel) fn invalidate_idle_post_effect_evidence_worker(
        &mut self,
    ) -> Result<(), KernelError> {
        let state = self
            .post_effect_evidence
            .get_mut()
            .map_err(|_| KernelError::Internal("post-effect evidence owner poisoned".into()))?;
        if state.as_ref().is_some_and(|worker| !worker.is_idle()) {
            return Err(KernelError::Internal(
                "cannot replace resources while post-effect evidence is retained".into(),
            ));
        }
        *state = None;
        Ok(())
    }

    pub(in crate::kernel) fn acquire_post_effect_evidence_slot(
        &self,
        bytes: NonZeroUsize,
    ) -> Result<EvidenceSlot, KernelError> {
        self.acquire_post_effect_evidence_slot_for(bytes, EvidenceReservation::NewDispatch)
    }

    pub(in crate::kernel) fn acquire_dispatched_child_evidence_slot(
        &self,
        bytes: NonZeroUsize,
    ) -> Result<EvidenceSlot, KernelError> {
        self.acquire_post_effect_evidence_slot_for(bytes, EvidenceReservation::DispatchedChild)
    }

    fn acquire_post_effect_evidence_slot_for(
        &self,
        bytes: NonZeroUsize,
        reservation: EvidenceReservation,
    ) -> Result<EvidenceSlot, KernelError> {
        let resources = EvidenceRecoveryResources {
            clock: self.authority_clock(),
            signer: Arc::clone(&self.signing_authority.backend),
            child_keypair: Arc::new(self.config.keypair.clone()),
            signing_identity: self.freeze_receipt_signing_identity()?,
            store: self.receipt_store.clone(),
            log: Arc::clone(&self.receipt_log),
            child_log: Arc::clone(&self.child_receipt_log),
            publication_sync: Arc::clone(&self.publication_sync),
            trace_sequence: Arc::clone(&self.runtime_trace_sequence),
            trace_observer: self.runtime_trace_observer.clone(),
            append_budget: self.config.deadlines.receipt_append_budget(),
            settlement_observation: self.settlement_observer.is_some(),
        };
        let mut state = self
            .post_effect_evidence
            .lock()
            .map_err(|_| KernelError::Internal("post-effect evidence owner poisoned".into()))?;
        if let Some(worker) = state.as_ref() {
            if !worker.matches_resources(&resources) {
                if !worker.is_idle() {
                    return Err(KernelError::Internal(
                        "post-effect evidence still owns the previous kernel resources".into(),
                    ));
                }
                *state = None;
            }
        }
        if state.is_none() {
            let slots = NonZeroUsize::new(self.config.memory_budget.post_effect_evidence_slots)
                .ok_or_else(invalid_capacity)?;
            let bytes = NonZeroUsize::new(self.config.memory_budget.post_effect_evidence_bytes)
                .ok_or_else(invalid_capacity)?;
            if self.post_effect_fault_template_limit() == 0
                || self.config.memory_budget.max_post_effect_child_receipts == 0
            {
                return Err(invalid_capacity());
            }
            let pool = EvidencePool::with_byte_limit(
                slots,
                bytes,
                Arc::clone(&self.post_effect_host_budget),
            )?;
            *state = Some(EvidenceRecovery::new(pool, slots.get(), resources)?);
        }
        let worker = state.as_ref().ok_or_else(invalid_capacity)?;
        match reservation {
            EvidenceReservation::NewDispatch => worker.acquire(bytes),
            EvidenceReservation::DispatchedChild => worker.acquire_for_dispatched_child(bytes),
        }
    }

    pub(in crate::kernel) fn post_effect_fault_template_limit(&self) -> usize {
        self.config
            .memory_budget
            .max_post_effect_fault_template_bytes
    }

    pub(in crate::kernel) fn buffer_post_effect_evidence(
        &self,
        slot: EvidenceSlot,
        pending: PendingPostEffectRecord,
    ) {
        slot.buffer(pending);
    }

    pub(in crate::kernel) fn ensure_post_effect_evidence_latch_clear(
        &self,
    ) -> Result<(), KernelError> {
        let state = self
            .post_effect_evidence
            .lock()
            .map_err(|_| KernelError::Internal("post-effect evidence owner poisoned".into()))?;
        state
            .as_ref()
            .map_or(Ok(()), EvidenceRecovery::ensure_clear)
    }
}

fn invalid_capacity() -> KernelError {
    KernelError::Internal("post-effect evidence limits must be nonzero".into())
}
