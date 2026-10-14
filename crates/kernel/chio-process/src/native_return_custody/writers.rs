//! Every remaining writer of the Process journal, routed through the native
//! current-write scope. Each method validates read-only under the Process
//! lock, releases it, and runs the existing write body only after the
//! Kernel-minted bank proof is revalidated against this exact file and the
//! physical capacity equation preserves every outstanding funded liability.
//! The Process lock is never held across the native scope, so the lock order
//! is Native then Process.
use super::CurrentWriter;
use crate::recovery::{RecoveryCallReservation, UnusedRecoveryReservationClosureData};
use crate::store::native_return_custody as price;
use crate::store::{self, ChildPlan, Collection};
use crate::{ChildSubmission, ChildWork, ProcessError};
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::crypto::Keypair;
use chio_kernel::execution_nonce::SignedExecutionNonce;
use chio_kernel::knowledge::{
    ArtifactBlobSealV1, VerifiedConfinedReturnCandidate, VerifiedConfinedReturnDelivery,
};
use chio_kernel::{ToolCallRequest, ToolInvocationContext};
use chio_security_types::confinement::{IsolationBoundaryV1, ReturnAdmissionV1};
use std::collections::BTreeMap;

/// A recovery row that vanished between validation and pricing is a
/// conflict, exactly as the unrouted writer reported it.
fn missing_is_conflict(error: ProcessError) -> ProcessError {
    match error {
        ProcessError::Sqlite(rusqlite::Error::QueryReturnedNoRows) => ProcessError::Conflict,
        other => other,
    }
}

impl CurrentWriter {
    /// Raise a predecessor journal to the enforced knowledge level, then
    /// require it. A journal already at the level is not written.
    pub(crate) fn activate_knowledge(&self) -> Result<(), ProcessError> {
        if self.with_store(|store| store.knowledge_activation_pending())? {
            self.run(
                price::price_feature_activation_rows,
                store::enable_knowledge_call,
            )?;
        }
        self.with_store(|store| store.require_enforced_knowledge())
    }

    pub(crate) fn stage_knowledge_object(
        &self,
        process: &str,
        object: &str,
        bytes: &[u8],
    ) -> Result<String, ProcessError> {
        if let Some(generation) =
            self.with_store(|store| store.staged_object_replay(process, object, bytes))?
        {
            return Ok(generation);
        }
        let (process, object, bytes) = (process.to_owned(), object.to_owned(), bytes.to_vec());
        self.run(
            |_| price::price_artifact_object_rows(),
            move |tx| store::stage_knowledge_object_call(tx, &process, &object, &bytes),
        )
    }

    /// Whether the identity exists; an existing live object is retired in
    /// place by the routed writer.
    pub(crate) fn collect_knowledge_object(
        &self,
        process: &str,
        object: &str,
        digest: &str,
        generation: &str,
    ) -> Result<bool, ProcessError> {
        match self
            .with_store(|store| store.object_collection(process, object, digest, generation))?
        {
            Collection::Absent => Ok(false),
            Collection::Retired => Ok(true),
            Collection::Pending => {
                let priced = (process.to_owned(), object.to_owned());
                let (process, object, digest, generation) = (
                    process.to_owned(),
                    object.to_owned(),
                    digest.to_owned(),
                    generation.to_owned(),
                );
                self.run(
                    move |tx| {
                        price::price_artifact_object_retirement_rows(tx, &priced.0, &priced.1)
                    },
                    move |tx| {
                        store::collect_knowledge_object_call(
                            tx,
                            &process,
                            &object,
                            &digest,
                            &generation,
                        )
                    },
                )
            }
        }
    }

    pub(crate) fn reserve_confined_return_slot(
        &self,
        child: &str,
        parent: &str,
        boundary: &str,
        digest: &str,
    ) -> Result<(), ProcessError> {
        let (child, parent, boundary, digest) = (
            child.to_owned(),
            parent.to_owned(),
            boundary.to_owned(),
            digest.to_owned(),
        );
        self.run(
            |_| price::price_confined_slot_reservation_rows(),
            move |tx| {
                store::reserve_confined_return_slot_call(tx, &child, &parent, &boundary, &digest)
            },
        )
    }

    pub(crate) fn fill_confined_return_slot(
        &self,
        verified: VerifiedConfinedReturnCandidate,
        boundary: &IsolationBoundaryV1,
        bytes: &[u8],
    ) -> Result<String, ProcessError> {
        let digest = self
            .with_store(|store| store.authorize_confined_return_fill(verified, boundary, bytes))?;
        let (boundary, bytes) = (boundary.clone(), bytes.to_vec());
        self.run(
            |_| price::price_confined_slot_fill_rows(),
            move |tx| store::fill_confined_return_slot_call(tx, &boundary, &digest, &bytes),
        )
    }

    pub(crate) fn begin_confined_delivery(
        &self,
        proof: VerifiedConfinedReturnDelivery,
        seal: &ArtifactBlobSealV1,
        admission: &ReturnAdmissionV1,
    ) -> Result<(), ProcessError> {
        let bytes =
            self.with_store(|store| store.authorize_confined_delivery(proof, seal, admission))?;
        let namespace = self.with_store(|store| Ok(store.namespace.clone()))?;
        self.run(price::price_confined_delivery_rows, move |tx| {
            store::begin_confined_delivery_call(tx, &namespace, &bytes)
        })
    }

    pub(crate) fn reserve_recovery(
        &self,
        reservation: &RecoveryCallReservation,
    ) -> Result<(), ProcessError> {
        if self.with_store(|store| store.recovery_reservation_replayed(reservation))? {
            return Ok(());
        }
        let namespace = self.with_store(|store| Ok(store.namespace.clone()))?;
        let process = reservation.process_id().to_owned();
        let reservation = reservation.clone();
        self.run(
            move |tx| price::price_recovery_reservation_rows(tx, &process),
            move |tx| store::reserve_recovery_call(tx, &namespace, &reservation),
        )
    }

    /// Finalize a reservation and, when the custody carries the original
    /// execution nonce, retain it in the same transaction.
    pub(crate) fn finalize_recovery(
        &self,
        reservation: &RecoveryCallReservation,
        request: &ToolCallRequest,
        binding: &str,
        nonce: Option<&SignedExecutionNonce>,
    ) -> Result<(), ProcessError> {
        let priced = (
            reservation.process_id().to_owned(),
            reservation.operation_key().to_owned(),
        );
        let retains_nonce = nonce.is_some();
        let (reservation, request, binding, nonce) = (
            reservation.clone(),
            request.clone(),
            binding.to_owned(),
            nonce.cloned(),
        );
        self.run(
            move |tx| {
                price::price_recovery_finalization_rows(tx, &priced.0, &priced.1, retains_nonce)
                    .map_err(missing_is_conflict)
            },
            move |tx| {
                store::finalize_recovery_call(tx, &reservation, &request, &binding)?;
                if let Some(nonce) = &nonce {
                    store::retain_nonce_call(
                        tx,
                        reservation.process_id(),
                        reservation.operation_key(),
                        1,
                        &binding,
                        nonce,
                    )?;
                }
                Ok(())
            },
        )
    }

    pub(crate) fn close_unused_recovery_reservation(
        &self,
        writer: (&str, &str),
        reservation: &RecoveryCallReservation,
    ) -> Result<UnusedRecoveryReservationClosureData, ProcessError> {
        self.with_store(|store| store.authorize_unused_recovery_closure(writer))?;
        let namespace = self.with_store(|store| Ok(store.namespace.clone()))?;
        let (authority, kernel_key) = (writer.0.to_owned(), writer.1.to_owned());
        let reservation = reservation.clone();
        let closure = self.run(price::price_unused_closure_rows, move |tx| {
            store::close_unused_recovery_reservation_call(
                tx,
                &namespace,
                (&authority, &kernel_key),
                &reservation,
            )
        })?;
        self.with_store(|store| store.confirm_unused_recovery_closure(writer))?;
        Ok(closure)
    }

    pub(crate) fn provision_signers(
        &self,
        keys: &[(String, &Keypair)],
    ) -> Result<(), ProcessError> {
        let pending = self.with_store(|store| store.signers_to_install(keys))?;
        if pending.is_empty() {
            return Ok(());
        }
        let count = pending.len();
        self.run(
            move |_| price::price_signer_rows(count),
            move |tx| store::provision_signers_call(tx, &pending),
        )
    }

    pub(crate) fn submit_child(
        &self,
        submission: ChildSubmission<'_>,
        issue: impl FnOnce(
            &CapabilityToken,
            &Keypair,
            &Keypair,
        ) -> Result<CapabilityToken, ProcessError>,
    ) -> Result<ChildWork, ProcessError> {
        match self.with_store(|store| store.plan_child_submission(submission, issue))? {
            ChildPlan::Existing(work) => Ok(work),
            ChildPlan::Insert(insert) => self.run(
                |_| price::price_child_submission_rows(),
                move |tx| store::submit_child_call(tx, &insert),
            ),
        }
    }

    pub(crate) fn wait_for_children(
        &self,
        context: &ToolInvocationContext,
        children: &[String],
        validate: impl FnOnce(&str, &BTreeMap<String, Vec<String>>) -> Result<(), ProcessError>,
    ) -> Result<String, ProcessError> {
        let wait = self.with_store(|store| store.wait_for_children(context, children, validate))?;
        self.record_wait(wait)
    }

    pub(crate) fn wait_for_settled_children(
        &self,
        context: &ToolInvocationContext,
        children: &[String],
        validate: impl FnOnce(&str, &BTreeMap<String, Vec<String>>) -> Result<(), ProcessError>,
    ) -> Result<String, ProcessError> {
        let wait =
            self.with_store(|store| store.wait_for_settled_children(context, children, validate))?;
        self.record_wait(wait)
    }

    fn record_wait(&self, wait: store::WaitInsert) -> Result<String, ProcessError> {
        self.run(
            |_| price::price_worker_wait_rows(),
            move |tx| store::record_wait_call(tx, &wait),
        )
    }

    #[cfg(feature = "worker-server")]
    pub(crate) fn issue_worker_credential(
        &self,
        process: &str,
        hash: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<(), ProcessError> {
        let (process, hash) = (process.to_owned(), hash.to_owned());
        self.run(
            |_| price::price_worker_credential_rows(),
            move |tx| store::issue_worker_credential_call(tx, &process, &hash, expires_at, now),
        )
    }

    /// Remove every credential of the process; a process without credentials
    /// is not written.
    #[cfg(feature = "worker-server")]
    pub(crate) fn revoke_worker_credentials(&self, process: &str) -> Result<usize, ProcessError> {
        if !self.with_store(|store| store.has_worker_credentials(process))? {
            return Ok(0);
        }
        let priced = process.to_owned();
        let process = process.to_owned();
        self.run(
            move |tx| price::price_worker_credential_revocation_rows(tx, &priced),
            move |tx| store::revoke_worker_credentials_call(tx, &process),
        )
    }
}
