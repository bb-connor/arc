//! Ownership of a captured attempt's dispatch claim.
//!
//! Exactly one execution path holds the claim, and its owner settles the
//! attempt on every exit, including an unwind. Before the dispatch commit is
//! attempted, settling releases the claim so that an exact retry can resume.
//! From the commit attempt on, the upstream effect may have happened, so the
//! claim is never released again: settling records the outcome as unknown.

use std::panic::{catch_unwind, AssertUnwindSafe};

use super::super::failure::failure_outcome_before_dispatch;
use super::super::{
    AttemptState, AttemptStore, AttemptTransitionEvidence, BrokerDispatchKnowledge, BrokerError,
    BrokerFailureStage, ExecutionFailure, ExecutionResult, FailureProjection, Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimStage {
    /// The claim is held and no dispatch commit has been attempted.
    Claimed,
    /// The dispatch commit was attempted and has not confirmed.
    Committing,
    /// The attempt is durably DispatchCommitted.
    Committed,
    /// An explicit transition settled the attempt.
    Settled,
}

/// The dispatch claim on one captured attempt. Dropping it before the
/// dispatch commit releases the claim; dropping it once the commit was
/// attempted marks the outcome unknown.
pub(in super::super) struct ClaimedCapture<'s> {
    attempts: &'s dyn AttemptStore,
    attempt_id: String,
    dispatch_claim_id: String,
    evidence: AttemptTransitionEvidence,
    claimed_at: u64,
    stage: ClaimStage,
}

/// The single point at which a claimed attempt may be committed for dispatch.
pub(in super::super) struct DispatchCommitPoint<'c, 's> {
    claim: &'c mut ClaimedCapture<'s>,
}

/// Evidence that [`DispatchCommitPoint::commit`] durably committed the attempt.
pub(in super::super) struct DispatchCommitProof(());

/// A dispatch-committed attempt. Dropping it marks the outcome unknown, so no
/// exit after the commit can leave the attempt resendable.
pub(in super::super) struct CommittedDispatch<'s> {
    attempts: &'s dyn AttemptStore,
    attempt_id: String,
    evidence: AttemptTransitionEvidence,
    committed_at: u64,
    armed: bool,
}

impl<'s> ClaimedCapture<'s> {
    /// Claims a captured attempt for this execution path. `evidence` is the
    /// capture evidence every later transition of the attempt carries.
    pub(in super::super) fn claim(
        attempts: &'s dyn AttemptStore,
        attempt_id: &str,
        dispatch_claim_id: String,
        evidence: AttemptTransitionEvidence,
        now_unix_seconds: u64,
    ) -> ExecutionResult<Self> {
        if !attempts.claim_captured_attempt(attempt_id, &dispatch_claim_id, now_unix_seconds)? {
            return Err(BrokerError::Conflict(
                "captured broker attempt is already owned by another execution path".to_string(),
            )
            .into());
        }
        Ok(Self {
            attempts,
            attempt_id: attempt_id.to_string(),
            dispatch_claim_id,
            evidence,
            claimed_at: now_unix_seconds,
            stage: ClaimStage::Claimed,
        })
    }

    /// Refuses dispatch and releases the claim. The failure carries a
    /// capture-stage projection only when the release is confirmed; otherwise
    /// its terminal is derived from the journal, which refuses one while the
    /// claim is live.
    pub(in super::super) fn refuse(mut self, error: BrokerError) -> ExecutionFailure {
        let released = matches!(self.release(), Ok(true));
        self.stage = ClaimStage::Settled;
        let projection = released.then(|| FailureProjection {
            stage: BrokerFailureStage::Capture,
            outcome: failure_outcome_before_dispatch(&error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        });
        ExecutionFailure { error, projection }
    }

    /// Runs `dispatch`, which must end by committing through the point it is
    /// handed. A failure before the commit attempt refuses dispatch; a
    /// failure once the commit was attempted leaves the outcome unknown.
    pub(in super::super) fn commit(
        mut self,
        dispatch: impl FnOnce(DispatchCommitPoint<'_, 's>) -> Result<DispatchCommitProof>,
    ) -> ExecutionResult<CommittedDispatch<'s>> {
        match dispatch(DispatchCommitPoint { claim: &mut self }) {
            Ok(DispatchCommitProof(())) => {
                self.stage = ClaimStage::Settled;
                Ok(CommittedDispatch {
                    attempts: self.attempts,
                    attempt_id: std::mem::take(&mut self.attempt_id),
                    evidence: std::mem::take(&mut self.evidence),
                    committed_at: self.claimed_at,
                    armed: true,
                })
            }
            Err(error) if self.stage == ClaimStage::Claimed => Err(self.refuse(error)),
            Err(error) => {
                let _ = self.mark_unknown();
                self.stage = ClaimStage::Settled;
                Err(error.into())
            }
        }
    }

    fn release(&self) -> Result<bool> {
        self.attempts.release_captured_attempt_claim(
            &self.attempt_id,
            &self.dispatch_claim_id,
            self.claimed_at,
        )
    }

    fn mark_unknown(&self) -> Result<()> {
        let from = if self.stage == ClaimStage::Committed {
            AttemptState::DispatchCommitted
        } else {
            AttemptState::Captured
        };
        self.attempts
            .transition(
                &self.attempt_id,
                from,
                AttemptState::UnknownOutcome,
                &self.evidence,
                self.claimed_at,
            )
            .map(drop)
    }
}

impl Drop for ClaimedCapture<'_> {
    fn drop(&mut self) {
        match self.stage {
            ClaimStage::Claimed => compensate(|| self.release().map(drop)),
            ClaimStage::Committing | ClaimStage::Committed => compensate(|| self.mark_unknown()),
            ClaimStage::Settled => {}
        }
    }
}

impl DispatchCommitPoint<'_, '_> {
    /// Commits the claimed attempt for dispatch. From this call on the claim
    /// is never released, whether or not the commit confirms.
    pub(in super::super) fn commit(
        self,
        dispatch_unix_seconds: u64,
    ) -> Result<DispatchCommitProof> {
        let claim = self.claim;
        claim.stage = ClaimStage::Committing;
        claim.attempts.commit_captured_attempt_dispatch(
            &claim.attempt_id,
            &claim.dispatch_claim_id,
            &claim.evidence,
            dispatch_unix_seconds,
        )?;
        claim.stage = ClaimStage::Committed;
        Ok(DispatchCommitProof(()))
    }
}

impl CommittedDispatch<'_> {
    /// Fails after dispatch with the outcome recorded as unknown.
    pub(in super::super) fn unknown(
        mut self,
        error: BrokerError,
        projection: FailureProjection,
        at_unix_seconds: u64,
    ) -> ExecutionFailure {
        let _ = self.mark_unknown(at_unix_seconds);
        self.armed = false;
        ExecutionFailure::at(error, projection)
    }

    /// Fails after dispatch and leaves the attempt DispatchCommitted. An exact
    /// retry resolves it to unknown without sending again.
    pub(in super::super) fn fail_committed(
        mut self,
        error: BrokerError,
        projection: FailureProjection,
    ) -> ExecutionFailure {
        self.armed = false;
        ExecutionFailure::at(error, projection)
    }

    /// Completes the attempt with the digest of its persisted response. A
    /// failed completion leaves the attempt DispatchCommitted with that
    /// response persisted, which an exact retry completes.
    pub(in super::super) fn complete(
        mut self,
        response_digest: String,
        at_unix_seconds: u64,
    ) -> Result<()> {
        self.armed = false;
        let completion = AttemptTransitionEvidence {
            response_digest: Some(response_digest),
            ..std::mem::take(&mut self.evidence)
        };
        self.attempts
            .transition(
                &self.attempt_id,
                AttemptState::DispatchCommitted,
                AttemptState::Completed,
                &completion,
                at_unix_seconds,
            )
            .map(drop)
    }

    fn mark_unknown(&self, at_unix_seconds: u64) -> Result<()> {
        self.attempts
            .transition(
                &self.attempt_id,
                AttemptState::DispatchCommitted,
                AttemptState::UnknownOutcome,
                &self.evidence,
                at_unix_seconds,
            )
            .map(drop)
    }
}

impl Drop for CommittedDispatch<'_> {
    fn drop(&mut self) {
        if self.armed {
            compensate(|| self.mark_unknown(self.committed_at));
        }
    }
}

/// Runs a compensating transition from `Drop`, which has no caller to report
/// to and must not unwind. A compensation that fails or panics leaves the
/// claim or the DispatchCommitted state in the journal, where startup
/// reconciliation and exact replay settle it, as after a crash.
fn compensate(transition: impl FnOnce() -> Result<()>) {
    let _ = catch_unwind(AssertUnwindSafe(transition));
}
