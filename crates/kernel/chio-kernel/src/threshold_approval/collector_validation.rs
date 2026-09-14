//! Validation at the canonical collector's persistence boundary.
//!
//! Stored records are transport data, not evidence of authorization. These checks
//! authenticate their signed artifacts and internal consistency. They do not
//! replace current request/capability context or the kernel's execution admission.

use super::{
    GovernedApprovalDecision, GovernedApprovalToken, PublicKey, ThresholdApprovalCollectorProposal,
    ThresholdApprovalCollectorState, ThresholdApprovalCollectorStoreError,
};
use crate::approval::{
    ApprovalStoreError, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalRegistration,
};
use std::collections::BTreeSet;

type CollectorResult<T = ()> = Result<T, ThresholdApprovalCollectorStoreError>;

fn conflict(message: impl ToString) -> ThresholdApprovalCollectorStoreError {
    ThresholdApprovalCollectorStoreError::Conflict(message.to_string())
}

pub(super) fn context_error(error: ApprovalStoreError) -> ThresholdApprovalCollectorStoreError {
    match error {
        ApprovalStoreError::Backend(message) => {
            ThresholdApprovalCollectorStoreError::Backend(message)
        }
        ApprovalStoreError::Serialization(message) => {
            ThresholdApprovalCollectorStoreError::Serialization(message)
        }
        error => conflict(error),
    }
}

impl ThresholdApprovalCollectorProposal {
    /// Compare immutable registration material by canonical representation.
    /// This is an idempotency check for storage ports, not authorization.
    pub fn registration_matches(&self, other: &Self) -> CollectorResult<bool> {
        let encode = |record: &Self| {
            chio_core::canonical_json_bytes(&(
                &record.proposal,
                &record.request_route,
                &record.requirement,
                &record.submitter,
                record.require_submitter_separation,
            ))
            .map_err(|error| ThresholdApprovalCollectorStoreError::Serialization(error.to_string()))
        };
        Ok(encode(self)? == encode(other)?)
    }

    pub(super) fn validate_current_context(
        &self,
        context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
    ) -> CollectorResult {
        let route = self.request_route.as_ref().ok_or_else(|| {
            conflict("threshold approval proposal requires authenticated context migration")
        })?;
        if route != context.matched_request() || &self.requirement != context.requirement() {
            return Err(conflict(
                "threshold approval request route or policy requirement changed",
            ));
        }
        let registration = ThresholdApprovalProposalRegistration::from_persisted_parts(
            self.proposal.clone(),
            route.server_id().to_string(),
            route.tool_name().to_string(),
            self.requirement
                .eligible_approvers
                .iter()
                .map(|approver| (approver.identifier.clone(), approver.public_key.clone()))
                .collect(),
            self.submitter.as_ref().map(PublicKey::to_hex),
            self.require_submitter_separation,
        )
        .map_err(context_error)?;
        registration
            .validate_current_context(context, trusted_policy_authorities)
            .map_err(context_error)
    }

    pub(super) fn validate_restored(
        &self,
        proposal_id: &str,
        active_policy_hash: &str,
        trusted_policy_authorities: &[PublicKey],
    ) -> CollectorResult {
        let proposal = &self.proposal;
        let body = &proposal.body;
        self.requirement.validate().map_err(conflict)?;
        if body.proposal_id != proposal_id {
            return Err(conflict(
                "threshold approval proposal storage key does not match",
            ));
        }
        if body.policy_hash != active_policy_hash
            || self.requirement.policy_hash != active_policy_hash
        {
            return Err(conflict(
                "threshold approval proposal is stale for the active policy",
            ));
        }
        if body.threshold != self.requirement.threshold
            || body.eligible_set_digest != self.requirement.eligible_set_digest
        {
            return Err(conflict(
                "threshold approval proposal does not match its approver requirement",
            ));
        }
        let latest_deadline = body
            .proposal_created_at
            .checked_add(self.requirement.timeout_seconds)
            .ok_or_else(|| conflict("threshold approval proposal deadline overflowed"))?;
        if body.proposal_deadline > latest_deadline {
            return Err(conflict(
                "threshold approval proposal exceeds its policy timeout",
            ));
        }
        let algorithm = proposal.algorithm.unwrap_or_default();
        if !trusted_policy_authorities.contains(&body.policy_authority)
            || body.policy_authority.algorithm() != algorithm
            || proposal.signature.algorithm() != algorithm
            || !proposal.verify_signature().map_err(conflict)?
        {
            return Err(conflict(
                "threshold approval proposal signer or signature is not trusted",
            ));
        }
        if self.require_submitter_separation && self.submitter.is_none() {
            return Err(conflict(
                "threshold approval separation requires an authenticated submitter",
            ));
        }
        if self.tokens.len() > self.requirement.eligible_approvers.len() {
            return Err(conflict(
                "threshold approval token set exceeds its eligible set",
            ));
        }
        if self.updated_at < body.proposal_created_at
            || (self.state != ThresholdApprovalCollectorState::Cancelled
                && self.updated_at >= body.proposal_deadline)
        {
            return Err(conflict(
                "threshold approval state timestamp is outside its proposal window",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut digests = BTreeSet::new();
        let mut signers = BTreeSet::new();
        let proposal_hash = proposal.artifact_digest().map_err(conflict)?;
        for token in &self.tokens {
            self.validate_token_binding(token, &proposal_hash)?;
            if token.issued_at > self.updated_at {
                return Err(conflict(
                    "threshold approval state precedes a collected token",
                ));
            }
            if !ids.insert(&token.id)
                || !digests.insert(token.artifact_digest().map_err(conflict)?)
                || !signers.insert(token.approver.to_hex())
            {
                return Err(conflict(
                    "threshold approval token id, digest, and signer must be unique",
                ));
            }
        }
        let active_count = self
            .tokens
            .iter()
            .filter(|token| token.is_valid_at(self.updated_at))
            .count();
        let threshold = usize::try_from(self.requirement.threshold).map_err(conflict)?;
        let terminal_transition = u64::from(self.state.is_terminal());
        let minimum_version = u64::try_from(self.tokens.len())
            .map_err(conflict)?
            .checked_add(terminal_transition)
            .ok_or_else(|| conflict("threshold approval version overflowed"))?;
        let quorum_matches = match self.state {
            ThresholdApprovalCollectorState::Collecting => active_count < threshold,
            ThresholdApprovalCollectorState::Ready | ThresholdApprovalCollectorState::Delivered => {
                active_count >= threshold
            }
            ThresholdApprovalCollectorState::Cancelled => true,
        };
        if !quorum_matches || self.version < minimum_version {
            return Err(conflict(
                "threshold approval state does not match its collected votes",
            ));
        }
        Ok(())
    }

    /// Validate all signed bindings, independently of whether a token is still
    /// live. Expired history must not hide a corrupt signature or duplicate vote.
    fn validate_token_binding(
        &self,
        token: &GovernedApprovalToken,
        proposal_hash: &str,
    ) -> CollectorResult {
        let body = &self.proposal.body;
        if token.id.is_empty()
            || token.id.len() > crate::approval::MAX_RESERVATION_IDENTIFIER_BYTES
            || token.id.as_bytes().contains(&0)
            || token.id.trim() != token.id
            || token.request_id != body.request_id
            || token.governed_intent_hash != body.governed_intent_hash
            || token.subject != body.subject
            || token.threshold_proposal_hash.as_deref() != Some(proposal_hash)
            || token.decision != GovernedApprovalDecision::Approved
            || token.issued_at < body.proposal_created_at
            || token.issued_at >= body.proposal_deadline
            || token.expires_at <= token.issued_at
            || token.expires_at > body.proposal_deadline
        {
            return Err(conflict(
                "threshold approval token does not match the signed proposal",
            ));
        }
        if !self
            .requirement
            .eligible_approvers
            .iter()
            .any(|eligible| eligible.public_key == token.approver)
        {
            return Err(conflict("threshold approval token signer is not eligible"));
        }
        if self.require_submitter_separation && self.submitter.as_ref() == Some(&token.approver) {
            return Err(conflict(
                "threshold approval submitter cannot approve their own proposal",
            ));
        }
        let algorithm = token.algorithm.unwrap_or_default();
        if token.approver.algorithm() != algorithm
            || token.signature.algorithm() != algorithm
            || !token.verify_signature().map_err(conflict)?
        {
            return Err(conflict(
                "threshold approval token signature did not verify",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_new_token(
        &self,
        token: &GovernedApprovalToken,
        now: u64,
    ) -> CollectorResult {
        let proposal_hash = self.proposal.artifact_digest().map_err(conflict)?;
        self.validate_token_binding(token, &proposal_hash)?;
        token.validate_time(now).map_err(conflict)
    }

    pub(super) fn validate_update_time(&self, now: u64) -> CollectorResult {
        if now < self.updated_at {
            return Err(conflict(
                "threshold approval update precedes its persisted state",
            ));
        }
        Ok(())
    }
}
