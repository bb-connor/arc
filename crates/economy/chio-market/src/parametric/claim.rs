use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::*;

pub const PARAMETRIC_CLAIM_RECORD_SCHEMA: &str = "chio.parametric.claim-record.v1";
pub const PARAMETRIC_CONTEST_SCHEMA: &str = "chio.parametric.contest.v1";
pub const PARAMETRIC_PAYOUT_INTENT_SCHEMA: &str = "chio.parametric.payout-intent.v1";
pub const PARAMETRIC_PAYOUT_BINDING_SCHEMA: &str = "chio.parametric.payout-binding.v1";
pub const PARAMETRIC_CONTEST_ID_DOMAIN: &str = "chio.parametric.contest.id.v1";
pub const PARAMETRIC_PAYOUT_INTENT_ID_DOMAIN: &str = "chio.parametric.payout-intent.id.v1";
pub const MAX_PARAMETRIC_CONTEST_EVIDENCE: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParametricClaimError {
    #[error(transparent)]
    Contract(#[from] ParametricContractError),
    #[error("parametric claim compare-and-swap conflict: {0}")]
    CompareAndSwapConflict(&'static str),
    #[error("parametric claim transition is invalid from state: {0}")]
    InvalidTransition(&'static str),
    #[error("parametric contest is outside its trusted receipt window")]
    ContestWindowClosed,
    #[error("parametric contest signer is not trusted")]
    UntrustedContestant,
    #[error("parametric contest signature is invalid")]
    InvalidContestSignature,
    #[error("parametric payout is not eligible")]
    PayoutNotEligible,
    #[error("parametric payout intent conflicts with the reserved intent")]
    PayoutIntentConflict,
    #[error("parametric claim arithmetic overflow: {0}")]
    ArithmeticOverflow(&'static str),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParametricClaimStateV1 {
    Ready,
    ContestOpen,
    Contested,
    UncontestedReleased,
    PayoutReserved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricClaimRecordV1 {
    schema: String,
    identity: ParametricClaimIdentity,
    coverage_authority_id: String,
    payer_id: String,
    beneficiary_id: String,
    funding_facility_id: String,
    payout_rail: ParametricPayoutRail,
    payout_mode: ParametricPayoutMode,
    trigger_magnitude: TriggerMagnitude,
    payout_amount: MonetaryAmount,
    opened_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contest_deadline: Option<u64>,
    state: ParametricClaimStateV1,
    version: u64,
    lifecycle_fence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contest_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payout_binding: Option<ParametricPayoutBindingV1>,
}

impl ParametricClaimRecordV1 {
    pub fn open(
        policy: &VerifiedParametricPolicy,
        trigger: &VerifiedFiredTriggerV1,
        trusted_opened_at: u64,
    ) -> Result<Self, ParametricClaimError> {
        policy.body().validate()?;
        trigger.ensure_policy(policy.body_digest())?;
        let identity = trigger.identity().clone();
        let trigger_magnitude = trigger.magnitude().clone();
        identity.validate()?;
        require_binding(
            identity.key.parametric_policy_body_digest == policy.body_digest(),
            "claim.policy_body_digest",
        )?;
        require_binding(
            identity.key.bound_coverage_body_digest == policy.body().bound_coverage_body_digest,
            "claim.bound_coverage_body_digest",
        )?;
        require_binding(
            identity.key.subject_key == policy.body().subject_key,
            "claim.subject_key",
        )?;
        if trusted_opened_at < identity.key.window_end {
            return Err(ParametricContractError::InvalidField("claim.opened_at").into());
        }
        let payout_amount = policy.body().payout_schedule.evaluate(
            &policy.body().predicate,
            &trigger_magnitude,
            &policy.body().coverage_amount,
        )?;
        let (state, contest_deadline) = match policy.body().payout_mode {
            ParametricPayoutMode::Automatic => (ParametricClaimStateV1::Ready, None),
            ParametricPayoutMode::Contestable { window_seconds } => (
                ParametricClaimStateV1::ContestOpen,
                Some(
                    trusted_opened_at
                        .checked_add(window_seconds)
                        .ok_or(ParametricClaimError::ArithmeticOverflow("contest_deadline"))?,
                ),
            ),
        };
        let record = Self {
            schema: PARAMETRIC_CLAIM_RECORD_SCHEMA.to_owned(),
            identity,
            coverage_authority_id: policy.body().coverage_authority_id.clone(),
            payer_id: policy.body().payer_id.clone(),
            beneficiary_id: policy.body().beneficiary_id.clone(),
            funding_facility_id: policy.body().funding_facility_id.clone(),
            payout_rail: policy.body().payout_rail.clone(),
            payout_mode: policy.body().payout_mode.clone(),
            trigger_magnitude,
            payout_amount,
            opened_at: trusted_opened_at,
            contest_deadline,
            state,
            version: 1,
            lifecycle_fence: 1,
            contest_digest: None,
            payout_binding: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_CLAIM_RECORD_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        self.identity.validate()?;
        validate_clean(&self.coverage_authority_id, "claim.coverage_authority_id")?;
        validate_clean(&self.payer_id, "claim.payer_id")?;
        validate_clean(&self.beneficiary_id, "claim.beneficiary_id")?;
        validate_clean(&self.funding_facility_id, "claim.funding_facility_id")?;
        self.payout_rail.validate()?;
        self.payout_mode.validate()?;
        validate_money(&self.payout_amount, "claim.payout_amount", false)?;
        if self.opened_at < self.identity.key.window_end {
            return Err(ParametricContractError::InvalidField("claim.opened_at").into());
        }
        if self.version == 0 || self.version != self.lifecycle_fence {
            return Err(ParametricContractError::InvalidField("claim.lifecycle_fence").into());
        }
        let deadline_matches = match (&self.payout_mode, self.contest_deadline) {
            (ParametricPayoutMode::Automatic, None) => true,
            (ParametricPayoutMode::Contestable { window_seconds }, Some(contest_deadline)) => self
                .opened_at
                .checked_add(*window_seconds)
                .is_some_and(|expected| expected == contest_deadline),
            _ => false,
        };
        if !deadline_matches {
            return Err(ParametricContractError::InvalidField("claim.contest_deadline").into());
        }
        let state_matches = match self.state {
            ParametricClaimStateV1::Ready => {
                matches!(self.payout_mode, ParametricPayoutMode::Automatic)
                    && self.contest_digest.is_none()
                    && self.payout_binding.is_none()
            }
            ParametricClaimStateV1::ContestOpen => {
                matches!(self.payout_mode, ParametricPayoutMode::Contestable { .. })
                    && self.contest_digest.is_none()
                    && self.payout_binding.is_none()
            }
            ParametricClaimStateV1::Contested => {
                matches!(self.payout_mode, ParametricPayoutMode::Contestable { .. })
                    && self.contest_digest.is_some()
                    && self.payout_binding.is_none()
            }
            ParametricClaimStateV1::UncontestedReleased => {
                matches!(self.payout_mode, ParametricPayoutMode::Contestable { .. })
                    && self.contest_digest.is_none()
                    && self.payout_binding.is_none()
            }
            ParametricClaimStateV1::PayoutReserved => {
                self.contest_digest.is_none() && self.payout_binding.is_some()
            }
        };
        if !state_matches {
            return Err(ParametricContractError::InvalidField("claim.state").into());
        }
        if let Some(binding) = self.payout_binding.as_ref() {
            binding.validate()?;
            let expected_version = binding
                .expected_claim_version
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?;
            let expected_fence = binding.expected_lifecycle_fence.checked_add(1).ok_or(
                ParametricClaimError::ArithmeticOverflow("claim.lifecycle_fence"),
            )?;
            if self.version != expected_version || self.lifecycle_fence != expected_fence {
                return Err(ParametricClaimError::CompareAndSwapConflict(
                    "payout_binding_head",
                ));
            }
            self.ensure_binding_matches(binding)?;
        }
        Ok(())
    }

    pub fn verify_semantic_replay(
        &self,
        policy: &VerifiedParametricPolicy,
        trigger: &VerifiedFiredTriggerV1,
    ) -> Result<(), ParametricClaimError> {
        self.validate()?;
        trigger.ensure_policy(policy.body_digest())?;
        let identity = trigger.identity();
        let magnitude = trigger.magnitude();
        identity.validate()?;
        let amount = policy.body().payout_schedule.evaluate(
            &policy.body().predicate,
            magnitude,
            &policy.body().coverage_amount,
        )?;
        if identity != &self.identity
            || policy.body_digest() != self.identity.key.parametric_policy_body_digest
            || policy.body().coverage_authority_id != self.coverage_authority_id
            || policy.body().payer_id != self.payer_id
            || policy.body().beneficiary_id != self.beneficiary_id
            || policy.body().funding_facility_id != self.funding_facility_id
            || policy.body().payout_rail != self.payout_rail
            || policy.body().payout_mode != self.payout_mode
            || magnitude != &self.trigger_magnitude
            || amount != self.payout_amount
        {
            return Err(ParametricClaimError::CompareAndSwapConflict(
                "semantic_replay",
            ));
        }
        Ok(())
    }

    pub fn file_contest(
        &self,
        expected_version: u64,
        expected_lifecycle_fence: u64,
        trusted_received_at: u64,
        contest: &VerifiedParametricContestV1,
    ) -> Result<Self, ParametricClaimError> {
        self.validate()?;
        let body = contest.body();
        if self.state == ParametricClaimStateV1::Contested {
            let replay_version = expected_version
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?;
            let replay_fence = expected_lifecycle_fence.checked_add(1).ok_or(
                ParametricClaimError::ArithmeticOverflow("claim.lifecycle_fence"),
            )?;
            if self.version == replay_version
                && self.lifecycle_fence == replay_fence
                && self.contest_digest.as_deref() == Some(contest.envelope_digest())
                && body.expected_claim_version == expected_version
                && body.expected_lifecycle_fence == expected_lifecycle_fence
            {
                return Ok(self.clone());
            }
            return Err(ParametricClaimError::CompareAndSwapConflict("contest"));
        }
        self.ensure_head(expected_version, expected_lifecycle_fence)?;
        if self.state != ParametricClaimStateV1::ContestOpen {
            return Err(ParametricClaimError::InvalidTransition("file_contest"));
        }
        if body.claim_id != self.identity.claim_id
            || body.parametric_policy_body_digest != self.identity.key.parametric_policy_body_digest
            || body.contestant_id != self.coverage_authority_id
            || body.expected_claim_version != expected_version
            || body.expected_lifecycle_fence != expected_lifecycle_fence
        {
            return Err(ParametricClaimError::CompareAndSwapConflict(
                "contest_binding",
            ));
        }
        let deadline = self
            .contest_deadline
            .ok_or(ParametricClaimError::InvalidTransition("file_contest"))?;
        if trusted_received_at >= deadline
            || trusted_received_at < body.issued_at
            || trusted_received_at >= body.expires_at
        {
            return Err(ParametricClaimError::ContestWindowClosed);
        }
        let (version, lifecycle_fence) = self.next_head()?;
        let mut next = self.clone();
        next.state = ParametricClaimStateV1::Contested;
        next.version = version;
        next.lifecycle_fence = lifecycle_fence;
        next.contest_digest = Some(contest.envelope_digest().to_owned());
        next.validate()?;
        Ok(next)
    }

    pub fn release_uncontested(
        &self,
        expected_version: u64,
        expected_lifecycle_fence: u64,
        trusted_now: u64,
    ) -> Result<Self, ParametricClaimError> {
        self.validate()?;
        if self.state == ParametricClaimStateV1::UncontestedReleased {
            let replay_version = expected_version
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?;
            let replay_fence = expected_lifecycle_fence.checked_add(1).ok_or(
                ParametricClaimError::ArithmeticOverflow("claim.lifecycle_fence"),
            )?;
            if self.version == replay_version && self.lifecycle_fence == replay_fence {
                return Ok(self.clone());
            }
        }
        self.ensure_head(expected_version, expected_lifecycle_fence)?;
        if self.state != ParametricClaimStateV1::ContestOpen {
            return Err(ParametricClaimError::InvalidTransition(
                "release_uncontested",
            ));
        }
        if trusted_now
            < self
                .contest_deadline
                .ok_or(ParametricClaimError::InvalidTransition(
                    "release_uncontested",
                ))?
        {
            return Err(ParametricClaimError::ContestWindowClosed);
        }
        let (version, lifecycle_fence) = self.next_head()?;
        let mut next = self.clone();
        next.state = ParametricClaimStateV1::UncontestedReleased;
        next.version = version;
        next.lifecycle_fence = lifecycle_fence;
        next.validate()?;
        Ok(next)
    }

    pub fn expected_payout_binding(
        &self,
        capital_instruction_body_digest: String,
    ) -> Result<ParametricPayoutBindingV1, ParametricClaimError> {
        self.validate()?;
        if !matches!(
            self.state,
            ParametricClaimStateV1::Ready | ParametricClaimStateV1::UncontestedReleased
        ) {
            return Err(ParametricClaimError::PayoutNotEligible);
        }
        let binding = ParametricPayoutBindingV1 {
            schema: PARAMETRIC_PAYOUT_BINDING_SCHEMA.to_owned(),
            claim_id: self.identity.claim_id.clone(),
            expected_claim_version: self.version,
            expected_lifecycle_fence: self.lifecycle_fence,
            bound_coverage_body_digest: self.identity.key.bound_coverage_body_digest.clone(),
            payer_id: self.payer_id.clone(),
            beneficiary_id: self.beneficiary_id.clone(),
            funding_facility_id: self.funding_facility_id.clone(),
            payout_rail: self.payout_rail.clone(),
            capital_instruction_body_digest,
            amount: self.payout_amount.clone(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn reserve_payout(
        &self,
        binding: ParametricPayoutBindingV1,
    ) -> Result<(Self, ParametricPayoutIntentV1), ParametricClaimError> {
        self.validate()?;
        binding.validate()?;
        if self.state == ParametricClaimStateV1::PayoutReserved {
            if self.payout_binding.as_ref() == Some(&binding)
                && self.version
                    == binding
                        .expected_claim_version
                        .checked_add(1)
                        .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?
                && self.lifecycle_fence
                    == binding.expected_lifecycle_fence.checked_add(1).ok_or(
                        ParametricClaimError::ArithmeticOverflow("claim.lifecycle_fence"),
                    )?
            {
                let intent = ParametricPayoutIntentV1::new(binding)?;
                intent.validate_against(self)?;
                return Ok((self.clone(), intent));
            }
            return Err(ParametricClaimError::PayoutIntentConflict);
        }
        if !matches!(
            self.state,
            ParametricClaimStateV1::Ready | ParametricClaimStateV1::UncontestedReleased
        ) {
            return Err(ParametricClaimError::PayoutNotEligible);
        }
        self.ensure_head(
            binding.expected_claim_version,
            binding.expected_lifecycle_fence,
        )?;
        self.ensure_binding_matches(&binding)?;
        let intent = ParametricPayoutIntentV1::new(binding.clone())?;
        let (version, lifecycle_fence) = self.next_head()?;
        let mut next = self.clone();
        next.state = ParametricClaimStateV1::PayoutReserved;
        next.version = version;
        next.lifecycle_fence = lifecycle_fence;
        next.payout_binding = Some(binding);
        next.validate()?;
        intent.validate_against(&next)?;
        Ok((next, intent))
    }

    fn ensure_head(
        &self,
        expected_version: u64,
        expected_lifecycle_fence: u64,
    ) -> Result<(), ParametricClaimError> {
        if self.version == expected_version && self.lifecycle_fence == expected_lifecycle_fence {
            Ok(())
        } else {
            Err(ParametricClaimError::CompareAndSwapConflict("claim_head"))
        }
    }

    fn next_head(&self) -> Result<(u64, u64), ParametricClaimError> {
        Ok((
            self.version
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?,
            self.lifecycle_fence
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow(
                    "claim.lifecycle_fence",
                ))?,
        ))
    }

    fn ensure_binding_matches(
        &self,
        binding: &ParametricPayoutBindingV1,
    ) -> Result<(), ParametricClaimError> {
        require_binding(
            binding.claim_id == self.identity.claim_id,
            "payout_binding.claim_id",
        )?;
        require_binding(
            binding.bound_coverage_body_digest == self.identity.key.bound_coverage_body_digest,
            "payout_binding.bound_coverage_body_digest",
        )?;
        require_binding(binding.payer_id == self.payer_id, "payout_binding.payer_id")?;
        require_binding(
            binding.beneficiary_id == self.beneficiary_id,
            "payout_binding.beneficiary_id",
        )?;
        require_binding(
            binding.funding_facility_id == self.funding_facility_id,
            "payout_binding.funding_facility_id",
        )?;
        require_binding(
            binding.payout_rail.kind == self.payout_rail.kind,
            "payout_binding.rail_kind",
        )?;
        require_binding(
            binding.payout_rail.rail_id == self.payout_rail.rail_id,
            "payout_binding.rail_id",
        )?;
        require_binding(
            binding.payout_rail.destination_account_digest
                == self.payout_rail.destination_account_digest,
            "payout_binding.destination_account_digest",
        )?;
        require_binding(
            binding.amount == self.payout_amount,
            "payout_binding.amount",
        )?;
        Ok(())
    }

    #[must_use]
    pub const fn state(&self) -> ParametricClaimStateV1 {
        self.state
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn lifecycle_fence(&self) -> u64 {
        self.lifecycle_fence
    }

    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.identity.claim_id
    }

    #[must_use]
    pub fn trigger_instance_id(&self) -> &str {
        &self.identity.trigger_instance_id
    }

    #[must_use]
    pub const fn contest_deadline(&self) -> Option<u64> {
        self.contest_deadline
    }

    #[must_use]
    pub const fn payout_amount(&self) -> &MonetaryAmount {
        &self.payout_amount
    }

    #[must_use]
    pub const fn payout_binding(&self) -> Option<&ParametricPayoutBindingV1> {
        self.payout_binding.as_ref()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParametricContestReasonCodeV1 {
    CorpusIntegrity,
    PredicateEvaluation,
    PolicyBinding,
    DuplicateEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricContestV1 {
    schema: String,
    contest_id: String,
    claim_id: String,
    parametric_policy_body_digest: String,
    expected_claim_version: u64,
    expected_lifecycle_fence: u64,
    contestant_id: String,
    issued_at: u64,
    expires_at: u64,
    reason_code: ParametricContestReasonCodeV1,
    evidence_digests: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParametricContestIdPreimage<'a> {
    claim_id: &'a str,
    parametric_policy_body_digest: &'a str,
    expected_claim_version: u64,
    expected_lifecycle_fence: u64,
    contestant_id: &'a str,
    issued_at: u64,
    expires_at: u64,
    reason_code: ParametricContestReasonCodeV1,
    evidence_digests: &'a [String],
}

impl ParametricContestV1 {
    pub fn new(
        claim: &ParametricClaimRecordV1,
        contestant_id: String,
        issued_at: u64,
        expires_at: u64,
        reason_code: ParametricContestReasonCodeV1,
        mut evidence_digests: Vec<String>,
    ) -> Result<Self, ParametricClaimError> {
        claim.validate()?;
        evidence_digests.sort_unstable();
        let mut contest = Self {
            schema: PARAMETRIC_CONTEST_SCHEMA.to_owned(),
            contest_id: String::new(),
            claim_id: claim.identity.claim_id.clone(),
            parametric_policy_body_digest: claim.identity.key.parametric_policy_body_digest.clone(),
            expected_claim_version: claim.version,
            expected_lifecycle_fence: claim.lifecycle_fence,
            contestant_id,
            issued_at,
            expires_at,
            reason_code,
            evidence_digests,
        };
        contest.contest_id = domain_digest(PARAMETRIC_CONTEST_ID_DOMAIN, &contest.id_preimage())?;
        contest.validate()?;
        Ok(contest)
    }

    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_CONTEST_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        validate_digest(&self.contest_id, "contest.contest_id")?;
        validate_digest(&self.claim_id, "contest.claim_id")?;
        validate_digest(
            &self.parametric_policy_body_digest,
            "contest.parametric_policy_body_digest",
        )?;
        if self.expected_claim_version == 0 || self.expected_lifecycle_fence == 0 {
            return Err(ParametricContractError::InvalidField("contest.claim_head").into());
        }
        validate_clean(&self.contestant_id, "contest.contestant_id")?;
        if self.issued_at == 0 || self.expires_at <= self.issued_at {
            return Err(ParametricContractError::InvalidField("contest.validity").into());
        }
        if self.evidence_digests.is_empty()
            || self.evidence_digests.len() > MAX_PARAMETRIC_CONTEST_EVIDENCE
            || !self
                .evidence_digests
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(ParametricContractError::InvalidField("contest.evidence_digests").into());
        }
        for digest in &self.evidence_digests {
            validate_digest(digest, "contest.evidence_digest")?;
        }
        require_binding(
            self.contest_id == domain_digest(PARAMETRIC_CONTEST_ID_DOMAIN, &self.id_preimage())?,
            "contest.contest_id",
        )?;
        Ok(())
    }

    fn id_preimage(&self) -> ParametricContestIdPreimage<'_> {
        ParametricContestIdPreimage {
            claim_id: &self.claim_id,
            parametric_policy_body_digest: &self.parametric_policy_body_digest,
            expected_claim_version: self.expected_claim_version,
            expected_lifecycle_fence: self.expected_lifecycle_fence,
            contestant_id: &self.contestant_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            reason_code: self.reason_code,
            evidence_digests: &self.evidence_digests,
        }
    }
}

pub type SignedParametricContestV1 = SignedExportEnvelope<ParametricContestV1>;

#[derive(Debug, Clone)]
pub struct VerifiedParametricContestV1 {
    signed: SignedParametricContestV1,
    envelope_digest: String,
}

impl VerifiedParametricContestV1 {
    pub fn verify(
        signed: SignedParametricContestV1,
        trusted_contestant_id: &str,
        trusted_contestant_key: &PublicKey,
    ) -> Result<Self, ParametricClaimError> {
        signed.body.validate()?;
        validate_clean(trusted_contestant_id, "trusted.contestant_id")?;
        if signed.body.contestant_id != trusted_contestant_id
            || &signed.signer_key != trusted_contestant_key
        {
            return Err(ParametricClaimError::UntrustedContestant);
        }
        if !signed
            .verify_signature()
            .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?
        {
            return Err(ParametricClaimError::InvalidContestSignature);
        }
        Ok(Self {
            envelope_digest: canonical_digest(&signed)?,
            signed,
        })
    }

    #[must_use]
    pub const fn body(&self) -> &ParametricContestV1 {
        &self.signed.body
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedParametricContestV1 {
        &self.signed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricPayoutBindingV1 {
    pub schema: String,
    pub claim_id: String,
    pub expected_claim_version: u64,
    pub expected_lifecycle_fence: u64,
    pub bound_coverage_body_digest: String,
    pub payer_id: String,
    pub beneficiary_id: String,
    pub funding_facility_id: String,
    pub payout_rail: ParametricPayoutRail,
    pub capital_instruction_body_digest: String,
    pub amount: MonetaryAmount,
}

impl ParametricPayoutBindingV1 {
    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_PAYOUT_BINDING_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        validate_digest(&self.claim_id, "payout_binding.claim_id")?;
        if self.expected_claim_version == 0 || self.expected_lifecycle_fence == 0 {
            return Err(ParametricContractError::InvalidField("payout_binding.claim_head").into());
        }
        validate_digest(
            &self.bound_coverage_body_digest,
            "payout_binding.bound_coverage_body_digest",
        )?;
        validate_clean(&self.payer_id, "payout_binding.payer_id")?;
        validate_clean(&self.beneficiary_id, "payout_binding.beneficiary_id")?;
        validate_clean(
            &self.funding_facility_id,
            "payout_binding.funding_facility_id",
        )?;
        self.payout_rail.validate()?;
        validate_digest(
            &self.capital_instruction_body_digest,
            "payout_binding.capital_instruction_body_digest",
        )?;
        validate_money(&self.amount, "payout_binding.amount", false)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricPayoutIntentV1 {
    pub schema: String,
    pub payout_intent_id: String,
    pub binding: ParametricPayoutBindingV1,
}

impl ParametricPayoutIntentV1 {
    fn new(binding: ParametricPayoutBindingV1) -> Result<Self, ParametricClaimError> {
        let intent = Self {
            schema: PARAMETRIC_PAYOUT_INTENT_SCHEMA.to_owned(),
            payout_intent_id: parametric_payout_intent_id(&binding.claim_id)?,
            binding,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_PAYOUT_INTENT_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        self.binding.validate()?;
        require_binding(
            self.payout_intent_id == parametric_payout_intent_id(&self.binding.claim_id)?,
            "payout_intent.payout_intent_id",
        )?;
        Ok(())
    }

    pub fn validate_against(
        &self,
        claim: &ParametricClaimRecordV1,
    ) -> Result<(), ParametricClaimError> {
        claim.validate()?;
        self.validate()?;
        if claim.state != ParametricClaimStateV1::PayoutReserved
            || claim.payout_binding.as_ref() != Some(&self.binding)
        {
            return Err(ParametricClaimError::PayoutIntentConflict);
        }
        claim.ensure_binding_matches(&self.binding)
    }
}

pub fn parametric_payout_intent_id(claim_id: &str) -> Result<String, ParametricClaimError> {
    validate_digest(claim_id, "payout_intent.claim_id")?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PayoutIntentIdPreimage<'a> {
        claim_id: &'a str,
    }
    Ok(domain_digest(
        PARAMETRIC_PAYOUT_INTENT_ID_DOMAIN,
        &PayoutIntentIdPreimage { claim_id },
    )?)
}
