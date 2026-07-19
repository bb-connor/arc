use chio_fiscal::{
    FiscalDenialReason, FiscalDomain, FiscalDomainParams, FiscalParams, FiscalResolution,
    FiscalResolver,
};

use crate::authority::verify_signed_fee_schedule;
use crate::crypto::PublicKey;
use crate::evaluation::{
    evaluate_open_market_penalty_with_trusted_signers, OpenMarketPenaltyEvaluation,
    OpenMarketPenaltyEvaluationRequest,
};
use crate::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketFeeScheduleArtifact,
    OpenMarketFeeScheduleIssueRequest, SignedOpenMarketFeeSchedule,
};
use crate::penalty::{
    build_open_market_penalty_artifact_with_trusted_signers, OpenMarketPenaltyArtifact,
    OpenMarketPenaltyIssueRequest,
};
use crate::{canonical_json_bytes, crypto::sha256_hex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiscalLegacyFeeScheduleBinding {
    pub fiscal_schedule_id: String,
    pub legacy_envelope_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FiscalOpenMarketError {
    #[error("fiscal open-market economics denied: {0:?}")]
    Denied(FiscalDenialReason),
    #[error("open-market economics are governed by an activated fiscal schedule")]
    GovernedExternally,
    #[error("open-market economics have not been activated")]
    NotActivated,
    #[error("the active fiscal schedule has no legacy fee-schedule binding")]
    MissingBinding,
    #[error("the supplied legacy fee schedule does not match the active fiscal binding")]
    BindingMismatch,
    #[error("the legacy fee schedule is invalid: {0}")]
    InvalidLegacySchedule(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiscalOpenMarketSchedule {
    pub legacy_body: OpenMarketFeeScheduleArtifact,
}

impl FiscalDomainParams for FiscalOpenMarketSchedule {
    fn from_fiscal_params(params: &FiscalParams) -> Option<Self> {
        match params {
            FiscalParams::OpenMarketFeeAndBondSchedule { legacy_body } => Some(Self {
                legacy_body: legacy_body.as_ref().clone(),
            }),
            _ => None,
        }
    }
}

pub fn build_fiscal_open_market_fee_schedule_artifact(
    local_operator_id: &str,
    local_operator_name: Option<String>,
    request: &OpenMarketFeeScheduleIssueRequest,
    issued_at: u64,
    resolver: &FiscalResolver<'_>,
) -> Result<OpenMarketFeeScheduleArtifact, FiscalOpenMarketError> {
    match resolver
        .resolve::<FiscalOpenMarketSchedule>(FiscalDomain::OpenMarketFeeAndBondSchedule, None)
    {
        FiscalResolution::Fallback(_) => build_open_market_fee_schedule_artifact(
            local_operator_id,
            local_operator_name,
            request,
            issued_at,
        )
        .map_err(FiscalOpenMarketError::InvalidLegacySchedule),
        FiscalResolution::Governed { .. } => Err(FiscalOpenMarketError::GovernedExternally),
        FiscalResolution::Denied(reason) => Err(FiscalOpenMarketError::Denied(reason)),
    }
}

pub fn materialize_fiscal_open_market_fee_schedule(
    resolver: &FiscalResolver<'_>,
) -> Result<OpenMarketFeeScheduleArtifact, FiscalOpenMarketError> {
    match resolver
        .resolve::<FiscalOpenMarketSchedule>(FiscalDomain::OpenMarketFeeAndBondSchedule, None)
    {
        FiscalResolution::Governed { params, .. } => Ok(params.legacy_body),
        FiscalResolution::Fallback(_) => Err(FiscalOpenMarketError::NotActivated),
        FiscalResolution::Denied(reason) => Err(FiscalOpenMarketError::Denied(reason)),
    }
}

pub fn authorize_fiscal_open_market_fee_schedule(
    schedule: &SignedOpenMarketFeeSchedule,
    binding: Option<&FiscalLegacyFeeScheduleBinding>,
    resolver: &FiscalResolver<'_>,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<(), FiscalOpenMarketError> {
    match resolver
        .resolve::<FiscalOpenMarketSchedule>(FiscalDomain::OpenMarketFeeAndBondSchedule, None)
    {
        FiscalResolution::Fallback(_) => {
            verify_legacy_schedule(schedule, trusted_local_operator_signers)
        }
        FiscalResolution::Governed {
            schedule_id,
            params,
            ..
        } => {
            let binding = binding.ok_or(FiscalOpenMarketError::MissingBinding)?;
            verify_fiscal_legacy_binding(
                schedule,
                binding,
                &schedule_id,
                &params.legacy_body,
                trusted_local_operator_signers,
            )
        }
        FiscalResolution::Denied(reason) => Err(FiscalOpenMarketError::Denied(reason)),
    }
}

pub fn build_fiscal_open_market_penalty_artifact(
    local_operator_id: &str,
    request: &OpenMarketPenaltyIssueRequest,
    issued_at: u64,
    binding: Option<&FiscalLegacyFeeScheduleBinding>,
    resolver: &FiscalResolver<'_>,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<OpenMarketPenaltyArtifact, FiscalOpenMarketError> {
    authorize_fiscal_open_market_fee_schedule(
        &request.fee_schedule,
        binding,
        resolver,
        trusted_local_operator_signers,
    )?;
    build_open_market_penalty_artifact_with_trusted_signers(
        local_operator_id,
        request,
        issued_at,
        trusted_local_operator_signers,
    )
    .map_err(FiscalOpenMarketError::InvalidLegacySchedule)
}

pub fn evaluate_fiscal_open_market_penalty(
    request: &OpenMarketPenaltyEvaluationRequest,
    now: u64,
    binding: Option<&FiscalLegacyFeeScheduleBinding>,
    resolver: &FiscalResolver<'_>,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<OpenMarketPenaltyEvaluation, FiscalOpenMarketError> {
    authorize_fiscal_open_market_fee_schedule(
        &request.fee_schedule,
        binding,
        resolver,
        trusted_local_operator_signers,
    )?;
    evaluate_open_market_penalty_with_trusted_signers(request, now, trusted_local_operator_signers)
        .map_err(FiscalOpenMarketError::InvalidLegacySchedule)
}

pub fn signed_fee_schedule_digest(
    schedule: &SignedOpenMarketFeeSchedule,
) -> Result<String, FiscalOpenMarketError> {
    canonical_json_bytes(schedule)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| FiscalOpenMarketError::InvalidLegacySchedule(error.to_string()))
}

pub fn verify_fiscal_legacy_binding(
    schedule: &SignedOpenMarketFeeSchedule,
    binding: &FiscalLegacyFeeScheduleBinding,
    fiscal_schedule_id: &str,
    fiscal_legacy_body: &OpenMarketFeeScheduleArtifact,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<(), FiscalOpenMarketError> {
    verify_legacy_schedule(schedule, trusted_local_operator_signers)?;
    let envelope_digest = signed_fee_schedule_digest(schedule)?;
    if binding.fiscal_schedule_id != fiscal_schedule_id
        || binding.legacy_envelope_digest != envelope_digest
        || &schedule.body != fiscal_legacy_body
    {
        return Err(FiscalOpenMarketError::BindingMismatch);
    }
    Ok(())
}

fn verify_legacy_schedule(
    schedule: &SignedOpenMarketFeeSchedule,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<(), FiscalOpenMarketError> {
    verify_signed_fee_schedule(schedule).map_err(FiscalOpenMarketError::InvalidLegacySchedule)?;
    if !trusted_local_operator_signers
        .iter()
        .any(|trusted| trusted == &schedule.signer_key)
    {
        return Err(FiscalOpenMarketError::InvalidLegacySchedule(
            "fee schedule signer does not match a trusted open-market governing authority signer"
                .to_owned(),
        ));
    }
    Ok(())
}
