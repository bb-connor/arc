//! Original-bound future ToolOutcome transaction envelopes are DATA, not loans.
//! Only the actual native finishing source supplies the original producing plan.
use super::security_participant_state::finishing_plan::NativeToolOutcomeSourcePlan;
use super::*;
use chio_kernel::tool_outcome::{EvaluationModeV1, EvaluationPhaseV1};

mod rows;
pub(super) use rows::{ToolOutcomeRowEnvelopeData, ToolOutcomeWriteTableData};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ToolOutcomeTransactionPurposeData {
    RawCustody,
    EvaluationBegin,
    EvaluationStage,
    Finalization { pure_prefix: u64 },
}

pub(super) struct ToolOutcomeTransactionEnvelopeData {
    purpose: ToolOutcomeTransactionPurposeData,
    rows: Vec<ToolOutcomeRowEnvelopeData>,
    admission_appends: u64,
    global_appends: u64,
}

impl ToolOutcomeTransactionEnvelopeData {
    pub(super) fn purpose(&self) -> ToolOutcomeTransactionPurposeData {
        self.purpose
    }

    pub(super) fn rows(&self) -> &[ToolOutcomeRowEnvelopeData] {
        &self.rows
    }

    pub(super) fn admission_appends(&self) -> u64 {
        self.admission_appends
    }

    pub(super) fn global_appends(&self) -> u64 {
        self.global_appends
    }
}

struct ToolOutcomeEnvelopeData {
    raw_bytes: u64,
    resolved_bytes: u64,
    outcome_bytes: u64,
    evaluation_bytes: u64,
    request_id_bytes: u64,
    claimant_bytes: u64,
    coordinator_lease_bytes: u64,
    global_row_bytes: u64,
    global_index_bytes: u64,
}

/// The declared source interface is authored with the native role owner. This
/// target is unregistered until that real role and its complete catalog exist.
/// Source verification must precede both the row description and pricing.
pub(super) fn describe_native_tool_outcome_transactions(
    source: &impl NativeToolOutcomeSourcePlan,
) -> Result<Vec<ToolOutcomeTransactionEnvelopeData>, AdmissionOperationStoreError> {
    let original = source.original();
    let profile = original
        .native_output_retention()
        .ok_or_else(|| invariant("original ToolOutcome producing bounds are absent"))?;
    let steps = source.frozen_steps();
    let selected = u64::try_from(steps.len())
        .map_err(|_| invariant("original frozen evaluation count exhausted"))?;
    if selected == 0
        || selected > u64::from(profile.envelopes().post_return_steps())
        || steps.iter().any(|step| {
            step.phase != EvaluationPhaseV1::OutputGuard
                || !matches!(step.mode, EvaluationModeV1::Pure)
        })
    {
        return Err(invariant(
            "original ToolOutcome producing program is unsupported",
        ));
    }
    // The native role checks the exact qualified bounded implementation, not
    // merely these schema variants or the configured maximum step capacity.
    let produced = source.tool_outcome_envelope();
    let global = source.global_commit_envelope();
    let envelope = ToolOutcomeEnvelopeData {
        raw_bytes: produced.raw_bytes(),
        resolved_bytes: produced.resolved_bytes(),
        outcome_bytes: produced.outcome_bytes(),
        evaluation_bytes: produced.evaluation_bytes(),
        request_id_bytes: u64::try_from(source.operation().binding().request_id().as_str().len())
            .map_err(|_| invariant("original request identifier bytes exhausted"))?,
        claimant_bytes: u64::try_from(produced.claimant_maximum_bytes())
            .map_err(|_| invariant("original future claimant bytes exhausted"))?,
        coordinator_lease_bytes: u64::try_from(
            chio_kernel::admission_operation::MAX_ADMISSION_IDENTIFIER_BYTES,
        )
        .map_err(|_| invariant("original coordinator identifier bound exhausted"))?,
        global_row_bytes: global.maximum_record_bytes(),
        global_index_bytes: global.maximum_index_record_bytes(),
    };
    validate_envelope(&envelope, profile.envelopes())?;
    let purposes = [
        ToolOutcomeTransactionPurposeData::RawCustody,
        ToolOutcomeTransactionPurposeData::EvaluationBegin,
        // The actual Kernel producer commits its selected Pure prefix and the
        // final pair atomically. N rewrites still retain N admission/globals.
        ToolOutcomeTransactionPurposeData::Finalization {
            pure_prefix: selected,
        },
    ];
    purposes
        .into_iter()
        .map(|purpose| transaction(&envelope, purpose))
        .collect()
}

fn validate_envelope(
    envelope: &ToolOutcomeEnvelopeData,
    bounds: &chio_kernel::admission_operation::NativeOutputEnvelopeBoundsV1,
) -> Result<(), AdmissionOperationStoreError> {
    let outcome_maximum = u64::try_from(crate::tool_outcome_store::outcome_record_maximum_bytes())
        .map_err(|_| invariant("ToolOutcome producer maximum exhausted"))?;
    let evaluation_maximum =
        u64::try_from(crate::tool_outcome_store::evaluation_record_maximum_bytes())
            .map_err(|_| invariant("evaluation producer maximum exhausted"))?;
    if envelope.raw_bytes == 0
        || envelope.raw_bytes > bounds.raw()
        || envelope.resolved_bytes == 0
        || envelope.resolved_bytes > bounds.resolved()
        || envelope.outcome_bytes == 0
        || envelope.outcome_bytes > outcome_maximum
        || envelope.evaluation_bytes == 0
        || envelope.evaluation_bytes > bounds.evaluation().min(evaluation_maximum)
        || !(1..=2_048).contains(&envelope.request_id_bytes)
        || !(1..=512).contains(&envelope.claimant_bytes)
        || !(1..=512).contains(&envelope.coordinator_lease_bytes)
        || envelope.global_row_bytes == 0
        || envelope.global_index_bytes == 0
    {
        return Err(invariant(
            "source-owned ToolOutcome envelope is outside its producer bound",
        ));
    }
    Ok(())
}

fn transaction(
    envelope: &ToolOutcomeEnvelopeData,
    purpose: ToolOutcomeTransactionPurposeData,
) -> Result<ToolOutcomeTransactionEnvelopeData, AdmissionOperationStoreError> {
    let appends = match purpose {
        ToolOutcomeTransactionPurposeData::RawCustody
        | ToolOutcomeTransactionPurposeData::EvaluationBegin => 2,
        ToolOutcomeTransactionPurposeData::EvaluationStage => 1,
        ToolOutcomeTransactionPurposeData::Finalization { pure_prefix } => pure_prefix
            .checked_add(1)
            .ok_or_else(|| invariant("original finalization append capacity exhausted"))?,
    };
    Ok(ToolOutcomeTransactionEnvelopeData {
        purpose,
        rows: rows::describe_transaction_rows(envelope, purpose)?,
        admission_appends: appends,
        global_appends: appends,
    })
}
