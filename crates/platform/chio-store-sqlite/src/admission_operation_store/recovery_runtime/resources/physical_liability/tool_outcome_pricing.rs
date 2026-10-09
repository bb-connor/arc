//! Every original custody transaction retains an independent full WAL amount.
//! A quoted amount cannot create or consume a native bank purpose.
use super::*;
use crate::admission_operation_store::security_participant_state::finishing_plan::NativeToolOutcomeSourcePlan;
use crate::admission_operation_store::tool_outcome_liability::{
    describe_native_tool_outcome_transactions, ToolOutcomeTransactionEnvelopeData,
    ToolOutcomeTransactionPurposeData, ToolOutcomeWriteTableData,
};
use crate::serving_owner::{NativeSourceTransactionOrigin, SqliteServingOwner};

const CURSOR_LEVELS: u64 = 20;
const BALANCE_PAGES_PER_LEVEL: u64 = 6;
const NEW_BALANCE_WALKS: u64 = 1;
const EXISTING_BALANCE_WALKS: u64 = 3;
const ALLOCATION_OR_FREE_FRAME_MULTIPLIER: u64 = 2;
const FRAME_HEADER_BYTES: u64 = 24;
const WAL_HEADER_BYTES: u64 = 32;
const MAX_WAL_SECTOR_BYTES: u64 = 65_536;
const ANCHOR_FILE_BYTES: u64 = 2 * 1_024;

pub(in crate::admission_operation_store) struct ToolOutcomeTransactionPriceData {
    purpose: ToolOutcomeTransactionPurposeData,
    physical: PhysicalLiabilityData,
    admission_appends: u64,
    profile: String,
}

impl ToolOutcomeTransactionPriceData {
    pub(in crate::admission_operation_store) fn purpose(
        &self,
    ) -> ToolOutcomeTransactionPurposeData {
        self.purpose
    }

    pub(in crate::admission_operation_store) fn physical(&self) -> &PhysicalLiabilityData {
        &self.physical
    }

    pub(in crate::admission_operation_store) fn admission_appends(&self) -> u64 {
        self.admission_appends
    }

    pub(in crate::admission_operation_store) fn profile(&self) -> &str {
        &self.profile
    }
}

pub(in crate::admission_operation_store) fn tool_outcome_price_algorithm_fingerprint(
) -> Result<String, AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.tool-outcome-frame-price.v1",
        (
            CURSOR_LEVELS,
            BALANCE_PAGES_PER_LEVEL,
            NEW_BALANCE_WALKS,
            EXISTING_BALANCE_WALKS,
            ALLOCATION_OR_FREE_FRAME_MULTIPLIER,
        ),
        (
            FRAME_HEADER_BYTES,
            WAL_HEADER_BYTES,
            MAX_WAL_SECTOR_BYTES,
            ANCHOR_FILE_BYTES,
        ),
        "possible before and maximum intermediate overflow; no future blob existence credit",
        "independent transactions retain independent WAL and history amounts",
    ))
    .map_err(|error| invariant(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// The owning bank must add its real funding/account/phase writes to each
/// transaction and preserve every other native, recovery and second-DB debt.
/// These component prices alone never enable pre-rail payment or capture.
pub(in crate::admission_operation_store) fn price_native_tool_outcome_phases(
    tx: &Transaction<'_>,
    writer: (&SqliteServingOwner, &NativeSourceTransactionOrigin<'_>),
    source: &impl NativeToolOutcomeSourcePlan,
) -> Result<Vec<ToolOutcomeTransactionPriceData>, AdmissionOperationStoreError> {
    source.verify_before(tx, writer.0, writer.1)?;
    let profile = source.physical_write_profile();
    let page_size = profile.page_size();
    // This exact full native profile must already authenticate UTF-8, FULL WAL,
    // auto-vacuum=0, current and pending reserved bytes=0, actual supported VFS,
    // whole source/index/trigger catalog and the original producing program.
    let transactions = describe_native_tool_outcome_transactions(source)?;
    transactions
        .iter()
        .map(|transaction| {
            Ok(ToolOutcomeTransactionPriceData {
                purpose: transaction.purpose(),
                physical: price_transaction(page_size, transaction)?,
                admission_appends: transaction.admission_appends(),
                profile: transaction_profile(source, transaction)?,
            })
        })
        .collect()
}

fn transaction_profile(
    source: &impl NativeToolOutcomeSourcePlan,
    transaction: &ToolOutcomeTransactionEnvelopeData,
) -> Result<String, AdmissionOperationStoreError> {
    let rows = transaction
        .rows()
        .iter()
        .map(|row| {
            (
                row.table().table_name(),
                row.possible_before_record_bytes(),
                row.maximum_after_record_bytes(),
                row.mutations(),
                row.index_record_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let purpose = match transaction.purpose() {
        ToolOutcomeTransactionPurposeData::RawCustody => ("raw", 0),
        ToolOutcomeTransactionPurposeData::EvaluationBegin => ("evaluation_begin", 0),
        ToolOutcomeTransactionPurposeData::EvaluationStage => ("evaluation_stage", 0),
        ToolOutcomeTransactionPurposeData::Finalization { pure_prefix } => {
            ("finalization", pure_prefix)
        }
    };
    let bytes = canonical_json_bytes(&(
        "chio.sqlite.original-tool-outcome-transaction-envelope.v1",
        source.physical_write_profile().fingerprint(),
        sha256_hex(source.original().canonical_bytes()),
        tool_outcome_price_algorithm_fingerprint()?,
        purpose,
        rows,
        transaction.admission_appends(),
        transaction.global_appends(),
    ))
    .map_err(|error| invariant(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn price_transaction(
    page_size: u64,
    transaction: &ToolOutcomeTransactionEnvelopeData,
) -> Result<PhysicalLiabilityData, AdmissionOperationStoreError> {
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(invariant("original custody page profile is unsupported"));
    }
    let usable_payload = page_size
        .checked_sub(4)
        .filter(|payload| *payload > 0)
        .ok_or_else(|| invariant("original custody overflow divisor is invalid"))?;
    let mut frames = 1_u64;
    for row in transaction.rows() {
        let mutations = row.mutations();
        let after = row.maximum_after_record_bytes();
        if mutations == 0 || after == 0 {
            return Err(invariant("original custody row lost its producing bound"));
        }
        if matches!(
            row.table(),
            ToolOutcomeWriteTableData::AdmissionMeta | ToolOutcomeWriteTableData::GlobalMeta
        ) {
            if row.possible_before_record_bytes().is_none()
                || !row.index_record_bytes().is_empty()
                || after
                    > page_size.checked_sub(100).ok_or_else(|| {
                        invariant("original custody singleton page margin exhausted")
                    })?
            {
                return Err(invariant("original custody singleton shape is invalid"));
            }
            frames = add(frames, mutations)?;
            continue;
        }
        let before = row.possible_before_record_bytes();
        let walks = if before.is_some() {
            EXISTING_BALANCE_WALKS
        } else {
            NEW_BALANCE_WALKS
        };
        let tree_frames = mul(
            mul(mul(mutations, walks)?, CURSOR_LEVELS)?,
            BALANCE_PAGES_PER_LEVEL,
        )?;
        let after_overflow = ceil(after, usable_payload)?;
        let old_or_intermediate_overflow = before
            .map(|before| ceil(before.max(after), usable_payload))
            .transpose()?
            .unwrap_or(0);
        let overflow = mul(
            add(after_overflow, old_or_intermediate_overflow)?,
            mutations,
        )?;
        frames = add(
            frames,
            mul(
                add(tree_frames, overflow)?,
                ALLOCATION_OR_FREE_FRAME_MULTIPLIER,
            )?,
        )?;
        for index_bytes in row.index_record_bytes() {
            if *index_bytes == 0 {
                return Err(invariant("original custody index lost its key bound"));
            }
            let overflow = mul(
                ceil(*index_bytes, usable_payload)?,
                if before.is_some() { 2 } else { 1 },
            )?;
            let index_frames = add(tree_frames, mul(overflow, mutations)?)?;
            frames = add(
                frames,
                mul(index_frames, ALLOCATION_OR_FREE_FRAME_MULTIPLIER)?,
            )?;
        }
    }
    // Intermediate full evaluation rewrites retain all independent history
    // appends even within one transaction. The frame envelope permits enabled
    // spilling, repeated tree work, old/new overflow and freelist trunk writes.
    // It makes no cross-transaction dirty-page or same-size reuse deduction.
    let frame_bytes = add(page_size, FRAME_HEADER_BYTES)?;
    let padding_frames = ceil(MAX_WAL_SECTOR_BYTES, frame_bytes)?;
    let wal_bytes = add(
        mul(add(frames, padding_frames)?, frame_bytes)?,
        WAL_HEADER_BYTES,
    )?;
    let price = PhysicalLiabilityData {
        wal_bytes,
        disk_bytes: add(mul(wal_bytes, 2)?, ANCHOR_FILE_BYTES)?,
        recovery_appends: 0,
        global_appends: transaction.global_appends(),
    };
    price.validate()?;
    Ok(price)
}

fn add(left: u64, right: u64) -> Result<u64, AdmissionOperationStoreError> {
    left.checked_add(right)
        .ok_or_else(|| invariant("original custody physical sum exhausted"))
}

fn mul(left: u64, right: u64) -> Result<u64, AdmissionOperationStoreError> {
    left.checked_mul(right)
        .ok_or_else(|| invariant("original custody physical product exhausted"))
}

fn ceil(value: u64, divisor: u64) -> Result<u64, AdmissionOperationStoreError> {
    if divisor == 0 {
        return Err(invariant("original custody physical divisor is zero"));
    }
    value
        .checked_div(divisor)
        .and_then(|quotient| quotient.checked_add(u64::from(!value.is_multiple_of(divisor))))
        .ok_or_else(|| invariant("original custody physical ceiling exhausted"))
}
