//! Complete future custody rows are cost DATA, never claim or loan authority.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) enum ToolOutcomeWriteTableData {
    Blobs,
    Outcomes,
    Evaluations,
    Operations,
    AdmissionCommits,
    AdmissionMeta,
    GlobalCommits,
    GlobalMeta,
}

impl ToolOutcomeWriteTableData {
    pub(in crate::admission_operation_store) fn table_name(self) -> &'static str {
        match self {
            Self::Blobs => "tool_outcome_blobs",
            Self::Outcomes => "tool_outcomes",
            Self::Evaluations => "post_return_evaluations",
            Self::Operations => "admission_operations",
            Self::AdmissionCommits => "admission_operation_commits",
            Self::AdmissionMeta => "admission_operation_commit_meta",
            Self::GlobalCommits => "authority_global_commits",
            Self::GlobalMeta => "authority_global_commit_meta",
        }
    }
}

/// Future images are maxima under the original producing contract. These are
/// deliberately distinct from the exact present-row Raw source descriptors.
pub(in crate::admission_operation_store) struct ToolOutcomeRowEnvelopeData {
    table: ToolOutcomeWriteTableData,
    possible_before_bytes: Option<u64>,
    maximum_after_bytes: u64,
    mutations: u64,
    index_bytes: Vec<u64>,
}

impl ToolOutcomeRowEnvelopeData {
    pub(in crate::admission_operation_store) fn table(&self) -> ToolOutcomeWriteTableData {
        self.table
    }

    pub(in crate::admission_operation_store) fn possible_before_record_bytes(&self) -> Option<u64> {
        self.possible_before_bytes
    }

    pub(in crate::admission_operation_store) fn maximum_after_record_bytes(&self) -> u64 {
        self.maximum_after_bytes
    }

    pub(in crate::admission_operation_store) fn mutations(&self) -> u64 {
        self.mutations
    }

    pub(in crate::admission_operation_store) fn index_record_bytes(&self) -> &[u64] {
        &self.index_bytes
    }
}

pub(super) fn describe_transaction_rows(
    envelope: &ToolOutcomeEnvelopeData,
    purpose: ToolOutcomeTransactionPurposeData,
) -> Result<Vec<ToolOutcomeRowEnvelopeData>, AdmissionOperationStoreError> {
    let operation = operation_bytes(envelope)?;
    let outcome = outcome_bytes(envelope)?;
    let evaluation = evaluation_bytes(envelope)?;
    let mut rows = Vec::new();
    let appends = match purpose {
        ToolOutcomeTransactionPurposeData::RawCustody => {
            rows.push(blob(envelope.raw_bytes)?);
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::Outcomes,
                possible_before_bytes: None,
                maximum_after_bytes: outcome,
                mutations: 1,
                index_bytes: vec![
                    record_bytes(&[64, 8])?,
                    record_bytes(&[64, 8])?,
                    record_bytes(&[64, 64, 8])?,
                ],
            });
            rows.push(operation_shape(operation, 2)?);
            2
        }
        ToolOutcomeTransactionPurposeData::EvaluationBegin => {
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::Evaluations,
                possible_before_bytes: None,
                maximum_after_bytes: evaluation,
                mutations: 1,
                index_bytes: vec![record_bytes(&[64, 8])?, record_bytes(&[64, 8])?],
            });
            // The real atomic claim renewal and participant append each write
            // updated_at and the recovery index. Active replay gives no credit.
            rows.push(operation_shape(operation, 2)?);
            2
        }
        ToolOutcomeTransactionPurposeData::EvaluationStage => {
            rows.push(existing(
                ToolOutcomeWriteTableData::Evaluations,
                evaluation,
                1,
            ));
            rows.push(operation_shape(operation, 1)?);
            1
        }
        ToolOutcomeTransactionPurposeData::Finalization { pure_prefix } => {
            let mutations = pure_prefix
                .checked_add(1)
                .ok_or_else(|| invariant("original evaluation append count exhausted"))?;
            rows.push(blob(envelope.resolved_bytes)?);
            // These actual identities are immutable. Updating their complete
            // bodies does not mutate the PK or outcome/evaluation ID indexes.
            rows.push(existing(ToolOutcomeWriteTableData::Outcomes, outcome, 1));
            rows.push(existing(
                ToolOutcomeWriteTableData::Evaluations,
                evaluation,
                mutations,
            ));
            rows.push(operation_shape(operation, mutations)?);
            mutations
        }
    };
    append_histories(&mut rows, envelope, appends)?;
    Ok(rows)
}

fn operation_bytes(
    envelope: &ToolOutcomeEnvelopeData,
) -> Result<u64, AdmissionOperationStoreError> {
    record_bytes(&[
        64,
        64,
        envelope.request_id_bytes,
        262_144,
        u64::try_from("dispatch_committed".len())
            .map_err(|_| invariant("original custody state size exhausted"))?,
        8,
        8,
        8,
        8,
        8,
        envelope.claimant_bytes,
        envelope.coordinator_lease_bytes,
        8,
        8,
        8,
        36,
        36,
        8,
    ])
}

fn outcome_bytes(envelope: &ToolOutcomeEnvelopeData) -> Result<u64, AdmissionOperationStoreError> {
    record_bytes(&[
        64,
        64,
        envelope.request_id_bytes,
        64,
        8,
        64,
        64,
        envelope.outcome_bytes,
        8,
        8,
        36,
        36,
        8,
    ])
}

fn evaluation_bytes(
    envelope: &ToolOutcomeEnvelopeData,
) -> Result<u64, AdmissionOperationStoreError> {
    record_bytes(&[
        64,
        64,
        64,
        8,
        64,
        64,
        envelope.evaluation_bytes,
        8,
        8,
        36,
        36,
        8,
    ])
}

fn blob(maximum_payload: u64) -> Result<ToolOutcomeRowEnvelopeData, AdmissionOperationStoreError> {
    let row = record_bytes(&[64, 8, maximum_payload, 8, 36, 36, 8])?;
    // Before effect the digest is not known. Price both the new-row PK insert
    // and the possibly existing compacted-row rehydration. A present identical
    // payload later becomes an exact producer replay, never new credit.
    // The actual content-addressed writer verifies size and exact bytes. Under
    // the source-owned producer bound an equal existing digest cannot introduce
    // an unrelated larger payload or an unbounded old blob before image.
    Ok(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::Blobs,
        possible_before_bytes: Some(row),
        maximum_after_bytes: row,
        mutations: 1,
        index_bytes: vec![record_bytes(&[64, 8])?],
    })
}

fn operation_shape(
    bytes: u64,
    mutations: u64,
) -> Result<ToolOutcomeRowEnvelopeData, AdmissionOperationStoreError> {
    Ok(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::Operations,
        possible_before_bytes: Some(bytes),
        maximum_after_bytes: bytes,
        mutations,
        index_bytes: vec![record_bytes(&[8, 8, 8, 64, 8])?],
    })
}

fn existing(
    table: ToolOutcomeWriteTableData,
    bytes: u64,
    mutations: u64,
) -> ToolOutcomeRowEnvelopeData {
    ToolOutcomeRowEnvelopeData {
        table,
        possible_before_bytes: Some(bytes),
        maximum_after_bytes: bytes,
        mutations,
        index_bytes: Vec::new(),
    }
}

fn append_histories(
    rows: &mut Vec<ToolOutcomeRowEnvelopeData>,
    envelope: &ToolOutcomeEnvelopeData,
    appends: u64,
) -> Result<(), AdmissionOperationStoreError> {
    rows.push(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::AdmissionCommits,
        possible_before_bytes: None,
        maximum_after_bytes: record_bytes(&[8, 64, 8, 18, 64, 64, 64, 64, 64, 36, 36, 8, 8, 8])?,
        mutations: appends,
        index_bytes: vec![record_bytes(&[64, 8, 8])?],
    });
    rows.push(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::GlobalCommits,
        possible_before_bytes: None,
        maximum_after_bytes: envelope.global_row_bytes,
        mutations: appends,
        index_bytes: vec![envelope.global_index_bytes],
    });
    for (table, cells) in [
        (ToolOutcomeWriteTableData::AdmissionMeta, vec![8, 8, 64, 8]),
        (ToolOutcomeWriteTableData::GlobalMeta, vec![8, 8, 64]),
    ] {
        rows.push(existing(table, record_bytes(&cells)?, appends));
    }
    Ok(())
}

fn record_bytes(cells: &[u64]) -> Result<u64, AdmissionOperationStoreError> {
    let fields = u64::try_from(cells.len())
        .map_err(|_| invariant("original custody row field count exhausted"))?;
    let header = fields
        .checked_add(1)
        .and_then(|fields| fields.checked_mul(9))
        .ok_or_else(|| invariant("original custody row header exhausted"))?;
    cells.iter().try_fold(header, |sum, bytes| {
        sum.checked_add(*bytes)
            .ok_or_else(|| invariant("original custody row payload exhausted"))
    })
}
