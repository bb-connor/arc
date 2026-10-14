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
    SecurityReleases,
    TerminalProjections,
    TerminalRecords,
    ObserverAttempts,
    PaymentJournal,
    PaymentReleaseEvidence,
    CapabilityGrantBudgets,
    BudgetAuthorizationHolds,
    BudgetMutationEvents,
    BudgetEventQuotaMembers,
    BudgetEventRevocationMembers,
    BudgetEventAuthorizationArtifacts,
    BudgetEventRevocationCommits,
    BudgetEventCumulativeApproval,
    BudgetReplicationMeta,
}

impl ToolOutcomeWriteTableData {
    pub(in crate::admission_operation_store) fn table_name(self) -> &'static str {
        match self {
            Self::SecurityReleases => "tool_outcome_security_releases",
            Self::TerminalProjections => "admission_operation_terminal_projections",
            Self::TerminalRecords => "admission_operation_terminal_records",
            Self::ObserverAttempts => "admission_operation_observer_attempts",
            Self::Blobs => "tool_outcome_blobs",
            Self::Outcomes => "tool_outcomes",
            Self::Evaluations => "post_return_evaluations",
            Self::Operations => "admission_operations",
            Self::AdmissionCommits => "admission_operation_commits",
            Self::AdmissionMeta => "admission_operation_commit_meta",
            Self::GlobalCommits => "authority_global_commits",
            Self::GlobalMeta => "authority_global_commit_meta",
            Self::PaymentJournal => "payment_journal",
            Self::PaymentReleaseEvidence => "payment_release_evidence",
            Self::CapabilityGrantBudgets => "capability_grant_budgets",
            Self::BudgetAuthorizationHolds => "budget_authorization_holds",
            Self::BudgetMutationEvents => "budget_mutation_events",
            Self::BudgetEventQuotaMembers => "budget_event_quota_members",
            Self::BudgetEventRevocationMembers => "budget_event_revocation_members",
            Self::BudgetEventAuthorizationArtifacts => "budget_event_authorization_artifacts",
            Self::BudgetEventRevocationCommits => "budget_event_revocation_commits",
            Self::BudgetEventCumulativeApproval => "budget_event_cumulative_approval",
            Self::BudgetReplicationMeta => "budget_replication_meta",
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

    pub(in crate::admission_operation_store) fn maximum_insertions(&self) -> u64 {
        if matches!(self.table, ToolOutcomeWriteTableData::Blobs)
            || self.possible_before_bytes.is_none()
        {
            self.mutations
        } else {
            0
        }
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
        ToolOutcomeTransactionPurposeData::SecurityRelease => {
            // One immutable release record (its CHECK bound) and the actual
            // participant update of the same admission transaction.
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::SecurityReleases,
                possible_before_bytes: None,
                maximum_after_bytes: record_bytes(&[64, 8_192, 64, 8, 36, 36, 8])?,
                mutations: 1,
                index_bytes: vec![record_bytes(&[64, 8])?],
            });
            rows.push(operation_shape(operation, 1)?);
            1
        }
        ToolOutcomeTransactionPurposeData::TerminalProjection { observer, payment } => {
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::TerminalProjections,
                possible_before_bytes: None,
                maximum_after_bytes: record_bytes(&[
                    64, 8, 8, 35, 64, 64, 4_194_304, 262_144, 8, 8, 36, 36, 8,
                ])?,
                mutations: 1,
                index_bytes: vec![record_bytes(&[64, 8])?],
            });
            // The signed receipt is bounded by the original receipt envelope;
            // the tool outcome, observation and payment terminal records by
            // their CHECK bound.
            let mut records = vec![
                ("receipt".len(), envelope.receipt_bytes),
                ("tool_outcome".len(), 1_048_576),
            ];
            if observer {
                records.push(("observation_attempt_zero".len(), 1_048_576));
            }
            if payment {
                records.push(("payment_terminal".len(), 1_048_576));
            }
            for (kind, json) in records {
                let kind = u64::try_from(kind)
                    .map_err(|_| invariant("terminal record kind size exhausted"))?;
                rows.push(ToolOutcomeRowEnvelopeData {
                    table: ToolOutcomeWriteTableData::TerminalRecords,
                    possible_before_bytes: None,
                    maximum_after_bytes: record_bytes(&[64, kind, 512, 64, json])?,
                    mutations: 1,
                    index_bytes: vec![
                        record_bytes(&[64, kind, 512, 8])?,
                        record_bytes(&[kind, 512, 8])?,
                        record_bytes(&[kind, 64, 8])?,
                    ],
                });
            }
            if observer {
                rows.push(ToolOutcomeRowEnvelopeData {
                    table: ToolOutcomeWriteTableData::ObserverAttempts,
                    possible_before_bytes: None,
                    maximum_after_bytes: record_bytes(&[
                        64, 512, 9, 8, 8, 8, 2_048, 64, 1_048_576, 8, 8, 36, 36, 8,
                    ])?,
                    mutations: 1,
                    index_bytes: vec![
                        record_bytes(&[64, 8])?,
                        record_bytes(&[512, 8])?,
                        record_bytes(&[9, 8, 64, 8])?,
                    ],
                });
            }
            rows.push(operation_shape(operation, 1)?);
            1
        }
        ToolOutcomeTransactionPurposeData::PaymentAuthorization
        | ToolOutcomeTransactionPurposeData::PaymentCompensation
        | ToolOutcomeTransactionPurposeData::PaymentSettlement
        | ToolOutcomeTransactionPurposeData::PaymentCompletion => {
            return Err(invariant(
                "payment journal transaction rows require their budget hold shape",
            ));
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

/// The actual budget hold a payment original placed before its account was
/// priced. Every member count bound below is read from the hold's own rows,
/// so a hold with more members prices a larger settlement transaction.
pub(super) struct PaymentHoldShape {
    quota_members: u64,
    revocation_members: u64,
    authorization_artifacts: u64,
    revocation_commit: bool,
    cumulative_approval: bool,
}

impl PaymentHoldShape {
    pub(super) fn load(
        tx: &Transaction<'_>,
        source: &VerifiedNativeInitialFinishingPlan<'_, '_>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let hold = source
            .operation()
            .budget_hold_id()
            .ok_or_else(|| invariant("payment original lost its budget hold"))?
            .as_str();
        let count = |sql: &str| -> Result<u64, AdmissionOperationStoreError> {
            let rows: i64 = tx
                .query_row(sql, [hold], |row| row.get(0))
                .map_err(sqlite_error)?;
            u64::try_from(rows).map_err(invariant)
        };
        let present = |sql: &str| -> Result<bool, AdmissionOperationStoreError> {
            let present: bool = tx
                .query_row(sql, [hold], |row| row.get(0))
                .map_err(sqlite_error)?;
            Ok(present)
        };
        let shape = Self {
            quota_members: count(
                "SELECT COUNT(*) FROM main.budget_hold_quota_members WHERE hold_id=?1",
            )?,
            revocation_members: count(
                "SELECT COUNT(*) FROM main.budget_hold_revocation_members WHERE hold_id=?1",
            )?,
            authorization_artifacts: count(
                "SELECT COUNT(*) FROM main.budget_hold_authorization_artifacts WHERE hold_id=?1",
            )?,
            revocation_commit: present(
                "SELECT EXISTS(SELECT 1 FROM main.budget_hold_revocation_commits
                 WHERE hold_id=?1)",
            )?,
            cumulative_approval: present(
                "SELECT EXISTS(SELECT 1 FROM main.budget_cumulative_approval_operations
                 WHERE hold_id=?1)",
            )?,
        };
        if shape.quota_members == 0 {
            return Err(invariant("payment original hold lost its quota members"));
        }
        Ok(shape)
    }
}

/// One journal row rewrite at its real column bound plus the state index the
/// advance always rewrites (state and updated_at are both indexed columns).
fn payment_journal_row() -> Result<ToolOutcomeRowEnvelopeData, AdmissionOperationStoreError> {
    let bytes = record_bytes(&[
        512, 8, 64, 512, 512, 8, 512, 512, 16, 512, 512, 8, 8, 8, 24, 512, 64, 8, 3, 16, 8, 8,
    ])?;
    Ok(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::PaymentJournal,
        possible_before_bytes: Some(bytes),
        maximum_after_bytes: bytes,
        mutations: 1,
        index_bytes: vec![record_bytes(&[16, 8, 512])?],
    })
}

/// The immutable release evidence row at its CHECK bound with its two trees.
fn payment_release_evidence_row() -> Result<ToolOutcomeRowEnvelopeData, AdmissionOperationStoreError>
{
    let bytes = record_bytes(&[512, 512, 24, 8, 1_048_576, 64, 8])?;
    Ok(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::PaymentReleaseEvidence,
        possible_before_bytes: None,
        maximum_after_bytes: bytes,
        mutations: 1,
        index_bytes: vec![record_bytes(&[512])?, record_bytes(&[512])?],
    })
}

/// The journal advance appends one global commit and rewrites its meta head.
fn payment_append_histories(
    rows: &mut Vec<ToolOutcomeRowEnvelopeData>,
    envelope: &ToolOutcomeEnvelopeData,
    appends: u64,
) -> Result<(), AdmissionOperationStoreError> {
    rows.push(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::GlobalCommits,
        possible_before_bytes: None,
        maximum_after_bytes: envelope.global_row_bytes,
        mutations: appends,
        index_bytes: vec![envelope.global_index_bytes],
    });
    rows.push(existing(
        ToolOutcomeWriteTableData::GlobalMeta,
        record_bytes(&[8, 8, 64])?,
        appends,
    ));
    Ok(())
}

/// The four priced payment journal transactions of one payment original.
/// Every row bound is the real schema CHECK or column bound of its table,
/// and every member count comes from the hold the original actually placed.
pub(super) fn payment_transaction(
    envelope: &ToolOutcomeEnvelopeData,
    purpose: ToolOutcomeTransactionPurposeData,
    hold: &PaymentHoldShape,
) -> Result<ToolOutcomeTransactionEnvelopeData, AdmissionOperationStoreError> {
    let mut rows = Vec::new();
    let global_appends = match purpose {
        ToolOutcomeTransactionPurposeData::PaymentAuthorization
        | ToolOutcomeTransactionPurposeData::PaymentCompletion => {
            rows.push(payment_journal_row()?);
            1
        }
        ToolOutcomeTransactionPurposeData::PaymentCompensation => {
            rows.push(payment_journal_row()?);
            rows.push(payment_release_evidence_row()?);
            1
        }
        ToolOutcomeTransactionPurposeData::PaymentSettlement => {
            // The composite budget reconcile: the usage row, the hold row,
            // one mutation event inserted then projected, its member rows,
            // the replication sequence and its joint global commit.
            let usage = record_bytes(&[512, 8, 8, 8, 8, 8, 8])?;
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::CapabilityGrantBudgets,
                possible_before_bytes: Some(usage),
                maximum_after_bytes: usage,
                mutations: 1,
                index_bytes: vec![record_bytes(&[8, 8])?],
            });
            let hold_row = record_bytes(&[512, 512, 8, 8, 8, 8, 8, 24, 512, 512, 8, 8, 8])?;
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::BudgetAuthorizationHolds,
                possible_before_bytes: Some(hold_row),
                maximum_after_bytes: hold_row,
                mutations: 1,
                index_bytes: Vec::new(),
            });
            // One mutation event is inserted and then rewritten by its
            // transition projection inside the same transaction.
            let event = record_bytes(&[
                512, 512, 512, 8, 24, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 512, 512, 8, 16, 512,
                64, 8, 8, 1, 1, 64, 16, 16, 16, 16, 16, 64, 512, 64, 64, 8, 8, 64, 8,
            ])?;
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::BudgetMutationEvents,
                possible_before_bytes: None,
                maximum_after_bytes: event,
                mutations: 1,
                index_bytes: vec![
                    record_bytes(&[512])?,
                    record_bytes(&[512, 8, 8])?,
                    record_bytes(&[8])?,
                ],
            });
            rows.push(existing(
                ToolOutcomeWriteTableData::BudgetMutationEvents,
                event,
                1,
            ));
            let quota_member = record_bytes(&[512, 40, 512, 8, 8, 8, 8, 8, 8])?;
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::BudgetEventQuotaMembers,
                possible_before_bytes: None,
                maximum_after_bytes: quota_member,
                mutations: hold.quota_members,
                index_bytes: vec![record_bytes(&[512, 40, 512, 8])?],
            });
            let revocation_member = record_bytes(&[512, 8, 512])?;
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::BudgetEventRevocationMembers,
                possible_before_bytes: None,
                maximum_after_bytes: revocation_member,
                mutations: hold.revocation_members,
                index_bytes: vec![record_bytes(&[512, 8])?, record_bytes(&[512, 512])?],
            });
            let artifact = record_bytes(&[512, 8, 64])?;
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::BudgetEventAuthorizationArtifacts,
                possible_before_bytes: None,
                maximum_after_bytes: artifact,
                mutations: hold.authorization_artifacts,
                index_bytes: vec![record_bytes(&[512, 8])?, record_bytes(&[512, 64])?],
            });
            if hold.revocation_commit {
                let commit = record_bytes(&[512, 512, 512, 8, 16, 8])?;
                rows.push(ToolOutcomeRowEnvelopeData {
                    table: ToolOutcomeWriteTableData::BudgetEventRevocationCommits,
                    possible_before_bytes: None,
                    maximum_after_bytes: commit,
                    mutations: 1,
                    index_bytes: vec![record_bytes(&[512])?],
                });
            }
            if hold.cumulative_approval {
                let cumulative = record_bytes(&[
                    512, 512, 512, 512, 512, 8, 512, 512, 64, 3, 8, 8, 8, 16, 16, 8, 8, 8, 8, 8, 8,
                ])?;
                rows.push(ToolOutcomeRowEnvelopeData {
                    table: ToolOutcomeWriteTableData::BudgetEventCumulativeApproval,
                    possible_before_bytes: None,
                    maximum_after_bytes: cumulative,
                    mutations: 1,
                    index_bytes: vec![record_bytes(&[512])?],
                });
            }
            rows.push(ToolOutcomeRowEnvelopeData {
                table: ToolOutcomeWriteTableData::BudgetReplicationMeta,
                possible_before_bytes: None,
                maximum_after_bytes: record_bytes(&[8, 8])?,
                mutations: 1,
                index_bytes: Vec::new(),
            });
            rows.push(payment_journal_row()?);
            rows.push(payment_release_evidence_row()?);
            2
        }
        // The producing program keeps its five custody purposes; the payment
        // family is described only through this hold-shaped path.
        _ => return Err(invariant("payment journal purpose is outside its family")),
    };
    payment_append_histories(&mut rows, envelope, global_appends)?;
    Ok(ToolOutcomeTransactionEnvelopeData {
        purpose,
        rows,
        admission_appends: 0,
        global_appends,
    })
}
