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
    BudgetInvocationQuotas,
    BudgetCumulativeApprovalAccounts,
    BudgetCumulativeApprovalOperations,
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
            Self::BudgetInvocationQuotas => "budget_invocation_quotas",
            Self::BudgetCumulativeApprovalAccounts => "budget_cumulative_approval_accounts",
            Self::BudgetCumulativeApprovalOperations => "budget_cumulative_approval_operations",
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
            // The terminal rewrite and, for a restarted coordinator, the
            // recovery claim this same funded transaction persists: two
            // operation row rewrites and two admission and global commits.
            rows.push(operation_shape(operation, 2)?);
            2
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

/// Byte bounds of every column the payment writers persist. A payment
/// identifier is 1 to 512 bytes (`payment::journal` validation); the payment
/// gate holds every other budget text of the operation's live holds to the
/// same bound before the external authorization.
const PAYMENT_TEXT: u64 = 512;
const DIGEST: u64 = 64;
/// Serving owner store and lease identities are canonical UUID-v7 text.
const FENCE_ID: u64 = 36;
const INTEGER: u64 = 8;
/// The longest suffix a payment hold's event identifier adds to its hold id:
/// `:authorize:rollback:recovery`. The reconcile (`:reconcile`) and the
/// digest-derived nonce preflight reversal identifiers are shorter.
const EVENT_SUFFIX: u64 = 28;

/// The bound of one budget event identifier derived from a payment hold.
fn event_id_bytes() -> u64 {
    PAYMENT_TEXT + EVENT_SUFFIX
}

/// The member inventory one composite hold of this payment original can carry,
/// derived from the authenticated original exactly as the Kernel binds the
/// hold: the leaf capability and its distinct delegation ancestors, plus a
/// supplemental claim's revocation identifiers, artifact and revocation
/// commit; at most the grant, aggregate and supplemental invocation quotas;
/// and a cumulative approval only under a governed intent. The
/// pre-authorization gate refuses every live hold outside this inventory, so
/// each count is an enforced bound, not an estimate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) struct PaymentHoldInventory {
    pub(in crate::admission_operation_store) revocations: u64,
    pub(in crate::admission_operation_store) quotas: u64,
    pub(in crate::admission_operation_store) artifacts: u64,
    pub(in crate::admission_operation_store) revocation_commit: bool,
    pub(in crate::admission_operation_store) cumulative: bool,
    pub(in crate::admission_operation_store) supplemental: bool,
}

impl PaymentHoldInventory {
    /// The executable hold of `request`, whose original selected a
    /// supplemental authorization exactly when `supplemental` is set.
    pub(in crate::admission_operation_store) fn executable(
        request: &chio_kernel::ToolCallRequest,
        supplemental: bool,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let count =
            |value: usize| u64::try_from(value).map_err(|error| invariant(error.to_string()));
        let mut lineage = request
            .capability
            .delegation_chain
            .iter()
            .map(|link| link.capability_id.as_str())
            .collect::<Vec<_>>();
        lineage.push(request.capability.id.as_str());
        lineage.sort_unstable();
        lineage.dedup();
        let claimed = if supplemental {
            count(chio_kernel::supplemental_quota::MAX_SUPPLEMENTAL_REVOCATION_IDS)?
        } else {
            0
        };
        let revocations = count(lineage.len())?
            .checked_add(claimed)
            .ok_or_else(|| invariant("payment hold revocation inventory exhausted"))?
            .min(count(
                chio_kernel::supplemental_quota::MAX_ADMISSION_REVOCATION_IDS,
            )?);
        Ok(Self {
            revocations,
            // The grant quota joins only an aggregate or supplemental quota.
            quotas: 2 + u64::from(supplemental),
            artifacts: u64::from(supplemental),
            revocation_commit: supplemental,
            cumulative: request.governed_intent.is_some(),
            supplemental,
        })
    }

    /// The nonce preflight hold binds the same capability and quotas but
    /// never evaluates cumulative approval.
    pub(in crate::admission_operation_store) fn preflight(self) -> Self {
        Self {
            cumulative: false,
            ..self
        }
    }

    fn verifier_bytes(&self) -> Result<u64, AdmissionOperationStoreError> {
        if !self.supplemental {
            return Ok(0);
        }
        u64::try_from(chio_kernel::supplemental_quota::MAX_SUPPLEMENTAL_CONTEXT_FIELD_BYTES)
            .map_err(|error| invariant(error.to_string()))
    }

    fn supplemental_digest_bytes(&self) -> u64 {
        if self.supplemental {
            DIGEST
        } else {
            0
        }
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
        index_bytes: vec![record_bytes(&[16, 8, INTEGER])?],
    })
}

/// The immutable release evidence row at its CHECK bound with its two keyed
/// indexes (operation_id and evidence_id, each with the row id).
fn payment_release_evidence_row() -> Result<ToolOutcomeRowEnvelopeData, AdmissionOperationStoreError>
{
    let bytes = record_bytes(&[512, 512, 24, 8, 1_048_576, 64, 8])?;
    Ok(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::PaymentReleaseEvidence,
        possible_before_bytes: None,
        maximum_after_bytes: bytes,
        mutations: 1,
        index_bytes: vec![
            record_bytes(&[512, INTEGER])?,
            record_bytes(&[512, INTEGER])?,
        ],
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

/// The full `budget_authorization_holds` record: the base columns, the
/// reservation columns and every composite projection column.
fn hold_record(
    text: &crate::budget_store::CompositeBudgetTextBounds,
    hold: &PaymentHoldInventory,
) -> Result<u64, AdmissionOperationStoreError> {
    record_bytes(&[
        // hold_id, capability_id, grant_index, authorized/remaining exposure,
        // invocation_count_debited, invocation_captured, disposition,
        // authority_id, lease_id, lease_epoch, created_at, updated_at
        PAYMENT_TEXT,
        PAYMENT_TEXT,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        text.disposition,
        FENCE_ID,
        FENCE_ID,
        INTEGER,
        INTEGER,
        INTEGER,
        // reserved_until, reserved_currency, reserved_payment_reference,
        // reserved_budget_total, reserved_delegation_depth,
        // reserved_root_budget_holder
        INTEGER,
        PAYMENT_TEXT,
        PAYMENT_TEXT,
        INTEGER,
        INTEGER,
        PAYMENT_TEXT,
        // operation_id, projection_kind, revocation_set_digest, expected
        // quota/revocation/artifact counts, cumulative and revocation-commit
        // flags, authorization_outcome, invocation_state, monetary_state
        PAYMENT_TEXT,
        text.projection_kind,
        DIGEST,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        text.authorization_outcome,
        text.invocation_state,
        text.monetary_state,
        // supplemental verifier id, config digest, artifact digest, expiry,
        // trusted_capture_time
        hold.verifier_bytes()?,
        hold.supplemental_digest_bytes(),
        hold.supplemental_digest_bytes(),
        INTEGER,
        INTEGER,
    ])
}

/// The full `budget_mutation_events` record: base, authority and composite
/// projection columns.
fn event_record(
    text: &crate::budget_store::CompositeBudgetTextBounds,
    hold: &PaymentHoldInventory,
) -> Result<u64, AdmissionOperationStoreError> {
    record_bytes(&[
        // event_id, hold_id, capability_id, grant_index, kind, allowed,
        // recorded_at, event_seq, usage_seq, exposure and spend units, the
        // three grant maxima and the three usage totals after the event
        event_id_bytes(),
        PAYMENT_TEXT,
        PAYMENT_TEXT,
        INTEGER,
        text.mutation_kind,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        // authority_id, lease_id, lease_epoch
        FENCE_ID,
        FENCE_ID,
        INTEGER,
        // operation_id, projection_kind, revocation_set_digest, expected
        // counts, flags, authorization_outcome, invocation and monetary
        // states before and after, cumulative approval set digest
        PAYMENT_TEXT,
        text.projection_kind,
        DIGEST,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        INTEGER,
        text.authorization_outcome,
        text.invocation_state,
        text.invocation_state,
        text.monetary_state,
        text.monetary_state,
        DIGEST,
        // supplemental verifier id, config digest, artifact digest, expiry,
        // invocation_quotas_explicit, trusted_time, expected_cumulative_state
        hold.verifier_bytes()?,
        hold.supplemental_digest_bytes(),
        hold.supplemental_digest_bytes(),
        INTEGER,
        INTEGER,
        INTEGER,
        text.cumulative_state,
    ])
}

/// One composite budget transition of each of `holds`: the usage row, the
/// hold row, the event inserted then projected, its member rows and the
/// replication head. `reversal` adds the quota and cumulative rewrites only a
/// reversal performs. A member table no hold can write prices no tree. Every
/// changed index is a separate delete and reinsert walk.
fn hold_transition_rows(
    text: &crate::budget_store::CompositeBudgetTextBounds,
    holds: &[PaymentHoldInventory],
    reversal: bool,
) -> Result<Vec<ToolOutcomeRowEnvelopeData>, AdmissionOperationStoreError> {
    let total = |member: fn(&PaymentHoldInventory) -> u64| {
        holds.iter().try_fold(0_u64, |sum, hold| {
            sum.checked_add(member(hold))
                .ok_or_else(|| invariant("payment hold transition rows exhausted"))
        })
    };
    let count = u64::try_from(holds.len()).map_err(|error| invariant(error.to_string()))?;
    let largest = |record: fn(
        &crate::budget_store::CompositeBudgetTextBounds,
        &PaymentHoldInventory,
    ) -> Result<u64, AdmissionOperationStoreError>| {
        holds.iter().try_fold(0_u64, |largest, hold| {
            Ok::<_, AdmissionOperationStoreError>(largest.max(record(text, hold)?))
        })
    };
    let mut rows = Vec::new();
    let mut members = |table, after: u64, mutations: u64, index_bytes: Vec<u64>| {
        if mutations != 0 {
            rows.push(ToolOutcomeRowEnvelopeData {
                table,
                possible_before_bytes: None,
                maximum_after_bytes: after,
                mutations,
                index_bytes,
            });
        }
    };
    let event_id = event_id_bytes();
    members(
        ToolOutcomeWriteTableData::BudgetEventQuotaMembers,
        record_bytes(&[event_id, text.quota_profile, PAYMENT_TEXT, 8, 8, 8, 8, 8, 8])?,
        total(|hold| hold.quotas)?,
        vec![record_bytes(&[
            event_id,
            text.quota_profile,
            PAYMENT_TEXT,
            INTEGER,
            INTEGER,
        ])?],
    );
    members(
        ToolOutcomeWriteTableData::BudgetEventRevocationMembers,
        record_bytes(&[event_id, 8, PAYMENT_TEXT])?,
        total(|hold| hold.revocations)?,
        vec![
            record_bytes(&[event_id, INTEGER, INTEGER])?,
            record_bytes(&[event_id, PAYMENT_TEXT, INTEGER])?,
        ],
    );
    members(
        ToolOutcomeWriteTableData::BudgetEventAuthorizationArtifacts,
        record_bytes(&[event_id, 8, DIGEST])?,
        total(|hold| hold.artifacts)?,
        vec![
            record_bytes(&[event_id, INTEGER, INTEGER])?,
            record_bytes(&[event_id, DIGEST, INTEGER])?,
        ],
    );
    members(
        ToolOutcomeWriteTableData::BudgetEventRevocationCommits,
        record_bytes(&[
            event_id,
            PAYMENT_TEXT,
            PAYMENT_TEXT,
            8,
            text.guarantee_level,
            8,
        ])?,
        total(|hold| u64::from(hold.revocation_commit))?,
        vec![record_bytes(&[event_id, INTEGER])?],
    );
    members(
        ToolOutcomeWriteTableData::BudgetEventCumulativeApproval,
        record_bytes(&[
            event_id,
            PAYMENT_TEXT,
            PAYMENT_TEXT,
            PAYMENT_TEXT,
            PAYMENT_TEXT,
            8,
            PAYMENT_TEXT,
            PAYMENT_TEXT,
            PAYMENT_TEXT,
            PAYMENT_TEXT,
            8,
            8,
            8,
            text.cumulative_state,
            text.cumulative_state,
            8,
            8,
            8,
            8,
            8,
            8,
        ])?,
        total(|hold| u64::from(hold.cumulative))?,
        vec![record_bytes(&[event_id, INTEGER])?],
    );
    // capability_grant_budgets: the same usage row is rewritten once per hold;
    // its updated_at and seq indexes change on every rewrite.
    let usage = record_bytes(&[PAYMENT_TEXT, 8, 8, 8, 8, 8, 8])?;
    rows.push(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::CapabilityGrantBudgets,
        possible_before_bytes: Some(usage),
        maximum_after_bytes: usage,
        mutations: count,
        index_bytes: vec![
            record_bytes(&[INTEGER, INTEGER])?,
            record_bytes(&[INTEGER, INTEGER])?,
        ],
    });
    // budget_authorization_holds: disposition changes, so the
    // (disposition, reserved_until) index entry is deleted and reinserted.
    let hold = largest(hold_record)?;
    rows.push(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::BudgetAuthorizationHolds,
        possible_before_bytes: Some(hold),
        maximum_after_bytes: hold,
        mutations: count,
        index_bytes: vec![record_bytes(&[text.disposition, INTEGER, INTEGER])?],
    });
    // budget_mutation_events: one insert with its primary key, capability
    // and sequence indexes, then the same-key projection rewrite.
    let event = largest(event_record)?;
    rows.push(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::BudgetMutationEvents,
        possible_before_bytes: None,
        maximum_after_bytes: event,
        mutations: count,
        index_bytes: vec![
            record_bytes(&[event_id, INTEGER])?,
            record_bytes(&[PAYMENT_TEXT, INTEGER, INTEGER, INTEGER])?,
            record_bytes(&[INTEGER, INTEGER])?,
        ],
    });
    rows.push(existing(
        ToolOutcomeWriteTableData::BudgetMutationEvents,
        event,
        count,
    ));
    rows.push(existing(
        ToolOutcomeWriteTableData::BudgetReplicationMeta,
        record_bytes(&[8, 8])?,
        count,
    ));
    if reversal {
        // The reversal releases each quota reservation and the cumulative
        // reservation: same-key rewrites with no changed index key.
        let quotas = total(|hold| hold.quotas)?;
        if quotas != 0 {
            rows.push(existing(
                ToolOutcomeWriteTableData::BudgetInvocationQuotas,
                record_bytes(&[text.quota_profile, PAYMENT_TEXT, 8, 8, 8, 8, 8])?,
                quotas,
            ));
        }
        let cumulative = total(|hold| u64::from(hold.cumulative))?;
        if cumulative != 0 {
            rows.push(existing(
                ToolOutcomeWriteTableData::BudgetCumulativeApprovalAccounts,
                record_bytes(&[
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    8,
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    8,
                    8,
                    8,
                    8,
                ])?,
                cumulative,
            ));
            rows.push(existing(
                ToolOutcomeWriteTableData::BudgetCumulativeApprovalOperations,
                record_bytes(&[
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    PAYMENT_TEXT,
                    8,
                    8,
                    8,
                    text.cumulative_state,
                    DIGEST,
                    8,
                ])?,
                cumulative,
            ));
        }
    }
    Ok(rows)
}

/// The per-tree maximum of two mutually exclusive transactions of one
/// purpose. Every tree price grows with its mutations and record bounds, so
/// the merged envelope bounds whichever transaction actually commits.
fn dominating_rows(
    left: Vec<ToolOutcomeRowEnvelopeData>,
    right: Vec<ToolOutcomeRowEnvelopeData>,
) -> Result<Vec<ToolOutcomeRowEnvelopeData>, AdmissionOperationStoreError> {
    let key = |row: &ToolOutcomeRowEnvelopeData| (row.table, row.possible_before_bytes.is_some());
    let mut merged: Vec<ToolOutcomeRowEnvelopeData> = Vec::new();
    for row in left.into_iter().chain(right) {
        match merged.iter_mut().find(|current| key(current) == key(&row)) {
            Some(current) => {
                if current.index_bytes.len() != row.index_bytes.len() {
                    return Err(invariant(
                        "payment alternatives disagree on a tree's indexes",
                    ));
                }
                current.possible_before_bytes =
                    current.possible_before_bytes.max(row.possible_before_bytes);
                current.maximum_after_bytes =
                    current.maximum_after_bytes.max(row.maximum_after_bytes);
                current.mutations = current.mutations.max(row.mutations);
                for (bytes, other) in current.index_bytes.iter_mut().zip(row.index_bytes) {
                    *bytes = (*bytes).max(other);
                }
            }
            None => merged.push(row),
        }
    }
    Ok(merged)
}

/// The four priced payment journal transactions of one payment original,
/// described before its budget hold exists: every row bound is the real
/// column set at its typed bound, and every member count is the inventory the
/// gate later enforces on the live holds. `preflight` is the nonce preflight
/// hold a pre-dispatch reversal can still find live.
pub(super) fn payment_transaction(
    envelope: &ToolOutcomeEnvelopeData,
    purpose: ToolOutcomeTransactionPurposeData,
    executable: PaymentHoldInventory,
    preflight: Option<PaymentHoldInventory>,
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
            // Either the settlement begin (the hold reconcile with its journal
            // intent and evidence, two global commits) or, before dispatch
            // after a released authorization, the reversal of every live hold
            // (one budget global commit each). Never both for one operation.
            let text = crate::budget_store::composite_budget_text_bounds();
            let mut settle = hold_transition_rows(&text, &[executable], false)?;
            settle.push(payment_journal_row()?);
            settle.push(payment_release_evidence_row()?);
            let reversed = [Some(executable), preflight]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            let reverse = hold_transition_rows(&text, &reversed, true)?;
            rows = dominating_rows(settle, reverse)?;
            u64::try_from(reversed.len())
                .map_err(|error| invariant(error.to_string()))?
                .max(2)
        }
        // The producing program keeps its five custody purposes; the payment
        // family is described only through this path.
        _ => return Err(invariant("payment journal purpose is outside its family")),
    };
    // A restarted coordinator persists its recovery claim inside this funded
    // write: the operation row rewrite with its recovery index, one admission
    // commit and its meta head, and one more global commit.
    rows.push(operation_shape(operation_bytes(envelope)?, 1)?);
    rows.push(ToolOutcomeRowEnvelopeData {
        table: ToolOutcomeWriteTableData::AdmissionCommits,
        possible_before_bytes: None,
        maximum_after_bytes: record_bytes(&[8, 64, 8, 18, 64, 64, 64, 64, 64, 36, 36, 8, 8, 8])?,
        mutations: 1,
        index_bytes: vec![record_bytes(&[64, 8, 8])?],
    });
    rows.push(existing(
        ToolOutcomeWriteTableData::AdmissionMeta,
        record_bytes(&[8, 8, 64, 8])?,
        1,
    ));
    let global_appends = global_appends
        .checked_add(1)
        .ok_or_else(|| invariant("payment claim global append exhausted"))?;
    payment_append_histories(&mut rows, envelope, global_appends)?;
    Ok(ToolOutcomeTransactionEnvelopeData {
        purpose,
        rows,
        admission_appends: 1,
        global_appends,
    })
}
