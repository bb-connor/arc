fn journal_state_str(state: chio_kernel::payment::PaymentJournalState) -> &'static str {
    use chio_kernel::payment::PaymentJournalState as State;
    match state {
        State::HoldPlaced => "hold_placed",
        State::Authorized => "authorized",
        State::Settling => "settling",
        State::Settled => "settled",
        State::Closed => "closed",
        State::ReconcileFailed => "reconcile_failed",
    }
}

fn parse_journal_state(
    value: &str,
) -> Result<chio_kernel::payment::PaymentJournalState, BudgetStoreError> {
    use chio_kernel::payment::PaymentJournalState as State;
    match value {
        "hold_placed" => Ok(State::HoldPlaced),
        "authorized" => Ok(State::Authorized),
        "settling" => Ok(State::Settling),
        "settled" => Ok(State::Settled),
        "closed" => Ok(State::Closed),
        "reconcile_failed" => Ok(State::ReconcileFailed),
        other => Err(BudgetStoreError::Invariant(format!(
            "unknown payment journal state `{other}`"
        ))),
    }
}

fn settle_action_str(action: chio_kernel::payment::PaymentSettleAction) -> &'static str {
    match action {
        chio_kernel::payment::PaymentSettleAction::Capture => "capture",
        chio_kernel::payment::PaymentSettleAction::Release => "release",
        chio_kernel::payment::PaymentSettleAction::Refund => "refund",
    }
}

fn parse_settle_action(
    value: &str,
) -> Result<chio_kernel::payment::PaymentSettleAction, BudgetStoreError> {
    match value {
        "capture" => Ok(chio_kernel::payment::PaymentSettleAction::Capture),
        "release" => Ok(chio_kernel::payment::PaymentSettleAction::Release),
        "refund" => Ok(chio_kernel::payment::PaymentSettleAction::Refund),
        other => Err(BudgetStoreError::Invariant(format!(
            "unknown payment settle action `{other}`"
        ))),
    }
}

type PaymentJournalRow = (
    String,
    String,
    u32,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<u64>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    u64,
    u64,
    Option<String>,
    Option<u64>,
    String,
    String,
    u64,
    Option<String>,
);

fn payment_journal_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PaymentJournalRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        budget_u32_from_row(row, 2, "payment grant_index")?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        optional_budget_u64_from_row(row, 7, "payment lease_epoch")?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        budget_u64_from_row(row, 12, "payment budget_exposure_units")?,
        budget_u64_from_row(row, 13, "payment amount_units")?,
        row.get(14)?,
        optional_budget_u64_from_row(row, 15, "payment settle_amount_units")?,
        row.get(16)?,
        row.get(17)?,
        budget_u64_from_row(row, 18, "payment created_at_unix_ms")?,
        row.get(19)?,
    ))
}

fn payment_journal_row_to_record(
    row: PaymentJournalRow,
) -> Result<chio_kernel::payment::PaymentJournalRecord, BudgetStoreError> {
    let (
        request_id,
        capability_id,
        grant_index,
        operation_id,
        request_binding_hash,
        authority_id,
        lease_id,
        lease_epoch,
        hold_id,
        rail,
        authorization_id,
        transaction_id,
        budget_exposure_units,
        amount_units,
        settle_action,
        settle_amount_units,
        currency,
        state,
        created_at,
        tenant_id,
    ) = row;
    let admission_operation = match (operation_id, request_binding_hash) {
        (None, None) => None,
        (Some(operation_id), Some(request_binding_hash)) => Some(
            BudgetAdmissionOperationBinding::new(operation_id, request_binding_hash)?,
        ),
        _ => {
            return Err(BudgetStoreError::Invariant(
                "payment journal operation binding is incomplete".to_string(),
            ));
        }
    };
    let authority = match (authority_id, lease_id, lease_epoch) {
        (None, None, None) => None,
        (Some(authority_id), Some(lease_id), Some(lease_epoch)) => Some(BudgetEventAuthority {
            authority_id,
            lease_id,
            lease_epoch,
        }),
        _ => {
            return Err(BudgetStoreError::Invariant(
                "payment journal budget authority binding is incomplete or invalid".to_string(),
            ));
        }
    };
    Ok(chio_kernel::payment::PaymentJournalRecord {
        request_id,
        capability_id,
        grant_index,
        admission_operation,
        authority,
        hold_id,
        rail,
        authorization_id,
        transaction_id,
        budget_exposure_units,
        amount_units,
        settle_action: settle_action
            .as_deref()
            .map(parse_settle_action)
            .transpose()?,
        settle_amount_units,
        currency,
        state: parse_journal_state(&state)?,
        created_at_unix_ms: created_at,
        tenant_id,
    })
}

fn journal_now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

fn budget_u64_to_sqlite(value: u64, field_name: &'static str) -> Result<i64, BudgetStoreError> {
    i64::try_from(value).map_err(|_| {
        BudgetStoreError::Overflow(format!(
            "{field_name} exceeds SQLite INTEGER range: {value}"
        ))
    })
}

fn optional_budget_u64_to_sqlite(
    value: Option<u64>,
    field_name: &'static str,
) -> Result<Option<i64>, BudgetStoreError> {
    value
        .map(|value| budget_u64_to_sqlite(value, field_name))
        .transpose()
}

pub(super) fn insert_payment_journal_tx(
    transaction: &rusqlite::Transaction<'_>,
    entry: &chio_kernel::payment::PaymentJournalRecord,
    allow_idempotent_retry: bool,
) -> Result<(), BudgetStoreError> {
    let operation_id = entry
        .admission_operation
        .as_ref()
        .map(BudgetAdmissionOperationBinding::operation_id);
    let request_binding_hash = entry
        .admission_operation
        .as_ref()
        .map(BudgetAdmissionOperationBinding::request_binding_hash);
    let sqlite_lease_epoch = entry
        .authority
        .as_ref()
        .map(|value| budget_u64_to_sqlite(value.lease_epoch, "payment lease_epoch"))
        .transpose()?;
    let sqlite_budget_exposure_units =
        budget_u64_to_sqlite(entry.budget_exposure_units, "payment budget_exposure_units")?;
    let sqlite_amount_units = budget_u64_to_sqlite(entry.amount_units, "payment amount_units")?;
    let sqlite_settle_amount_units =
        optional_budget_u64_to_sqlite(entry.settle_amount_units, "payment settle_amount_units")?;
    let sqlite_created_at =
        budget_u64_to_sqlite(entry.created_at_unix_ms, "payment created_at_unix_ms")?;
    let changed = transaction.execute(
        "INSERT INTO payment_journal (request_id, capability_id, grant_index, operation_id, \
         request_binding_hash, authority_id, lease_id, lease_epoch, hold_id, rail, \
         authorization_id, transaction_id, budget_exposure_units, amount_units, settle_action, \
         settle_amount_units, \
         currency, state, created_at, updated_at, tenant_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                 ?16, ?17, ?18, ?19, ?20, ?21) \
         ON CONFLICT(request_id) DO NOTHING",
        params![
            entry.request_id,
            entry.capability_id,
            i64::from(entry.grant_index),
            operation_id,
            request_binding_hash,
            entry
                .authority
                .as_ref()
                .map(|value| value.authority_id.as_str()),
            entry
                .authority
                .as_ref()
                .map(|value| value.lease_id.as_str()),
            sqlite_lease_epoch,
            entry.hold_id,
            entry.rail,
            entry.authorization_id,
            entry.transaction_id,
            sqlite_budget_exposure_units,
            sqlite_amount_units,
            entry.settle_action.map(settle_action_str),
            sqlite_settle_amount_units,
            entry.currency,
            journal_state_str(entry.state),
            sqlite_created_at,
            journal_now_unix_ms(),
            entry.tenant_id,
        ],
    )?;
    if changed == 0 {
        if allow_idempotent_retry {
            let existing = transaction
                .query_row(
                    "SELECT request_id, capability_id, grant_index, operation_id, \
                            request_binding_hash, authority_id, lease_id, lease_epoch, hold_id, \
                            rail, authorization_id, transaction_id, budget_exposure_units, \
                            amount_units, settle_action, settle_amount_units, currency, state, \
                            created_at, tenant_id \
                     FROM payment_journal WHERE request_id = ?1",
                    params![entry.request_id],
                    payment_journal_row,
                )
                .optional()?;
            if existing
                .map(payment_journal_row_to_record)
                .transpose()?
                .as_ref()
                == Some(entry)
            {
                return Ok(());
            }
        }
        return Err(BudgetStoreError::Invariant(format!(
            "payment journal request_id already recorded: {}",
            entry.request_id
        )));
    }
    Ok(())
}

pub(super) fn validate_payment_journal_authorization_binding(
    journal: Option<&chio_kernel::payment::PaymentJournalRecord>,
    admission_operation: Option<&BudgetAdmissionOperationBinding>,
    authority: Option<&BudgetEventAuthority>,
    capability_id: &str,
    grant_index: usize,
    hold_id: Option<&str>,
    budget_exposure_units: u64,
) -> Result<(), BudgetStoreError> {
    let Some(journal) = journal else {
        return Ok(());
    };
    if journal.admission_operation.as_ref() != admission_operation {
        return Err(BudgetStoreError::Invariant(
            "payment journal admission operation does not match its budget authorization"
                .to_string(),
        ));
    }
    if journal.authority.as_ref() != authority {
        return Err(BudgetStoreError::Invariant(
            "payment journal authority does not match its budget authorization".to_string(),
        ));
    }
    if journal.capability_id != capability_id
        || journal.grant_index as usize != grant_index
        || journal.hold_id.as_deref() != hold_id
        || journal.budget_exposure_units != budget_exposure_units
    {
        return Err(BudgetStoreError::Invariant(
            "payment journal budget hold identity does not match its authorization".to_string(),
        ));
    }
    if journal.state != chio_kernel::payment::PaymentJournalState::HoldPlaced
        || journal.authorization_id.is_some()
        || journal.transaction_id.is_some()
        || journal.settle_action.is_some()
        || journal.settle_amount_units.is_some()
    {
        return Err(BudgetStoreError::Invariant(
            "new payment journal row must be an unadvanced HoldPlaced record".to_string(),
        ));
    }
    Ok(())
}
