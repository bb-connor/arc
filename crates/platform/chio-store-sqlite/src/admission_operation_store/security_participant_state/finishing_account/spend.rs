//! Post-effect writers spend exactly their own prepaid purpose in their own
//! transaction. An ordinary original owes nothing; a native original with an
//! output profile can never write without its Confirmed account.
use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;

/// Whether the writer's original is an ordinary call or spent its purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) enum NativeFinishingSpend {
    Ordinary,
    Spent,
}

/// Consume `purpose` for this operation inside the writer's transaction.
/// The account transition, bank update and funded capacity check commit or
/// roll back with the writer's own rows.
pub(in crate::admission_operation_store) fn spend_native_finishing_purpose(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
    purpose: NativeFinishingPurposeV1,
) -> Result<NativeFinishingSpend, AdmissionOperationStoreError> {
    if !native_original(tx, operation)? {
        return Ok(NativeFinishingSpend::Ordinary);
    }
    let retained = load_native_finishing_account(tx, operation.binding().operation_id().as_str())?
        .ok_or_else(|| invalid("native original writer has no finishing account"))?;
    let next = retained.account.consuming(purpose)?;
    persist_native_finishing_transition(tx, owner, &retained, &next)?;
    Ok(NativeFinishingSpend::Spent)
}

/// Before a funded writer's first write, raise this transaction's page cap
/// by exactly the growth its outstanding purposes on the operation's own
/// Confirmed account allow. The file's pages plus every owed growth must lie
/// within the smallest retained ceiling. A purpose with a page recipe adds its
/// recipe growth within its own bucket; that growth is already owed, so every
/// other loan stays reserved. A purpose priced without a recipe adds at most
/// its priced frames, and only inside the page budget left beyond all owed
/// growth. An ordinary original, or one no longer owing these purposes, keeps
/// the ordinary cap; its later spend refuses on its own terms.
pub(in crate::admission_operation_store) fn authorize_native_finishing_growth(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
    purposes: &[NativeFinishingPurposeV1],
) -> Result<(), AdmissionOperationStoreError> {
    if !native_original(tx, operation)? {
        return Ok(());
    }
    let Some(retained) =
        load_native_finishing_account(tx, operation.binding().operation_id().as_str())?
    else {
        return Ok(());
    };
    let account = &retained.account;
    if account.state != NativeFinishingStateV1::Confirmed {
        return Ok(());
    }
    let pragma = |name: &str| -> Result<u64, AdmissionOperationStoreError> {
        let value: i64 = tx
            .query_row(&format!("PRAGMA main.{name}"), [], |row| row.get(0))
            .map_err(sqlite_error)?;
        u64::try_from(value).map_err(invalid)
    };
    let pages = pragma("page_count")?;
    let frame = pragma("page_size")?
        .checked_add(24)
        .ok_or_else(|| invalid("native authority frame size exhausted"))?;
    let budget = crate::admission_operation_store::native_authority_file_page_debt(
        tx,
        &owner.fence.store_uuid,
    )?;
    let owed_through = pages
        .checked_add(budget.owed_pages)
        .ok_or_else(|| invalid("native authority page budget exhausted"))?;
    if budget
        .page_ceiling
        .is_some_and(|ceiling| owed_through > ceiling)
    {
        return Err(invalid(
            "native authority file exceeds its smallest owed page ceiling",
        ));
    }
    for purpose in purposes {
        let Some(liability) = account.outstanding_in_slot(*purpose) else {
            continue;
        };
        let identity = format!("{}:purpose:{purpose:?}", account.identity.operation_id);
        owner
            .native_capacity()
            .authorize_table_rows(&identity, &liability.row_loans)
            .map_err(invalid)?;
        let growth = match liability.page_recipe {
            Some(recipe) => recipe.page_growth,
            None => {
                // Preserve interpretation of older retained recipes. New
                // accounts give every purpose an explicit prepaid growth loan.
                let frames = liability.liability.wal_bytes() / frame;
                budget
                    .page_ceiling
                    .map_or(frames, |ceiling| frames.min(ceiling - owed_through))
            }
        };
        owner
            .native_capacity()
            .authorize_funded_growth(tx, &identity, growth)
            .map_err(invalid)?;
    }
    Ok(())
}

/// The seal allowance this operation's account priced before its effect.
pub(in crate::admission_operation_store) fn native_finishing_seal_allowance(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
) -> Result<
    Option<crate::admission_operation_store::security_participant_state::finishing_plan::NativeSealAllowanceData>,
    AdmissionOperationStoreError,
>{
    if !native_original(tx, operation)? {
        return Ok(None);
    }
    let retained = load_native_finishing_account(tx, operation.binding().operation_id().as_str())?
        .ok_or_else(|| invalid("native owed append has no finishing account"))?;
    if retained.account.state != NativeFinishingStateV1::Confirmed {
        return Err(invalid("native owed append requires a Confirmed account"));
    }
    if retained
        .account
        .outstanding_in_slot(NativeFinishingPurposeV1::OutputJoin)
        .is_none()
    {
        return Err(invalid("native owed append has no outstanding Output join"));
    }
    Ok(Some(retained.account.identity.seal_allowance))
}

/// Fresh capture and external authorization require the exact Confirmed
/// account of this original with every native post-effect purpose still
/// outstanding and, for a Process member, its authenticated enrollment.
/// One phase-specific exception: the retained authorization purpose may
/// already be consumed exactly when this operation's own payment journal
/// retained the external hold it consumed the purpose for. The journal, not
/// a marker, is the evidence; a consumed purpose without a retained
/// authorization refuses, and every other payment purpose must still be
/// outstanding at a fresh admission or capture boundary.
pub(in crate::admission_operation_store) fn require_confirmed_native_finishing(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    original: &RetainedToolAdmissionRequestV1,
    binding: &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
) -> Result<(), AdmissionOperationStoreError> {
    let retained = load_native_finishing_account(tx, operation.binding().operation_id().as_str())?
        .ok_or_else(|| invalid("fresh native capture lacks authenticated finishing funding"))?;
    let account = &retained.account;
    let identity = &account.identity;
    if account.state != NativeFinishingStateV1::Confirmed
        || identity.request_binding_digest != operation.binding().request_binding_hash().as_str()
        || identity.original_digest != sha256_hex(original.canonical_bytes())
        || identity.role_map_digest != digest_of(binding)?
        || identity.process.is_some() != account.process_enrollment.is_some()
        || account.liabilities.iter().any(|liability| {
            liability.purpose.file_role() == NativeFinishingFileRoleV1::Native
                && liability.purpose != NativeFinishingPurposeV1::PaymentAuthorization
                && liability.disposition != NativeFinishingDispositionV1::Outstanding
        })
    {
        return Err(invalid(
            "fresh native capture lacks authenticated finishing funding",
        ));
    }
    // The one consumed purpose a fresh boundary may see is the retained
    // authorization, and only in its exact phase: a reversible-hold journal
    // still Authorized, or a final prepayment already Settled. The journal
    // row of this exact operation is the evidence; a consumed purpose in any
    // other phase, or without its retained authorization, refuses.
    if account.liabilities.iter().any(|liability| {
        liability.purpose == NativeFinishingPurposeV1::PaymentAuthorization
            && liability.disposition == NativeFinishingDispositionV1::Consumed
    }) {
        let journal = crate::budget_store::load_payment_journal(
            tx,
            operation.binding().operation_id().as_str(),
        )
        .map_err(|error| invalid(error.to_string()))?
        .ok_or_else(|| invalid("consumed native payment authorization lost its journal"))?;
        let retained_phase = match journal.state {
            chio_kernel::payment::PaymentJournalState::Authorized => {
                journal.rail_mode == chio_kernel::payment::PaymentRailMode::ReversibleHold
            }
            chio_kernel::payment::PaymentJournalState::Settled => {
                journal.rail_mode == chio_kernel::payment::PaymentRailMode::PrepaidFinal
            }
            chio_kernel::payment::PaymentJournalState::HoldPlaced
            | chio_kernel::payment::PaymentJournalState::Settling
            | chio_kernel::payment::PaymentJournalState::Closed
            | chio_kernel::payment::PaymentJournalState::ReconcileFailed => false,
        };
        if !retained_phase || journal.authorization_id.is_none() {
            return Err(invalid(
                "consumed native payment authorization is not retained in its authorized phase",
            ));
        }
    }
    Ok(())
}

/// The terminal projection of a native original. After a dispatch commit it
/// is the operation's own post-effect write and spends its prepaid purpose.
/// Without one no effect exists: the account is released at once unless a
/// selected Process member must still retain its no-future-return fate.
pub(in crate::admission_operation_store) fn native_finishing_at_terminal(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    terminal: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !native_original(tx, terminal)? {
        return Ok(());
    }
    let Some(retained) =
        load_native_finishing_account(tx, terminal.binding().operation_id().as_str())?
    else {
        // Preparation precedes nonce issuance and the first dispatch Input;
        // a native original refused before it never opened an account.
        if terminal.dispatch_commit().is_some() {
            return Err(invalid(
                "dispatched native original has no finishing account",
            ));
        }
        return Ok(());
    };
    if terminal.dispatch_commit().is_some() || payment_was_authorized(tx, terminal)? {
        // A dispatched effect, or an external payment authorization released
        // before dispatch, makes this terminal a post-effect write: it spends
        // its own prepaid purpose and never falls back to ordinary intake.
        let next = retained
            .account
            .consuming(NativeFinishingPurposeV1::TerminalProjection)?;
        return persist_native_finishing_transition(tx, owner, &retained, &next);
    }
    if retained.account.state == NativeFinishingStateV1::Settled
        || retained.account.identity.process.is_some()
    {
        return Ok(());
    }
    let next = retained.account.settling()?;
    persist_native_finishing_transition(tx, owner, &retained, &next)?;
    // No effect was dispatched, so the terminal's own rows are not a prepaid
    // purpose: this COMMIT is ordinary intake under the ordinary cap.
    owner
        .native_capacity()
        .withdraw_funding(tx)
        .map_err(invalid)
}

/// Whether this operation's payment journal retained a real external
/// authorization. A hold cancelled before any authorization has none.
fn payment_was_authorized(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
) -> Result<bool, AdmissionOperationStoreError> {
    if !operation.binding().participant_requirements().payment {
        return Ok(false);
    }
    Ok(
        crate::budget_store::load_payment_journal(tx, operation.binding().operation_id().as_str())
            .map_err(|error| invalid(error.to_string()))?
            .is_some_and(|journal| journal.authorization_id.is_some()),
    )
}

/// The prepaid purpose and phase of one durable payment journal transition.
/// The phase decides which account state may legitimately admit the write:
/// only the hold cancellation can precede a funded Confirmed account, and
/// only an external effect or its settlement can follow one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) enum NativePaymentJournalWrite {
    /// The genuinely pre-effect cancellation of a budget hold that no
    /// external authorization ever retained.
    PreEffectCancellation,
    /// A post-authorization journal write against the funded account.
    PostEffect(NativeFinishingPurposeV1),
    /// A transition with no priced native shape on the advance path.
    Unpriced,
}

/// Classify one durable journal transition. The settlement begin owns its
/// PaymentSettlement purpose inside begin_payment_settlement; through the
/// advance path BeginCapture takes the refusal like Close, because an
/// advance-path spend would consume the settlement slot and strand the real
/// settlement begin.
pub(in crate::admission_operation_store) fn native_payment_journal_write(
    transition: &chio_kernel::payment::PaymentJournalTransition,
) -> NativePaymentJournalWrite {
    use chio_kernel::payment::PaymentJournalTransition as Transition;
    match transition {
        // The only journal write that can legitimately precede a funded
        // account: the hold is cancelled before any external authorization.
        Transition::CancelBeforeAuthorization => NativePaymentJournalWrite::PreEffectCancellation,
        Transition::AuthorizationHeld { .. } | Transition::PrepaymentSettled { .. } => {
            NativePaymentJournalWrite::PostEffect(NativeFinishingPurposeV1::PaymentAuthorization)
        }
        Transition::BeginRelease { .. } | Transition::ReconcileFailed => {
            NativePaymentJournalWrite::PostEffect(NativeFinishingPurposeV1::PaymentCompensation)
        }
        Transition::SettlementCompleted { .. } => {
            NativePaymentJournalWrite::PostEffect(NativeFinishingPurposeV1::PaymentCompletion)
        }
        Transition::BeginCapture { .. } | Transition::Close => NativePaymentJournalWrite::Unpriced,
    }
}

impl NativePaymentJournalWrite {
    /// The purpose a funded Confirmed account would spend for this write.
    pub(in crate::admission_operation_store) fn funded_purpose(
        self,
    ) -> Option<NativeFinishingPurposeV1> {
        match self {
            Self::PreEffectCancellation => Some(NativeFinishingPurposeV1::PaymentCompensation),
            Self::PostEffect(purpose) => Some(purpose),
            Self::Unpriced => None,
        }
    }
}

/// Spend the prepaid purpose of one actual payment journal write inside the
/// writer's own transaction. An ordinary original owes nothing. A native
/// original classifies the write by its exact phase: the hold cancellation
/// alone may use ordinary intake while no funded account exists or the
/// account is still only Prepared, every post-authorization write requires
/// the Confirmed funded account, and no write may follow a settled account.
pub(in crate::admission_operation_store) fn spend_native_payment_purpose(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
    write: NativePaymentJournalWrite,
) -> Result<NativeFinishingSpend, AdmissionOperationStoreError> {
    if !native_original(tx, operation)? {
        return Ok(NativeFinishingSpend::Ordinary);
    }
    let account = load_native_finishing_account(tx, operation.binding().operation_id().as_str())?;
    let funded = |purpose| -> Result<NativeFinishingSpend, AdmissionOperationStoreError> {
        let retained = account
            .as_ref()
            .ok_or_else(|| invalid("native payment journal write lost its funded account"))?;
        let next = retained.account.consuming(purpose)?;
        persist_native_finishing_transition(tx, owner, retained, &next)?;
        Ok(NativeFinishingSpend::Spent)
    };
    match (
        write,
        account.as_ref().map(|retained| retained.account.state),
    ) {
        // Genuinely pre-effect: the hold was cancelled before this original
        // had any funded account to spend, or while it was still Prepared.
        (
            NativePaymentJournalWrite::PreEffectCancellation,
            None | Some(NativeFinishingStateV1::Prepared),
        ) => Ok(NativeFinishingSpend::Ordinary),
        // A funded cancellation or any post-authorization write spends its
        // own purpose inside the writer's transaction.
        (
            NativePaymentJournalWrite::PreEffectCancellation,
            Some(NativeFinishingStateV1::Confirmed),
        ) => funded(NativeFinishingPurposeV1::PaymentCompensation),
        (
            NativePaymentJournalWrite::PostEffect(purpose),
            Some(NativeFinishingStateV1::Confirmed),
        ) => funded(purpose),
        // Every other combination is a broken phase: a post-authorization
        // write without the funded Confirmed account, or any write after the
        // account settled, refuses rather than downgrading to intake.
        _ => Err(invalid(
            "native payment journal write lacks its funded Confirmed account",
        )),
    }
}

/// A payment journal transition with no priced native shape refuses on every
/// native original: the only pre-effect native journal write (the hold
/// cancellation) carries its own prepaid purpose and never reaches this
/// path. An ordinary original owes nothing.
pub(in crate::admission_operation_store) fn refuse_unpriced_native_payment_write(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !native_original(tx, operation)? {
        return Ok(());
    }
    Err(invalid(
        "native payment journal transition has no priced native shape",
    ))
}

/// The Confirmed account of a payment original must price every journal
/// purpose the external authorization would owe before that authorization
/// happens. The roster reserved them before any effect; this check binds
/// them to this exact operation's still-outstanding account.
pub(in crate::admission_operation_store) fn require_outstanding_native_payment_purposes(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let retained = load_native_finishing_account(tx, operation.binding().operation_id().as_str())?
        .ok_or_else(|| invalid("native payment original lacks its finishing account"))?;
    for purpose in [
        NativeFinishingPurposeV1::PaymentAuthorization,
        NativeFinishingPurposeV1::PaymentCompensation,
        NativeFinishingPurposeV1::PaymentSettlement,
        NativeFinishingPurposeV1::PaymentCompletion,
    ] {
        if retained.account.outstanding_in_slot(purpose).is_none() {
            return Err(invalid(
                "native external authorization lacks a priced payment settlement purpose",
            ));
        }
    }
    Ok(())
}

/// The retained original selected the bounded native output program.
pub(in crate::admission_operation_store) fn native_original(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
) -> Result<bool, AdmissionOperationStoreError> {
    Ok(
        crate::admission_operation_store::retained_request::load_retained_request_tx(
            tx, operation,
        )?
        .is_some_and(|original| original.native_output_retention().is_some()),
    )
}
