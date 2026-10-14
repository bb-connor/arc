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
                && liability.disposition != NativeFinishingDispositionV1::Outstanding
        })
    {
        return Err(invalid(
            "fresh native capture lacks authenticated finishing funding",
        ));
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
    if terminal.dispatch_commit().is_some() {
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

/// The retained original selected the bounded native output program.
fn native_original(
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
