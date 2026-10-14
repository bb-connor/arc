//! The real native original owns pre-effect finishing obligations.
use super::*;
use chio_kernel::admission_operation::NativeSecurityEgressContext;

impl SqliteAdmissionOperationStore {
    /// This boundary precedes an external authorization. Borrowed context and
    /// retained envelope data cannot provide prepaid finishing authority; only
    /// the exact Confirmed account of this original can, and only when its
    /// roster prices the payment settlement the authorization would owe.
    pub(in crate::admission_operation_store) fn require_native_pre_authorization_finishing_funding_from_port(
        &self,
        context: &NativeSecurityEgressContext<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operation = context.operation;
        operation.validate()?;
        if operation.state() != AdmissionOperationState::CapturePending
            || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
            || operation.dispatch_commit().is_some()
            || operation.budget_hold_id().is_none()
            || operation.provider_attempt().is_none_or(|attempt| {
                attempt.is_caller_report() && !attempt.is_native_caller_report()
            })
        {
            return Err(invalid(
                "native pre-authorization requires fresh kernel capture custody",
            ));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(context.lease.store_fence()))?;
        let origin = self
            .serving_owner
            .prepare_native_source_transaction(&tx)
            .map_err(map_owner_error)?;
        let now = observed_time(&tx, context.trusted_now_unix_ms)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, context.lease, now)?;
        ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
        let original = retained_request::load_retained_request_tx(&tx, operation)?
            .ok_or_else(|| invalid("native pre-authorization lost its actual original"))?;
        original.validate_binding(operation.binding())?;
        original.validate_request_material(context.request)?;
        original.validate_native_security_authority(context.binding)?;
        original.validate_native_security_context(context.security_context)?;
        if original.authority_profile().is_none()
            || context.binding.store_uuid().as_str() != self.serving_owner.fence.store_uuid
        {
            return Err(invalid(
                "native pre-authorization changed its original authority",
            ));
        }
        // Startup authenticated the complete source history. These bounded
        // immutable fields independently bind this actual owner and initial
        // transaction cut; no caller-selected initialization is accepted.
        records::load_current_metadata(&tx, context.binding)?;
        origin.verify(&tx).map_err(map_owner_error)?;
        super::finishing_account::require_confirmed_native_finishing(
            &tx,
            operation,
            &original,
            context.binding,
        )
        .map_err(|_| {
            invalid("native external authorization lacks authenticated finishing funding")
        })?;
        // This original is a payment participant: its Confirmed account
        // prepaid the complete journal family before any effect, and every
        // purpose is still outstanding here, before the external rail hold.
        // The later writers spend each purpose in their own transaction, so
        // the authorization this gate admits can always be settled, released
        // or compensated without new authority.
        if !operation.binding().participant_requirements().payment {
            return Err(invalid(
                "native pre-authorization is not a priced payment participant",
            ));
        }
        super::finishing_account::require_outstanding_native_payment_purposes(&tx, operation)?;
        let requirements = operation.binding().participant_requirements();
        let executable =
            crate::admission_operation_store::tool_outcome_liability::PaymentHoldInventory::executable(
                context.request,
                requirements.supplemental_authorization,
            )?;
        require_priced_payment_holds(&tx, operation, executable)?;
        Ok(())
    }
}

/// The payment text bound the account priced for budget text without a typed
/// bound of its own (`payment::journal` validates payment identifiers to it).
const PAYMENT_HOLD_TEXT_BYTES: i64 = 512;

/// Every live hold of this operation already holds all the budget rows and
/// text a funded settlement or reversal later rewrites: no member row is added
/// after the external authorization. Measure them here, before the effect,
/// against the inventory and text bound its account priced.
fn require_priced_payment_holds(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    executable: crate::admission_operation_store::tool_outcome_liability::PaymentHoldInventory,
) -> Result<(), AdmissionOperationStoreError> {
    let mut holds = Vec::new();
    if let Some(hold_id) = operation.budget_hold_id() {
        holds.push((hold_id.as_str().to_owned(), executable));
    }
    if let Some(preflight) =
        crate::admission_operation_store::nonce_preflight::load_recovery(tx, operation)?
    {
        if preflight.hold()
            != chio_kernel::admission_operation::AdmissionNoncePreflightHoldDisposition::Reversed
        {
            holds.push((
                preflight.identity().hold_id().as_str().to_owned(),
                executable.preflight(),
            ));
        }
    }
    for (hold_id, inventory) in holds {
        // The member rows a later funded transition copies into its event,
        // and the supplemental columns it rewrites, lie inside the inventory
        // the account priced from this same authenticated original.
        let (quotas, revocations, artifacts, commits, cumulative, verifier): (
            i64,
            i64,
            i64,
            i64,
            i64,
            bool,
        ) = tx
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM main.budget_hold_quota_members WHERE hold_id=?1),
                     (SELECT COUNT(*) FROM main.budget_hold_revocation_members WHERE hold_id=?1),
                     (SELECT COUNT(*) FROM main.budget_hold_authorization_artifacts
                      WHERE hold_id=?1),
                     (SELECT COUNT(*) FROM main.budget_hold_revocation_commits WHERE hold_id=?1),
                     (SELECT COUNT(*) FROM main.budget_cumulative_approval_operations
                      WHERE hold_id=?1),
                     EXISTS(SELECT 1 FROM main.budget_authorization_holds
                            WHERE hold_id=?1 AND (supplemental_verifier_id IS NOT NULL
                                 OR supplemental_verifier_config_digest IS NOT NULL
                                 OR supplemental_artifact_digest IS NOT NULL))",
                [hold_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(sqlite_error)?;
        let within =
            |actual: i64, priced: u64| u64::try_from(actual).is_ok_and(|actual| actual <= priced);
        if !within(quotas, inventory.quotas)
            || !within(revocations, inventory.revocations)
            || !within(artifacts, inventory.artifacts)
            || !within(commits, u64::from(inventory.revocation_commit))
            || !within(cumulative, u64::from(inventory.cumulative))
            || (verifier && !inventory.supplemental)
        {
            return Err(invalid(
                "native payment hold carries members its account did not price",
            ));
        }
        let exceeds: bool = tx
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM main.budget_authorization_holds WHERE hold_id=?1 AND (
                         length(CAST(hold_id AS BLOB))>?2
                         OR length(CAST(capability_id AS BLOB))>?2
                         OR length(CAST(operation_id AS BLOB))>?2
                         OR length(CAST(reserved_currency AS BLOB))>?2
                         OR length(CAST(reserved_payment_reference AS BLOB))>?2
                         OR length(CAST(reserved_root_budget_holder AS BLOB))>?2)
                     UNION ALL
                     SELECT 1 FROM main.budget_hold_quota_members
                     WHERE hold_id=?1 AND length(CAST(owner_id AS BLOB))>?2
                     UNION ALL
                     SELECT 1 FROM main.budget_hold_revocation_commits WHERE hold_id=?1 AND (
                         length(CAST(authority_id AS BLOB))>?2
                         OR length(CAST(lease_id AS BLOB))>?2)
                     UNION ALL
                     SELECT 1 FROM main.budget_cumulative_approval_operations AS operation
                     JOIN main.budget_cumulative_approval_accounts AS account
                       ON account.authority_id=operation.authority_id
                      AND account.owner_id=operation.owner_id
                      AND account.approval_budget_id=operation.approval_budget_id
                      AND account.approval_budget_epoch=operation.approval_budget_epoch
                     WHERE operation.hold_id=?1 AND (
                         length(CAST(operation.operation_id AS BLOB))>?2
                         OR length(CAST(account.authority_id AS BLOB))>?2
                         OR length(CAST(account.owner_id AS BLOB))>?2
                         OR length(CAST(account.approval_budget_id AS BLOB))>?2
                         OR length(CAST(account.root_grant_hash AS BLOB))>?2
                         OR length(CAST(account.delegation_root_id AS BLOB))>?2
                         OR length(CAST(account.root_binding_digest AS BLOB))>?2
                         OR length(CAST(account.currency AS BLOB))>?2))",
                rusqlite::params![hold_id, PAYMENT_HOLD_TEXT_BYTES],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if exceeds {
            return Err(invalid(
                "native payment hold text exceeds the bound its account priced",
            ));
        }
    }
    Ok(())
}
