//! The SQLite owner of the native original finishing account.
//!
//! Prepared is published before nonce issuance or the first dispatch Input
//! with its complete priced roster. Confirmed follows the authenticated
//! Process enrollment. Capture requires Confirmed; every post-effect writer
//! spends its own purpose; settlement follows the authentic terminal, the
//! retained receipt and, for a Process member, its committed reconciliation.
use super::finishing_plan::{
    prepare_native_initial_finishing_plan, NativeInitialFinishingCustody,
    StoreNativeInitialFinishingPhase, VerifiedNativeInitialFinishingPlan,
};
use super::*;
use crate::admission_operation_store::recovery::resources::PhysicalLiabilityData;
use crate::admission_operation_store::recovery::storage::{
    load_native_finishing_account, load_native_finishing_account_for_source,
    native_finishing_account_key, native_finishing_bank_key, native_finishing_bank_scope,
    native_finishing_flow_scope, native_finishing_publication, native_finishing_version_commit,
    persist_native_finishing_transition, persist_prepared_native_finishing_account,
    NativeFinishingAccountV1, NativeFinishingDispositionV1, NativeFinishingFileRoleV1,
    NativeFinishingFileV1, NativeFinishingIdentityV1, NativeFinishingLiabilityV1,
    NativeFinishingProcessEnrollmentV1, NativeFinishingProcessV1, NativeFinishingPurposeV1,
    NativeFinishingStateV1, NativeFinishingTransitionAllowanceV1, RetainedNativeFinishingAccount,
    NATIVE_FINISHING_ACCOUNT_MAX_BYTES, NATIVE_FINISHING_BANK_MAX_BYTES,
};
use crate::serving_owner::NativeSourceTransactionOrigin;
use chio_kernel::native_finishing::{
    NativeInitialFinishingAuthority, NativeInitialFinishingPhase,
    NativeProcessFinishingSourceProvider, OriginalNativeFinishingPreparationData,
};
use chio_kernel::process_return_custody::{
    canonical_process_return_source_data, process_return_account_intent_digest,
    validate_process_return_funding_data, NativeReturnSequenceDomainDataV1,
    ProcessReturnFundingDataV1, ProcessReturnSourceDataV1, PROCESS_RETURN_FUNDING_SCHEMA,
};
use chio_kernel::receipt_store::NativeReceiptStoreRegistration;
use chio_process::native_return_custody::ProcessNativeFinishingSource;

mod process_custody;
mod roster;
mod row_plan;
mod spend;
pub(in crate::admission_operation_store) use spend::{
    authorize_native_finishing_growth, native_finishing_at_terminal,
    native_finishing_seal_allowance, native_original, native_payment_journal_write,
    refuse_unpriced_native_payment_write, require_confirmed_native_finishing,
    require_outstanding_native_payment_purposes, spend_native_finishing_purpose,
    spend_native_payment_purpose, NativeFinishingSpend, NativePaymentJournalWrite,
};

impl SqliteAdmissionOperationStore {
    /// Publish the complete before-effect Prepared account, or return the
    /// retained account for an exact replay of the same original.
    pub(in crate::admission_operation_store) fn prepare_original_native_finishing_from_port(
        &self,
        authority: &NativeInitialFinishingAuthority<'_>,
        provider: Option<&dyn NativeProcessFinishingSourceProvider>,
    ) -> Result<OriginalNativeFinishingPreparationData, AdmissionOperationStoreError> {
        let lease = authority.lease();
        let fence = lease.store_fence();
        let now = authority.trusted_now_unix_ms();
        authority
            .process_bank_issuer()
            .require_scoped_owner(self, fence, now)?;
        let process = concrete_process(provider)?;
        require_process_roster(authority.request(), process)?;
        let receipts = receipt_sink(authority.configured_receipt_registration())?;
        let operation = authority.operation();
        let operation_id = operation.binding().operation_id().as_str();
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        require_attached_receipt_sink(&tx, &self.serving_owner, receipts)?;
        if let Some(retained) = load_native_finishing_account(&tx, operation_id)? {
            let replay = replay_preparation(authority, process, &retained)?;
            tx.rollback().map_err(sqlite_error)?;
            return Ok(replay);
        }
        if authority.phase() == NativeInitialFinishingPhase::ExistingAccountBeforeInput {
            return Err(invalid(
                "native finishing nonce replay lost its original account",
            ));
        }
        let origin = self
            .serving_owner
            .prepare_native_source_transaction(&tx)
            .map_err(map_owner_error)?;
        let plan = prepare_native_initial_finishing_plan(
            &tx,
            &self.serving_owner,
            &origin,
            NativeInitialFinishingCustody {
                operation,
                lease,
                binding: authority.binding(),
                context: authority.context(),
                request: authority.request(),
                trusted_now_unix_ms: now,
            },
        )?;
        let phase = match (plan.phase(), authority.phase()) {
            (
                StoreNativeInitialFinishingPhase::BeforeNonce,
                NativeInitialFinishingPhase::BeforeNonce,
            ) => "before_nonce",
            (
                StoreNativeInitialFinishingPhase::BeforeInput,
                NativeInitialFinishingPhase::BeforeInput,
            ) => "before_input",
            _ => {
                return Err(invalid(
                    "native finishing phase differs from its physical source",
                ))
            }
        };
        let original = plan.original();
        let profile = original
            .native_output_retention()
            .ok_or_else(|| invalid("native finishing original lost its output profile"))?;
        let security_authority = plan.initialized().authority.as_str().to_owned();
        let flow_scope = native_finishing_flow_scope(&security_authority, plan.key())?;
        let account_key = native_finishing_account_key(operation_id);
        let process_quote = process.map(roster::price_process).transpose()?;
        // The producer copies the original capability's lineage keys into the
        // receipt row. The snapshot is written before the effect from the
        // presented token; its keys are immutable once recorded.
        let capability = &authority.request().capability;
        chio_kernel::receipt_store::ReceiptStore::record_capability_snapshot(
            receipts,
            capability,
            capability
                .delegation_chain
                .last()
                .map(|link| link.capability_id.as_str()),
        )
        .map_err(|error| {
            invalid(format!(
                "native receipt capability lineage refused: {error}"
            ))
        })?;
        let (sink_device, sink_inode) = receipts
            .native_receipt_file()
            .map_err(|error| invalid(error.to_string()))?;
        let owed_pages = crate::admission_operation_store::native_registered_file_debt(
            &tx,
            &self.serving_owner.fence.store_uuid,
            sink_device,
            sink_inode,
        )?
        .map_or(0, |debt| debt.owed_pages);
        let receipt_quote = roster::price_receipt_sink(
            receipts,
            plan.tool_outcome_envelope().receipt_bytes(),
            capability.id.as_str(),
            owed_pages,
        )?;
        let receipt_file = receipt_quote.file.clone();
        let (receipt_device, receipt_inode) = (receipt_file.device, receipt_file.inode);
        let receipt_digest = receipt_quote.registration_digest.clone();
        let process_future = process_quote
            .as_ref()
            .map(|quote| quote.future_transactions_digest.clone());
        let priced = roster::price_roster(
            &tx,
            &self.serving_owner,
            &origin,
            &plan,
            &account_key,
            &flow_scope,
            process_quote,
            receipt_quote,
        )?;
        // Every price was taken on this exact source cut; nothing was written.
        plan.verify_before(&tx, &self.serving_owner, &origin)?;
        let native_file = chio_sqlite_file_identity::main_database_file_identity(&tx)
            .map_err(|error| invalid(error.to_string()))?;
        let mut files = vec![
            NativeFinishingFileV1 {
                role: NativeFinishingFileRoleV1::Native,
                device: native_file.device,
                inode: native_file.inode,
            },
            receipt_file,
        ];
        let process_member = match process {
            Some(source) => {
                let data = source.source();
                files.push(NativeFinishingFileV1 {
                    role: NativeFinishingFileRoleV1::Process,
                    device: data.file_device,
                    inode: data.file_inode,
                });
                Some(NativeFinishingProcessV1 {
                    source: data.clone(),
                    source_digest: source_digest(data)?,
                    future_transactions_digest: process_future
                        .ok_or_else(|| invalid("native Process quote disappeared"))?,
                })
            }
            None => None,
        };
        files.sort();
        let fence = &self.serving_owner.fence;
        let identity = NativeFinishingIdentityV1 {
            operation_id: operation_id.to_owned(),
            request_binding_digest: operation
                .binding()
                .request_binding_hash()
                .as_str()
                .to_owned(),
            original_digest: sha256_hex(original.canonical_bytes()),
            profile_digest: digest_of(profile)?,
            context_digest: digest_of(authority.context())?,
            actor_digest: actor_digest(authority.request())?,
            role_map_digest: digest_of(authority.binding())?,
            flow_scope_digest: flow_scope,
            security_authority,
            store_uuid: fence.store_uuid.clone(),
            store_lease_id: fence.lease_id.clone(),
            store_owner_epoch: fence.owner_epoch,
            coordinator_lease_id: lease.coordinator_lease_id().as_str().to_owned(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            phase: phase.to_owned(),
            source_cut: plan.initial_source_head().0,
            source_cut_digest: plan.initial_source_head().1.clone(),
            physical_recipe_digest: priced.recipe_digest,
            seal_allowance: plan.native_seal_price().clone(),
            files,
            receipt_registration_digest: Some(receipt_digest),
            process: process_member,
        };
        let account =
            NativeFinishingAccountV1::prepared(identity, priced.liabilities, priced.transitions)?;
        persist_prepared_native_finishing_account(&tx, &self.serving_owner, &account)?;
        // The new receipt reserve is intake on the sink's own volume. It is
        // published with the sink's writer gate closed, so no receipt
        // transaction commits between this check and the native COMMIT.
        let receipt_debt = crate::admission_operation_store::native_registered_file_debt(
            &tx,
            &self.serving_owner.fence.store_uuid,
            receipt_device,
            receipt_inode,
        )?
        .ok_or_else(|| invalid("native finishing bank lost its receipt reserve"))?;
        receipts
            .publish_native_receipt_loan(&receipt_debt, || self.commit_write(tx))
            .map_err(|error| invalid(format!("native receipt sink capacity refused: {error}")))??;
        self.sync_after_write(&connection)?;
        Ok(OriginalNativeFinishingPreparationData::Prepared {
            process_source: process.map(|source| source.source().clone()),
        })
    }

    /// Enroll the Process member with funding minted from the Prepared
    /// account by the Kernel's scoped issuer, under the held native writer.
    pub(in crate::admission_operation_store) fn enroll_original_native_finishing_process_from_port(
        &self,
        provider: &dyn NativeProcessFinishingSourceProvider,
        authority: &NativeInitialFinishingAuthority<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let process = concrete_process(Some(provider))?
            .ok_or_else(|| invalid("native finishing enrollment lost its Process source"))?;
        let fence = authority.lease().store_fence();
        let now = authority.trusted_now_unix_ms();
        let issuer = authority.process_bank_issuer();
        issuer.require_scoped_owner(self, fence, now)?;
        let retained = self.read_native_finishing_account(
            authority.operation().binding().operation_id().as_str(),
            fence,
            now,
        )?;
        require_same_original(authority, &retained.account)?;
        let member = retained
            .account
            .identity
            .process
            .as_ref()
            .ok_or_else(|| invalid("native finishing account has no Process member"))?;
        // The concrete Process writer distinguishes first enrollment from an
        // authenticated replay. Fresh enrollment requires the exact source cut;
        // replay consumes this proof against its original retained source after
        // verifying the current call identity. Enrollment itself changes the cut.
        if retained.account.state != NativeFinishingStateV1::Prepared {
            return Err(invalid(
                "native finishing enrollment changed its original Process source",
            ));
        }
        let port = process_custody::FinishingCustodyPort { store: self };
        let funded = issuer.fund_original_enrollment_in_writer(self, &port, &member.source)?;
        process
            .enroll(funded)
            .map_err(|error| invalid(format!("native Process enrollment refused: {error}")))?;
        Ok(())
    }

    /// Publish Confirmed after reading the committed Process enrollment back.
    pub(in crate::admission_operation_store) fn confirm_original_native_finishing_from_port(
        &self,
        authority: &NativeInitialFinishingAuthority<'_>,
        provider: Option<&dyn NativeProcessFinishingSourceProvider>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let process = concrete_process(provider)?;
        let fence = authority.lease().store_fence();
        let now = authority.trusted_now_unix_ms();
        authority
            .process_bank_issuer()
            .require_scoped_owner(self, fence, now)?;
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let operation_id = authority.operation().binding().operation_id().as_str();
        let retained = load_native_finishing_account(&tx, operation_id)?
            .ok_or_else(|| invalid("native finishing confirmation lost its account"))?;
        require_same_original(authority, &retained.account)?;
        if retained.account.state != NativeFinishingStateV1::Prepared {
            return Err(invalid("native finishing account is not Prepared"));
        }
        let enrollment = match (&retained.account.identity.process, process) {
            (Some(member), Some(source)) => {
                let funding = funding_data(&tx, &retained.account)?;
                let expected = process_return_account_intent_digest(&member.source, &funding)?;
                let receipt = source.restore(&expected).map_err(|error| {
                    invalid(format!(
                        "native Process enrollment readback refused: {error}"
                    ))
                })?;
                if receipt.account_digest() != expected {
                    return Err(invalid(
                        "native Process enrollment differs from its funding",
                    ));
                }
                Some(NativeFinishingProcessEnrollmentV1 {
                    account_digest: expected,
                    event_sequence: receipt.event_sequence(),
                    event_digest: receipt.event_digest().to_owned(),
                })
            }
            (None, None) => None,
            _ => {
                return Err(invalid(
                    "native finishing confirmation changed its Process roster",
                ))
            }
        };
        let next = retained.account.confirming(enrollment)?;
        persist_native_finishing_transition(&tx, &self.serving_owner, &retained, &next)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(())
    }

    /// Restore the earlier enrollment on an exact nonce or restart replay.
    /// No Process source, quote, account or native record is written.
    pub(in crate::admission_operation_store) fn restore_original_native_finishing_process_from_port(
        &self,
        provider: &dyn NativeProcessFinishingSourceProvider,
        original_account_digest: &str,
        authority: &NativeInitialFinishingAuthority<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let process = concrete_process(Some(provider))?
            .ok_or_else(|| invalid("native finishing restore lost its Process source"))?;
        let fence = authority.lease().store_fence();
        let now = authority.trusted_now_unix_ms();
        authority
            .process_bank_issuer()
            .require_scoped_owner(self, fence, now)?;
        let retained = self.read_native_finishing_account(
            authority.operation().binding().operation_id().as_str(),
            fence,
            now,
        )?;
        require_same_original(authority, &retained.account)?;
        let enrollment = retained
            .account
            .process_enrollment
            .as_ref()
            .filter(|enrollment| {
                retained.account.state == NativeFinishingStateV1::Confirmed
                    && enrollment.account_digest == original_account_digest
            })
            .ok_or_else(|| invalid("native finishing restore lost its Confirmed enrollment"))?;
        let receipt = process.restore(original_account_digest).map_err(|error| {
            invalid(format!(
                "native Process enrollment readback refused: {error}"
            ))
        })?;
        if receipt.event_sequence() != enrollment.event_sequence
            || receipt.event_digest() != enrollment.event_digest
        {
            return Err(invalid(
                "native Process enrollment differs from its Confirmed receipt",
            ));
        }
        Ok(())
    }

    /// Settle a native-only account after its authentic terminal and receipt.
    /// An account with a Process member settles after Process reconciliation.
    pub(in crate::admission_operation_store) fn settle_native_finishing_after_terminal_from_port(
        &self,
        operation_id: &AdmissionOperationId,
        receipts: Option<&NativeReceiptStoreRegistration>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        observed_time(&tx, now)?;
        let Some(retained) = load_native_finishing_account(&tx, operation_id.as_str())? else {
            tx.rollback().map_err(sqlite_error)?;
            return Ok(());
        };
        let process_member = retained.account.identity.process.is_some();
        if retained.account.state == NativeFinishingStateV1::Settled || process_member {
            tx.rollback().map_err(sqlite_error)?;
            return Ok(());
        }
        require_authentic_completion(&tx, &retained.account, receipts)?;
        let next = retained.account.settling()?;
        persist_native_finishing_transition(&tx, &self.serving_owner, &retained, &next)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        drop(connection);
        refresh_sink_page_cap(receipt_sink(receipts)?)
    }

    /// Settle an account whose Process member committed its reconciliation.
    /// The Process journal is read back through the concrete source only.
    pub(in crate::admission_operation_store) fn settle_original_native_finishing_process_from_port(
        &self,
        provider: &dyn NativeProcessFinishingSourceProvider,
        receipts: Option<&NativeReceiptStoreRegistration>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let process = concrete_process(Some(provider))?
            .ok_or_else(|| invalid("native finishing settlement lost its Process source"))?;
        let original = process
            .enrolled_source()
            .map_err(|error| invalid(format!("native Process custody refused: {error}")))?
            .ok_or_else(|| invalid("native Process source has no retained account"))?;
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        observed_time(&tx, now)?;
        let retained = load_native_finishing_account_for_source(&tx, &source_digest(&original)?)?
            .ok_or_else(|| invalid("native Process source has no native account"))?;
        if retained.account.state == NativeFinishingStateV1::Settled {
            tx.rollback().map_err(sqlite_error)?;
            return Ok(());
        }
        let enrollment = retained
            .account
            .process_enrollment
            .as_ref()
            .ok_or_else(|| invalid("native finishing settlement lost its enrollment"))?;
        let reconciled = process
            .reconciliation()
            .map_err(|error| invalid(format!("native Process readback refused: {error}")))?
            .ok_or_else(|| {
                AdmissionOperationStoreError::Unavailable(
                    "native Process reconciliation is not committed".into(),
                )
            })?;
        if reconciled.account_digest() != enrollment.account_digest {
            return Err(invalid(
                "native Process reconciliation belongs to another account",
            ));
        }
        require_authentic_completion(&tx, &retained.account, receipts)?;
        let next = retained.account.settling()?;
        persist_native_finishing_transition(&tx, &self.serving_owner, &retained, &next)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        drop(connection);
        refresh_sink_page_cap(receipt_sink(receipts)?)
    }

    /// The authenticated bank a receipt sink must preserve from its first
    /// write, read from this authority's own fenced serving owner and file.
    pub fn native_receipt_bank_attachment(
        &self,
    ) -> Result<crate::receipt_store::NativeReceiptBankAttachment, AdmissionOperationStoreError>
    {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        let view = bank_view(&tx, &self.serving_owner)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(crate::receipt_store::NativeReceiptBankAttachment::new(
            view,
            Arc::clone(&self.connection),
            Arc::clone(&self.serving_owner),
        ))
    }

    /// Attach this authority's bank to the registered receipt sink. Every
    /// later commit of the sink preserves the bank's outstanding debt.
    pub(in crate::admission_operation_store) fn attach_native_receipt_sink_from_port(
        &self,
        registration: &NativeReceiptStoreRegistration,
    ) -> Result<(), AdmissionOperationStoreError> {
        let receipts = receipt_sink(Some(registration))?;
        let view = {
            let connection = self.connection()?;
            bank_view(&connection, &self.serving_owner)?
        };
        receipts
            .attach_native_finishing_bank(view)
            .map_err(|error| invalid(error.to_string()))
    }

    /// Retain the native original's one receipt under its prepaid ReceiptSink
    /// purpose, then spend the purpose. The sink COMMIT precedes the spend, so
    /// a crash between them leaves the purpose outstanding with the receipt
    /// retained; that replay spends without another sink write.
    pub(in crate::admission_operation_store) fn materialize_native_finishing_receipt_from_port(
        &self,
        operation_id: &AdmissionOperationId,
        receipt: &chio_core::receipt::body::ChioReceipt,
        pending_visible_at_ms: Option<u64>,
        receipts: Option<&NativeReceiptStoreRegistration>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let sink = receipt_sink(receipts)?;
        let funding = {
            let mut connection = self.connection()?;
            let tx = self.begin_read(&mut connection)?;
            verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
            verify_trusted_time(&tx, now)?;
            require_attached_receipt_sink(&tx, &self.serving_owner, sink)?;
            let funding = receipt_funding(&tx, operation_id, receipt, sink)?;
            tx.commit().map_err(sqlite_error)?;
            funding
        };
        let retained = |sink: &crate::SqliteReceiptStore| {
            sink.native_receipt_retained(receipt)
                .map_err(|error| invalid(format!("native receipt readback refused: {error}")))
        };
        let Some(funding) = funding else {
            return if retained(sink)? {
                Ok(())
            } else {
                Err(invalid(
                    "native receipt purpose was spent without its receipt",
                ))
            };
        };
        if !retained(sink)? {
            if let Err(error) =
                sink.append_native_finishing_receipt(receipt, pending_visible_at_ms, funding)
            {
                if !retained(sink)? {
                    return Err(invalid(format!("native receipt append refused: {error}")));
                }
            }
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        observed_time(&tx, now)?;
        let retained = load_native_finishing_account(&tx, operation_id.as_str())?
            .ok_or_else(|| invalid("native finishing receipt lost its account"))?;
        let outstanding = retained
            .account
            .liability(NativeFinishingPurposeV1::ReceiptSink)
            .is_some_and(|liability| {
                liability.disposition == NativeFinishingDispositionV1::Outstanding
            });
        if !outstanding {
            tx.rollback().map_err(sqlite_error)?;
            return Ok(());
        }
        let next = retained
            .account
            .consuming(NativeFinishingPurposeV1::ReceiptSink)?;
        persist_native_finishing_transition(&tx, &self.serving_owner, &retained, &next)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        drop(connection);
        refresh_sink_page_cap(sink)
    }

    /// Startup sweep after receipt reconciliation: every unsettled account
    /// without a Process member settles once its authentic terminal
    /// and receipt are retained. One not yet terminal keeps its debt.
    pub(in crate::admission_operation_store) fn settle_native_finishing_at_startup_from_port(
        &self,
        receipts: Option<&NativeReceiptStoreRegistration>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operations = {
            let mut connection = self.connection()?;
            let tx = self.begin_read(&mut connection)?;
            verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
            let operations =
                crate::admission_operation_store::recovery::storage::unsettled_native_only_accounts(
                    &tx,
                )?;
            tx.commit().map_err(sqlite_error)?;
            operations
        };
        for operation in operations {
            let operation_id = AdmissionOperationId::from_persisted(operation)
                .map_err(|error| invalid(error.to_string()))?;
            match self.settle_native_finishing_after_terminal_from_port(
                &operation_id,
                receipts,
                fence,
                now,
            ) {
                Ok(()) | Err(AdmissionOperationStoreError::Unavailable(_)) => (),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// A freshly signed native receipt id is named by no lineage statement.
    /// A named id refuses before the terminal publishes it; the retried
    /// terminal signs a new id.
    pub(in crate::admission_operation_store) fn require_native_receipt_unnamed_from_port(
        &self,
        receipt_id: &str,
        receipts: Option<&NativeReceiptStoreRegistration>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let named = receipt_sink(receipts)?
            .native_receipt_named(receipt_id)
            .map_err(|error| {
                invalid(format!("native receipt lineage readback refused: {error}"))
            })?;
        if named {
            return Err(AdmissionOperationStoreError::Unavailable(
                "native receipt id is already named by receipt lineage".into(),
            ));
        }
        Ok(())
    }

    /// Startup reconciliation: a missing receipt whose terminal belongs to a
    /// native account is retained under its prepaid purpose. Every other
    /// receipt keeps the ordinary projection.
    pub(in crate::admission_operation_store) fn reconcile_native_finishing_receipt_from_port(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
        pending_visible_at_ms: Option<u64>,
        registration: &NativeReceiptStoreRegistration,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<bool, AdmissionOperationStoreError> {
        let operation = {
            let mut connection = self.connection()?;
            let tx = self.begin_read(&mut connection)?;
            let operation: Option<String> = tx
                .query_row(
                    "SELECT operation_id FROM main.admission_operation_terminal_records
                     WHERE record_kind='receipt' AND record_id=?1",
                    [receipt.id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_error)?;
            let native = match operation.as_deref() {
                Some(operation) => load_native_finishing_account(&tx, operation)?.is_some(),
                None => false,
            };
            tx.commit().map_err(sqlite_error)?;
            operation.filter(|_| native)
        };
        let Some(operation) = operation else {
            return Ok(false);
        };
        let operation_id = AdmissionOperationId::from_persisted(operation)
            .map_err(|error| invalid(error.to_string()))?;
        self.materialize_native_finishing_receipt_from_port(
            &operation_id,
            receipt,
            pending_visible_at_ms,
            Some(registration),
            fence,
            now,
        )?;
        Ok(true)
    }

    fn read_native_finishing_account(
        &self,
        operation_id: &str,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RetainedNativeFinishingAccount, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&tx, now)?;
        let retained = load_native_finishing_account(&tx, operation_id)?
            .ok_or_else(|| invalid("native finishing account is absent"))?;
        tx.commit().map_err(sqlite_error)?;
        Ok(retained)
    }
}

/// The Kernel marker must be exactly the concrete Process source.
fn concrete_process(
    provider: Option<&dyn NativeProcessFinishingSourceProvider>,
) -> Result<Option<&ProcessNativeFinishingSource>, AdmissionOperationStoreError> {
    provider
        .map(|provider| {
            provider
                .as_any()
                .downcast_ref::<ProcessNativeFinishingSource>()
                .ok_or_else(|| invalid("native finishing accepts only the concrete Process source"))
        })
        .transpose()
}

/// A Process-issued request identity always carries its Process member.
fn require_process_roster(
    request: &chio_kernel::ToolCallRequest,
    process: Option<&ProcessNativeFinishingSource>,
) -> Result<(), AdmissionOperationStoreError> {
    let process_request = request.request_id.starts_with("process:");
    match process {
        Some(source) if source.source().request_id == request.request_id => Ok(()),
        None if !process_request => Ok(()),
        _ => Err(invalid(
            "native finishing roster differs from its Process call identity",
        )),
    }
}

/// The registered receipt sink must be the concrete SQLite receipt store.
fn receipt_sink(
    registration: Option<&NativeReceiptStoreRegistration>,
) -> Result<&crate::SqliteReceiptStore, AdmissionOperationStoreError> {
    registration
        .and_then(NativeReceiptStoreRegistration::downcast_ref::<crate::SqliteReceiptStore>)
        .ok_or_else(|| invalid("native finishing requires its registered receipt owner"))
}

/// A smaller bank debt raises the sink's ordinary page cap again.
fn refresh_sink_page_cap(
    sink: &crate::SqliteReceiptStore,
) -> Result<(), AdmissionOperationStoreError> {
    sink.refresh_native_page_cap()
        .map_err(|error| invalid(format!("native receipt page cap refresh refused: {error}")))
}

/// This authority's bank as its receipt sink reads it.
fn bank_view(
    connection: &Connection,
    owner: &SqliteServingOwner,
) -> Result<crate::receipt_store::NativeReceiptBankViewData, AdmissionOperationStoreError> {
    let native_path = connection
        .path()
        .ok_or_else(|| invalid("native finishing requires a persistent authority file"))?
        .to_owned();
    let file = chio_sqlite_file_identity::main_database_file_identity(connection)
        .map_err(|error| invalid(error.to_string()))?;
    Ok(crate::receipt_store::NativeReceiptBankViewData {
        native_path,
        native_device: file.device,
        native_inode: file.inode,
        store_uuid: owner.fence.store_uuid.clone(),
    })
}

/// A receipt reserve is funded only on a sink that preserves this bank.
fn require_attached_receipt_sink(
    connection: &Connection,
    owner: &SqliteServingOwner,
    receipts: &crate::SqliteReceiptStore,
) -> Result<(), AdmissionOperationStoreError> {
    if receipts.native_finishing_bank() != Some(&bank_view(connection, owner)?) {
        return Err(invalid(
            "native receipt sink does not preserve this finishing bank",
        ));
    }
    Ok(())
}

/// The outstanding ReceiptSink purpose of this exact terminal receipt, or
/// `None` once the purpose was spent.
fn receipt_funding(
    tx: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    receipt: &chio_core::receipt::body::ChioReceipt,
    sink: &crate::SqliteReceiptStore,
) -> Result<Option<crate::receipt_store::NativeReceiptFundingData>, AdmissionOperationStoreError> {
    let retained = load_native_finishing_account(tx, operation_id.as_str())?
        .ok_or_else(|| invalid("native receipt has no finishing account"))?;
    let account = &retained.account;
    let recorded: Option<String> = tx
        .query_row(
            "SELECT record_id FROM main.admission_operation_terminal_records
             WHERE operation_id=?1 AND record_kind='receipt'",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if recorded.as_deref() != Some(receipt.id.as_str()) {
        return Err(invalid("native receipt differs from its terminal record"));
    }
    let liability = account
        .liability(NativeFinishingPurposeV1::ReceiptSink)
        .ok_or_else(|| invalid("native finishing account has no receipt purpose"))?;
    if liability.disposition != NativeFinishingDispositionV1::Outstanding {
        return Ok(None);
    }
    if account.state != NativeFinishingStateV1::Confirmed {
        return Err(invalid(
            "native receipt purpose requires a Confirmed account",
        ));
    }
    let file = account
        .identity
        .files
        .iter()
        .find(|file| file.role == NativeFinishingFileRoleV1::ReceiptSink)
        .ok_or_else(|| invalid("native finishing account has no receipt file"))?;
    let registration_digest = roster::receipt_registration_digest(sink, file.device, file.inode)?;
    if account.identity.receipt_registration_digest.as_deref() != Some(registration_digest.as_str())
    {
        return Err(invalid("native receipt sink differs from its registration"));
    }
    let operation = crate::admission_operation_store::load_by_operation_id_tx(tx, operation_id)?
        .ok_or_else(|| invalid("native receipt operation is absent"))?
        .operation;
    let original = crate::admission_operation_store::retained_request::load_retained_request_tx(
        tx, &operation,
    )?
    .ok_or_else(|| invalid("native receipt lost its retained original"))?;
    if sha256_hex(original.canonical_bytes()) != account.identity.original_digest {
        return Err(invalid("native receipt original differs from its account"));
    }
    let profile = original
        .native_output_retention()
        .ok_or_else(|| invalid("native receipt original lost its output profile"))?;
    let recipe = liability
        .page_recipe
        .ok_or_else(|| invalid("native receipt purpose lost its page recipe"))?;
    Ok(Some(crate::receipt_store::NativeReceiptFundingData {
        receipt_bytes: profile.envelopes().receipt(),
        registration_digest,
        profile_digest: liability.profile_digest.clone(),
        wal_bytes: liability.liability.wal_bytes(),
        disk_bytes: liability.liability.disk_bytes(),
        page_bucket: recipe.page_bucket,
        page_growth: recipe.page_growth,
    }))
}

fn replay_preparation(
    authority: &NativeInitialFinishingAuthority<'_>,
    process: Option<&ProcessNativeFinishingSource>,
    retained: &RetainedNativeFinishingAccount,
) -> Result<OriginalNativeFinishingPreparationData, AdmissionOperationStoreError> {
    let account = &retained.account;
    require_same_original(authority, account)?;
    if account.identity.process.is_some() != process.is_some() {
        return Err(invalid(
            "native finishing replay changed its Process roster",
        ));
    }
    let source = account
        .identity
        .process
        .as_ref()
        .map(|member| member.source.clone());
    match account.state {
        NativeFinishingStateV1::Prepared => Ok(OriginalNativeFinishingPreparationData::Prepared {
            process_source: source,
        }),
        NativeFinishingStateV1::Confirmed => {
            Ok(OriginalNativeFinishingPreparationData::Confirmed {
                original_process_source: source,
                original_process_account_digest: account
                    .process_enrollment
                    .as_ref()
                    .map(|enrollment| enrollment.account_digest.clone()),
            })
        }
        NativeFinishingStateV1::Settled => {
            Err(invalid("native finishing account is already settled"))
        }
    }
}

/// The current invocation must be the exact original the account froze.
fn require_same_original(
    authority: &NativeInitialFinishingAuthority<'_>,
    account: &NativeFinishingAccountV1,
) -> Result<(), AdmissionOperationStoreError> {
    let identity = &account.identity;
    let operation = authority.operation();
    if identity.operation_id != operation.binding().operation_id().as_str()
        || identity.request_binding_digest != operation.binding().request_binding_hash().as_str()
        || identity.original_digest != sha256_hex(authority.original().canonical_bytes())
        || identity.role_map_digest != digest_of(authority.binding())?
        || identity.actor_digest != actor_digest(authority.request())?
        || identity.store_uuid != authority.lease().store_fence().store_uuid
    {
        return Err(invalid(
            "native finishing account belongs to another original",
        ));
    }
    Ok(())
}

/// Every native purpose that will ever be written is finished: the operation
/// is terminal and its retained receipt is in the registered sink.
fn require_authentic_completion(
    tx: &Transaction<'_>,
    account: &NativeFinishingAccountV1,
    receipts: Option<&NativeReceiptStoreRegistration>,
) -> Result<(), AdmissionOperationStoreError> {
    let terminal: Option<String> = tx
        .query_row(
            "SELECT terminal_state FROM main.admission_operation_terminal_projections
             WHERE operation_id=?1",
            [account.identity.operation_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if terminal.is_none() {
        return Err(AdmissionOperationStoreError::Unavailable(
            "native finishing operation is not terminal".into(),
        ));
    }
    let receipt_id: Option<String> = tx
        .query_row(
            "SELECT record_id FROM main.admission_operation_terminal_records
             WHERE operation_id=?1 AND record_kind='receipt'",
            [account.identity.operation_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some(receipt_id) = receipt_id {
        let sink = receipt_sink(receipts)?;
        let connection = sink
            .connection()
            .map_err(|error| invalid(format!("native receipt sink unavailable: {error}")))?;
        let identity = chio_sqlite_file_identity::main_database_file_identity(&connection)
            .map_err(|error| invalid(error.to_string()))?;
        let registered = account.identity.files.iter().any(|file| {
            file.role == NativeFinishingFileRoleV1::ReceiptSink
                && file.device == identity.device
                && file.inode == identity.inode
        });
        let retained: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.chio_tool_receipts WHERE receipt_id=?1)",
                [&receipt_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !registered || !retained {
            return Err(AdmissionOperationStoreError::Unavailable(
                "native finishing receipt is not retained by its registered sink".into(),
            ));
        }
    }
    Ok(())
}

/// Deterministic funding DATA of the Prepared account: identical on every
/// replay, so restart reconstructs exactly what the Process enrolled.
pub(super) fn funding_data(
    tx: &Connection,
    account: &NativeFinishingAccountV1,
) -> Result<ProcessReturnFundingDataV1, AdmissionOperationStoreError> {
    let identity = &account.identity;
    let member = identity
        .process
        .as_ref()
        .ok_or_else(|| invalid("native finishing account has no Process member"))?;
    let publication = native_finishing_publication(tx, identity)?;
    let mut funding = ProcessReturnFundingDataV1 {
        schema: PROCESS_RETURN_FUNDING_SCHEMA.to_owned(),
        process_source_digest: member.source_digest.clone(),
        process_account_digest: String::new(),
        native_operation_id: identity.operation_id.clone(),
        native_request_binding_digest: identity.request_binding_digest.clone(),
        native_account_digest: publication.record_digest.clone(),
        native_account_sequence: publication.global_commit_sequence,
        native_account_sequence_domain: NativeReturnSequenceDomainDataV1::AuthorityGlobalCommit,
        native_bank_epoch: publication.global_commit_sequence,
        original_native_source_epoch_digest: identity.source_cut_digest.clone(),
        original_store_uuid: identity.store_uuid.clone(),
        original_store_lease_id: identity.store_lease_id.clone(),
        original_store_lease_epoch: identity.store_owner_epoch,
        original_coordinator_lease_id: identity.coordinator_lease_id.clone(),
        original_coordinator_lease_epoch: identity.coordinator_lease_epoch,
        original_profile_digest: identity.profile_digest.clone(),
        original_actor_digest: identity.actor_digest.clone(),
        original_context_digest: identity.context_digest.clone(),
        original_role_map_digest: identity.role_map_digest.clone(),
        physical_recipe_digest: identity.physical_recipe_digest.clone(),
        process_future_transactions_digest: member.future_transactions_digest.clone(),
        original_native_publication: publication,
    };
    funding.process_account_digest =
        process_return_account_intent_digest(&member.source, &funding)?;
    validate_process_return_funding_data(&member.source, &funding)?;
    Ok(funding)
}

fn source_digest(
    source: &ProcessReturnSourceDataV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&canonical_process_return_source_data(source)?))
}

fn actor_digest(
    request: &chio_kernel::ToolCallRequest,
) -> Result<String, AdmissionOperationStoreError> {
    digest_of(&(
        "chio.native-finishing-actor.v1",
        &request.agent_id,
        &request.capability.id,
    ))
}

fn digest_of(value: &impl Serialize) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&canonical_json_bytes(value).map_err(invalid)?))
}
