//! One native original finishing account per admitted operation.
//!
//! Version 1 publishes the complete before-effect Prepared liabilities under
//! the actual store fence. Version 2 is Confirmed once every enrolled producer
//! is authenticated. Each later Confirmed version consumes exactly one prepaid
//! purpose, and the terminal Settled version releases whatever remains. Every
//! version spends one unit of the priced transition allowance, so the account's
//! own writes, including settlement, are always covered. The account and the
//! authority bank head are typed protected commands outside every generic pool.
use super::super::resources::{
    check_funded_committing, check_intake_committing, physical_command_write_profile,
    price_protected_command_with_row_limits, PhysicalLiabilityData, ProtectedCommandLiabilityPlan,
};
use super::native_finishing_bank::{
    reservation_shape, NativeFinishingWidthRecipeV1, NativeFinishingWidthReservationV1,
};
use super::*;
use crate::native_authority_capacity::rows::{
    self as row_capacity, NativeTableRowDebt, NativeTableRowLoan, NativeTableRowReservation,
};
use chio_kernel::process_return_custody::{
    NativeReturnSequenceDomainDataV1, ProcessNativeAccountPublicationDataV1,
    ProcessReturnBankReadbackDataV1, ProcessReturnInventoryDataV1, ProcessReturnSourceDataV1,
    PROCESS_RETURN_BANK_READBACK_SCHEMA,
};

pub(in crate::admission_operation_store) const NATIVE_FINISHING_ACCOUNT_PREFIX: &str =
    "native-finishing-account:";
const NATIVE_FINISHING_BANK_PREFIX: &str = "native-finishing-bank:";
const NATIVE_FINISHING_SOURCE_PREFIX: &str = "native-finishing-source:";
const SOURCE_ALIAS_SCHEMA: &str = "chio.native-finishing-source-alias.v1";
const NATIVE_FINISHING_NAMESPACE_START: &str = "native-finishing-";
const NATIVE_FINISHING_NAMESPACE_END: &str = "native-finishing.";
const ACCOUNT_SCHEMA: &str = "chio.native-finishing-account.v1";
const BANK_SCHEMA: &str = "chio.native-finishing-bank.v1";
const PUBLICATION_SCHEMA: &str = "chio.native-finishing-prepared-publication.v1";
const MAX_LIABILITIES: usize = 20;
/// Bounds of the account's own typed records, enforced by their writer and
/// used to price every later account and bank head rewrite.
pub(in crate::admission_operation_store) const NATIVE_FINISHING_ACCOUNT_MAX_BYTES: u64 = 131_072;
pub(in crate::admission_operation_store) const NATIVE_FINISHING_BANK_MAX_BYTES: u64 = 32_768;
const MAX_TRANSITIONS: u64 = 2 + MAX_LIABILITIES as u64;
const MAX_OUTSTANDING_ACCOUNTS: u64 = 4_096;
const MAX_BANK_FILES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::admission_operation_store) enum NativeFinishingStateV1 {
    Prepared,
    Confirmed,
    Settled,
}

/// The physical file a purpose writes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::admission_operation_store) enum NativeFinishingFileRoleV1 {
    Native,
    Process,
    ReceiptSink,
}

/// Each purpose authorizes exactly one future transaction of its producer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::admission_operation_store) enum NativeFinishingPurposeV1 {
    RawCustody,
    EvaluationBegin,
    Finalization { pure_prefix: u64 },
    SecurityRelease,
    TerminalProjection,
    OutputJoin,
    NativeJournalSeal,
    ReceiptSink,
    PaymentAuthorization,
    PaymentCompensation,
    PaymentSettlement,
    PaymentCompletion,
    ProcessEnrollment,
    ProcessNonceCustody,
    ProcessUnavailableNotice,
    ProcessFinalCustody,
    ProcessReconciliation,
}

impl NativeFinishingPurposeV1 {
    pub(in crate::admission_operation_store) fn file_role(self) -> NativeFinishingFileRoleV1 {
        match self {
            Self::RawCustody
            | Self::EvaluationBegin
            | Self::Finalization { .. }
            | Self::SecurityRelease
            | Self::TerminalProjection
            | Self::OutputJoin
            | Self::NativeJournalSeal
            | Self::PaymentAuthorization
            | Self::PaymentCompensation
            | Self::PaymentSettlement
            | Self::PaymentCompletion => NativeFinishingFileRoleV1::Native,
            Self::ReceiptSink => NativeFinishingFileRoleV1::ReceiptSink,
            Self::ProcessEnrollment
            | Self::ProcessNonceCustody
            | Self::ProcessUnavailableNotice
            | Self::ProcessFinalCustody
            | Self::ProcessReconciliation => NativeFinishingFileRoleV1::Process,
        }
    }

    /// Single-use identity: a purpose appears at most once per account, and a
    /// finalization appears exactly once whatever its pure prefix.
    fn slot(self) -> u8 {
        match self {
            Self::RawCustody => 0,
            Self::EvaluationBegin => 1,
            Self::Finalization { .. } => 2,
            Self::OutputJoin => 3,
            Self::NativeJournalSeal => 4,
            Self::ReceiptSink => 5,
            Self::PaymentAuthorization => 13,
            Self::PaymentCompensation => 14,
            Self::PaymentSettlement => 15,
            Self::PaymentCompletion => 16,
            Self::ProcessEnrollment => 6,
            Self::ProcessNonceCustody => 7,
            Self::ProcessUnavailableNotice => 8,
            Self::ProcessFinalCustody => 9,
            Self::ProcessReconciliation => 10,
            Self::SecurityRelease => 11,
            Self::TerminalProjection => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::admission_operation_store) enum NativeFinishingDispositionV1 {
    Outstanding,
    Consumed,
    Released,
}

/// One prepaid purpose with its exact priced maximum on its own file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingLiabilityV1 {
    pub(in crate::admission_operation_store) purpose: NativeFinishingPurposeV1,
    pub(in crate::admission_operation_store) profile_digest: String,
    pub(in crate::admission_operation_store) liability: PhysicalLiabilityData,
    pub(in crate::admission_operation_store) disposition: NativeFinishingDispositionV1,
    /// The receipt sink quote's page recipe; present exactly for ReceiptSink.
    pub(in crate::admission_operation_store) page_recipe: Option<NativeFinishingPageRecipeV1>,
    /// The Output join's retained generation-width recipe; present exactly
    /// for OutputJoin.
    #[serde(default)]
    pub(in crate::admission_operation_store) width_recipe: Option<NativeFinishingWidthRecipeV1>,
    /// Priced WAL frames of a write on another registered file; native
    /// purposes are priced on the authority file in bytes and appends only.
    pub(in crate::admission_operation_store) wal_frames: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::admission_operation_store) row_loans: Vec<NativeTableRowLoan>,
}

/// The page recipe one receipt sink quote assumed: the power-of-two page
/// ceiling of its pointer-map term and the most pages its append can add.
/// Every current writer of the file keeps the page count plus all owed growth
/// within the smallest outstanding ceiling, so no write invalidates the loan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingPageRecipeV1 {
    pub(in crate::admission_operation_store) page_bucket: u64,
    pub(in crate::admission_operation_store) page_growth: u64,
}

impl NativeFinishingPageRecipeV1 {
    fn validate(self) -> Result<(), AdmissionOperationStoreError> {
        if !self.page_bucket.is_power_of_two()
            || self.page_growth == 0
            || self.page_growth > self.page_bucket
        {
            return Err(invariant("native finishing page recipe is not canonical"));
        }
        Ok(())
    }
}

/// The account's own future writes: one account version and one bank head
/// version per transition, priced once and spent one unit per transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingTransitionAllowanceV1 {
    pub(in crate::admission_operation_store) profile_digest: String,
    pub(in crate::admission_operation_store) per_transition: PhysicalLiabilityData,
    pub(in crate::admission_operation_store) remaining: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::admission_operation_store) page_recipe: Option<NativeFinishingPageRecipeV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::admission_operation_store) row_loans: Vec<NativeTableRowLoan>,
}

/// A registered physical file by its stable identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingFileV1 {
    pub(in crate::admission_operation_store) role: NativeFinishingFileRoleV1,
    pub(in crate::admission_operation_store) device: u64,
    pub(in crate::admission_operation_store) inode: u64,
}

/// The immutable Process member selected before the effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingProcessV1 {
    pub(in crate::admission_operation_store) source: ProcessReturnSourceDataV1,
    pub(in crate::admission_operation_store) source_digest: String,
    pub(in crate::admission_operation_store) future_transactions_digest: String,
}

/// The authenticated Process enrollment receipt published by Confirmed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingProcessEnrollmentV1 {
    pub(in crate::admission_operation_store) account_digest: String,
    pub(in crate::admission_operation_store) event_sequence: u64,
    pub(in crate::admission_operation_store) event_digest: String,
}

/// Immutable original identity, frozen at Prepared under the actual fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingIdentityV1 {
    pub(in crate::admission_operation_store) operation_id: String,
    pub(in crate::admission_operation_store) request_binding_digest: String,
    pub(in crate::admission_operation_store) original_digest: String,
    pub(in crate::admission_operation_store) profile_digest: String,
    pub(in crate::admission_operation_store) context_digest: String,
    pub(in crate::admission_operation_store) actor_digest: String,
    pub(in crate::admission_operation_store) role_map_digest: String,
    pub(in crate::admission_operation_store) flow_scope_digest: String,
    pub(in crate::admission_operation_store) security_authority: String,
    pub(in crate::admission_operation_store) store_uuid: String,
    pub(in crate::admission_operation_store) store_lease_id: String,
    pub(in crate::admission_operation_store) store_owner_epoch: u64,
    pub(in crate::admission_operation_store) coordinator_lease_id: String,
    pub(in crate::admission_operation_store) coordinator_lease_epoch: u64,
    pub(in crate::admission_operation_store) phase: String,
    pub(in crate::admission_operation_store) source_cut: u64,
    pub(in crate::admission_operation_store) source_cut_digest: String,
    pub(in crate::admission_operation_store) physical_recipe_digest: String,
    pub(in crate::admission_operation_store) seal_allowance:
        crate::admission_operation_store::security_participant_state::finishing_plan::NativeSealAllowanceData,
    pub(in crate::admission_operation_store) files: Vec<NativeFinishingFileV1>,
    pub(in crate::admission_operation_store) receipt_registration_digest: Option<String>,
    pub(in crate::admission_operation_store) process: Option<NativeFinishingProcessV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingAccountV1 {
    pub(in crate::admission_operation_store) schema: String,
    pub(in crate::admission_operation_store) revision: u64,
    pub(in crate::admission_operation_store) state: NativeFinishingStateV1,
    pub(in crate::admission_operation_store) identity: NativeFinishingIdentityV1,
    pub(in crate::admission_operation_store) liabilities: Vec<NativeFinishingLiabilityV1>,
    pub(in crate::admission_operation_store) transitions: NativeFinishingTransitionAllowanceV1,
    pub(in crate::admission_operation_store) process_enrollment:
        Option<NativeFinishingProcessEnrollmentV1>,
}

/// Immutable Prepared alias from one Process source to its native account.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeFinishingSourceAliasV1 {
    schema: String,
    operation_id: String,
}

/// Outstanding liability of every unsettled account on one registered file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingBankFileV1 {
    pub(in crate::admission_operation_store) file: NativeFinishingFileV1,
    accounts: u64,
    outstanding: PhysicalLiabilityData,
    /// Priced WAL frames every outstanding loan on this registered file owes.
    outstanding_wal_frames: u64,
    /// Pages every outstanding receipt loan on this file may still add.
    owed_pages: u64,
    /// Outstanding loans per page ceiling, ascending; the first is binding.
    page_buckets: Vec<NativeFinishingPageBucketV1>,
    /// Outstanding width loans per (tenant, width class), ascending.
    #[serde(default)]
    pub(in crate::admission_operation_store) width_reservations:
        Vec<NativeFinishingWidthReservationV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    row_reservations: Vec<NativeTableRowReservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeFinishingPageBucketV1 {
    page_bucket: u64,
    loans: u64,
}

impl NativeFinishingBankFileV1 {
    fn owe_pages(
        &mut self,
        recipe: NativeFinishingPageRecipeV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.owed_pages = self
            .owed_pages
            .checked_add(recipe.page_growth)
            .ok_or_else(|| invariant("native finishing page budget overflow"))?;
        match self
            .page_buckets
            .iter_mut()
            .find(|bucket| bucket.page_bucket == recipe.page_bucket)
        {
            Some(bucket) => {
                bucket.loans = bucket
                    .loans
                    .checked_add(1)
                    .ok_or_else(|| invariant("native finishing page bucket overflow"))?;
            }
            None => {
                self.page_buckets.push(NativeFinishingPageBucketV1 {
                    page_bucket: recipe.page_bucket,
                    loans: 1,
                });
                self.page_buckets.sort_by_key(|bucket| bucket.page_bucket);
            }
        }
        Ok(())
    }

    fn release_pages(
        &mut self,
        recipe: NativeFinishingPageRecipeV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.owed_pages = self
            .owed_pages
            .checked_sub(recipe.page_growth)
            .ok_or_else(|| invariant("native finishing page budget underflow"))?;
        let position = self
            .page_buckets
            .iter()
            .position(|bucket| bucket.page_bucket == recipe.page_bucket)
            .ok_or_else(|| invariant("native finishing bank lost a page bucket"))?;
        let bucket = &mut self.page_buckets[position];
        bucket.loans = bucket
            .loans
            .checked_sub(1)
            .ok_or_else(|| invariant("native finishing page bucket underflow"))?;
        if bucket.loans == 0 {
            self.page_buckets.remove(position);
        }
        Ok(())
    }
}

/// Retain one account's width recipe in the bank file's per-tenant
/// reservations, aggregating loans, growth and allowance per width class.
fn owe_width(
    reservations: &mut Vec<NativeFinishingWidthReservationV1>,
    recipe: &NativeFinishingWidthRecipeV1,
) -> Result<(), AdmissionOperationStoreError> {
    recipe.validate()?;
    match reservations.iter_mut().find(|reservation| {
        reservation.security_authority == recipe.security_authority
            && reservation.tenant_id == recipe.tenant_id
            && reservation.width_class == recipe.width_class
    }) {
        Some(reservation) => {
            reservation.loans = reservation
                .loans
                .checked_add(1)
                .ok_or_else(|| invariant("native finishing width bucket overflow"))?;
            reservation.n_grow = reservation
                .n_grow
                .checked_add(recipe.n_grow)
                .ok_or_else(|| invariant("native finishing width growth overflow"))?;
            reservation.allowance = reservation
                .allowance
                .checked_add(recipe.allocation_allowance)
                .ok_or_else(|| invariant("native finishing width allowance overflow"))?;
        }
        None => {
            reservations.push(NativeFinishingWidthReservationV1 {
                security_authority: recipe.security_authority.clone(),
                tenant_id: recipe.tenant_id.clone(),
                width_class: recipe.width_class,
                loans: 1,
                n_grow: recipe.n_grow,
                allowance: recipe.allocation_allowance,
            });
            reservations.sort();
        }
    }
    Ok(())
}

/// Release one account's retained width recipe, restoring the exact state.
fn release_width(
    reservations: &mut Vec<NativeFinishingWidthReservationV1>,
    recipe: &NativeFinishingWidthRecipeV1,
) -> Result<(), AdmissionOperationStoreError> {
    let position = reservations
        .iter()
        .position(|reservation| {
            reservation.security_authority == recipe.security_authority
                && reservation.tenant_id == recipe.tenant_id
                && reservation.width_class == recipe.width_class
        })
        .ok_or_else(|| invariant("native finishing bank lost a width reservation"))?;
    let reservation = &mut reservations[position];
    reservation.loans = reservation
        .loans
        .checked_sub(1)
        .ok_or_else(|| invariant("native finishing width bucket underflow"))?;
    reservation.n_grow = reservation
        .n_grow
        .checked_sub(recipe.n_grow)
        .ok_or_else(|| invariant("native finishing width growth underflow"))?;
    reservation.allowance = reservation
        .allowance
        .checked_sub(recipe.allocation_allowance)
        .ok_or_else(|| invariant("native finishing width allowance underflow"))?;
    if reservation.loans == 0 {
        reservations.remove(position);
    }
    Ok(())
}

/// The single authority bank head: the exact per-file sum of every unsettled
/// account. Startup recomputes the sum from the accounts.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingBankV1 {
    schema: String,
    store_uuid: String,
    outstanding_accounts: u64,
    pub(in crate::admission_operation_store) files: Vec<NativeFinishingBankFileV1>,
}

impl NativeFinishingAccountV1 {
    pub(in crate::admission_operation_store) fn validate(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        let identity = &self.identity;
        if self.schema != ACCOUNT_SCHEMA
            || self.revision == 0
            || (self.state == NativeFinishingStateV1::Prepared) != (self.revision == 1)
            || self.liabilities.is_empty()
            || self.liabilities.len() > MAX_LIABILITIES
            || self.transitions.remaining > MAX_TRANSITIONS
            || identity.store_owner_epoch == 0
            || identity.coordinator_lease_epoch == 0
            || identity.coordinator_lease_id.is_empty()
            || identity.coordinator_lease_id.len() > 256
            || identity.store_lease_id.is_empty()
            || identity.store_uuid.is_empty()
            || identity.security_authority.is_empty()
            || !matches!(identity.phase.as_str(), "before_nonce" | "before_input")
        {
            return Err(invariant("native finishing account is outside its profile"));
        }
        for digest in [
            &identity.operation_id,
            &identity.request_binding_digest,
            &identity.original_digest,
            &identity.profile_digest,
            &identity.context_digest,
            &identity.actor_digest,
            &identity.role_map_digest,
            &identity.flow_scope_digest,
            &identity.source_cut_digest,
            &identity.physical_recipe_digest,
            &self.transitions.profile_digest,
        ] {
            require_lower_digest(digest)?;
        }
        if let Some(digest) = &identity.receipt_registration_digest {
            require_lower_digest(digest)?;
        }
        self.validate_files()?;
        if let Some(recipe) = self.transitions.page_recipe {
            recipe.validate()?;
        }
        for loan in &self.transitions.row_loans {
            loan.validate().map_err(invariant)?;
        }
        let mut slots = [false; 17];
        let mut process_purposes = 0_usize;
        let mut payment_purposes = 0_usize;
        for liability in &self.liabilities {
            require_lower_digest(&liability.profile_digest)?;
            for loan in &liability.row_loans {
                loan.validate().map_err(invariant)?;
            }
            if !liability.row_loans.is_empty()
                && liability.purpose.file_role() != NativeFinishingFileRoleV1::Native
            {
                return Err(invariant("native table loan is on another file"));
            }
            // The receipt sink and the Output join always carry their page
            // recipe; another native-file purpose may; a Process purpose never.
            let recipe_required = matches!(
                liability.purpose,
                NativeFinishingPurposeV1::ReceiptSink | NativeFinishingPurposeV1::OutputJoin
            );
            let recipe_permitted = recipe_required
                || liability.purpose.file_role() == NativeFinishingFileRoleV1::Native;
            if (recipe_required && liability.page_recipe.is_none())
                || (!recipe_permitted && liability.page_recipe.is_some())
            {
                return Err(invariant("native finishing page recipe is misplaced"));
            }
            if let Some(recipe) = liability.page_recipe {
                recipe.validate()?;
            }
            // The Output join always carries its retained width recipe; no
            // other purpose reserves generation width.
            let width_required = liability.purpose == NativeFinishingPurposeV1::OutputJoin;
            if (width_required && liability.width_recipe.is_none())
                || (!width_required && liability.width_recipe.is_some())
            {
                return Err(invariant("native finishing width recipe is misplaced"));
            }
            if let Some(recipe) = &liability.width_recipe {
                recipe.validate()?;
                // The retained recipe is bound to this account's actual
                // security authority; a foreign authority cannot reserve
                // generation slots in this account's name.
                if recipe.security_authority != identity.security_authority {
                    return Err(invariant(
                        "native finishing width recipe belongs to another authority",
                    ));
                }
            }
            let registered = liability.purpose.file_role() != NativeFinishingFileRoleV1::Native;
            if liability.wal_frames.is_some() != registered
                || liability
                    .wal_frames
                    .is_some_and(|frames| (frames == 0) != (liability.liability.wal_bytes() == 0))
            {
                return Err(invariant(
                    "native finishing registered-file purpose lost its frame price",
                ));
            }
            let slot = usize::from(liability.purpose.slot());
            if slots[slot] || !self.has_file(liability.purpose.file_role()) {
                return Err(invariant(
                    "native finishing account repeats or misplaces a purpose",
                ));
            }
            slots[slot] = true;
            if liability.purpose.file_role() == NativeFinishingFileRoleV1::Process {
                process_purposes += 1;
            }
            if matches!(
                liability.purpose,
                NativeFinishingPurposeV1::PaymentAuthorization
                    | NativeFinishingPurposeV1::PaymentCompensation
                    | NativeFinishingPurposeV1::PaymentSettlement
                    | NativeFinishingPurposeV1::PaymentCompletion
            ) {
                payment_purposes += 1;
            }
        }
        // The payment participant's journal purposes are one complete prepaid
        // family: a partial roster could authorize an external payment whose
        // later settlement write has no funded owner.
        if payment_purposes != 0 && payment_purposes != 4 {
            return Err(invariant(
                "native finishing account carries a partial payment roster",
            ));
        }
        let has = |purpose: NativeFinishingPurposeV1| slots[usize::from(purpose.slot())];
        if !has(NativeFinishingPurposeV1::RawCustody)
            || !has(NativeFinishingPurposeV1::EvaluationBegin)
            || !has(NativeFinishingPurposeV1::Finalization { pure_prefix: 0 })
            || !has(NativeFinishingPurposeV1::SecurityRelease)
            || !has(NativeFinishingPurposeV1::TerminalProjection)
            || !has(NativeFinishingPurposeV1::OutputJoin)
            || !has(NativeFinishingPurposeV1::NativeJournalSeal)
            || has(NativeFinishingPurposeV1::ReceiptSink)
                != self.has_file(NativeFinishingFileRoleV1::ReceiptSink)
        {
            return Err(invariant(
                "native finishing account omits a required purpose",
            ));
        }
        match &identity.process {
            Some(process) => {
                require_lower_digest(&process.source_digest)?;
                require_lower_digest(&process.future_transactions_digest)?;
                if chio_kernel::process_return_custody::canonical_process_return_source_data(
                    &process.source,
                )
                .map(|bytes| sha256_hex(&bytes))?
                    != process.source_digest
                    || process.source.journal_authority != identity.store_uuid
                {
                    return Err(invariant(
                        "native finishing account changed its Process source",
                    ));
                }
                let nonce = process.source.original_nonce_pending;
                if !self.has_file(NativeFinishingFileRoleV1::Process)
                    || !has(NativeFinishingPurposeV1::ProcessEnrollment)
                    || !has(NativeFinishingPurposeV1::ProcessUnavailableNotice)
                    || !has(NativeFinishingPurposeV1::ProcessFinalCustody)
                    || !has(NativeFinishingPurposeV1::ProcessReconciliation)
                    || has(NativeFinishingPurposeV1::ProcessNonceCustody) != nonce
                {
                    return Err(invariant(
                        "native finishing account omits its Process member",
                    ));
                }
            }
            None if process_purposes != 0 || self.has_file(NativeFinishingFileRoleV1::Process) => {
                return Err(invariant(
                    "native finishing account owes an unselected Process purpose",
                ))
            }
            None => (),
        }
        if let Some(enrollment) = &self.process_enrollment {
            require_lower_digest(&enrollment.account_digest)?;
            require_lower_digest(&enrollment.event_digest)?;
            if enrollment.event_sequence == 0 {
                return Err(invariant("native finishing Process receipt is invalid"));
            }
        }
        let enrolled = self.process_enrollment.is_some();
        let process_selected = identity.process.is_some();
        let enrollment_consistent = match self.state {
            NativeFinishingStateV1::Prepared => !enrolled,
            NativeFinishingStateV1::Confirmed => enrolled == process_selected,
            NativeFinishingStateV1::Settled => !enrolled || process_selected,
        };
        let consumed = self.count(NativeFinishingDispositionV1::Consumed);
        let outstanding = self.count(NativeFinishingDispositionV1::Outstanding);
        let released = self.count(NativeFinishingDispositionV1::Released);
        let dispositions_consistent = match self.state {
            NativeFinishingStateV1::Prepared => consumed == 0 && released == 0,
            NativeFinishingStateV1::Confirmed => released == 0,
            NativeFinishingStateV1::Settled => outstanding == 0,
        };
        if !enrollment_consistent || !dispositions_consistent {
            return Err(invariant(
                "native finishing account dispositions differ from its state",
            ));
        }
        Ok(())
    }

    fn validate_files(&self) -> Result<(), AdmissionOperationStoreError> {
        let files = &self.identity.files;
        let natives = files
            .iter()
            .filter(|file| file.role == NativeFinishingFileRoleV1::Native)
            .count();
        let mut sorted = files.clone();
        sorted.sort();
        sorted.dedup_by(|left, right| left.role == right.role);
        if natives != 1
            || sorted.len() != files.len()
            || files.iter().any(|file| file.inode == 0)
            || files.iter().enumerate().any(|(index, file)| {
                files[index + 1..]
                    .iter()
                    .any(|other| other.inode == file.inode && other.device == file.device)
            })
        {
            return Err(invariant(
                "native finishing account registers an invalid file set",
            ));
        }
        Ok(())
    }

    fn has_file(&self, role: NativeFinishingFileRoleV1) -> bool {
        self.identity.files.iter().any(|file| file.role == role)
    }

    fn count(&self, disposition: NativeFinishingDispositionV1) -> usize {
        self.liabilities
            .iter()
            .filter(|liability| liability.disposition == disposition)
            .count()
    }

    /// Outstanding liability owed on one registered file.
    fn outstanding_on(
        &self,
        role: NativeFinishingFileRoleV1,
    ) -> Result<PhysicalLiabilityData, AdmissionOperationStoreError> {
        if self.state == NativeFinishingStateV1::Settled {
            return Ok(PhysicalLiabilityData::zero());
        }
        let mut total = self
            .liabilities
            .iter()
            .filter(|liability| {
                liability.disposition == NativeFinishingDispositionV1::Outstanding
                    && liability.purpose.file_role() == role
            })
            .try_fold(PhysicalLiabilityData::zero(), |total, liability| {
                total.checked_add(&liability.liability)
            })?;
        if role == NativeFinishingFileRoleV1::Native {
            for _ in 0..self.transitions.remaining {
                total = total.checked_add(&self.transitions.per_transition)?;
            }
        }
        Ok(total)
    }

    /// Priced WAL frames still owed on one registered file.
    fn outstanding_frames_on(
        &self,
        role: NativeFinishingFileRoleV1,
    ) -> Result<u64, AdmissionOperationStoreError> {
        if self.state == NativeFinishingStateV1::Settled {
            return Ok(0);
        }
        self.liabilities
            .iter()
            .filter(|liability| {
                liability.disposition == NativeFinishingDispositionV1::Outstanding
                    && liability.purpose.file_role() == role
            })
            .try_fold(0_u64, |total, liability| {
                total
                    .checked_add(liability.wal_frames.unwrap_or(0))
                    .ok_or_else(|| invariant("native finishing frame debt overflow"))
            })
    }

    /// The page recipe still owed on one registered file.
    fn outstanding_page_recipes(
        &self,
        role: NativeFinishingFileRoleV1,
    ) -> Vec<NativeFinishingPageRecipeV1> {
        if self.state == NativeFinishingStateV1::Settled {
            return Vec::new();
        }
        let mut recipes: Vec<_> = self
            .liabilities
            .iter()
            .filter(|liability| {
                liability.disposition == NativeFinishingDispositionV1::Outstanding
                    && liability.purpose.file_role() == role
            })
            .filter_map(|liability| liability.page_recipe)
            .collect();
        if role == NativeFinishingFileRoleV1::Native {
            if let Some(recipe) = self.transitions.page_recipe {
                recipes.extend((0..self.transitions.remaining).map(|_| recipe));
            }
        }
        recipes
    }

    fn outstanding_row_loans(&self, role: NativeFinishingFileRoleV1) -> Vec<NativeTableRowLoan> {
        if self.state == NativeFinishingStateV1::Settled
            || role != NativeFinishingFileRoleV1::Native
        {
            return Vec::new();
        }
        let mut loans: Vec<_> = self
            .liabilities
            .iter()
            .filter(|liability| liability.disposition == NativeFinishingDispositionV1::Outstanding)
            .flat_map(|liability| liability.row_loans.iter().cloned())
            .collect();
        for _ in 0..self.transitions.remaining {
            loans.extend(self.transitions.row_loans.iter().cloned());
        }
        loans
    }

    /// The retained width recipes still owed on one registered file.
    fn outstanding_width_recipes(
        &self,
        role: NativeFinishingFileRoleV1,
    ) -> Vec<NativeFinishingWidthRecipeV1> {
        if self.state == NativeFinishingStateV1::Settled {
            return Vec::new();
        }
        self.liabilities
            .iter()
            .filter(|liability| {
                liability.disposition == NativeFinishingDispositionV1::Outstanding
                    && liability.purpose.file_role() == role
            })
            .filter_map(|liability| liability.width_recipe.clone())
            .collect()
    }

    /// Exactly one monotone step from this version, spending one transition.
    fn require_successor(&self, next: &Self) -> Result<(), AdmissionOperationStoreError> {
        if next.schema != self.schema
            || self.revision.checked_add(1) != Some(next.revision)
            || next.identity != self.identity
            || next.liabilities.len() != self.liabilities.len()
            || next.transitions.profile_digest != self.transitions.profile_digest
            || next.transitions.per_transition != self.transitions.per_transition
            || next.transitions.page_recipe != self.transitions.page_recipe
            || next.transitions.row_loans != self.transitions.row_loans
            || self.transitions.remaining.checked_sub(1) != Some(next.transitions.remaining)
        {
            return Err(invariant(
                "native finishing account changed its original identity",
            ));
        }
        let mut consumed = 0_usize;
        let mut released = 0_usize;
        for (before, after) in self.liabilities.iter().zip(&next.liabilities) {
            if before.purpose != after.purpose
                || before.profile_digest != after.profile_digest
                || before.liability != after.liability
                || before.page_recipe != after.page_recipe
                || before.width_recipe != after.width_recipe
                || before.wal_frames != after.wal_frames
                || before.row_loans != after.row_loans
            {
                return Err(invariant("native finishing account repriced a purpose"));
            }
            match (before.disposition, after.disposition) {
                (left, right) if left == right => (),
                (
                    NativeFinishingDispositionV1::Outstanding,
                    NativeFinishingDispositionV1::Consumed,
                ) => consumed += 1,
                (
                    NativeFinishingDispositionV1::Outstanding,
                    NativeFinishingDispositionV1::Released,
                ) => released += 1,
                _ => {
                    return Err(invariant(
                        "native finishing purpose cannot leave its final disposition",
                    ))
                }
            }
        }
        let enrollment_unchanged = next.process_enrollment == self.process_enrollment;
        let step = match (self.state, next.state) {
            (NativeFinishingStateV1::Prepared, NativeFinishingStateV1::Confirmed) => {
                consumed == 0
                    && released == 0
                    && self.process_enrollment.is_none()
                    && next.process_enrollment.is_some() == self.identity.process.is_some()
            }
            (NativeFinishingStateV1::Confirmed, NativeFinishingStateV1::Confirmed) => {
                consumed == 1 && released == 0 && enrollment_unchanged
            }
            (
                NativeFinishingStateV1::Prepared | NativeFinishingStateV1::Confirmed,
                NativeFinishingStateV1::Settled,
            ) => consumed == 0 && enrollment_unchanged,
            _ => false,
        };
        if !step {
            return Err(invariant(
                "native finishing account transition is not one monotone step",
            ));
        }
        Ok(())
    }

    /// The first Prepared version of a complete priced roster.
    pub(in crate::admission_operation_store) fn prepared(
        identity: NativeFinishingIdentityV1,
        liabilities: Vec<NativeFinishingLiabilityV1>,
        transitions: NativeFinishingTransitionAllowanceV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let account = Self {
            schema: ACCOUNT_SCHEMA.to_owned(),
            revision: 1,
            state: NativeFinishingStateV1::Prepared,
            identity,
            liabilities,
            transitions,
            process_enrollment: None,
        };
        account.validate()?;
        Ok(account)
    }

    /// The Confirmed successor that consumes exactly one outstanding purpose.
    /// A finalization is matched by its single-use slot, never by a caller's
    /// prefix, so a different prefix cannot open a second prepaid write.
    pub(in crate::admission_operation_store) fn consuming(
        &self,
        purpose: NativeFinishingPurposeV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if self.state != NativeFinishingStateV1::Confirmed {
            return Err(invariant(
                "native finishing purpose requires a Confirmed account",
            ));
        }
        let mut next = self.successor()?;
        let liability = next
            .liabilities
            .iter_mut()
            .find(|liability| liability.purpose.slot() == purpose.slot())
            .ok_or_else(|| invariant("native finishing purpose was not prepaid"))?;
        if liability.disposition != NativeFinishingDispositionV1::Outstanding {
            return Err(invariant("native finishing purpose was already spent"));
        }
        liability.disposition = NativeFinishingDispositionV1::Consumed;
        Ok(next)
    }

    /// The terminal successor releasing every outstanding purpose.
    pub(in crate::admission_operation_store) fn settling(
        &self,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let mut next = self.successor()?;
        next.state = NativeFinishingStateV1::Settled;
        for liability in &mut next.liabilities {
            if liability.disposition == NativeFinishingDispositionV1::Outstanding {
                liability.disposition = NativeFinishingDispositionV1::Released;
            }
        }
        Ok(next)
    }

    /// The Confirmed successor publishing the authenticated producer roster.
    pub(in crate::admission_operation_store) fn confirming(
        &self,
        enrollment: Option<NativeFinishingProcessEnrollmentV1>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if self.state != NativeFinishingStateV1::Prepared {
            return Err(invariant("native finishing account is not Prepared"));
        }
        let mut next = self.successor()?;
        next.state = NativeFinishingStateV1::Confirmed;
        next.process_enrollment = enrollment;
        Ok(next)
    }

    fn successor(&self) -> Result<Self, AdmissionOperationStoreError> {
        let mut next = self.clone();
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| invariant("native finishing account revision exhausted"))?;
        next.transitions.remaining = self
            .transitions
            .remaining
            .checked_sub(1)
            .ok_or_else(|| invariant("native finishing transition allowance exhausted"))?;
        Ok(next)
    }

    /// The still outstanding liability in `purpose`'s single-use slot.
    pub(in crate::admission_operation_store) fn outstanding_in_slot(
        &self,
        purpose: NativeFinishingPurposeV1,
    ) -> Option<&NativeFinishingLiabilityV1> {
        self.liabilities.iter().find(|liability| {
            liability.purpose.slot() == purpose.slot()
                && liability.disposition == NativeFinishingDispositionV1::Outstanding
        })
    }

    pub(in crate::admission_operation_store) fn liability(
        &self,
        purpose: NativeFinishingPurposeV1,
    ) -> Option<&NativeFinishingLiabilityV1> {
        self.liabilities
            .iter()
            .find(|liability| liability.purpose == purpose)
    }
}

/// The widest record any version of an account with this immutable identity,
/// roster and transition loans can encode to. Between versions only the
/// revision, state, dispositions, transition price, count and page recipe,
/// the purposes' page recipes and the Process enrollment change; each is taken
/// at its widest encoding (every integer at `u64::MAX`, the longest state and
/// disposition, every recipe and the selected enrollment present). It is not
/// capped: an older account's hypothetical widest encoding may exceed the cap.
fn native_finishing_account_encoded_maximum(
    identity: &NativeFinishingIdentityV1,
    liabilities: &[NativeFinishingLiabilityV1],
    transition_row_loans: &[NativeTableRowLoan],
) -> Result<u64, AdmissionOperationStoreError> {
    let widest_recipe = NativeFinishingPageRecipeV1 {
        page_bucket: u64::MAX,
        page_growth: u64::MAX,
    };
    let widest_digest = "0".repeat(64);
    let widest = NativeFinishingAccountV1 {
        schema: ACCOUNT_SCHEMA.to_owned(),
        revision: u64::MAX,
        state: NativeFinishingStateV1::Confirmed,
        identity: identity.clone(),
        liabilities: liabilities
            .iter()
            .cloned()
            .map(|mut liability| {
                liability.disposition = NativeFinishingDispositionV1::Outstanding;
                if liability.page_recipe.is_some()
                    || liability.purpose.file_role() == NativeFinishingFileRoleV1::Native
                {
                    liability.page_recipe = Some(widest_recipe);
                }
                liability
            })
            .collect(),
        transitions: NativeFinishingTransitionAllowanceV1 {
            profile_digest: widest_digest.clone(),
            per_transition: PhysicalLiabilityData::saturated(),
            remaining: u64::MAX,
            page_recipe: Some(widest_recipe),
            row_loans: transition_row_loans.to_vec(),
        },
        process_enrollment: identity
            .process
            .as_ref()
            .map(|_| NativeFinishingProcessEnrollmentV1 {
                account_digest: widest_digest.clone(),
                event_sequence: u64::MAX,
                event_digest: widest_digest.clone(),
            }),
    };
    u64::try_from(encode(&widest)?.len())
        .map_err(|_| invariant("native finishing account bound exhausted"))
}

/// The bound a new account's transitions are priced at: its widest version
/// must fit the record cap, or the original cannot be prepared at all.
pub(in crate::admission_operation_store) fn native_finishing_account_bound(
    identity: &NativeFinishingIdentityV1,
    liabilities: &[NativeFinishingLiabilityV1],
    transition_row_loans: &[NativeTableRowLoan],
) -> Result<u64, AdmissionOperationStoreError> {
    let bytes =
        native_finishing_account_encoded_maximum(identity, liabilities, transition_row_loans)?;
    if bytes > NATIVE_FINISHING_ACCOUNT_MAX_BYTES {
        return Err(invariant(
            "native finishing account exceeds its record bound",
        ));
    }
    Ok(bytes)
}

/// The bound every later version of a retained account is written within.
/// An account priced at its widest encoding keeps that bound; one retained
/// from before that sizing was priced at the record cap and keeps the cap.
/// The smaller of the two covers both, so no supported successor gains a
/// refusal its retained price already funds.
fn native_finishing_successor_bound(
    account: &NativeFinishingAccountV1,
) -> Result<u64, AdmissionOperationStoreError> {
    Ok(native_finishing_account_encoded_maximum(
        &account.identity,
        &account.liabilities,
        &account.transitions.row_loans,
    )?
    .min(NATIVE_FINISHING_ACCOUNT_MAX_BYTES))
}

/// The smallest retained row ceiling per table across every loan this account
/// publishes. The bank enforces the smallest ceiling of every outstanding loan,
/// so each value bounds its table's rows from this account's publication on.
fn account_row_ceilings(
    account: &NativeFinishingAccountV1,
) -> std::collections::BTreeMap<String, u64> {
    let mut ceilings = std::collections::BTreeMap::<String, u64>::new();
    for loan in account
        .liabilities
        .iter()
        .flat_map(|liability| liability.row_loans.iter())
        .chain(account.transitions.row_loans.iter())
    {
        ceilings
            .entry(loan.table.clone())
            .and_modify(|ceiling| *ceiling = (*ceiling).min(loan.ceiling))
            .or_insert(loan.ceiling);
    }
    ceilings
}

/// Exact current account with its protected record version.
pub(in crate::admission_operation_store) struct RetainedNativeFinishingAccount {
    pub(in crate::admission_operation_store) account: NativeFinishingAccountV1,
    pub(in crate::admission_operation_store) version: u64,
}

pub(in crate::admission_operation_store) fn native_finishing_account_key(
    operation_id: &str,
) -> String {
    format!("{NATIVE_FINISHING_ACCOUNT_PREFIX}{operation_id}")
}

pub(in crate::admission_operation_store) fn native_finishing_bank_key(store_uuid: &str) -> String {
    format!("{NATIVE_FINISHING_BANK_PREFIX}{store_uuid}")
}

fn native_finishing_source_key(source_digest: &str) -> String {
    format!("{NATIVE_FINISHING_SOURCE_PREFIX}{source_digest}")
}

/// The account a Process source enrolled, by the source's exact digest.
pub(in crate::admission_operation_store) fn load_native_finishing_account_for_source(
    tx: &Connection,
    source_digest: &str,
) -> Result<Option<RetainedNativeFinishingAccount>, AdmissionOperationStoreError> {
    require_lower_digest(source_digest)?;
    let Some(row) = raw_checked(tx, &native_finishing_source_key(source_digest))? else {
        return Ok(None);
    };
    let alias: NativeFinishingSourceAliasV1 = decode(&row.payload)?;
    let retained = load_native_finishing_account(tx, &alias.operation_id)?
        .ok_or_else(|| invariant("native finishing source alias lost its account"))?;
    if row.kind != "command"
        || row.version != 1
        || alias.schema != SOURCE_ALIAS_SCHEMA
        || row.scope != retained.account.identity.flow_scope_digest
        || retained
            .account
            .identity
            .process
            .as_ref()
            .map(|process| process.source_digest.as_str())
            != Some(source_digest)
    {
        return Err(invariant("native finishing source alias is not canonical"));
    }
    Ok(Some(retained))
}

pub(in crate::admission_operation_store) fn native_finishing_bank_scope(
    store_uuid: &str,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode(&(
        "chio.native-finishing-bank-scope.v1",
        store_uuid,
    ))?))
}

/// Flow scope binds the account to its tenant, principal, lineage, session
/// and isolation epoch under the native authority.
pub(in crate::admission_operation_store) fn native_finishing_flow_scope(
    authority: &str,
    key: &chio_security_types::ports::FlowStateKey,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode(&(
        "chio.native-finishing-account-scope.v1",
        authority,
        key,
    ))?))
}

pub(in crate::admission_operation_store) fn load_native_finishing_account(
    tx: &Connection,
    operation_id: &str,
) -> Result<Option<RetainedNativeFinishingAccount>, AdmissionOperationStoreError> {
    let key = native_finishing_account_key(operation_id);
    let Some(row) = raw_checked(tx, &key)? else {
        return Ok(None);
    };
    let account: NativeFinishingAccountV1 = decode(&row.payload)?;
    account.validate()?;
    if row.kind != "command"
        || account.identity.operation_id != operation_id
        || row.scope != account.identity.flow_scope_digest
        || row.version != account.revision
    {
        return Err(invariant(
            "native finishing account lost its protected coordinates",
        ));
    }
    verify_prepared_fence(tx, &account.identity)?;
    Ok(Some(RetainedNativeFinishingAccount {
        account,
        version: row.version,
    }))
}

/// The version-1 global commit must have been written by the exact store
/// owner fence the account froze. Later owners keep that historical identity.
fn verify_prepared_fence(
    tx: &Connection,
    identity: &NativeFinishingIdentityV1,
) -> Result<(), AdmissionOperationStoreError> {
    let key = native_finishing_account_key(&identity.operation_id);
    let fence: Option<(String, Option<String>, i64)> = tx
        .query_row(
            "SELECT store_uuid,store_lease_id,store_owner_epoch FROM main.authority_global_commits
             WHERE projection_kind='recovery' AND projection_key=?1 AND projection_sequence=1",
            [&key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let (store_uuid, lease_id, epoch) =
        fence.ok_or_else(|| invariant("native finishing account lost its Prepared commit"))?;
    if store_uuid != identity.store_uuid
        || lease_id.as_deref() != Some(identity.store_lease_id.as_str())
        || stored_u64(epoch, "native finishing Prepared epoch")? != identity.store_owner_epoch
    {
        return Err(invariant(
            "native finishing account was not Prepared by its frozen owner",
        ));
    }
    Ok(())
}

/// Publish the before-effect Prepared account and add its liabilities to the
/// bank inside the intake band. Every outstanding account must still fit
/// inside the settlement reserve after this account is added.
pub(in crate::admission_operation_store) fn persist_prepared_native_finishing_account(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    account: &NativeFinishingAccountV1,
) -> Result<ProcessNativeAccountPublicationDataV1, AdmissionOperationStoreError> {
    account.validate()?;
    let identity = &account.identity;
    if account.state != NativeFinishingStateV1::Prepared
        || identity.store_uuid != owner.fence.store_uuid
        || identity.store_lease_id != owner.fence.lease_id
        || identity.store_owner_epoch != owner.fence.owner_epoch
    {
        return Err(invariant(
            "native finishing account is not a fresh Prepared under the actual fence",
        ));
    }
    let key = native_finishing_account_key(&identity.operation_id);
    if raw_checked(tx, &key)?.is_some() {
        return Err(invariant("native finishing account already exists"));
    }
    let mut bank = load_bank(tx, &owner.fence.store_uuid)?;
    bank.outstanding_accounts = bank
        .outstanding_accounts
        .checked_add(1)
        .filter(|count| *count <= MAX_OUTSTANDING_ACCOUNTS)
        .ok_or_else(|| invariant("native finishing bank account capacity exhausted"))?;
    bank.apply(None, Some(account))?;
    let payload = bounded(
        account,
        native_finishing_account_bound(
            &account.identity,
            &account.liabilities,
            &account.transitions.row_loans,
        )?,
    )?;
    let alias = if let Some(process) = &identity.process {
        Some((
            native_finishing_source_key(&process.source_digest),
            encode(&NativeFinishingSourceAliasV1 {
                schema: SOURCE_ALIAS_SCHEMA.to_owned(),
                operation_id: identity.operation_id.clone(),
            })?,
        ))
    } else {
        None
    };
    // Price this writer before changing its source cut. Prepared is ordinary
    // intake and pays for the account, source alias and bank publication as
    // well as retaining every future purpose. Its own WAL is not future debt.
    let mut publication = ProtectedCommandLiabilityPlan::new();
    publication.add_new_command(
        tx,
        &key,
        &identity.flow_scope_digest,
        u64::try_from(payload.len()).map_err(|error| invariant(error.to_string()))?,
    )?;
    if let Some((key, bytes)) = &alias {
        publication.add_new_command(
            tx,
            key,
            &identity.flow_scope_digest,
            u64::try_from(bytes.len()).map_err(|error| invariant(error.to_string()))?,
        )?;
    }
    let bank_key = native_finishing_bank_key(&bank.store_uuid);
    let bank_scope = native_finishing_bank_scope(&bank.store_uuid)?;
    if raw_checked(tx, &bank_key)?.is_some() {
        publication.add_owned_rewrite(
            tx,
            &bank_key,
            &bank_scope,
            NATIVE_FINISHING_BANK_MAX_BYTES,
        )?;
    } else {
        publication.add_new_command(tx, &bank_key, &bank_scope, NATIVE_FINISHING_BANK_MAX_BYTES)?;
    }
    // This transaction publishes the account's row loans with the bank, and
    // the committing bank enforces their ceilings on every history tree the
    // publication writes before its COMMIT. The account's own loans therefore
    // bound those trees' cursor depth exactly as they bound its later writers.
    let liability =
        price_protected_command_with_row_limits(tx, &publication, &account_row_ceilings(account))?;
    let frame = physical_command_write_profile(tx)?.page_size() + 24;
    let publication_price = AuthorityCurrentWritePrice {
        wal_bytes: liability.wal_bytes(),
        disk_bytes: liability.disk_bytes(),
        // Every allocated page is included in the complete dirty-frame bound.
        growth_pages: liability.wal_bytes() / frame + 1,
    };
    persist_record(
        tx,
        owner,
        &key,
        &identity.flow_scope_digest,
        "command",
        &payload,
        None,
    )?;
    if let Some((key, bytes)) = &alias {
        persist_record(
            tx,
            owner,
            key,
            &identity.flow_scope_digest,
            "command",
            bytes,
            None,
        )?;
    }
    persist_bank(tx, owner, &bank)?;
    // Intake admits the account only while every outstanding debt, now
    // including this account's complete roster, keeps its floors.
    #[cfg(feature = "admission-test-support")]
    {
        for liability in &account.liabilities {
            eprintln!(
                "native prepared purpose={:?} wal={} disk={}",
                liability.purpose,
                liability.liability.wal_bytes(),
                liability.liability.disk_bytes(),
            );
        }
        eprintln!(
            "native prepared transition wal={} remaining={}",
            account.transitions.per_transition.wal_bytes(),
            account.transitions.remaining,
        );
    }
    // No frame can spill before COMMIT. Recheck the complete current price
    // against the newly published bank, not just the observer's predecessor.
    owner
        .authorize_current_write(tx, &publication_price)
        .map_err(|error| invariant(error.to_string()))?;
    check_intake_committing(tx)?;
    native_finishing_publication(tx, identity)
}

/// Persist exactly one monotone successor of the retained version. The
/// write spends one unit of the account's own priced transition allowance.
pub(in crate::admission_operation_store) fn persist_native_finishing_transition(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    retained: &RetainedNativeFinishingAccount,
    next: &NativeFinishingAccountV1,
) -> Result<(), AdmissionOperationStoreError> {
    next.validate()?;
    retained.account.require_successor(next)?;
    let current = load_native_finishing_account(tx, &next.identity.operation_id)?
        .ok_or_else(|| invariant("native finishing account disappeared"))?;
    if current.version != retained.version
        || current.account != retained.account
        || next.identity.store_uuid != owner.fence.store_uuid
    {
        return Err(invariant(
            "native finishing account changed before its transition",
        ));
    }
    let mut bank = load_bank(tx, &owner.fence.store_uuid)?;
    bank.apply(Some(&retained.account), Some(next))?;
    if next.state == NativeFinishingStateV1::Settled {
        bank.outstanding_accounts = bank
            .outstanding_accounts
            .checked_sub(1)
            .ok_or_else(|| invariant("native finishing bank lost an account"))?;
    }
    let identity = format!(
        "{}:transition:{}",
        next.identity.operation_id, next.revision
    );
    owner
        .native_capacity()
        .authorize_table_rows(&identity, &retained.account.transitions.row_loans)
        .map_err(invariant)?;
    if let Some(recipe) = retained.account.transitions.page_recipe {
        owner
            .native_capacity()
            .authorize_funded_growth(tx, &identity, recipe.page_growth)
            .map_err(invariant)?;
    }
    persist_record(
        tx,
        owner,
        &native_finishing_account_key(&next.identity.operation_id),
        &next.identity.flow_scope_digest,
        "command",
        &bounded(next, native_finishing_successor_bound(next)?)?,
        None,
    )?;
    persist_bank(tx, owner, &bank)?;
    // This transition spends one priced account write and, when consuming,
    // its purpose's own native write in the same transaction.
    let mut spent = retained.account.transitions.per_transition.clone();
    for (before, after) in retained.account.liabilities.iter().zip(&next.liabilities) {
        if before.disposition == NativeFinishingDispositionV1::Outstanding
            && after.disposition == NativeFinishingDispositionV1::Consumed
            && after.purpose.file_role() == NativeFinishingFileRoleV1::Native
        {
            spent = spent.checked_add(&after.liability)?;
        }
    }
    check_funded_committing(tx, &spent)?;
    // This transaction's COMMIT is checked against the amount it spent.
    owner
        .native_capacity()
        .spend(spent.wal_bytes(), spent.disk_bytes())
        .map_err(invariant)
}

/// The authenticated version-1 publication of one account.
pub(in crate::admission_operation_store) fn native_finishing_publication(
    tx: &Connection,
    identity: &NativeFinishingIdentityV1,
) -> Result<ProcessNativeAccountPublicationDataV1, AdmissionOperationStoreError> {
    let key = native_finishing_account_key(&identity.operation_id);
    let (record_digest, global_commit_sequence) = historical_record_reference(tx, &key, 1)?;
    let event: i64 = tx
        .query_row(
            "SELECT sequence FROM main.admission_operation_recovery_events
             WHERE record_key=?1 AND record_version=1",
            [&key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let publication = ProcessNativeAccountPublicationDataV1 {
        schema: PUBLICATION_SCHEMA.to_owned(),
        record_key: key,
        scope_key: identity.flow_scope_digest.clone(),
        record_kind: "command".to_owned(),
        record_version: 1,
        record_digest,
        event_sequence: stored_u64(event, "native finishing publication event")?,
        global_commit_sequence,
        original_source_cut: identity.source_cut,
        authority_global_sequence_domain: NativeReturnSequenceDomainDataV1::AuthorityGlobalCommit,
    };
    publication.validate()?;
    Ok(publication)
}

/// The global commit of one exact account version.
pub(in crate::admission_operation_store) fn native_finishing_version_commit(
    tx: &Connection,
    operation_id: &str,
    version: u64,
) -> Result<(String, u64), AdmissionOperationStoreError> {
    historical_record_reference(tx, &native_finishing_account_key(operation_id), version)
}

/// Current bank coordinates for one registered file: the bank head's global
/// commit (epoch), its record digest (frontier) and that file's reserve.
pub(in crate::admission_operation_store) fn native_finishing_bank_readback(
    tx: &Connection,
    store_uuid: &str,
    file: &NativeFinishingFileV1,
) -> Result<(u64, String, PhysicalLiabilityData), AdmissionOperationStoreError> {
    let key = native_finishing_bank_key(store_uuid);
    let row =
        raw_checked(tx, &key)?.ok_or_else(|| invariant("native finishing bank is not open"))?;
    let bank = load_bank(tx, store_uuid)?;
    let (digest, commit) = historical_record_reference(tx, &key, row.version)?;
    let reserved = bank
        .files
        .iter()
        .find(|entry| entry.file == *file)
        .map_or_else(PhysicalLiabilityData::zero, |entry| {
            entry.outstanding.clone()
        });
    Ok((commit, digest, reserved))
}

/// Outstanding debt every writer of the native authority file must preserve:
/// its own file's debt and each other registered file on the same volume.
pub(in crate::admission_operation_store) struct NativeFinishingFileDebt {
    pub(in crate::admission_operation_store) this_file: PhysicalLiabilityData,
    pub(in crate::admission_operation_store) other_files: Vec<PhysicalLiabilityData>,
}

/// Read the bank head of the connection's own store. The native authority
/// file keeps its debt across relocation; Process and receipt files count only
/// while they share the authority file's current volume.
pub(in crate::admission_operation_store) fn native_finishing_debt_for_file(
    connection: &Connection,
) -> Result<Option<NativeFinishingFileDebt>, AdmissionOperationStoreError> {
    let Some((_, bank)) = authenticated_authority_bank(connection, None)? else {
        return Ok(None);
    };
    if bank.files.is_empty() {
        return Ok(None);
    }
    let device = chio_sqlite_file_identity::main_database_file_identity(connection)
        .map_err(|error| invariant(error.to_string()))?
        .device;
    let mut this_file = PhysicalLiabilityData::zero();
    let mut other_files = Vec::new();
    for entry in &bank.files {
        if entry.file.role == NativeFinishingFileRoleV1::Native {
            this_file = this_file.checked_add(&entry.outstanding)?;
        } else if entry.file.device == device {
            other_files.push(entry.outstanding.clone());
        }
    }
    Ok(Some(NativeFinishingFileDebt {
        this_file,
        other_files,
    }))
}

/// The latest admission schema without the native finishing family.
const NATIVE_FINISHING_PREDECESSOR_SCHEMA: i64 = 34;

/// The native finishing bank of an authority file, authenticated from the
/// file's own admission schema and serving owner. A pristine file before its
/// admission schema and a supported predecessor at or below version 34
/// positively owe nothing. Current data carries its bank head, or an empty
/// account namespace proving the bank was never opened. A lost bank family,
/// an unsupported version or another serving owner refuses.
pub(in crate::admission_operation_store) fn authenticated_authority_bank(
    connection: &Connection,
    expected_owner: Option<&str>,
) -> Result<Option<(String, NativeFinishingBankV1)>, AdmissionOperationStoreError> {
    let table = |name: &str| -> Result<bool, AdmissionOperationStoreError> {
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name=?1)",
                [name],
                |row| row.get(0),
            )
            .map_err(sqlite_error)
    };
    let version: Option<i64> = if table("chio_store_schema_versions")? {
        connection
            .query_row(
                "SELECT version FROM main.chio_store_schema_versions
                 WHERE store_key='admission_operation'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?
    } else {
        None
    };
    let namespace_used = |connection: &Connection| -> Result<bool, AdmissionOperationStoreError> {
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.admission_operation_recovery_records
                 WHERE record_key >= ?1 AND record_key < ?2)",
                params![
                    NATIVE_FINISHING_NAMESPACE_START,
                    NATIVE_FINISHING_NAMESPACE_END
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)
    };
    match version {
        None if !table("admission_operations")? => return Ok(None),
        None => {
            return Err(invariant(
                "native authority lost its admission schema version",
            ))
        }
        Some(version) if version <= NATIVE_FINISHING_PREDECESSOR_SCHEMA => {
            if table("admission_operation_recovery_records")? && namespace_used(connection)? {
                return Err(invariant(
                    "native finishing records exist on predecessor admission data",
                ));
            }
            return Ok(None);
        }
        Some(version)
            if version
                == i64::from(
                    crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
                ) => {}
        Some(_) => {
            return Err(invariant(
                "native authority admission schema is unsupported",
            ))
        }
    }
    let owner: String = connection
        .query_row(
            "SELECT store_uuid FROM main.chio_serving_owner WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if expected_owner.is_some_and(|expected| expected != owner) {
        return Err(invariant(
            "native finishing bank belongs to another serving owner",
        ));
    }
    if raw_checked(connection, &native_finishing_bank_key(&owner))?.is_some() {
        let bank = load_bank(connection, &owner)?;
        return Ok(Some((owner, bank)));
    }
    if namespace_used(connection)? {
        return Err(invariant("native finishing accounts lost their bank"));
    }
    Ok(None)
}

/// The priced current write of one ordinary authority transaction: the WAL,
/// disk and page growth of its complete write shape under the held
/// transaction's verified physical profile. Only
/// the verified whole-shape or protected-command producer constructs it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityCurrentWritePrice {
    wal_bytes: u64,
    disk_bytes: u64,
    growth_pages: u64,
}

impl AuthorityCurrentWritePrice {
    pub(crate) fn wal_bytes(&self) -> u64 {
        self.wal_bytes
    }

    pub(crate) fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    pub(crate) fn growth_pages(&self) -> u64 {
        self.growth_pages
    }
}

/// Price an ordinary writer's whole transaction on its held authority
/// transaction: every table, index, trigger and global-history tree the
/// transaction writes must be in `shape`. The profile check binds the price to
/// this file's source, page geometry, spill-free WAL and command catalog.
pub(crate) fn authority_current_write_price(
    tx: &Connection,
    shape: &chio_sqlite_file_identity::SqliteTransactionWriteShapeData,
) -> Result<AuthorityCurrentWritePrice, AdmissionOperationStoreError> {
    let frames = authority_current_write_profile(tx)?;
    let priced = shape.price_without_spill(&frames).map_err(invariant)?;
    Ok(AuthorityCurrentWritePrice {
        wal_bytes: priced.wal_bytes(),
        disk_bytes: priced.disk_bytes(),
        growth_pages: shape.maximum_page_growth(&frames).map_err(invariant)?,
    })
}

/// Authenticate the real serving writer before any mutation. A read-only
/// COMMIT observer cannot establish the serving connection's spill settings.
pub(crate) fn authority_current_write_profile(
    tx: &Connection,
) -> Result<chio_sqlite_file_identity::SqliteFramePriceProfileData, AdmissionOperationStoreError> {
    let profile = physical_command_write_profile(tx)?;
    chio_sqlite_file_identity::SqliteFramePriceProfileData::checked(profile.page_size(), 0)
        .map_err(invariant)
}

/// Pages the native authority file's outstanding loans may still add and the
/// smallest page ceiling any of them retains.
pub(crate) struct NativeAuthorityPageDebtData {
    pub(crate) owed_pages: u64,
    pub(crate) page_ceiling: Option<u64>,
}

/// The authenticated page budget of the native authority file: every
/// outstanding recipe on a native-file purpose of every unsettled account.
pub(crate) fn native_authority_file_page_debt(
    connection: &Connection,
    store_uuid: &str,
) -> Result<NativeAuthorityPageDebtData, AdmissionOperationStoreError> {
    let mut debt = NativeAuthorityPageDebtData {
        owed_pages: 0,
        page_ceiling: None,
    };
    let Some((_, bank)) = authenticated_authority_bank(connection, Some(store_uuid))? else {
        return Ok(debt);
    };
    for entry in bank
        .files
        .iter()
        .filter(|entry| entry.file.role == NativeFinishingFileRoleV1::Native)
    {
        debt.owed_pages = debt
            .owed_pages
            .checked_add(entry.owed_pages)
            .ok_or_else(|| invariant("native authority page budget overflow"))?;
        if let Some(bucket) = entry.page_buckets.first() {
            debt.page_ceiling = Some(debt.page_ceiling.map_or(bucket.page_bucket, |ceiling| {
                ceiling.min(bucket.page_bucket)
            }));
        }
    }
    Ok(debt)
}

/// Every outstanding debt a writer of the native authority file preserves:
/// its own disk debt, every other registered file's disk debt on its volume,
/// and its page budget.
pub(crate) struct NativeAuthorityDebtData {
    pub(crate) this_file: chio_sqlite_file_identity::SqlitePhysicalDebtAmountData,
    pub(crate) other_files: Vec<chio_sqlite_file_identity::SqlitePhysicalDebtAmountData>,
    pub(crate) pages: NativeAuthorityPageDebtData,
}

/// The authenticated debt of the authority file on `device`.
pub(crate) fn native_authority_debt(
    connection: &Connection,
    store_uuid: &str,
    device: u64,
) -> Result<NativeAuthorityDebtData, AdmissionOperationStoreError> {
    let amount = |liability: &PhysicalLiabilityData| {
        chio_sqlite_file_identity::SqlitePhysicalDebtAmountData::checked(
            liability.wal_bytes(),
            liability.disk_bytes(),
        )
        .map_err(invariant)
    };
    let pages = native_authority_file_page_debt(connection, store_uuid)?;
    let Some((_, bank)) = authenticated_authority_bank(connection, Some(store_uuid))? else {
        return Ok(NativeAuthorityDebtData {
            this_file: amount(&PhysicalLiabilityData::zero())?,
            other_files: Vec::new(),
            pages,
        });
    };
    let mut this_file = PhysicalLiabilityData::zero();
    let mut other_files = Vec::new();
    for entry in &bank.files {
        if entry.file.role == NativeFinishingFileRoleV1::Native {
            this_file = this_file.checked_add(&entry.outstanding)?;
        } else if entry.file.device == device {
            other_files.push(amount(&entry.outstanding)?);
        }
    }
    Ok(NativeAuthorityDebtData {
        this_file: amount(&this_file)?,
        other_files,
        pages,
    })
}

/// Outstanding native debt one registered receipt or Process file preserves:
/// its own reserve and every other bank file on the same volume.
pub(crate) struct NativeRegisteredFileDebtData {
    pub(crate) this_file: chio_sqlite_file_identity::SqlitePhysicalDebtAmountData,
    pub(crate) other_files: Vec<chio_sqlite_file_identity::SqlitePhysicalDebtAmountData>,
    /// Pages the file's outstanding receipt loans may still add.
    pub(crate) owed_pages: u64,
    /// The smallest outstanding page ceiling on this file, if any loan owes one.
    pub(crate) page_ceiling: Option<u64>,
}

/// Read the bank head of `store_uuid` for the registered file `(device,
/// inode)`. The authority file must still be served by that owner; a bank the
/// owner never opened owes nothing on any registered file.
pub(crate) fn native_registered_file_debt(
    connection: &Connection,
    store_uuid: &str,
    device: u64,
    inode: u64,
) -> Result<Option<NativeRegisteredFileDebtData>, AdmissionOperationStoreError> {
    let owner: String = connection
        .query_row(
            "SELECT store_uuid FROM main.chio_serving_owner WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if owner != store_uuid {
        return Err(invariant(
            "native finishing bank belongs to another serving owner",
        ));
    }
    // Only an authenticated absence owes nothing: a lost bank with retained
    // accounts, or an unsupported admission schema, refuses.
    let Some((_, bank)) = authenticated_authority_bank(connection, Some(store_uuid))? else {
        return Ok(None);
    };
    if bank.files.is_empty() {
        return Ok(None);
    }
    let amount = |liability: &PhysicalLiabilityData| {
        chio_sqlite_file_identity::SqlitePhysicalDebtAmountData::checked(
            liability.wal_bytes(),
            liability.disk_bytes(),
        )
        .map_err(invariant)
    };
    let mut this_file = PhysicalLiabilityData::zero();
    let mut other_files = Vec::new();
    let mut owed_pages = 0_u64;
    let mut page_ceiling: Option<u64> = None;
    for entry in &bank.files {
        let same_file = entry.file.role != NativeFinishingFileRoleV1::Native
            && entry.file.device == device
            && entry.file.inode == inode;
        if same_file {
            this_file = this_file.checked_add(&entry.outstanding)?;
            owed_pages = owed_pages
                .checked_add(entry.owed_pages)
                .ok_or_else(|| invariant("native finishing page budget overflow"))?;
            if let Some(bucket) = entry.page_buckets.first() {
                page_ceiling = Some(page_ceiling.map_or(bucket.page_bucket, |ceiling| {
                    ceiling.min(bucket.page_bucket)
                }));
            }
        } else if entry.file.device == device {
            other_files.push(amount(&entry.outstanding)?);
        }
    }
    Ok(Some(NativeRegisteredFileDebtData {
        this_file: amount(&this_file)?,
        other_files,
        owed_pages,
        page_ceiling,
    }))
}

/// The native bank readback of one actual Process file inventory, read under
/// the held native mutation sequencer. The whole account inverse is first
/// authenticated against the bank head. This journal's enrolled accounts must
/// be exactly the Process accounts the inventory retains, on exactly its file,
/// so an omitted, replaced or torn journal with retained lending refuses. A
/// file no account ever lent to owes a measured zero. The epoch and frontier
/// are the bank head's own global commit, or the authority's global head
/// before any bank exists.
pub(in crate::admission_operation_store) fn process_return_bank_readback(
    tx: &Connection,
    store_uuid: &str,
    inventory: &ProcessReturnInventoryDataV1,
) -> Result<ProcessReturnBankReadbackDataV1, AdmissionOperationStoreError> {
    verify_native_finishing_inventory(tx)?;
    let lending = process_file_enrollments(tx, inventory)?;
    let enrolled = lending.enrolled;
    let latest_enrollment = lending.latest_enrollment;
    if enrolled != inventory.account_count
        || latest_enrollment > inventory.history_sequence
        || (enrolled == 0 && (inventory.phase_count != 0 || inventory.history_sequence != 0))
    {
        return Err(invariant(
            "Process inventory differs from its retained native lending",
        ));
    }
    let bank = load_bank(tx, store_uuid)?;
    let mut this_file = PhysicalLiabilityData::zero();
    let mut this_frames = 0_u64;
    let mut other_disk = 0_u64;
    for entry in &bank.files {
        let same_file = entry.file.role == NativeFinishingFileRoleV1::Process
            && entry.file.device == inventory.file_device
            && entry.file.inode == inventory.file_inode;
        if same_file {
            this_file = this_file.checked_add(&entry.outstanding)?;
            this_frames = this_frames
                .checked_add(entry.outstanding_wal_frames)
                .ok_or_else(|| invariant("native finishing frame debt overflow"))?;
        } else if entry.file.device == inventory.file_device {
            other_disk = other_disk
                .checked_add(entry.outstanding.disk_bytes())
                .ok_or_else(|| invariant("native finishing same-volume debt overflow"))?;
        }
    }
    let key = native_finishing_bank_key(store_uuid);
    let (epoch, frontier) = match raw_checked(tx, &key)? {
        Some(row) => {
            let (digest, commit) = historical_record_reference(tx, &key, row.version)?;
            (commit, digest)
        }
        None => authority_global_head(tx)?,
    };
    Ok(ProcessReturnBankReadbackDataV1 {
        schema: PROCESS_RETURN_BANK_READBACK_SCHEMA.to_owned(),
        inventory_digest: sha256_hex(
            &canonical_json_bytes(inventory).map_err(|error| invariant(error.to_string()))?,
        ),
        native_bank_epoch: epoch,
        native_frontier_digest: frontier,
        registered_files_digest: sha256_hex(
            &canonical_json_bytes(&("chio.native-finishing-registered-files.v1", &bank.files))
                .map_err(|error| invariant(error.to_string()))?,
        ),
        same_filesystem_other_disk_bytes: other_disk,
        this_file_reserved_wal_bytes: this_file.wal_bytes(),
        this_file_reserved_disk_bytes: this_file.disk_bytes(),
        this_file_reserved_wal_frames: this_frames,
        current_write_publication: None,
    })
}

/// Authenticated lending to one actual Process file. Unconfirmed accounts
/// remain debt until the actual enrollment inverse and native terminal prove
/// that no producer can still consume their funding.
pub(in crate::admission_operation_store) struct ProcessFileLending {
    pub(in crate::admission_operation_store) enrolled: u64,
    pub(in crate::admission_operation_store) latest_enrollment: u64,
    pub(in crate::admission_operation_store) unconfirmed: Vec<String>,
}

/// Enrolled native accounts of the inventory's journal and their latest
/// enrollment event. Lending to the same journal on another file refuses.
pub(in crate::admission_operation_store) fn process_file_enrollments(
    tx: &Connection,
    inventory: &ProcessReturnInventoryDataV1,
) -> Result<ProcessFileLending, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key >= ?1 AND record_key < ?2 ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            NATIVE_FINISHING_ACCOUNT_PREFIX,
            "native-finishing-account;"
        ])
        .map_err(sqlite_error)?;
    let mut lending = ProcessFileLending {
        enrolled: 0,
        latest_enrollment: 0,
        unconfirmed: Vec::new(),
    };
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let operation = key
            .strip_prefix(NATIVE_FINISHING_ACCOUNT_PREFIX)
            .ok_or_else(|| invariant("native finishing account namespace refused"))?;
        let retained = load_native_finishing_account(tx, operation)?
            .ok_or_else(|| invariant("native finishing account disappeared"))?;
        let Some(member) = &retained.account.identity.process else {
            continue;
        };
        let source = &member.source;
        // Identity is physical first: the same held file may not appear under
        // another journal namespace, authority or key to hide retained
        // lending, and the same journal may not move to another file.
        let same_file = (source.file_device, source.file_inode)
            == (inventory.file_device, inventory.file_inode);
        let same_journal = source.journal_namespace == inventory.journal_namespace
            && source.journal_authority == inventory.journal_authority;
        if same_file != same_journal
            || (same_file && source.kernel_key_digest != inventory.kernel_key_digest)
        {
            return Err(invariant(
                "Process journal differs from its retained native lending",
            ));
        }
        if !same_file {
            continue;
        }
        if let Some(enrollment) = &retained.account.process_enrollment {
            lending.enrolled = lending
                .enrolled
                .checked_add(1)
                .ok_or_else(|| invariant("native finishing enrollment count overflow"))?;
            lending.latest_enrollment = lending.latest_enrollment.max(enrollment.event_sequence);
        } else if retained.account.state == NativeFinishingStateV1::Prepared {
            if !u64::try_from(lending.unconfirmed.len())
                .is_ok_and(|count| count < MAX_OUTSTANDING_ACCOUNTS)
            {
                return Err(invariant(
                    "native unconfirmed accounts exceed the bank bound",
                ));
            }
            lending.unconfirmed.push(operation.to_owned());
        }
    }
    Ok(lending)
}

/// The authority's current global commit head before any bank exists.
fn authority_global_head(tx: &Connection) -> Result<(u64, String), AdmissionOperationStoreError> {
    let (sequence, digest): (i64, String) = tx
        .query_row(
            "SELECT head_sequence,head_chain_digest FROM main.authority_global_commit_meta
             WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    let sequence = stored_u64(sequence, "authority global head")?;
    if sequence == 0 {
        return Err(invariant("authority global head has no commit"));
    }
    require_lower_digest(&digest)?;
    Ok((sequence, digest))
}

/// Unsettled accounts without a Process member, in key order. A
/// Process member settles only after its own reconciliation.
pub(in crate::admission_operation_store) fn unsettled_native_only_accounts(
    tx: &Connection,
) -> Result<Vec<String>, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key >= ?1 AND record_key < ?2 ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            NATIVE_FINISHING_ACCOUNT_PREFIX,
            "native-finishing-account;"
        ])
        .map_err(sqlite_error)?;
    let mut operations = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let operation = key
            .strip_prefix(NATIVE_FINISHING_ACCOUNT_PREFIX)
            .ok_or_else(|| invariant("native finishing account namespace refused"))?;
        let retained = load_native_finishing_account(tx, operation)?
            .ok_or_else(|| invariant("native finishing account disappeared"))?;
        if retained.account.state != NativeFinishingStateV1::Settled
            && retained.account.identity.process.is_none()
        {
            if !u64::try_from(operations.len()).is_ok_and(|count| count < MAX_OUTSTANDING_ACCOUNTS)
            {
                return Err(invariant(
                    "native finishing outstanding accounts exceed the bank bound",
                ));
            }
            operations.push(operation.to_owned());
        }
    }
    Ok(operations)
}

/// Whether `receipt_id` is the terminal receipt of an account whose prepaid
/// ReceiptSink purpose is still outstanding. Until its funded append commits
/// no other writer may name it in a receipt lineage statement.
pub(crate) fn native_receipt_is_owed(
    connection: &Connection,
    receipt_id: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    let operation: Option<String> = connection
        .query_row(
            "SELECT operation_id FROM main.admission_operation_terminal_records
             WHERE record_kind='receipt' AND record_id=?1",
            [receipt_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(operation) = operation else {
        return Ok(false);
    };
    let Some(retained) = load_native_finishing_account(connection, &operation)? else {
        return Ok(false);
    };
    Ok(retained.account.state != NativeFinishingStateV1::Settled
        && retained
            .account
            .liability(NativeFinishingPurposeV1::ReceiptSink)
            .is_some_and(|liability| {
                liability.disposition == NativeFinishingDispositionV1::Outstanding
            }))
}

impl NativeFinishingBankV1 {
    /// Replace one account's outstanding contribution with its successor's.
    fn apply(
        &mut self,
        before: Option<&NativeFinishingAccountV1>,
        after: Option<&NativeFinishingAccountV1>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let account = after
            .or(before)
            .ok_or_else(|| invariant("native finishing bank update has no account"))?;
        for file in &account.identity.files {
            let old = before.map_or(Ok(PhysicalLiabilityData::zero()), |account| {
                account.outstanding_on(file.role)
            })?;
            let new = after.map_or(Ok(PhysicalLiabilityData::zero()), |account| {
                account.outstanding_on(file.role)
            })?;
            let was_open =
                before.is_some_and(|account| account.state != NativeFinishingStateV1::Settled);
            let is_open =
                after.is_some_and(|account| account.state != NativeFinishingStateV1::Settled);
            let position = self.files.iter().position(|entry| entry.file == *file);
            let entry = match position {
                Some(position) => &mut self.files[position],
                None => {
                    if was_open || !is_open {
                        return Err(invariant("native finishing bank lost a registered file"));
                    }
                    if self.files.len() >= MAX_BANK_FILES {
                        return Err(invariant("native finishing bank file capacity exhausted"));
                    }
                    self.files.push(NativeFinishingBankFileV1 {
                        file: file.clone(),
                        accounts: 0,
                        outstanding: PhysicalLiabilityData::zero(),
                        outstanding_wal_frames: 0,
                        owed_pages: 0,
                        page_buckets: Vec::new(),
                        width_reservations: Vec::new(),
                        row_reservations: Vec::new(),
                    });
                    self.files
                        .last_mut()
                        .ok_or_else(|| invariant("native finishing bank lost a registered file"))?
                }
            };
            entry.outstanding = entry.outstanding.checked_sub(&old)?.checked_add(&new)?;
            row_capacity::replace_loans(
                &mut entry.row_reservations,
                &before.map_or_else(Vec::new, |account| account.outstanding_row_loans(file.role)),
                &after.map_or_else(Vec::new, |account| account.outstanding_row_loans(file.role)),
            )
            .map_err(invariant)?;
            let old_frames =
                before.map_or(Ok(0), |account| account.outstanding_frames_on(file.role))?;
            let new_frames =
                after.map_or(Ok(0), |account| account.outstanding_frames_on(file.role))?;
            entry.outstanding_wal_frames = entry
                .outstanding_wal_frames
                .checked_sub(old_frames)
                .and_then(|frames| frames.checked_add(new_frames))
                .ok_or_else(|| invariant("native finishing bank frame debt exhausted"))?;
            if let Some(account) = before {
                for recipe in account.outstanding_page_recipes(file.role) {
                    entry.release_pages(recipe)?;
                }
                for recipe in account.outstanding_width_recipes(file.role) {
                    release_width(&mut entry.width_reservations, &recipe)?;
                }
            }
            if let Some(account) = after {
                for recipe in account.outstanding_page_recipes(file.role) {
                    entry.owe_pages(recipe)?;
                }
                for recipe in account.outstanding_width_recipes(file.role) {
                    owe_width(&mut entry.width_reservations, &recipe)?;
                }
            }
            match (was_open, is_open) {
                (false, true) => {
                    entry.accounts = entry
                        .accounts
                        .checked_add(1)
                        .ok_or_else(|| invariant("native finishing bank file overflow"))?
                }
                (true, false) => {
                    entry.accounts = entry
                        .accounts
                        .checked_sub(1)
                        .ok_or_else(|| invariant("native finishing bank file underflow"))?
                }
                _ => (),
            }
        }
        if self.files.iter().any(|entry| {
            entry.accounts == 0
                && (entry.outstanding != PhysicalLiabilityData::zero()
                    || entry.outstanding_wal_frames != 0
                    || entry.owed_pages != 0
                    || !entry.page_buckets.is_empty()
                    || !entry.width_reservations.is_empty()
                    || !entry.row_reservations.is_empty())
        }) {
            return Err(invariant(
                "native finishing bank would drop an owed file reserve",
            ));
        }
        self.files.retain(|entry| entry.accounts != 0);
        self.files.sort_by(|left, right| left.file.cmp(&right.file));
        Ok(())
    }

    fn validate(&self, store_uuid: &str) -> Result<(), AdmissionOperationStoreError> {
        let open: u64 = self
            .files
            .iter()
            .map(|entry| entry.accounts)
            .max()
            .unwrap_or(0);
        // One retained width class per outstanding (authority, tenant) scope:
        // disagreeing classes would let a wider loan hide a narrower bound.
        let mut scoped: Vec<(&str, &str, u8)> = Vec::new();
        let scopes_agree = self.files.iter().all(|entry| {
            entry.width_reservations.iter().all(|reservation| {
                match scoped
                    .iter()
                    .find(|(authority, tenant, _)| {
                        *authority == reservation.security_authority.as_str()
                            && *tenant == reservation.tenant_id.as_str()
                    })
                    .map(|&(_, _, class)| class)
                {
                    Some(class) => class == reservation.width_class,
                    None => {
                        scoped.push((
                            reservation.security_authority.as_str(),
                            reservation.tenant_id.as_str(),
                            reservation.width_class,
                        ));
                        true
                    }
                }
            })
        });
        if !scopes_agree
            || self.schema != BANK_SCHEMA
            || self.store_uuid != store_uuid
            || self.outstanding_accounts > MAX_OUTSTANDING_ACCOUNTS
            || self.files.len() > MAX_BANK_FILES
            || open > self.outstanding_accounts
            || self.files.iter().any(|entry| entry.accounts == 0)
            || self
                .files
                .windows(2)
                .any(|pair| pair[0].file >= pair[1].file)
            || (self.outstanding_accounts == 0) != self.files.is_empty()
            || self.files.iter().any(|entry| {
                (entry.file.role != NativeFinishingFileRoleV1::Native
                    && (entry.outstanding_wal_frames == 0) != (entry.outstanding.wal_bytes() == 0))
                    || (!entry.row_reservations.is_empty()
                        && entry.file.role != NativeFinishingFileRoleV1::Native)
                    || entry.row_reservations.iter().any(|reservation| {
                        reservation.references == 0 || reservation.loan.validate().is_err()
                    })
                    || entry.row_reservations.windows(2).any(|pair| {
                        (&pair[0].loan.table, pair[0].loan.ceiling)
                            >= (&pair[1].loan.table, pair[1].loan.ceiling)
                    })
                    || entry.page_buckets.is_empty() != (entry.owed_pages == 0)
                    || entry
                        .page_buckets
                        .iter()
                        .any(|bucket| bucket.loans == 0 || !bucket.page_bucket.is_power_of_two())
                    || entry
                        .page_buckets
                        .windows(2)
                        .any(|pair| pair[0].page_bucket >= pair[1].page_bucket)
                    || entry
                        .width_reservations
                        .iter()
                        .any(|reservation| reservation_shape(reservation).is_err())
                    || entry
                        .width_reservations
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
            })
        {
            return Err(invariant("native finishing bank head is not canonical"));
        }
        Ok(())
    }
}

fn load_bank(
    tx: &Connection,
    store_uuid: &str,
) -> Result<NativeFinishingBankV1, AdmissionOperationStoreError> {
    let Some(row) = raw_checked(tx, &native_finishing_bank_key(store_uuid))? else {
        return Ok(NativeFinishingBankV1 {
            schema: BANK_SCHEMA.to_owned(),
            store_uuid: store_uuid.to_owned(),
            ..NativeFinishingBankV1::default()
        });
    };
    let bank: NativeFinishingBankV1 = decode(&row.payload)?;
    if row.kind != "command" || row.scope != native_finishing_bank_scope(store_uuid)? {
        return Err(invariant("native finishing bank head is not canonical"));
    }
    bank.validate(store_uuid)?;
    Ok(bank)
}

fn persist_bank(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    bank: &NativeFinishingBankV1,
) -> Result<(), AdmissionOperationStoreError> {
    bank.validate(&owner.fence.store_uuid)?;
    persist_record(
        tx,
        owner,
        &native_finishing_bank_key(&bank.store_uuid),
        &native_finishing_bank_scope(&bank.store_uuid)?,
        "command",
        &bounded(bank, NATIVE_FINISHING_BANK_MAX_BYTES)?,
        None,
    )?;
    let debts = bank_row_debt(bank)?;
    owner
        .native_capacity()
        .preserve_committing_bank(tx, &debts)
        .map_err(invariant)
}

fn bank_row_debt(
    bank: &NativeFinishingBankV1,
) -> Result<std::collections::BTreeMap<String, NativeTableRowDebt>, AdmissionOperationStoreError> {
    row_capacity::aggregate(
        bank.files
            .iter()
            .filter(|entry| entry.file.role == NativeFinishingFileRoleV1::Native)
            .flat_map(|entry| {
                entry
                    .row_reservations
                    .iter()
                    .map(|entry| entry.loan.clone())
            }),
    )
    .map_err(invariant)
}

pub(crate) fn native_authority_table_row_debt(
    connection: &Connection,
    store_uuid: &str,
) -> Result<std::collections::BTreeMap<String, NativeTableRowDebt>, AdmissionOperationStoreError> {
    let Some((_, bank)) = authenticated_authority_bank(connection, Some(store_uuid))? else {
        return Ok(std::collections::BTreeMap::new());
    };
    bank_row_debt(&bank)
}

/// Canonical bytes within the bound the transition allowance priced.
fn bounded(value: &impl Serialize, maximum: u64) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    let bytes = encode(value)?;
    if u64::try_from(bytes.len())
        .map_err(|_| invariant("native finishing record size exhausted"))?
        > maximum
    {
        return Err(invariant(
            "native finishing record exceeds its priced bound",
        ));
    }
    Ok(bytes)
}

fn require_lower_digest(value: &str) -> Result<(), AdmissionOperationStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invariant("native finishing digest is not canonical"));
    }
    Ok(())
}

/// Cold inventory over the complete retained history with bounded memory:
/// rows stream in key order, every account is authenticated at its version
/// against the actual store identity, and only the per-file sums of unsettled
/// accounts are retained. The bank head must equal those sums exactly.
pub(in crate::admission_operation_store) fn verify_native_finishing_inventory(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key >= ?1 AND record_key < ?2 ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            NATIVE_FINISHING_NAMESPACE_START,
            NATIVE_FINISHING_NAMESPACE_END
        ])
        .map_err(sqlite_error)?;
    let mut store_uuid: Option<String> = None;
    let mut expected = NativeFinishingBankV1::default();
    let mut bank_seen = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let actual_store = match &store_uuid {
            Some(store) => store.clone(),
            None => {
                let store: String = tx
                    .query_row(
                        "SELECT store_uuid FROM main.chio_serving_owner WHERE singleton=1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(sqlite_error)?;
                expected.schema = BANK_SCHEMA.to_owned();
                expected.store_uuid = store.clone();
                store_uuid = Some(store.clone());
                store
            }
        };
        if let Some(operation) = key.strip_prefix(NATIVE_FINISHING_ACCOUNT_PREFIX) {
            let retained = load_native_finishing_account(tx, operation)?
                .ok_or_else(|| invariant("native finishing account disappeared"))?;
            if retained.account.identity.store_uuid != actual_store {
                return Err(invariant(
                    "native finishing account belongs to another store",
                ));
            }
            if let Some(process) = &retained.account.identity.process {
                if raw_checked(tx, &native_finishing_source_key(&process.source_digest))?.is_none()
                {
                    return Err(invariant(
                        "native finishing account lost its Process source alias",
                    ));
                }
            }
            if retained.account.state != NativeFinishingStateV1::Settled {
                expected.outstanding_accounts = expected
                    .outstanding_accounts
                    .checked_add(1)
                    .ok_or_else(|| invariant("native finishing inventory overflow"))?;
                expected.apply(None, Some(&retained.account))?;
            }
        } else if key == native_finishing_bank_key(&actual_store) {
            bank_seen = true;
        } else if let Some(source_digest) = key.strip_prefix(NATIVE_FINISHING_SOURCE_PREFIX) {
            load_native_finishing_account_for_source(tx, source_digest)?
                .ok_or_else(|| invariant("native finishing source alias disappeared"))?;
        } else {
            return Err(invariant("native finishing record namespace refused"));
        }
    }
    let Some(store) = store_uuid else {
        return Ok(());
    };
    let bank = load_bank(tx, &store)?;
    if !bank_seen || bank != expected {
        return Err(invariant(
            "native finishing bank differs from its unsettled accounts",
        ));
    }
    Ok(())
}
