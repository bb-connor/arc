//! Authority-scoped native hydration under the serving fence and global anchor.
//! The initialized projection remains inactive and cannot serve invocations.

use super::*;

pub(super) mod dispatch_ledger;
pub(super) mod egress;
pub(super) mod nonce_preflight;
mod recovery_basis;
pub(in crate::admission_operation_store) use recovery_basis::{
    prove_recovery_source_history, prove_semantic_before_input_source_history,
    prove_semantic_source_history,
};
pub(super) mod output;
pub(crate) use nonce_preflight::NativeNoncePreflightJoinAuthority;
pub(crate) use output::NativeOutputJoinAuthority;
pub(super) mod knowledge;
pub(crate) use knowledge::NativeKnowledgeJoinAuthority;
mod finishing_account;
pub(in crate::admission_operation_store) use finishing_account::{
    authorize_native_finishing_growth, native_finishing_at_terminal,
    native_original as native_finishing_original, native_payment_journal_write,
    refuse_unpriced_native_payment_write, spend_native_finishing_purpose,
    spend_native_payment_purpose, NativePaymentJournalWrite,
};
mod finishing_funding;
pub(in crate::admission_operation_store) mod finishing_plan;
mod history;
pub(crate) use egress::NativeEgressAuthority;
pub use egress::SecurityParticipantEgressHistory;
pub(in crate::admission_operation_store) use history::segments::{
    NativeSealAdmission, VerifiedNativeJournalSeal,
};
pub(in crate::admission_operation_store) use knowledge::{
    VerifiedImportedInfluenceRoot, VerifiedNativeInfluenceHeads,
};
mod integrity;
mod mutations;
mod observation;
pub(crate) use mutations::NativeFlowJoinAuthority;
mod readback;
mod records;
pub use readback::SecurityParticipantFlowJoinHistory;
pub(super) mod schema;
mod storage;

pub(crate) use integrity::projection_reference;
pub(super) use integrity::{verify_coverage, verify_pristine};
pub(super) use records::verify_all;

pub(super) fn verify_predecessor(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let records = records::verify_all_version(connection, 28)?;
    let future: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_global_commits
         WHERE projection_kind = 'security_participant_state' AND projection_sequence != 1)",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if future {
        return Err(invalid("pre-v29 native references contain mutations"));
    }
    integrity::verify_initializations(connection, &records).map_err(map_owner_error)
}

const PROJECTION_KIND: &str = "security_participant_state";
const MUTATION_KIND: &str = "hydrate_security_participant_state";

/// Verified initialization history, not a live mutable store or execution permit.
#[derive(Clone, Eq, PartialEq)]
pub struct SecurityParticipantStateInitialization {
    authority: AdmissionIdentifier,
    expectation: AdmissionIdentifier,
    fingerprint: String,
    schema: String,
    initialized_at: u64,
    fence: StoreMutationFence,
    digest: String,
}

impl SecurityParticipantStateInitialization {
    /// Stable data for trusted host selection at original admission. This is
    /// not activation, current ownership, a recovery lease or a write permit.
    pub fn admission_binding(
        &self,
    ) -> Result<
        chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
        AdmissionOperationStoreError,
    > {
        Ok(
            chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1::new(
                AdmissionIdentifier::try_new("native_store_uuid", self.fence.store_uuid.clone())?,
                self.authority.clone(),
                AdmissionDigest::try_new("native_initialization_digest", self.digest.clone())?,
            ),
        )
    }

    pub fn security_authority_id(&self) -> &AdmissionIdentifier {
        &self.authority
    }
    pub fn expectation_id(&self) -> &AdmissionIdentifier {
        &self.expectation
    }
    pub fn initialization_digest(&self) -> &str {
        &self.digest
    }
}

impl std::fmt::Debug for SecurityParticipantStateInitialization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityParticipantStateInitialization")
            .field("state", &"hydrated_inactive")
            .finish_non_exhaustive()
    }
}

impl SqliteAdmissionOperationStore {
    /// Hydrate actual native relational rows for exactly one imported authority.
    /// No source I/O or historical command re-execution occurs here. The entire
    /// projection and its initialization record share one anchored outer commit.
    pub fn hydrate_security_participant_state(
        &self,
        authority: &AdmissionIdentifier,
        expectation: &AdmissionIdentifier,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<SecurityParticipantStateInitialization, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let observed = observed_time(&tx, trusted_now_unix_ms)?;
        let source = security_participant_migration::load_imported_source(&tx, authority.as_str())?;
        if source.expectation_id() != expectation
            || source
                .snapshot()
                .binding()
                .destination_store_uuid()
                .as_str()
                != fence.store_uuid
        {
            return Err(invalid("native initialization source binding mismatch"));
        }
        if let Some(existing) = records::load(&tx, authority.as_str())? {
            if existing.expectation_id() != expectation {
                return Err(invalid("native initialization generation conflict"));
            }
            knowledge::verify_imported_scope_index(&tx, &existing)?;
            return Ok(existing);
        }
        let record = records::new(&source, observed, fence)?;
        storage::hydrate(&tx, &source)?;
        cutpoint(2)?;
        records::insert(&tx, &record)?;
        records::verify_all(&tx)?;
        cutpoint(3)?;
        self.serving_owner
            .append_global_commit(&tx, MUTATION_KIND, PROJECTION_KIND, authority.as_str(), 1)
            .map_err(map_owner_error)?;
        // The source verified above is the one indexed, in this same commit.
        knowledge::install_imported_scope_index(&tx, &self.serving_owner, &record)?;
        cutpoint(4)?;
        self.commit_write(tx)?;
        #[cfg(test)]
        super::tests::security_participant_state::crash_cutpoint(6);
        self.sync_after_write(&connection)?;
        cutpoint(5)?;
        drop(connection);
        let readback = self
            .load_security_participant_state(authority, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invalid("native initialization readback absent"))?;
        if readback != record {
            return Err(invalid("native initialization readback mismatch"));
        }
        Ok(readback)
    }

    /// Fenced, anchored initialization readback. This cannot claim, release or
    /// dispatch a participant and does not reactivate any old source consumer.
    pub fn load_security_participant_state(
        &self,
        authority: &AdmissionIdentifier,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<SecurityParticipantStateInitialization>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        observed_time(&tx, trusted_now_unix_ms)?;
        verify_current_catalogs(&tx)?;
        let record = records::load_current(&tx, authority.as_str())?;
        if record
            .as_ref()
            .is_some_and(|record| record.fence.store_uuid != fence.store_uuid)
        {
            return Err(invalid("native initialization destination mismatch"));
        }
        Ok(record)
    }
}

/// Every native journal family catalog, checked in a warm read without
/// reading history. A family the recorded format includes must hold its exact
/// catalog; an absent family must predate that format and have no global
/// reference. These are the catalog rules of the cold family walks.
fn verify_current_catalogs(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    type Present = fn(&Connection) -> Result<bool, AdmissionOperationStoreError>;
    type Catalog = fn(&Connection) -> Result<(), AdmissionOperationStoreError>;
    let version: i32 = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let families: [(&str, i32, Present, Catalog); 3] = [
        (
            "security_participant_egress",
            30,
            egress::exists,
            egress::verify_catalog,
        ),
        (
            "security_participant_output",
            32,
            output::exists,
            output::verify_catalog,
        ),
        (
            "security_participant_nonce_preflight",
            33,
            nonce_preflight::exists,
            nonce_preflight::verify_catalog,
        ),
    ];
    for (projection, introduced, present, catalog) in families {
        if present(tx)? {
            catalog(tx)?;
            continue;
        }
        let referenced: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = ?1)",
                [projection],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if referenced || version >= introduced {
            return Err(invalid(format!(
                "{projection} requires its current catalog"
            )));
        }
    }
    Ok(())
}

fn observed_time(tx: &Transaction<'_>, supplied: u64) -> Result<u64, AdmissionOperationStoreError> {
    super::schema::authority_validation_time(tx, supplied)?;
    let observed = super::schema::observe_authority_time(tx)?;
    if observed < native_high_water(tx)? {
        return Err(invalid("native initialization clock regressed"));
    }
    Ok(observed)
}

/// The latest native observation, without a history scan. Every native writer
/// refuses to append below it, and the cold walk refuses a sequence gap or an
/// earlier observation after a later one across each authority's families
/// (`history/ordered.rs`), with each family loader binding its stored
/// `observed_at` column to the canonical record. So each initialized
/// authority's last row in a family carries that family's high water.
/// Initializations and migration events are bounded tables.
fn native_high_water(tx: &Connection) -> Result<u64, AdmissionOperationStoreError> {
    let mut high_water: i64 = tx
        .query_row(
            "SELECT MAX(value) FROM (
             SELECT COALESCE(MAX(initialized_at), 0) AS value
               FROM security_participant_state_initializations
             UNION ALL SELECT COALESCE(MAX(observed_at_unix_ms), 0)
               FROM security_participant_migration_events
             UNION ALL SELECT COALESCE(MAX((SELECT observed_at
               FROM security_participant_state_mutations AS latest
               WHERE latest.security_authority_id = initialized.security_authority_id
               ORDER BY latest.sequence DESC LIMIT 1)), 0)
               FROM security_participant_state_initializations AS initialized)",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    for (present, table) in [
        (egress::exists(tx)?, "security_participant_egress_events"),
        (output::exists(tx)?, "security_participant_output_events"),
    ] {
        if !present {
            continue;
        }
        let latest: i64 = tx
            .query_row(
                &format!(
                    "SELECT COALESCE(MAX((SELECT observed_at FROM {table} AS latest
                     WHERE latest.security_authority_id = initialized.security_authority_id
                     ORDER BY latest.sequence DESC LIMIT 1)), 0)
                     FROM security_participant_state_initializations AS initialized"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        high_water = high_water.max(latest);
    }
    u64::try_from(high_water).map_err(invalid)
}

fn invalid(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    invariant(format!("native security state: {detail}"))
}

/// Test-only construction of a genuine initialization from the compiled
/// native catalog selected by the recorded admission stamp (`recorded_version`:
/// v28 for admission 28, v29 for admission 29 through 34). No existing history
/// is rewritten into old evidence.
#[cfg(test)]
pub(crate) fn hydrate_predecessor_fixture(
    store: &SqliteAdmissionOperationStore,
    source: &SecurityParticipantMigrationRecord,
    fence: &StoreMutationFence,
    now: u64,
) -> Result<SecurityParticipantStateInitialization, AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    let version = schema::recorded_version(&tx)?;
    if !matches!(version, 28 | 29) {
        return Err(invalid(
            "predecessor fixture is not a supported predecessor",
        ));
    }
    let record = records::new_with_catalog(source, now, fence, schema::digest_version(version)?)?;
    storage::hydrate_at_version(&tx, source, version)?;
    records::insert(&tx, &record)?;
    records::verify_all_version(&tx, version)?;
    store
        .serving_owner
        .append_global_commit(
            &tx,
            MUTATION_KIND,
            PROJECTION_KIND,
            record.authority.as_str(),
            1,
        )
        .map_err(map_owner_error)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    Ok(record)
}

/// Decide an Output entry that cannot fit the live journal segment, without
/// appending it. The owed band refuses without an allowance; the pre-effect
/// band seals first. Returns whether a seal was written.
#[cfg(test)]
pub(crate) fn decide_unfitting_output_fixture(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    initialization: &SecurityParticipantStateInitialization,
    owed: bool,
) -> Result<bool, AdmissionOperationStoreError> {
    history::segments::decide_unfitting_output(tx, owner, initialization, owed)
        .map(|boundary| boundary == history::segments::Boundary::Sealed)
}

#[cfg(test)]
fn cutpoint(stage: u8) -> Result<(), AdmissionOperationStoreError> {
    super::tests::security_participant_state::cutpoint(stage)
}
#[cfg(not(test))]
fn cutpoint(_: u8) -> Result<(), AdmissionOperationStoreError> {
    Ok(())
}

pub(super) use observation::{
    verify_current_recovery_initialization, verify_recovery_initialization,
};
