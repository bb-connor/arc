//! Authority-scoped native hydration under the serving fence and global anchor.
//! The initialized projection remains inactive and cannot serve invocations.

use super::*;

pub(super) mod dispatch_ledger;
pub(super) mod egress;
pub(super) mod nonce_preflight;
pub(super) mod output;
pub(crate) use nonce_preflight::NativeNoncePreflightJoinAuthority;
pub(crate) use output::NativeOutputJoinAuthority;
mod history;
pub(crate) use egress::NativeEgressAuthority;
pub use egress::SecurityParticipantEgressHistory;
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
        verify_coverage(&tx).map_err(map_owner_error)?;
        let record = records::load(&tx, authority.as_str())?;
        if record
            .as_ref()
            .is_some_and(|record| record.fence.store_uuid != fence.store_uuid)
        {
            return Err(invalid("native initialization destination mismatch"));
        }
        Ok(record)
    }
}

fn observed_time(tx: &Transaction<'_>, supplied: u64) -> Result<u64, AdmissionOperationStoreError> {
    super::schema::authority_validation_time(tx, supplied)?;
    let observed = super::schema::observe_authority_time(tx)?;
    let high_water: i64 = tx.query_row(
        "SELECT MAX(value) FROM (
         SELECT COALESCE(MAX(initialized_at), 0) AS value FROM security_participant_state_initializations
         UNION ALL SELECT COALESCE(MAX(observed_at_unix_ms), 0) FROM security_participant_migration_events
         UNION ALL SELECT COALESCE(MAX(observed_at), 0) FROM security_participant_state_mutations)",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let high_water = if egress::exists(tx)? {
        let egress: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(observed_at),0) FROM security_participant_egress_events",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        high_water.max(egress)
    } else {
        high_water
    };
    let high_water = if output::exists(tx)? {
        let output: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(observed_at),0) FROM security_participant_output_events",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        high_water.max(output)
    } else {
        high_water
    };
    if observed < u64::try_from(high_water).map_err(invalid)? {
        return Err(invalid("native initialization clock regressed"));
    }
    Ok(observed)
}

fn invalid(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    invariant(format!("native security state: {detail}"))
}

/// Test-only construction of a genuine v28 initialization from its compiled
/// predecessor schema. No existing history is rewritten into old evidence.
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
    if schema::recorded_version(&tx)? != 28 {
        return Err(invalid("predecessor fixture is not v28"));
    }
    let record = records::new_with_catalog(source, now, fence, schema::digest_version(28)?)?;
    storage::hydrate_at_version(&tx, source, 28)?;
    records::insert(&tx, &record)?;
    records::verify_all_version(&tx, 28)?;
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

#[cfg(test)]
fn cutpoint(stage: u8) -> Result<(), AdmissionOperationStoreError> {
    super::tests::security_participant_state::cutpoint(stage)
}
#[cfg(not(test))]
fn cutpoint(_: u8) -> Result<(), AdmissionOperationStoreError> {
    Ok(())
}
