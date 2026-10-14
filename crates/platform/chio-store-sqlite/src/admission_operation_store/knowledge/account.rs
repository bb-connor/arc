//! Tenant accounting is created once, in the installation's native transaction.
use super::reference_source::ReferenceCutoff;
use super::references::ReferenceAccount;
use super::*;
use std::ops::Deref;

/// Only the installation writer can establish a new account. The proof never
/// leaves that transaction; existing installations cannot reset their counters.
pub(in crate::admission_operation_store) struct NewKnowledgeAccount<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    scope: RecoveryScopeV1,
    cutoff: ReferenceCutoff,
}

pub(super) fn initialize_or_verify(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &NativeKnowledgeInstallationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let recovery = protected::deployment_tx(tx, &profile.scope)?;
    validate_installation(tx, &recovery, profile)?;
    if has_installation(tx, &profile.scope)? {
        protected::verify_knowledge_reference_account(tx, &profile.scope)?;
        return publication_capacity::verify_account(tx, &profile.scope);
    }
    let proof = NewKnowledgeAccount {
        transaction: tx,
        scope: profile.scope.clone(),
        cutoff: ReferenceCutoff::capture(tx, owner)?,
    };
    protected::initialize_knowledge_reference_account(tx, owner, &proof)?;
    publication_capacity::initialize_account(tx, owner, &proof)
}

impl<'conn> NewKnowledgeAccount<'_, 'conn> {
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }

    pub(in crate::admission_operation_store) fn cutoff(&self) -> &ReferenceCutoff {
        &self.cutoff
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx))
            || has_installation(tx, &self.scope)?
        {
            return Err(refused(
                "new knowledge account changed its installation writer",
            ));
        }
        self.cutoff.verify(tx)
    }
}

/// Include immutable keys so losing a profile projection cannot manufacture
/// an empty tenant. All supported knowledge writers require an installation.
fn has_installation(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let account = ReferenceAccount::from_scope(scope);
    let mut statement = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-profile:*'
         UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'knowledge-profile:*'
         UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'knowledge-profile:*' ORDER BY 1",
    ).map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut found = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let profile: NativeKnowledgeInstallationV1 = load(tx, &key)?
            .ok_or_else(|| refused("knowledge account lost an installed profile"))?;
        let source = protected::source_reference(tx, &key)?;
        if key != profile_key(&profile.scope)?
            || source.kind() != "command"
            || source.scope_key() != scope_key(&profile.scope)?
        {
            return Err(refused("knowledge account profile changed its scope"));
        }
        found |= ReferenceAccount::from_scope(&profile.scope) == account;
    }
    Ok(found)
}

/// Absence must hold in both the projection and immutable custody. A missing
/// current counter is corruption, never permission to allocate it again.
pub(in crate::admission_operation_store) fn require_unused_key(
    tx: &Connection,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key=?1)
         OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key=?1)
         OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key=?1)",
        [key], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if exists {
        return Err(refused(
            "knowledge account initialization would replace retained custody",
        ));
    }
    Ok(())
}

impl std::fmt::Debug for NewKnowledgeAccount<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewKnowledgeAccount([redacted])")
    }
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Interrupt the final account write on its real native connection.
    /// The TEMP trigger cannot alter protected data or the persistent catalog.
    pub fn set_knowledge_account_completion_failure_for_test(
        &self,
        enabled: bool,
    ) -> Result<(), AdmissionOperationStoreError> {
        let sql = if enabled {
            "CREATE TEMP TRIGGER reject_account_completion BEFORE INSERT ON main.admission_operation_recovery_records
             WHEN NEW.record_key GLOB 'knowledge-publication-ready:*'
             BEGIN SELECT RAISE(ABORT,'account initialization interrupted'); END;"
        } else {
            "DROP TRIGGER temp.reject_account_completion"
        };
        self.connection()?.execute_batch(sql).map_err(sqlite_error)
    }
}
