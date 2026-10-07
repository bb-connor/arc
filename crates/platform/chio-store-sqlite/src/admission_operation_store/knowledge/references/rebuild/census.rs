//! Complete current and historical leaf custody is verified before rebuilding.
use super::*;
use crate::admission_operation_store::knowledge::references::reader::{
    indexed, verify_owner_leaf, Indexed,
};
use std::ops::Deref;

/// Connection-local spill guards preserve every historical key while bounded
/// buckets retain only live owner digests. The table never grants authority.
pub(super) struct VerifiedKnowledgeReferenceRebuild<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    authority: VerifiedKnowledgeReferenceRebuildAuthority<'tx, 'conn>,
    aggregate: Indexed<ReferenceAggregate>,
    guards: String,
}

impl<'tx, 'conn> VerifiedKnowledgeReferenceRebuild<'tx, 'conn> {
    pub(super) fn capture(
        tx: &'tx Transaction<'conn>,
        authority: VerifiedKnowledgeReferenceRebuildAuthority<'tx, 'conn>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        authority.verify(tx)?;
        let state = load_reference_state(tx, authority.reference())?;
        if !matches!(
            state.aggregate.value.inventory,
            ReferenceInventory::LegacyOverflow { .. }
        ) || state.aggregate.value.active_owners.get() > MAX_ACTIVE_REFERENCE_OWNERS
            || !state.buckets.is_empty()
        {
            return Err(refused(
                "reference rebuild requires bounded retained overflow",
            ));
        }
        let guards = format!(
            "knowledge_reference_rebuild_{}",
            uuid::Uuid::new_v4().simple()
        );
        tx.execute_batch(&format!(
            "CREATE TEMP TABLE {guards}(record_key TEXT PRIMARY KEY,source BLOB NOT NULL,active INTEGER NOT NULL) WITHOUT ROWID;"
        )).map_err(sqlite_error)?;
        let proof = Self {
            transaction: tx,
            authority,
            aggregate: state.aggregate,
            guards,
        };
        proof.visit_union(tx, |key, leaf| {
            tx.execute(
                &format!(
                    "INSERT INTO {}(record_key,source,active) VALUES(?1,?2,?3)",
                    proof.guards
                ),
                params![
                    key,
                    protected::encode(&SourceAnchor::capture(&leaf.head))?,
                    leaf.value.state == ReferenceOwnerState::Active
                ],
            )
            .map_err(sqlite_error)?;
            Ok(())
        })?;
        proof.verify_current(tx)?;
        Ok(proof)
    }

    pub(super) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }

    pub(super) fn reference(&self) -> &ArtifactVersionRefV1 {
        self.authority.reference()
    }

    pub(super) fn aggregate(&self) -> &Indexed<ReferenceAggregate> {
        &self.aggregate
    }

    pub(super) fn verify_current(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("reference rebuild changed its physical writer"));
        }
        self.authority.verify(tx)?;
        protected::verify_source_reference(tx, &self.aggregate.head)?;
        let mut observed = 0_u64;
        self.visit_union(tx, |key, leaf| {
            observed = observed
                .checked_add(1)
                .ok_or_else(|| refused("reference rebuild guard count overflow"))?;
            let stored: Option<(Vec<u8>, bool)> = tx
                .query_row(
                    &format!(
                        "SELECT source,active FROM {} WHERE record_key=?1",
                        self.guards
                    ),
                    [key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sqlite_error)?;
            let Some((body, active)) = stored else {
                return Err(refused("reference rebuild encountered an unguarded source"));
            };
            let original: SourceAnchor = protected::decode(&body)?;
            if original != SourceAnchor::capture(&leaf.head)
                || active != (leaf.value.state == ReferenceOwnerState::Active)
            {
                return Err(refused("reference rebuild source advanced after preflight"));
            }
            Ok(())
        })?;
        let count: i64 = tx
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", self.guards),
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if u64::try_from(count).map_err(refused)? != observed {
            return Err(refused("reference rebuild lost an original source"));
        }
        Ok(())
    }

    pub(super) fn visit_active_owners(
        &self,
        mut visit: impl FnMut(CanonicalPayloadDigest) -> Result<(), AdmissionOperationStoreError>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_current(self.transaction)?;
        let state = load_reference_state(self.transaction, self.reference())?;
        let identity = reference_identity(self.reference())?;
        let mut statement = self
            .transaction
            .prepare(&format!(
                "SELECT record_key FROM {} WHERE active=1 ORDER BY record_key",
                self.guards
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let key: String = row.get(0).map_err(sqlite_error)?;
            let leaf = indexed::<ReferenceLeaf>(self.transaction, &key, &self.reference().scope)?
                .ok_or_else(|| refused("reference rebuild active source disappeared"))?;
            verify_owner_leaf(self.transaction, self.reference(), &key, &leaf, &state)?;
            if leaf.value.state != ReferenceOwnerState::Active {
                return Err(refused("reference rebuild source no longer active"));
            }
            visit(leaf.value.owner.identity(identity)?)?;
        }
        Ok(())
    }

    fn visit_union(
        &self,
        tx: &Connection,
        mut visit: impl FnMut(&str, &Indexed<ReferenceLeaf>) -> Result<(), AdmissionOperationStoreError>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let state = load_reference_state(tx, self.reference())?;
        if SourceAnchor::capture(&state.aggregate.head)
            != SourceAnchor::capture(&self.aggregate.head)
            || !matches!(
                state.aggregate.value.inventory,
                ReferenceInventory::LegacyOverflow { .. }
            )
        {
            return Err(refused("reference rebuild lost its retained overflow"));
        }
        let identity = reference_identity(self.reference())?;
        let pattern = format!(
            "knowledge-reference-owner:{}:*",
            hex::encode(identity.as_bytes())
        );
        let mut statement = tx.prepare(
            "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB ?1
             UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB ?1
             UNION SELECT projection_key FROM authority_global_commits
              WHERE projection_kind='recovery' AND projection_key GLOB ?1 ORDER BY 1"
        ).map_err(sqlite_error)?;
        let mut rows = statement.query([pattern]).map_err(sqlite_error)?;
        let mut total = 0_u64;
        let mut active = 0_u64;
        let mut retired = 0_u64;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let key: String = row.get(0).map_err(sqlite_error)?;
            let leaf = indexed::<ReferenceLeaf>(tx, &key, &self.reference().scope)?
                .ok_or_else(|| refused("reference rebuild source lost its current head"))?;
            verify_owner_leaf(tx, self.reference(), &key, &leaf, &state)?;
            total = total
                .checked_add(1)
                .ok_or_else(|| refused("reference rebuild total count overflow"))?;
            match leaf.value.state {
                ReferenceOwnerState::Active => {
                    active = active
                        .checked_add(1)
                        .ok_or_else(|| refused("reference rebuild active count overflow"))?;
                }
                ReferenceOwnerState::Retired => {
                    retired = retired
                        .checked_add(1)
                        .ok_or_else(|| refused("reference rebuild retirement count overflow"))?;
                }
            }
            visit(&key, &leaf)?;
        }
        if total != state.aggregate.value.baseline.active_owners.get()
            || active != state.aggregate.value.active_owners.get()
            || retired != state.aggregate.value.retired.get()
            || active > MAX_ACTIVE_REFERENCE_OWNERS
        {
            return Err(refused(
                "reference rebuild differs from its complete owner census",
            ));
        }
        Ok(())
    }
}

impl Drop for VerifiedKnowledgeReferenceRebuild<'_, '_> {
    fn drop(&mut self) {
        // Temporary cleanup does not change native custody or durable history.
        let _ = self
            .transaction
            .execute_batch(&format!("DROP TABLE IF EXISTS temp.{};", self.guards));
    }
}
