//! Only the actual native knowledge join owns its encoding append.
use super::super::{head, load_with_digest, record_key, records, Record};
use crate::admission_operation_store::knowledge::encoding::chunks::EncodingOwner;
use crate::admission_operation_store::recovery::storage as protected;
use crate::admission_operation_store::{invariant, AdmissionOperationStoreError};
use rusqlite::{Connection, Transaction};
use std::ops::Deref;

/// This source borrows the actual post-join record and originating native Tx.
/// No public construction, Clone, Deserialize or decoded purpose exists.
pub(in crate::admission_operation_store) struct AuthenticatedNativeKnowledgeEncodingSource<
    'tx,
    'conn,
> {
    transaction: &'tx Transaction<'conn>,
    record: &'tx Record,
}

impl<'tx, 'conn> AuthenticatedNativeKnowledgeEncodingSource<'tx, 'conn> {
    /// Private to the encoding owner reached directly after join_native_knowledge.
    pub(super) fn after_native_join(
        transaction: &'tx Transaction<'conn>,
        record: &'tx Record,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source = Self {
            transaction,
            record,
        };
        source.verify(transaction)?;
        Ok(source)
    }
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn expected_root(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        None
    }
    pub(in crate::admission_operation_store) fn owner(&self) -> EncodingOwner {
        EncodingOwner::Journal {
            scope: self.record.scope.clone(),
            authority: self.record.authority.clone(),
            sequence: self.record.sequence,
            release: self.record.release.release.clone(),
        }
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(invalid());
        }
        self.record.validate()?;
        let initialized =
            records::load_metadata(tx, &self.record.authority)?.ok_or_else(invalid)?;
        if initialized.digest != self.record.initialization
            || initialized.authority.as_str() != self.record.authority
            || head(tx, &self.record.authority)?.checked_add(1) != Some(self.record.sequence)
            || protected::raw_checked(
                tx,
                &record_key(&self.record.authority, self.record.sequence),
            )?
            .is_some()
        {
            return Err(invalid());
        }
        let previous = if self.record.sequence == 1 {
            initialized.digest
        } else {
            load_with_digest(tx, &self.record.authority, self.record.sequence - 1)?.1
        };
        if previous != self.record.previous {
            return Err(invalid());
        }
        crate::security_state::verify_native_join_snapshot(
            tx,
            &self.record.authority,
            &self.record.result,
        )
        .map_err(|_| invalid())
    }
    pub(in crate::admission_operation_store) fn verify_stored_body(
        &self,
        body: &[u8],
    ) -> Result<(), AdmissionOperationStoreError> {
        let decoded = super::atoms::decode_body(body)?;
        if chio_core::canonical_json_bytes(&decoded).map_err(|_| invalid())?
            != chio_core::canonical_json_bytes(self.record).map_err(|_| invalid())?
            || super::atoms::logical_body(self.record)? != body
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> AdmissionOperationStoreError {
    invariant("native knowledge encoding lost its owning join")
}
