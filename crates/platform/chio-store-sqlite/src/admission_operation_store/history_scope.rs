//! Checked history is local to one immutable connection/transaction snapshot.
use super::*;
use std::cell::RefCell;

pub(super) struct CheckedHistoryScope<'a> {
    connection: &'a Connection,
    checked_head: RefCell<Option<commit_chain::AdmissionCommitHead>>,
}

impl<'a> CheckedHistoryScope<'a> {
    pub(super) fn new(connection: &'a Connection) -> Self {
        Self {
            connection,
            checked_head: RefCell::new(None),
        }
    }

    // The sole audit caller has already checked exact chronology and this head
    // through verify_admission_commit_chain before entering its projection loop.
    pub(super) fn from_verified_chain(
        connection: &'a Connection,
        head: commit_chain::AdmissionCommitHead,
    ) -> Self {
        Self {
            connection,
            checked_head: RefCell::new(Some(head)),
        }
    }

    pub(super) fn require_connection(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq(self.connection, connection) {
            return Err(invariant(
                "checked admission history belongs to another connection",
            ));
        }
        if let Some(head) = self.checked_head.borrow().as_ref() {
            if &commit_chain::load_admission_commit_head(connection)? != head {
                return Err(invariant("checked admission history snapshot changed"));
            }
        }
        Ok(())
    }

    pub(super) fn qualify(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.require_connection(connection)?;
        if self.checked_head.borrow().is_some() {
            return Ok(());
        }
        super::schema::verify_admission_commit_chronology(connection)?;
        let verified = commit_chain::verify_admission_commit_chain(connection)?;
        let _ = self.checked_head.replace(Some(verified));
        Ok(())
    }
}

pub(super) struct TerminalCasBinding<'a> {
    pub(super) operation_id: &'a str,
    pub(super) operation_version: u64,
    pub(super) operation_digest: &'a str,
    pub(super) recovery_claim_digest: Option<&'a str>,
    pub(super) fence: &'a StoreMutationFence,
    pub(super) recorded_at_unix_ms: u64,
}
