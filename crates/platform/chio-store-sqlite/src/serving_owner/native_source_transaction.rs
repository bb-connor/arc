//! Opaque pre-mutation data survives the owning Transaction wrapper's move.
//! It grants no finishing, mutation purpose, effect/retry or release authority.
use super::*;

struct NativeSourceTransactionCut<'owner> {
    connection_identity: usize,
    owner: &'owner SqliteServingOwner,
    fence: StoreMutationFence,
    anchor: AnchorRecord,
    global_sequence: u64,
}

/// No serde/Clone/public ctor. Each source privately retains the SAME exact
/// initial cut. The returned final source still borrows its actual Transaction.
pub(crate) struct NativeSourceTransactionOrigin<'owner> {
    cut: Arc<NativeSourceTransactionCut<'owner>>,
}

impl SqliteServingOwner {
    /// The actual owning transaction calls this BEFORE its first mutation.
    /// No returned borrow of the stack Transaction prevents native join APIs
    /// from moving and returning that wrapper over the same Connection.
    pub(crate) fn prepare_native_source_transaction<'owner>(
        &'owner self,
        tx: &Transaction<'_>,
    ) -> Result<NativeSourceTransactionOrigin<'owner>, SqliteServingOwnerError> {
        self.verify_authority_anchor(tx)?;
        let anchor = self.companion_anchor()?;
        self.verify_companion_custody(tx, &anchor)?;
        let head = super::global_commit_chain::load_global_commit_head(tx)?;
        Ok(NativeSourceTransactionOrigin {
            cut: Arc::new(NativeSourceTransactionCut {
                connection_identity: &**tx as *const Connection as usize,
                owner: self,
                fence: self.fence.clone(),
                anchor,
                global_sequence: head.head_sequence,
            }),
        })
    }
}

impl NativeSourceTransactionOrigin<'_> {
    pub(crate) fn verify(&self, tx: &Transaction<'_>) -> Result<(), SqliteServingOwnerError> {
        if &**tx as *const Connection as usize != self.cut.connection_identity
            || self.cut.owner.fence != self.cut.fence
        {
            return Err(SqliteServingOwnerError::Invalid(
                "native source changed its prepared connection or owner".into(),
            ));
        }
        self.cut.owner.require_connection_current(tx)?;
        // Compare the filesystem anchor with the PREPARED file cut, not SQL's
        // advanced head. A committed/synced transaction cannot reuse this cut.
        if self.cut.owner.companion_anchor()? != self.cut.anchor {
            return Err(SqliteServingOwnerError::Invalid(
                "native source prepared anchor is no longer current".into(),
            ));
        }
        self.cut
            .owner
            .verify_companion_custody(tx, &self.cut.anchor)
    }
    pub(crate) fn matches_owner(&self, owner: &SqliteServingOwner) -> bool {
        std::ptr::eq(self.cut.owner, owner) && self.cut.fence == owner.fence
    }
    pub(crate) fn prepared_global_sequence(&self) -> u64 {
        self.cut.global_sequence
    }
    pub(crate) fn fork_for_source(&self) -> Self {
        Self {
            cut: self.cut.clone(),
        }
    }
}
