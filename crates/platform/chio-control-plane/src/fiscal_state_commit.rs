use chio_fiscal::{
    commit_fiscal_continuity_advance, FiscalAuthorityState, FiscalCharterRegistry,
    FiscalGenesisPolicy, FiscalStateAnchor, FiscalStateAnchorError,
    VerifiedFiscalContinuityAdvance, VerifiedFiscalContinuityCheckpoint,
};
use chio_kernel::admission_operation::StoreMutationFence;
use chio_store_sqlite::fiscal_store::{FiscalStoreError, SqliteFiscalStore};

#[derive(Debug, thiserror::Error)]
pub enum FiscalStateCommitError {
    #[error("fiscal state could not be staged locally: {0}")]
    Store(#[from] FiscalStoreError),
    #[error("fiscal state could not advance at the independent anchor: {0}")]
    Anchor(#[from] FiscalStateAnchorError),
}

pub fn commit_fiscal_state_advance(
    store: &SqliteFiscalStore,
    anchor: &dyn FiscalStateAnchor,
    advance: VerifiedFiscalContinuityAdvance,
    next_authority: &FiscalAuthorityState,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
    fence: &StoreMutationFence,
) -> Result<VerifiedFiscalContinuityCheckpoint, FiscalStateCommitError> {
    let staged = store.stage_advance(&advance, next_authority, fence)?;
    let committed = commit_fiscal_continuity_advance(anchor, advance, policy, charters)?;
    let checkpoint = committed.checkpoint().clone();
    store.mark_anchor_advanced(&staged.transition_id, &checkpoint, fence)?;
    store.finalize_advance(&staged.transition_id, &checkpoint, next_authority, fence)?;
    Ok(checkpoint)
}
