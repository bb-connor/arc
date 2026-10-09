//! Extension of a published snapshot in finite cycles. Each cycle pins a
//! target, authenticates only the claim entries, checkpoints and lineage rows
//! appended since the previous version, and never re-reads authenticated
//! history.
use std::time::Instant;

use super::db::SnapshotBatch;
use super::service::Published;
use super::walk::{
    authenticate, authenticate_checkpoints, check_sources, commit_in_holds, copy_checkpoints,
    copy_claims, copy_lineage, observe, owned_checkpoint, pending_leaves, Observation, WalkContext,
    WalkError,
};

/// Pending leaves settled per hold while verifying a checkpoint's root.
const SETTLE_CHUNK: i64 = 65_536;
/// Lineage rows read per refresh step.
const LINEAGE_CHUNK: i64 = 256;
/// Receipt rows updated per lineage refresh hold.
const REFRESH_CHUNK: i64 = 256;

/// Run one extension cycle against `published`. Freshness advances only when
/// the cycle has covered its whole target.
pub(super) fn extend_cycle(
    ctx: &WalkContext<'_>,
    published: &Published,
    now_ms: &dyn Fn() -> Result<u64, WalkError>,
) -> Result<Observation, WalkError> {
    let observation = observe(ctx)?;
    let observed_at = Instant::now();
    let observed_at_ms = now_ms()?;
    let state = published.extension_state()?;
    if observation.head < state.through_entry_seq {
        return Err(WalkError::Regressed(format!(
            "claim receipt log head {} is below the authenticated snapshot at entry {}",
            observation.head, state.through_entry_seq
        )));
    }
    if observation.watermark < state.watermark {
        return Err(WalkError::Regressed(format!(
            "retention watermark {} is below the previously observed watermark {}",
            observation.watermark, state.watermark
        )));
    }

    let mut sink = published.sink();
    let mut next = state.through_entry_seq + 1;
    while next <= observation.head {
        ctx.check_cancel()?;
        let rows = copy_claims(ctx, next, observation.head)?;
        let entries = authenticate(ctx, rows, None)?;
        let (tools, children) = check_sources(ctx, &entries)?;
        let last = entries.last().map_or(next, |entry| entry.row.entry_seq);
        let pending = pending_leaves(&entries);
        commit_in_holds(&mut sink, &ctx.limits, tools, children, pending)?;
        next = last + 1;
    }

    let mut seq = state.checkpoint_seq + 1;
    while seq <= observation.checkpoint {
        ctx.check_cancel()?;
        let rows = copy_checkpoints(ctx, seq, observation.checkpoint)?;
        let (mut previous, mut chain) = published.head_and_chain()?;
        let mut accepted_chain = chain.clone();
        let verified = authenticate_checkpoints(ctx, rows, &mut previous, &mut chain)?;
        for (checkpoint, _) in verified {
            let owned = owned_checkpoint(&checkpoint)?;
            settle_streaming(published, &owned)?;
            accepted_chain.append(
                chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint.body)
                    .map_err(|error| WalkError::Integrity(error.to_string()))?,
            );
            published.accept_checkpoint(
                &SnapshotBatch {
                    checkpoints: vec![owned.clone()],
                    settle_pending: Some((owned.batch_start, owned.batch_end)),
                    ..SnapshotBatch::default()
                },
                checkpoint,
                accepted_chain.clone(),
            )?;
            seq = owned.seq + 1;
        }
    }

    let mut after = state.lineage_rowid;
    while after < observation.lineage_rowid {
        ctx.check_cancel()?;
        let rows = copy_lineage(ctx, after, observation.lineage_rowid, LINEAGE_CHUNK)?;
        let Some(last) = rows.last().map(|(rowid, _, _)| *rowid) else {
            break;
        };
        for (_, capability, subject) in rows {
            refresh_capability(published, &capability, &subject)?;
        }
        after = last;
    }
    published.observed(observation, observed_at_ms, observed_at)?;
    Ok(observation)
}

/// Fill absent unsigned subjects of one capability's receipts, in holds.
fn refresh_capability(
    published: &Published,
    capability: &str,
    subject: &str,
) -> Result<(), WalkError> {
    let mut after_seq = 0_i64;
    loop {
        let outcome = published
            .with_db_mut(|db| db.refresh_subject(capability, subject, after_seq, REFRESH_CHUNK))?;
        match outcome {
            Ok(rows) => {
                let Some(last) = rows.last().copied() else {
                    return Ok(());
                };
                if i64::try_from(rows.len()).unwrap_or(i64::MAX) < REFRESH_CHUNK {
                    return Ok(());
                }
                after_seq = last;
            }
            Err(seq) => {
                return Err(WalkError::Integrity(format!(
                    "capability lineage changed the subject of receipt seq {seq} for capability {capability}"
                )))
            }
        }
    }
}

/// Verify a checkpoint's root over the owned pending leaves of its range,
/// streaming them in bounded holds.
fn settle_streaming(
    published: &Published,
    checkpoint: &super::db::OwnedCheckpoint,
) -> Result<(), WalkError> {
    let mut frontier = chio_kernel::checkpoint::CheckpointChainFrontier::empty();
    let mut expected = checkpoint.batch_start;
    while expected <= checkpoint.batch_end {
        let high = expected
            .saturating_add(SETTLE_CHUNK - 1)
            .min(checkpoint.batch_end);
        let leaves = published.with_db(|db| db.pending_leaves(expected, high))?;
        for leaf in &leaves {
            if leaf.entry_seq != expected {
                return Err(WalkError::Integrity(format!(
                    "checkpoint {} covers entry {expected}, which the snapshot has not authenticated",
                    checkpoint.seq
                )));
            }
            if leaf.signer != checkpoint.kernel_key {
                return Err(WalkError::Integrity(format!(
                    "checkpoint {} covers mixed receipt signer range: entry {} uses kernel key {}, expected {}",
                    checkpoint.seq, leaf.entry_seq, leaf.signer, checkpoint.kernel_key
                )));
            }
            frontier.append(chio_core::hashing::Hash::from_bytes(leaf.leaf_hash));
            expected += 1;
        }
        if leaves.is_empty() {
            return Err(WalkError::Integrity(format!(
                "checkpoint {} covers entry {expected}, which the snapshot has not authenticated",
                checkpoint.seq
            )));
        }
    }
    let count = i64::try_from(frontier.leaf_count()).unwrap_or(i64::MAX);
    if count != checkpoint.tree_size {
        return Err(WalkError::Integrity(format!(
            "checkpoint {} tree_size {} does not match the authenticated entries {}..={}",
            checkpoint.seq, checkpoint.tree_size, checkpoint.batch_start, checkpoint.batch_end
        )));
    }
    if frontier.root().map(|root| *root.as_bytes()) != Some(checkpoint.merkle_root) {
        return Err(WalkError::Integrity(format!(
            "checkpoint {} merkle_root does not match the authenticated entries {}..={}",
            checkpoint.seq, checkpoint.batch_start, checkpoint.batch_end
        )));
    }
    Ok(())
}
