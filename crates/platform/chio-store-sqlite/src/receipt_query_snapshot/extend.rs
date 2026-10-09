//! Extension of a published snapshot in finite cycles. Each cycle pins a
//! target, authenticates only the claim entries, checkpoints and lineage rows
//! appended since the previous version, and never re-reads authenticated
//! history.
//!
//! A range that a checkpoint in the target covers is published only after
//! the checkpoint's signed root is verified over it: its leaves are staged
//! first, out of every reader's sight, and each row is then bound to its
//! verified leaf as it is published. Only the uncheckpointed tail beyond the
//! newest such checkpoint is published on receipt signatures alone.
use std::time::Instant;

use super::db::{SnapshotBatch, DIM_CAPABILITY};
use super::service::Published;
use super::walk::{
    authenticate, authenticate_checkpoints, check_sources, checked_prefix, commit_in_holds,
    copy_checkpoints, copy_claims, copy_lineage, observe, owned_checkpoint, pending_leaves,
    within_target, Observation, WalkContext, WalkError,
};

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

    // Pending leaves read or removed per hold, the same bound as inserts.
    let chunk = i64::try_from(ctx.limits.insert_rows.max(1)).unwrap_or(i64::MAX);
    // Leaves an interrupted cycle staged past the published version are
    // staged again below.
    published.settle_residual(state.through_entry_seq + 1, i64::MAX, chunk)?;

    let mut sink = published.sink();
    let mut next = state.through_entry_seq + 1;
    let mut staged = state.through_entry_seq;
    let mut seq = state.checkpoint_seq + 1;
    while seq <= observation.checkpoint {
        ctx.check_cancel()?;
        let rows = copy_checkpoints(ctx, seq, observation.checkpoint)?;
        let (mut previous, mut chain) = published.head_and_chain()?;
        let mut accepted_chain = chain.clone();
        let verified = authenticate_checkpoints(ctx, rows, &mut previous, &mut chain)?;
        for (checkpoint, _) in verified {
            let owned = owned_checkpoint(&checkpoint)?;
            within_target(&owned, observation.head)?;
            stage_leaves(ctx, published, &mut staged, owned.batch_end)?;
            #[cfg(test)]
            published.test_gate(super::service::GatePoint::Settlement)?;
            settle_streaming(published, &owned, chunk)?;
            publish_verified(ctx, &mut sink, published, &mut next, owned.batch_end)?;
            accepted_chain.append(
                chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint.body)
                    .map_err(|error| WalkError::Integrity(error.to_string()))?,
            );
            published.accept_checkpoint(
                &SnapshotBatch {
                    checkpoints: vec![owned.clone()],
                    ..SnapshotBatch::default()
                },
                checkpoint,
                accepted_chain.clone(),
            )?;
            published.settle_residual(owned.batch_start, owned.batch_end, chunk)?;
            seq = owned.seq + 1;
        }
    }

    // The uncheckpointed tail: rows and their pending leaves together.
    while next <= observation.head {
        ctx.check_cancel()?;
        let rows = copy_claims(ctx, next, observation.head)?;
        let entries = authenticate(ctx, rows, None)?;
        let (tools, children) = check_sources(ctx, &entries)?;
        let entries = checked_prefix(&entries, tools.len() + children.len());
        let last = entries.last().map_or(next, |entry| entry.row.entry_seq);
        let pending = pending_leaves(entries);
        commit_in_holds(&mut sink, &ctx.limits, tools, children, pending)?;
        next = last + 1;
    }

    let mut after = state.lineage_rowid;
    while after < observation.lineage_rowid {
        ctx.check_cancel()?;
        let rows = copy_lineage(ctx, after, observation.lineage_rowid, LINEAGE_CHUNK)?;
        let Some(last) = rows.last().map(|row| row.rowid) else {
            break;
        };
        for row in rows {
            match row.subject {
                Ok(subject) => refresh_capability(published, &row.capability_id, &subject)?,
                Err(reason) => refuse_lineage(published, &row.capability_id, &reason)?,
            }
        }
        after = last;
    }
    published.observed(observation, observed_at_ms, observed_at)?;
    Ok(observation)
}

/// Stage the signature-authenticated leaves of the entries after `staged`
/// through `end`, without publishing any row, in holds of at most
/// `insert_rows` leaves.
fn stage_leaves(
    ctx: &WalkContext<'_>,
    published: &Published,
    staged: &mut i64,
    end: i64,
) -> Result<(), WalkError> {
    let hold = ctx.limits.insert_rows.max(1);
    while *staged < end {
        ctx.check_cancel()?;
        let rows = copy_claims(ctx, *staged + 1, end)?;
        let entries = authenticate(ctx, rows, None)?;
        let Some(last) = entries.last().map(|entry| entry.row.entry_seq) else {
            return Err(WalkError::Integrity(format!(
                "claim entry {} that a checkpoint covers is missing",
                *staged + 1
            )));
        };
        for leaves in pending_leaves(&entries).chunks(hold) {
            published.stage(&SnapshotBatch {
                pending: leaves.to_vec(),
                ..SnapshotBatch::default()
            })?;
        }
        *staged = last;
    }
    Ok(())
}

/// Publish the rows of entries `next..=end`, whose leaves a checkpoint root
/// has just verified. Each row is read and authenticated again and must
/// carry exactly the leaf that was verified, so nothing that changed in the
/// meantime is published.
fn publish_verified(
    ctx: &WalkContext<'_>,
    sink: &mut super::service::PublishedSink<'_>,
    published: &Published,
    next: &mut i64,
    end: i64,
) -> Result<(), WalkError> {
    while *next <= end {
        ctx.check_cancel()?;
        #[cfg(test)]
        published.test_gate(super::service::GatePoint::Publication)?;
        let rows = copy_claims(ctx, *next, end)?;
        let entries = authenticate(ctx, rows, None)?;
        let (tools, children) = check_sources(ctx, &entries)?;
        let entries = checked_prefix(&entries, tools.len() + children.len());
        let (Some(first), Some(last)) = (entries.first(), entries.last()) else {
            return Err(WalkError::Integrity(format!(
                "claim entry {} that a checkpoint covers is missing",
                *next
            )));
        };
        let (first, last) = (first.row.entry_seq, last.row.entry_seq);
        let verified = published.with_db(|db| db.pending_leaves(first, last))?;
        if verified != pending_leaves(entries) {
            return Err(WalkError::Integrity(format!(
                "claim entries {first}..={last} changed after their checkpoint root was verified"
            )));
        }
        commit_in_holds(sink, &ctx.limits, tools, children, Vec::new())?;
        *next = last + 1;
    }
    Ok(())
}

/// A lineage row the canonical local reader refuses attributes nothing. When
/// the snapshot holds receipts of its capability, the snapshot is refused.
/// This is deliberately conservative: a build or recertification consults
/// lineage only for a receipt whose signed subject or issuer is absent, so it
/// would refuse the same row for those receipts but not for a capability
/// whose receipts are all fully signed. A row for a capability the snapshot
/// does not hold is validated again when a receipt first needs it.
fn refuse_lineage(published: &Published, capability: &str, reason: &str) -> Result<(), WalkError> {
    let held = published.with_db(|db| Ok(db.dim_id(DIM_CAPABILITY, capability).is_some()))?;
    if held {
        return Err(WalkError::Integrity(format!(
            "capability lineage of {capability} is refused by the local reader: {reason}"
        )));
    }
    Ok(())
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
    chunk: i64,
) -> Result<(), WalkError> {
    let mut frontier = chio_kernel::checkpoint::CheckpointChainFrontier::empty();
    let mut expected = checkpoint.batch_start;
    while expected <= checkpoint.batch_end {
        let high = expected.saturating_add(chunk - 1).min(checkpoint.batch_end);
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
