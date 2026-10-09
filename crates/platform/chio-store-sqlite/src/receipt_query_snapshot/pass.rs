//! Full authentication passes. A build inserts the authenticated history into
//! an unpublished snapshot; a recertification walks the same history again and
//! compares it with the owned rows. Both advance in bounded, resumable steps.
use std::time::Instant;

use chio_kernel::checkpoint::{CheckpointChainFrontier, KernelCheckpoint};

use super::db::{ChildCursor, OwnedCheckpoint, ProjectedToolRow, SnapshotBatch, SnapshotDb};
use super::walk::{
    authenticate, authenticate_checkpoints, check_sources, checked_prefix, commit_in_holds,
    copy_checkpoints, copy_claims, owned_checkpoint, pending_leaves, verify_source_bijection,
    OwnedSink, WalkContext, WalkError,
};

/// Rows counted per hold while verifying the source bijection.
const COUNT_CHUNK: i64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PassMode {
    Build,
    Recertify,
}

/// A pass's fixed target, pinned in one starting observation.
#[derive(Debug, Clone, Copy)]
pub(super) struct Target {
    /// Last claim entry the pass covers.
    pub(super) head: i64,
    /// Newest checkpoint whose batch ends at or below `head`.
    pub(super) checkpoint: i64,
    /// Capability lineage rowid observed with `head`.
    pub(super) lineage_rowid: i64,
    /// Live tool and child source maxima observed with `head`.
    pub(super) max_source_seqs: (i64, i64),
    pub(super) observed_at_ms: u64,
    pub(super) observed_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Chain { next: i64 },
    Batches { next: i64 },
    Tail { next: i64 },
    Final,
    Done,
}

struct BatchState {
    checkpoint: OwnedCheckpoint,
    next_entry: i64,
    leaves: CheckpointChainFrontier,
    count: i64,
}

/// What a completed pass established.
pub(super) struct PassResult {
    pub(super) target: Target,
    pub(super) head: Option<KernelCheckpoint>,
    pub(super) chain: CheckpointChainFrontier,
}

pub(super) enum PassProgress {
    Continue,
    Done(Box<PassResult>),
}

pub(super) struct Pass {
    mode: PassMode,
    target: Target,
    phase: Phase,
    previous: Option<KernelCheckpoint>,
    chain: CheckpointChainFrontier,
    expected_witnesses: u64,
    authenticated: u64,
    batch: Option<BatchState>,
}

impl Pass {
    pub(super) fn new(mode: PassMode, target: Target) -> Self {
        let phase = if target.checkpoint >= 1 {
            Phase::Chain { next: 1 }
        } else {
            Phase::Tail { next: 1 }
        };
        Self {
            mode,
            target,
            phase,
            previous: None,
            chain: CheckpointChainFrontier::empty(),
            expected_witnesses: 0,
            authenticated: 0,
            batch: None,
        }
    }

    /// `(authenticated entries, target entries)` for status reporting.
    pub(super) fn progress(&self) -> (u64, u64) {
        (
            self.authenticated,
            u64::try_from(self.target.head).unwrap_or(0),
        )
    }

    /// Advance by one bounded unit of work. A failed step leaves the pass at
    /// the position it started from, except for an unpublished build whose
    /// failure discards the whole snapshot.
    pub(super) fn step<S: OwnedSink>(
        &mut self,
        ctx: &WalkContext<'_>,
        owned: &mut S,
    ) -> Result<PassProgress, WalkError> {
        ctx.check_cancel()?;
        match self.phase {
            Phase::Chain { next } => self.chain_step(ctx, owned, next),
            Phase::Batches { next } => self.batch_step(ctx, owned, next),
            Phase::Tail { next } => self.tail_step(ctx, owned, next),
            Phase::Final => self.final_step(ctx, owned),
            Phase::Done => Ok(PassProgress::Done(Box::new(self.result()))),
        }
    }

    fn result(&self) -> PassResult {
        PassResult {
            target: self.target,
            head: self.previous.clone(),
            chain: self.chain.clone(),
        }
    }

    fn chain_step<S: OwnedSink>(
        &mut self,
        ctx: &WalkContext<'_>,
        owned: &mut S,
        next: i64,
    ) -> Result<PassProgress, WalkError> {
        let rows = copy_checkpoints(ctx, next, self.target.checkpoint)?;
        let mut previous = self.previous.clone();
        let mut chain = self.chain.clone();
        let verified = authenticate_checkpoints(ctx, rows, &mut previous, &mut chain)?;
        let mut checkpoints = Vec::with_capacity(verified.len());
        let mut witnesses = 0_u64;
        for (checkpoint, _) in &verified {
            if checkpoint.body.previous_checkpoint_sha256.is_some() {
                witnesses = witnesses.saturating_add(1);
            }
            checkpoints.push(owned_checkpoint(checkpoint)?);
        }
        match self.mode {
            PassMode::Build => {
                let batch = SnapshotBatch {
                    checkpoints: checkpoints.clone(),
                    ..SnapshotBatch::default()
                };
                owned.commit(&batch, 0)?;
            }
            PassMode::Recertify => {
                for checkpoint in &checkpoints {
                    let stored = owned.read(|db| db.load_checkpoint(checkpoint.seq))?;
                    if stored.as_ref() != Some(checkpoint) {
                        return Err(WalkError::Integrity(format!(
                            "checkpoint {} differs from the authenticated snapshot",
                            checkpoint.seq
                        )));
                    }
                }
            }
        }
        let last = checkpoints.last().map_or(next, |checkpoint| checkpoint.seq);
        self.previous = previous;
        self.chain = chain;
        self.expected_witnesses = self.expected_witnesses.saturating_add(witnesses);
        self.phase = if last >= self.target.checkpoint {
            Phase::Batches { next: 1 }
        } else {
            Phase::Chain { next: last + 1 }
        };
        Ok(PassProgress::Continue)
    }

    fn batch_step<S: OwnedSink>(
        &mut self,
        ctx: &WalkContext<'_>,
        owned: &mut S,
        next: i64,
    ) -> Result<PassProgress, WalkError> {
        if self.batch.is_none() {
            let checkpoint = owned.read(|db| db.load_checkpoint(next))?.ok_or_else(|| {
                WalkError::Integrity(format!("checkpoint {next} is missing from the snapshot"))
            })?;
            self.batch = Some(BatchState {
                next_entry: checkpoint.batch_start,
                checkpoint,
                leaves: CheckpointChainFrontier::empty(),
                count: 0,
            });
        }
        let Some(state) = self.batch.as_ref() else {
            return Err(WalkError::Integrity(
                "checkpoint batch state is missing".into(),
            ));
        };
        let checkpoint = state.checkpoint.clone();
        let rows = copy_claims(ctx, state.next_entry, checkpoint.batch_end)?;
        let entries = authenticate(ctx, rows, Some(&checkpoint))?;
        let (tools, children) = check_sources(ctx, &entries)?;
        let entries = checked_prefix(&entries, tools.len() + children.len());
        let last = entries
            .last()
            .map_or(state.next_entry, |entry| entry.row.entry_seq);
        let mut leaves = state.leaves.clone();
        for entry in entries {
            leaves.append(chio_core::hashing::Hash::from_bytes(entry.leaf_hash));
        }
        let count = state.count + i64::try_from(entries.len()).unwrap_or(i64::MAX);
        self.apply(owned, entries, tools, children, Vec::new(), &ctx.limits)?;
        if last >= checkpoint.batch_end {
            if count != checkpoint.tree_size {
                return Err(WalkError::Integrity(format!(
                    "checkpoint {} tree_size {} does not match claim receipt log range {}..={} length {count}",
                    checkpoint.seq, checkpoint.tree_size, checkpoint.batch_start, checkpoint.batch_end
                )));
            }
            if leaves.root().map(|root| *root.as_bytes()) != Some(checkpoint.merkle_root) {
                return Err(WalkError::Integrity(format!(
                    "checkpoint {} merkle_root does not match claim receipt log range {}..={}",
                    checkpoint.seq, checkpoint.batch_start, checkpoint.batch_end
                )));
            }
            self.batch = None;
            self.phase = if checkpoint.seq >= self.target.checkpoint {
                Phase::Tail {
                    next: checkpoint.batch_end + 1,
                }
            } else {
                Phase::Batches {
                    next: checkpoint.seq + 1,
                }
            };
        } else if let Some(state) = self.batch.as_mut() {
            state.next_entry = last + 1;
            state.leaves = leaves;
            state.count = count;
        }
        Ok(PassProgress::Continue)
    }

    fn tail_step<S: OwnedSink>(
        &mut self,
        ctx: &WalkContext<'_>,
        owned: &mut S,
        next: i64,
    ) -> Result<PassProgress, WalkError> {
        if next > self.target.head {
            self.phase = Phase::Final;
            return Ok(PassProgress::Continue);
        }
        let rows = copy_claims(ctx, next, self.target.head)?;
        let entries = authenticate(ctx, rows, None)?;
        let (tools, children) = check_sources(ctx, &entries)?;
        let entries = checked_prefix(&entries, tools.len() + children.len());
        let last = entries.last().map_or(next, |entry| entry.row.entry_seq);
        let pending = pending_leaves(entries);
        self.apply(owned, entries, tools, children, pending, &ctx.limits)?;
        self.phase = Phase::Tail { next: last + 1 };
        Ok(PassProgress::Continue)
    }

    /// Insert (build) or compare (recertification) one authenticated range.
    fn apply<S: OwnedSink>(
        &mut self,
        owned: &mut S,
        entries: &[super::walk::AuthenticatedEntry],
        tools: Vec<ProjectedToolRow>,
        children: Vec<ChildCursor>,
        pending: Vec<super::db::PendingLeaf>,
        limits: &super::walk::WalkLimits,
    ) -> Result<(), WalkError> {
        let (Some(first), Some(last)) = (entries.first(), entries.last()) else {
            return Ok(());
        };
        let (first, last) = (first.row.entry_seq, last.row.entry_seq);
        match self.mode {
            PassMode::Build => commit_in_holds(owned, limits, tools, children, pending)?,
            PassMode::Recertify => {
                let (owned_tools, owned_children) = owned.read(|db| db.owned_range(first, last))?;
                compare_tools(&owned_tools, &tools)?;
                if owned_children != children {
                    return Err(WalkError::Integrity(format!(
                        "child receipt cursors in entries {first}..={last} differ from the authenticated snapshot"
                    )));
                }
                // Tail leaves that a verified checkpoint already settled are no
                // longer pending; those still pending must match exactly.
                let owned_pending = owned.read(|db| db.pending_leaves(first, last))?;
                for leaf in &owned_pending {
                    if !pending.contains(leaf) {
                        return Err(WalkError::Integrity(format!(
                            "pending leaf of entry {} differs from the authenticated snapshot",
                            leaf.entry_seq
                        )));
                    }
                }
            }
        }
        self.authenticated = self
            .authenticated
            .saturating_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    fn final_step<S: OwnedSink>(
        &mut self,
        ctx: &WalkContext<'_>,
        owned: &mut S,
    ) -> Result<PassProgress, WalkError> {
        let head = self.target.head;
        let mut owned_counts = |watermark: i64| -> Result<(u64, u64), WalkError> {
            let mut totals = (0_u64, 0_u64);
            let mut low = watermark;
            while low < head {
                let high = low.saturating_add(COUNT_CHUNK).min(head);
                let (tools, children) = owned.read(|db| db.owned_counts_between(low, high))?;
                totals = (totals.0 + tools, totals.1 + children);
                low = high;
            }
            Ok(totals)
        };
        verify_source_bijection(
            ctx,
            self.target.max_source_seqs,
            &mut owned_counts,
            self.target.checkpoint,
            self.expected_witnesses,
        )?;
        self.phase = Phase::Done;
        Ok(PassProgress::Done(Box::new(self.result())))
    }
}

/// Owned rows must equal freshly authenticated rows. The one permitted
/// difference is an unsigned subject that a lineage refresh filled in, in
/// either order relative to this pass.
fn compare_tools(
    owned: &[ProjectedToolRow],
    expected: &[ProjectedToolRow],
) -> Result<(), WalkError> {
    if owned.len() != expected.len() {
        return Err(WalkError::Integrity(format!(
            "snapshot holds {} tool receipts where the claim log authenticates {}",
            owned.len(),
            expected.len()
        )));
    }
    for (owned, expected) in owned.iter().zip(expected) {
        let subject_refreshed = !expected.subject_signed
            && !owned.subject_signed
            && (owned.subject.is_none() || expected.subject.is_none());
        let mut comparable = owned.clone();
        if subject_refreshed {
            comparable.subject.clone_from(&expected.subject);
        }
        if &comparable != expected {
            return Err(WalkError::Integrity(format!(
                "tool receipt at entry {} differs from the authenticated snapshot",
                expected.entry_seq
            )));
        }
    }
    Ok(())
}

/// Build-only access: the unpublished snapshot is owned by the walker.
pub(super) fn build_snapshot(
    ctx: &WalkContext<'_>,
    target: Target,
    quota_bytes: u64,
    on_progress: &mut dyn FnMut(u64, u64),
) -> Result<(SnapshotDb, PassResult), WalkError> {
    let mut db = SnapshotDb::open_private(quota_bytes)?;
    let mut pass = Pass::new(PassMode::Build, target);
    loop {
        let progress = retry_busy(ctx, || pass.step(ctx, &mut db))?;
        let (done, total) = pass.progress();
        on_progress(done, total);
        if let PassProgress::Done(result) = progress {
            return Ok((db, *result));
        }
    }
}

/// Retry a step that met contention, with bounded exponential backoff and
/// cancellation. Every other outcome is returned.
pub(super) fn retry_busy<T>(
    ctx: &WalkContext<'_>,
    mut step: impl FnMut() -> Result<T, WalkError>,
) -> Result<T, WalkError> {
    let mut delay = std::time::Duration::from_millis(10);
    loop {
        match step() {
            Err(WalkError::Busy(_)) => {
                ctx.check_cancel()?;
                std::thread::sleep(delay);
                delay = (delay * 2).min(std::time::Duration::from_secs(1));
            }
            other => return other,
        }
    }
}
