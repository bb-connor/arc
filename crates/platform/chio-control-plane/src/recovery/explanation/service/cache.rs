//! Bounded process-local retention of original native advisory graphs.
use super::*;
use std::sync::Weak;

mod bounds;
mod compact;
mod flat_label;

pub(super) const MAX_GRAPHS: usize = 32;
pub(super) const MAX_GRAPHS_PER_ACTOR: usize = 8;

struct Entry {
    workflow: WorkflowId,
    graph: Arc<compact::CompactGraph>,
    expanded: Weak<ProtectedRecoveryExplanationV1>,
}

pub(super) struct GraphCache {
    entries: BTreeMap<ExplanationRef, Entry>,
    reservation: usize,
    maximum_reserved: usize,
}

impl GraphCache {
    pub(super) fn new() -> Result<Self, RecoveryRuntimeError> {
        let reservation = bounds::reservation_bytes()?;
        let maximum_reserved = reservation
            .checked_mul(MAX_GRAPHS)
            .ok_or(RecoveryRuntimeError::UnsupportedProfile)?;
        Ok(Self {
            entries: BTreeMap::new(),
            reservation,
            maximum_reserved,
        })
    }

    fn expire(&mut self, now: u64) {
        self.entries
            .retain(|_, entry| now < entry.graph.expires_at());
    }

    pub(super) fn insert(
        &mut self,
        workflow: &WorkflowId,
        graph: Arc<compact::CompactGraph>,
        now: u64,
    ) -> Result<(), RecoveryRuntimeError> {
        self.expire(now);
        let next_reserved = self
            .entries
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(self.reservation))
            .ok_or(RecoveryRuntimeError::Unavailable)?;
        if !graph.valid_at(now)
            || self.entries.contains_key(graph.reference())
            || next_reserved > self.maximum_reserved
            || self
                .entries
                .values()
                .filter(|entry| entry.graph.recipient() == graph.recipient())
                .count()
                >= MAX_GRAPHS_PER_ACTOR
        {
            return Err(RecoveryRuntimeError::Unavailable);
        }
        self.entries.insert(
            graph.reference().clone(),
            Entry {
                workflow: workflow.clone(),
                graph,
                expanded: Weak::new(),
            },
        );
        Ok(())
    }

    pub(super) fn graph(
        &mut self,
        workflow: &WorkflowId,
        reference: &ExplanationRef,
        now: u64,
    ) -> Result<
        (
            Arc<compact::CompactGraph>,
            Option<Arc<ProtectedRecoveryExplanationV1>>,
        ),
        RecoveryRuntimeError,
    > {
        self.expire(now);
        let entry = self
            .entries
            .get(reference)
            .filter(|entry| &entry.workflow == workflow && entry.graph.valid_at(now))
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?;
        Ok((entry.graph.clone(), entry.expanded.upgrade()))
    }

    pub(super) fn remember_expansion(
        &mut self,
        workflow: &WorkflowId,
        reference: &ExplanationRef,
        original: &Arc<compact::CompactGraph>,
        expanded: Arc<ProtectedRecoveryExplanationV1>,
        now: u64,
    ) -> Result<Arc<ProtectedRecoveryExplanationV1>, RecoveryRuntimeError> {
        self.expire(now);
        let entry = self
            .entries
            .get_mut(reference)
            .filter(|entry| {
                &entry.workflow == workflow
                    && entry.graph.valid_at(now)
                    && Arc::ptr_eq(&entry.graph, original)
            })
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?;
        if let Some(existing) = entry.expanded.upgrade() {
            return Ok(existing);
        }
        entry.expanded = Arc::downgrade(&expanded);
        Ok(expanded)
    }
}

impl core::fmt::Debug for GraphCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GraphCache([redacted])")
    }
}

pub(super) fn compact(
    artifact: ProtectedRecoveryExplanationV1,
) -> Result<Arc<compact::CompactGraph>, RecoveryRuntimeError> {
    compact::CompactGraph::new(artifact).map(Arc::new)
}
