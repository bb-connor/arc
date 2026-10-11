use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::{
    AdmitMode, BudgetRegistry, BudgetSplit, BudgetSplitError, MAX_BUDGET_PARENTS,
    MAX_BUDGET_SHARE_BPS, MAX_REGISTRY_CHILD_EDGES, MAX_REGISTRY_RETAINED_ID_BYTES,
};

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;

#[derive(Debug, Clone)]
struct RegisteredParent {
    split: BudgetSplit,
    /// Expiry of the verified parent token, in Unix seconds. `None` marks
    /// operator state, which never expires.
    expires_at_secs: Option<u64>,
}

/// Pure in-memory [`BudgetRegistry`] backed by a [`BTreeMap`].
///
/// This implementation is `no_std` friendly: it keeps a deterministic map
/// keyed by parent capability id and never reaches for clocks, locks, or
/// allocators outside `alloc`. Hosted callers that need shared mutable
/// access across threads should wrap it in their own `Mutex` / `RwLock`.
///
/// Retention is bounded registry-wide by [`MAX_BUDGET_PARENTS`],
/// [`MAX_REGISTRY_CHILD_EDGES`] and [`MAX_REGISTRY_RETAINED_ID_BYTES`]. The
/// counters below always equal the retained state.
#[derive(Debug, Default, Clone)]
pub struct InMemoryBudgetRegistry {
    parents: BTreeMap<String, RegisteredParent>,
    child_edges: usize,
    /// Owned id bytes: each parent id twice (map key and split) plus every
    /// child id.
    retained_id_bytes: usize,
    /// Highest trusted time supplied with a verified parent registration.
    latest_trusted_now_secs: Option<u64>,
}

impl InMemoryBudgetRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the live split for `parent_token_id`, if any. Useful for
    /// tests and operator dashboards that want to inspect headroom.
    #[must_use]
    pub fn split(&self, parent_token_id: &str) -> Option<&BudgetSplit> {
        self.parents
            .get(parent_token_id)
            .map(|parent| &parent.split)
    }

    /// Return the recorded expiry of `parent_token_id`, or `None` when the
    /// parent is unknown or registered as non-expiring operator state.
    #[must_use]
    pub fn parent_expires_at_secs(&self, parent_token_id: &str) -> Option<u64> {
        self.parents
            .get(parent_token_id)
            .and_then(|parent| parent.expires_at_secs)
    }

    /// Register a verified parent token together with its expiry and the
    /// trusted time at which it was verified.
    ///
    /// `now_secs` raises the registry's trusted-time watermark, which is the
    /// only time expired parents are reclaimed against. A parent already
    /// registered without an expiry and with the same share stays
    /// non-expiring; the same expiry and share is idempotent. Any other
    /// existing registration is kept and the call refuses. A new parent
    /// that is already expired at the watermark registers nothing.
    pub fn register_expiring_parent(
        &mut self,
        parent_token_id: String,
        parent_share_bps: u16,
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<(), BudgetSplitError> {
        let now_secs = self
            .latest_trusted_now_secs
            .map_or(now_secs, |latest| latest.max(now_secs));
        self.latest_trusted_now_secs = Some(now_secs);
        if let Some(existing) = self.parents.get(&parent_token_id) {
            if existing.split.parent_share_bps != parent_share_bps {
                return Err(BudgetSplitError::DuplicateChild {
                    child_id: parent_token_id,
                });
            }
            return match existing.expires_at_secs {
                None => Ok(()),
                Some(recorded) if recorded == expires_at_secs => Ok(()),
                Some(_) => Err(BudgetSplitError::ParentExpiryConflict { parent_token_id }),
            };
        }
        if now_secs >= expires_at_secs {
            return Err(BudgetSplitError::ExpiredParent { parent_token_id });
        }
        self.insert_parent(parent_token_id, parent_share_bps, Some(expires_at_secs))
    }

    fn insert_parent(
        &mut self,
        parent_token_id: String,
        parent_share_bps: u16,
        expires_at_secs: Option<u64>,
    ) -> Result<(), BudgetSplitError> {
        if parent_share_bps > MAX_BUDGET_SHARE_BPS {
            return Err(BudgetSplitError::ChildShareExceedsCap {
                child_id: parent_token_id,
                share_bps: parent_share_bps,
            });
        }
        let id_bytes = parent_token_id
            .len()
            .checked_mul(2)
            .ok_or_else(|| capacity_exhausted(&parent_token_id))?;
        let retained_id_bytes = self.reserve(&parent_token_id, 1, 0, id_bytes)?;
        self.parents.insert(
            parent_token_id.clone(),
            RegisteredParent {
                split: BudgetSplit::new(parent_token_id, parent_share_bps),
                expires_at_secs,
            },
        );
        self.retained_id_bytes = retained_id_bytes;
        Ok(())
    }

    /// Return the retained id bytes after adding `id_bytes`, reclaiming
    /// expired parents once if a registry-wide bound would be exceeded.
    fn reserve(
        &mut self,
        parent_token_id: &str,
        new_parents: usize,
        new_edges: usize,
        id_bytes: usize,
    ) -> Result<usize, BudgetSplitError> {
        if let Some(retained) = self.fits(new_parents, new_edges, id_bytes) {
            return Ok(retained);
        }
        self.reclaim_expired_parents();
        self.fits(new_parents, new_edges, id_bytes)
            .ok_or_else(|| capacity_exhausted(parent_token_id))
    }

    fn fits(&self, new_parents: usize, new_edges: usize, id_bytes: usize) -> Option<usize> {
        let parents = self.parents.len().checked_add(new_parents)?;
        let edges = self.child_edges.checked_add(new_edges)?;
        let retained = self.retained_id_bytes.checked_add(id_bytes)?;
        (parents <= MAX_BUDGET_PARENTS
            && edges <= MAX_REGISTRY_CHILD_EDGES
            && retained <= MAX_REGISTRY_RETAINED_ID_BYTES)
            .then_some(retained)
    }

    /// Evict every parent that is expired at the trusted-time watermark and
    /// has no live lease holder. Without a watermark nothing is reclaimed.
    fn reclaim_expired_parents(&mut self) {
        let Some(now_secs) = self.latest_trusted_now_secs else {
            return;
        };
        let expired: Vec<String> = self
            .parents
            .iter()
            .filter(|(_, parent)| {
                parent
                    .expires_at_secs
                    .is_some_and(|expires_at_secs| now_secs >= expires_at_secs)
                    && !parent
                        .split
                        .children
                        .values()
                        .any(|admission| admission.holders > 0)
            })
            .map(|(parent_token_id, _)| parent_token_id.clone())
            .collect();
        for parent_token_id in expired {
            self.remove_parent(&parent_token_id);
        }
    }

    fn remove_parent(&mut self, parent_token_id: &str) {
        let Some(parent) = self.parents.remove(parent_token_id) else {
            return;
        };
        let parent_id_bytes = parent_token_id.len().saturating_mul(2);
        self.child_edges = self.child_edges.saturating_sub(parent.split.child_count());
        self.retained_id_bytes = self
            .retained_id_bytes
            .saturating_sub(parent_id_bytes)
            .saturating_sub(parent.split.retained_child_id_bytes);
    }

    fn admit(
        &mut self,
        parent_token_id: &str,
        child_token_id: String,
        share_bps: u16,
        mode: AdmitMode,
    ) -> Result<(), BudgetSplitError> {
        let is_fresh = match self.parents.get(parent_token_id) {
            Some(parent) => parent.split.child_share_bps(&child_token_id).is_none(),
            None => {
                return Err(BudgetSplitError::UnknownParent {
                    parent_token_id: parent_token_id.into(),
                })
            }
        };
        let retained_id_bytes = if is_fresh {
            Some(self.reserve(parent_token_id, 0, 1, child_token_id.len())?)
        } else {
            None
        };
        let Some(parent) = self.parents.get_mut(parent_token_id) else {
            return Err(BudgetSplitError::UnknownParent {
                parent_token_id: parent_token_id.into(),
            });
        };
        let edges_before = parent.split.child_count();
        parent.split.admit_child(child_token_id, share_bps, mode)?;
        if let Some(retained_id_bytes) = retained_id_bytes {
            if parent.split.child_count() > edges_before {
                self.child_edges = self.child_edges.saturating_add(1);
                self.retained_id_bytes = retained_id_bytes;
            }
        }
        Ok(())
    }
}

fn capacity_exhausted(parent_token_id: &str) -> BudgetSplitError {
    BudgetSplitError::RegistryCapacityExhausted {
        parent_token_id: parent_token_id.into(),
    }
}

impl BudgetRegistry for InMemoryBudgetRegistry {
    fn register_parent(
        &mut self,
        parent_token_id: String,
        parent_share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        if let Some(existing) = self.parents.get(&parent_token_id) {
            if existing.split.parent_share_bps == parent_share_bps {
                return Ok(());
            }
            return Err(BudgetSplitError::DuplicateChild {
                child_id: parent_token_id,
            });
        }
        self.insert_parent(parent_token_id, parent_share_bps, None)
    }

    fn try_admit_child(
        &mut self,
        parent_token_id: &str,
        child_token_id: String,
        share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        self.admit(parent_token_id, child_token_id, share_bps, AdmitMode::Lease)
    }

    fn verify_child_admission(
        &mut self,
        parent_token_id: &str,
        child_token_id: String,
        share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        self.admit(
            parent_token_id,
            child_token_id,
            share_bps,
            AdmitMode::VerifyOnly,
        )
    }

    fn release_child(
        &mut self,
        parent_token_id: &str,
        child_token_id: &str,
        expected_share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        let Some(parent) = self.parents.get_mut(parent_token_id) else {
            return Ok(());
        };
        let edges_before = parent.split.child_count();
        parent
            .split
            .release_child(child_token_id, expected_share_bps)?;
        if parent.split.child_count() < edges_before {
            self.child_edges = self.child_edges.saturating_sub(1);
            self.retained_id_bytes = self.retained_id_bytes.saturating_sub(child_token_id.len());
        }
        Ok(())
    }

    fn evict_parent(&mut self, parent_token_id: &str) {
        self.remove_parent(parent_token_id);
    }
}
