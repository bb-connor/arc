use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum BudgetStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare budget store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("budget arithmetic overflow: {0}")]
    Overflow(String),

    #[error("budget state invariant violated: {0}")]
    Invariant(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,
    pub total_cost_charged: u64,
}

pub trait BudgetStore: Send {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError>;

    /// Atomically check monetary budget limits and charge cost if within bounds.
    ///
    /// Checks:
    /// 1. `invocation_count < max_invocations` (if set)
    /// 2. `cost_units <= max_cost_per_invocation` (if set)
    /// 3. `total_cost_charged + cost_units <= max_total_cost_units` (if set)
    ///
    /// On pass: increments `invocation_count` by 1 and `total_cost_charged` by
    /// `cost_units`, allocates a new replication seq, returns `Ok(true)`.
    /// On any limit exceeded: rolls back, returns `Ok(false)`.
    ///
    // SAFETY: HA overrun bound = max_cost_per_invocation x node_count
    // In a split-brain scenario, each HA node may independently approve up to
    // one invocation at the full per-invocation cap before the LWW merge
    // propagates the updated total. The maximum possible overrun is therefore
    // bounded by max_cost_per_invocation multiplied by the number of active
    // nodes in the HA cluster.
    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    /// Reverse a previously applied monetary charge for a pre-execution denial path.
    fn reverse_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    /// Reduce a previously charged monetary amount without changing invocation count.
    ///
    /// This is used when the kernel pre-debits `max_cost_per_invocation` before
    /// execution and later reconciles the charge down to the actual reported cost.
    fn reduce_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError>;
}

#[derive(Default)]
pub struct InMemoryBudgetStore {
    counts: HashMap<(String, usize), BudgetUsageRecord>,
    next_seq: u64,
}

impl InMemoryBudgetStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BudgetStore for InMemoryBudgetStore {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        let key = (capability_id.to_string(), grant_index);
        let next_seq = self.next_seq.saturating_add(1);
        self.next_seq = next_seq;
        let entry = self.counts.entry(key).or_insert_with(|| BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index: grant_index as u32,
            invocation_count: 0,
            updated_at: unix_now(),
            seq: 0,
            total_cost_charged: 0,
        });
        if let Some(max) = max_invocations {
            if entry.invocation_count >= max {
                return Ok(false);
            }
        }
        entry.invocation_count = entry.invocation_count.saturating_add(1);
        entry.updated_at = unix_now();
        entry.seq = next_seq;
        Ok(true)
    }

    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        let key = (capability_id.to_string(), grant_index);
        let entry = self.counts.entry(key).or_insert_with(|| BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index: grant_index as u32,
            invocation_count: 0,
            updated_at: unix_now(),
            seq: 0,
            total_cost_charged: 0,
        });

        // Check invocation count limit
        if let Some(max) = max_invocations {
            if entry.invocation_count >= max {
                return Ok(false);
            }
        }

        // Check per-invocation cost cap
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                return Ok(false);
            }
        }

        // Check total cost cap
        if let Some(max_total) = max_total_cost_units {
            // Use checked_add to detect overflow: if the addition overflows, deny
            // fail-closed -- an overflowing total cannot be safely compared.
            let new_total = entry
                .total_cost_charged
                .checked_add(cost_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_charged + cost_units overflowed u64".to_string(),
                    )
                })?;
            if new_total > max_total {
                return Ok(false);
            }
        }

        // All checks passed: atomically update counts
        let next_seq = self.next_seq.saturating_add(1);
        self.next_seq = next_seq;
        entry.invocation_count = entry.invocation_count.saturating_add(1);
        // Safe: we already verified no overflow above when max_total is set;
        // when there is no cap, use saturating_add as a defensive measure.
        entry.total_cost_charged = entry.total_cost_charged.saturating_add(cost_units);
        entry.updated_at = unix_now();
        entry.seq = next_seq;
        Ok(true)
    }

    fn reverse_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let key = (capability_id.to_string(), grant_index);
        let entry = self
            .counts
            .get_mut(&key)
            .ok_or_else(|| BudgetStoreError::Invariant("missing charged budget row".to_string()))?;

        if entry.invocation_count == 0 {
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge with zero invocation_count".to_string(),
            ));
        }
        if entry.total_cost_charged < cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge larger than total_cost_charged".to_string(),
            ));
        }

        let next_seq = self.next_seq.saturating_add(1);
        self.next_seq = next_seq;
        entry.invocation_count -= 1;
        entry.total_cost_charged -= cost_units;
        entry.updated_at = unix_now();
        entry.seq = next_seq;
        Ok(())
    }

    fn reduce_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        let key = (capability_id.to_string(), grant_index);
        let entry = self
            .counts
            .get_mut(&key)
            .ok_or_else(|| BudgetStoreError::Invariant("missing charged budget row".to_string()))?;

        if entry.total_cost_charged < cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot reduce charge larger than total_cost_charged".to_string(),
            ));
        }

        let next_seq = self.next_seq.saturating_add(1);
        self.next_seq = next_seq;
        entry.total_cost_charged -= cost_units;
        entry.updated_at = unix_now();
        entry.seq = next_seq;
        Ok(())
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut records = self
            .counts
            .values()
            .filter(|record| capability_id.is_none_or(|value| record.capability_id == value))
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.capability_id.cmp(&right.capability_id))
                .then_with(|| left.grant_index.cmp(&right.grant_index))
        });
        records.truncate(limit);
        Ok(records)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        Ok(self
            .counts
            .get(&(capability_id.to_string(), grant_index))
            .cloned())
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
