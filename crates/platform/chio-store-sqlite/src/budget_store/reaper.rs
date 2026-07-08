use super::*;

use std::collections::HashMap;

use chio_kernel::budget_store::{BudgetReconcileHoldRequest, BudgetReverseHoldRequest};

/// Outcome of a startup reap pass over orphaned open holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapSummary {
    pub reconciled: usize,
    pub reversed: usize,
}

impl SqliteBudgetStore {
    /// Reconcile or reverse every hold still `open` at startup. Holds present in
    /// `realized_by_hold` (arbitrated by the ADR-0013 durable receipt log) are
    /// reconciled to their realized spend; holds absent from it (never durably
    /// admitted) are reversed. This is fail-closed against double-spend: a naive
    /// blanket release is never used.
    pub fn reap_orphaned_holds(
        &self,
        realized_by_hold: &HashMap<String, u64>,
    ) -> Result<ReapSummary, BudgetStoreError> {
        let open_holds = self.list_open_holds()?;
        let mut summary = ReapSummary {
            reconciled: 0,
            reversed: 0,
        };
        for (hold_id, capability_id, grant_index, exposure) in open_holds {
            match realized_by_hold.get(&hold_id) {
                Some(&realized) => {
                    self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: grant_index as usize,
                        exposed_cost_units: exposure,
                        realized_spend_units: realized.min(exposure),
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reconcile")),
                        authority: None,
                    })?;
                    summary.reconciled += 1;
                }
                None => {
                    self.reverse_budget_hold(BudgetReverseHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: grant_index as usize,
                        reversed_exposure_units: exposure,
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reverse")),
                        authority: None,
                    })?;
                    summary.reversed += 1;
                }
            }
        }
        Ok(summary)
    }

    /// Rows still `open`: `(hold_id, capability_id, grant_index, remaining_exposure_units)`.
    fn list_open_holds(&self) -> Result<Vec<(String, String, u32, u64)>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let mut statement = connection.prepare(
            "SELECT hold_id, capability_id, grant_index, remaining_exposure_units \
             FROM budget_authorization_holds WHERE disposition = 'open'",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u32,
                row.get::<_, i64>(3)? as u64,
            ))
        })?;
        let mut holds = Vec::new();
        for row in rows {
            holds.push(row?);
        }
        Ok(holds)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };
    use std::collections::HashMap;

    fn open_temp_store() -> SqliteBudgetStore {
        let dir = std::env::temp_dir().join(format!("chio-reaper-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap()
    }

    fn authorize(store: &SqliteBudgetStore, hold_id: &str, cap: &str) {
        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: cap.to_string(),
                grant_index: 0,
                max_invocations: Some(10),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1000),
                hold_id: Some(hold_id.to_string()),
                event_id: Some(format!("{hold_id}:authorize")),
                authority: None,
            })
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }

    #[test]
    fn reaper_reconciles_admitted_hold_and_reverses_orphan() {
        // R3: SIGKILL after authorize commits but before reconcile. A naive
        // "release Open on restart" would enable double-spend; instead the
        // durable receipt log arbitrates.
        let store = open_temp_store();
        authorize(&store, "hold-admitted", "cap-a"); // durably admitted, realized 40
        authorize(&store, "hold-orphan", "cap-b"); // never admitted downstream
                                                   // Before reap both holds inflate committed_cost by their worst-case 100.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );

        let mut realized = HashMap::new();
        realized.insert("hold-admitted".to_string(), 40u64);
        let summary = store.reap_orphaned_holds(&realized).unwrap();
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.reversed, 1);

        // cap-a reconciled down to realized 40; cap-b reversed back to 0.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            0
        );
    }
}
