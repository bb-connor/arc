use super::*;

use std::collections::HashMap;

use chio_kernel::budget_store::{
    BudgetReconcileHoldRequest, BudgetReleaseHoldRequest, BudgetReverseHoldRequest,
};

/// Outcome of a startup reap pass over orphaned open holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapSummary {
    pub reconciled: usize,
    pub reversed: usize,
}

/// An open reserved hold past its TTL deadline:
/// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority)`.
type ExpiredReservedHold = (String, String, u32, u64, Option<BudgetEventAuthority>);

impl SqliteBudgetStore {
    /// Reconcile or reverse every hold still `open` at startup. Holds present in
    /// `realized_by_hold` (arbitrated by the ADR-0013 durable receipt log) are
    /// reconciled to their realized spend; holds absent from it (never durably
    /// admitted) are reversed. This is fail-closed against double-spend: a naive
    /// blanket release is never used.
    ///
    /// Called by the `BudgetStore` trait implementation of `reap_orphaned_holds`.
    pub fn reap_holds_by_map(
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

    /// Release every reserved hold that is still `open` and whose
    /// `reserved_until` deadline is at or before `now_unix_secs`, freeing the
    /// reserved exposure back to the grant. Fail-closed: only holds explicitly
    /// marked reserved (a non-NULL `reserved_until`) and past expiry are
    /// touched; a not-yet-expired reserved hold and any non-open hold are left
    /// alone. Returns the number of holds released.
    pub fn reap_expired_reserved_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<usize, BudgetStoreError> {
        let expired = self.list_expired_reserved_holds(now_unix_secs)?;
        let mut released = 0usize;
        for (hold_id, capability_id, grant_index, remaining, authority) in expired {
            self.release_budget_hold(BudgetReleaseHoldRequest {
                capability_id,
                grant_index: grant_index as usize,
                released_exposure_units: remaining,
                hold_id: Some(hold_id.clone()),
                event_id: Some(format!("{hold_id}:ttl-reap-release")),
                authority,
            })?;
            released += 1;
        }
        Ok(released)
    }

    /// Open reserved holds past their expiry:
    /// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority)`.
    fn list_expired_reserved_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<Vec<ExpiredReservedHold>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let mut statement = connection.prepare(
            "SELECT hold_id, capability_id, grant_index, remaining_exposure_units, \
             authority_id, lease_id, lease_epoch \
             FROM budget_authorization_holds \
             WHERE disposition = 'open' AND reserved_until IS NOT NULL AND reserved_until <= ?1",
        )?;
        let rows = statement.query_map([now_unix_secs], |row| {
            let authority = sqlite_budget_event_authority(row.get(4)?, row.get(5)?, row.get(6)?)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u32,
                row.get::<_, i64>(3)? as u64,
                authority,
            ))
        })?;
        let mut holds = Vec::new();
        for row in rows {
            holds.push(row?);
        }
        Ok(holds)
    }

    /// Stamp an open hold with a TTL reaper deadline. Errors fail-closed when the
    /// hold is missing or is no longer open.
    pub fn mark_hold_reserved_until(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
    ) -> Result<(), BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let affected = connection.execute(
            "UPDATE budget_authorization_holds \
             SET reserved_until = ?2 \
             WHERE hold_id = ?1 AND disposition = 'open'",
            params![hold_id, reserved_until_unix_secs],
        )?;
        if affected == 0 {
            return Err(BudgetStoreError::Invariant(format!(
                "cannot mark budget hold `{hold_id}` reserved: missing or not open"
            )));
        }
        Ok(())
    }

    /// Project a single hold by id, including its reserved-until deadline.
    pub fn budget_hold_snapshot(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        connection
            .query_row(
                "SELECT hold_id, capability_id, grant_index, authorized_exposure_units, \
                 remaining_exposure_units, disposition, reserved_until, \
                 authority_id, lease_id, lease_epoch \
                 FROM budget_authorization_holds WHERE hold_id = ?1",
                params![hold_id],
                |row| {
                    let disposition = row.get::<_, String>(5)?;
                    let disposition = HoldDisposition::parse(&disposition)
                        .map(|value| match value {
                            HoldDisposition::Open => BudgetHoldDispositionView::Open,
                            HoldDisposition::Released => BudgetHoldDispositionView::Released,
                            HoldDisposition::Reversed => BudgetHoldDispositionView::Reversed,
                            HoldDisposition::Reconciled => BudgetHoldDispositionView::Reconciled,
                        })
                        .ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                5,
                                rusqlite::types::Type::Text,
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("unknown hold disposition `{disposition}`"),
                                )),
                            )
                        })?;
                    let authority =
                        sqlite_budget_event_authority(row.get(7)?, row.get(8)?, row.get(9)?)?;
                    Ok(BudgetHoldSnapshot {
                        hold_id: row.get::<_, String>(0)?,
                        capability_id: row.get::<_, String>(1)?,
                        grant_index: row.get::<_, i64>(2)? as usize,
                        authorized_exposure_units: row.get::<_, i64>(3)? as u64,
                        remaining_exposure_units: row.get::<_, i64>(4)? as u64,
                        disposition,
                        reserved_until: row.get::<_, Option<i64>>(6)?,
                        authority,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Rows still `open`: `(hold_id, capability_id, grant_index, remaining_exposure_units)`.
    pub(super) fn list_open_holds(
        &self,
    ) -> Result<Vec<(String, String, u32, u64)>, BudgetStoreError> {
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
    fn ttl_reaper_releases_only_expired_unreconciled_reserved_holds() {
        use chio_kernel::budget_store::{BudgetHoldDispositionView, BudgetReconcileHoldRequest};

        let store = open_temp_store();
        // Expired reserved hold.
        authorize(&store, "hold-expired", "cap-a");
        store.mark_hold_reserved_until("hold-expired", 100).unwrap();
        // Not-yet-expired reserved hold.
        authorize(&store, "hold-fresh", "cap-b");
        store.mark_hold_reserved_until("hold-fresh", 5_000).unwrap();
        // Reconciled reserved hold.
        authorize(&store, "hold-done", "cap-c");
        store.mark_hold_reserved_until("hold-done", 100).unwrap();
        store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-c".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 40,
                hold_id: Some("hold-done".to_string()),
                event_id: Some("hold-done:reconcile".to_string()),
                authority: None,
            })
            .unwrap();

        let released = store.reap_expired_reserved_holds(1_000).unwrap();
        assert_eq!(released, 1, "only the expired reserved hold is released");

        // cap-a expired reserved hold released, exposure freed to 0.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-expired")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Released
        );
        // cap-b not-yet-expired reserved hold untouched.
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-fresh")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Open
        );
        // cap-c reconciled hold untouched (realized 40).
        assert_eq!(
            store
                .get_usage("cap-c", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-done")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
    }

    #[test]
    fn budget_hold_snapshot_projects_reserved_hold() {
        use chio_kernel::budget_store::BudgetHoldDispositionView;

        let store = open_temp_store();
        authorize(&store, "hold-snap", "cap-snap");
        assert!(store
            .budget_hold_snapshot("hold-missing")
            .unwrap()
            .is_none());
        store.mark_hold_reserved_until("hold-snap", 4_242).unwrap();
        let snapshot = store.budget_hold_snapshot("hold-snap").unwrap().unwrap();
        assert_eq!(snapshot.capability_id, "cap-snap");
        assert_eq!(snapshot.remaining_exposure_units, 100);
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.reserved_until, Some(4_242));
    }

    #[test]
    fn mark_hold_reserved_on_missing_hold_fails_closed() {
        let store = open_temp_store();
        assert!(store.mark_hold_reserved_until("nope", 100).is_err());
    }

    #[test]
    fn reaper_reconciles_admitted_hold_and_reverses_orphan() {
        // SIGKILL after authorize commits but before reconcile. A naive
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
        let summary = store.reap_holds_by_map(&realized).unwrap();
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
