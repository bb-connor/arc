#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use super::*;

use std::collections::HashMap;

use chio_kernel::budget_store::{
    BudgetCaptureInvocationRequest, BudgetReconcileHoldRequest, BudgetReverseHoldRequest,
};

/// Outcome of a startup reap pass over orphaned open holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapSummary {
    pub reconciled: usize,
    pub reversed: usize,
}

/// A hold still `open` at startup:
/// `(hold_id, capability_id, grant_index, remaining_exposure_units,
/// invocation_captured, authority)`.
type OpenHold = (String, String, u32, u64, bool, Option<BudgetEventAuthority>);

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
        let mut first_error = None;
        for (hold_id, capability_id, grant_index, exposure, captured, authority) in open_holds {
            // Kernel-authored holds carry a BudgetEventAuthority lease that the
            // reconcile/reverse authority check enforces. Present each hold's stored
            // authority so orphaned kernel holds are reclaimed rather than rejected;
            // a hold whose authority columns cannot be loaded fails closed in
            // `list_open_holds` rather than silently reaping with no authority.
            let result = (|| match realized_by_hold.get(&hold_id) {
                Some(&realized) => {
                    if !captured {
                        self.capture_invocation_reservations(BudgetCaptureInvocationRequest {
                            capability_id: capability_id.clone(),
                            grant_index: crate::integer::checked::<_, usize>(grant_index)?,
                            hold_id: hold_id.clone(),
                            event_id: format!("{hold_id}:reap-capture-invocation"),
                            trusted_time: None,
                            authority: authority.clone(),
                        })?;
                    }
                    if exposure > 0 {
                        self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                            capability_id: capability_id.clone(),
                            grant_index: crate::integer::checked::<_, usize>(grant_index)?,
                            exposed_cost_units: exposure,
                            realized_spend_units: realized.min(exposure),
                            hold_id: Some(hold_id.clone()),
                            event_id: Some(format!("{hold_id}:reap-reconcile")),
                            authority,
                        })?;
                    }
                    Ok(true)
                }
                None if captured => {
                    if exposure > 0 {
                        self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                            capability_id: capability_id.clone(),
                            grant_index: crate::integer::checked::<_, usize>(grant_index)?,
                            exposed_cost_units: exposure,
                            realized_spend_units: exposure,
                            hold_id: Some(hold_id.clone()),
                            event_id: Some(format!("{hold_id}:reap-unknown-outcome")),
                            authority,
                        })?;
                    }
                    Ok(true)
                }
                None => {
                    self.reverse_budget_hold(BudgetReverseHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: crate::integer::checked::<_, usize>(grant_index)?,
                        reversed_exposure_units: exposure,
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reverse")),
                        authority,
                        expected_cumulative_approval_state: None,
                    })?;
                    Ok(false)
                }
            })();
            match result {
                Ok(true) => {
                    summary.reconciled = summary
                        .reconciled
                        .checked_add(1)
                        .ok_or_else(|| BudgetStoreError::Overflow("reap count overflow".into()))?
                }
                Ok(false) => {
                    summary.reversed = summary
                        .reversed
                        .checked_add(1)
                        .ok_or_else(|| BudgetStoreError::Overflow("reap count overflow".into()))?
                }
                Err(error) => {
                    tracing::warn!(
                        hold_id,
                        error = %error,
                        "orphan budget hold cleanup failed"
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        first_error.map_or(Ok(summary), Err)
    }

    /// Project a hold and its mutation authority by id.
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
                 remaining_exposure_units, disposition, authority_id, lease_id, lease_epoch \
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
                        sqlite_budget_event_authority(row.get(6)?, row.get(7)?, row.get(8)?)?;
                    Ok(BudgetHoldSnapshot {
                        hold_id: row.get::<_, String>(0)?,
                        capability_id: row.get::<_, String>(1)?,
                        grant_index: crate::integer::checked::<_, usize>(row.get::<_, i64>(2)?)?,
                        authorized_exposure_units: crate::integer::checked::<_, u64>(
                            row.get::<_, i64>(3)?,
                        )?,
                        remaining_exposure_units: crate::integer::checked::<_, u64>(
                            row.get::<_, i64>(4)?,
                        )?,
                        disposition,
                        authority,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Rows still `open`:
    /// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority)`.
    /// A hold with inconsistent authority lease columns is rejected fail-closed.
    pub(super) fn list_open_holds(&self) -> Result<Vec<OpenHold>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let mut statement = connection.prepare(
            "SELECT hold_id, capability_id, grant_index, remaining_exposure_units, \
             invocation_captured, authority_id, lease_id, lease_epoch \
             FROM budget_authorization_holds WHERE disposition = 'open'",
        )?;
        let rows = statement.query_map([], |row| {
            let authority = sqlite_budget_event_authority(row.get(5)?, row.get(6)?, row.get(7)?)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                crate::integer::checked::<_, u32>(row.get::<_, i64>(2)?)?,
                crate::integer::checked::<_, u64>(row.get::<_, i64>(3)?)?,
                row.get::<_, i64>(4)? != 0,
                authority,
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetHoldDispositionView,
        BudgetStore,
    };
    use std::collections::HashMap;

    fn open_temp_store() -> SqliteBudgetStore {
        let dir = std::env::temp_dir().join(format!("chio-reaper-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap()
    }

    fn authorize(store: &SqliteBudgetStore, hold_id: &str, cap: &str) {
        authorize_with_authority(store, hold_id, cap, None);
    }

    fn capture_invocation(store: &SqliteBudgetStore, hold_id: &str, cap: &str) {
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: cap.to_string(),
                grant_index: 0,
                hold_id: hold_id.to_string(),
                event_id: format!("{hold_id}:capture-invocation"),
                trusted_time: None,
                authority: None,
            })
            .unwrap();
    }

    fn authorize_with_authority(
        store: &SqliteBudgetStore,
        hold_id: &str,
        cap: &str,
        authority: Option<BudgetEventAuthority>,
    ) {
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
                authority,
                invocation_quotas: Vec::new(),
                cumulative_approval: None,
                admission_binding: None,
            })
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }

    #[test]
    fn budget_hold_snapshot_preserves_authority() -> Result<(), Box<dyn std::error::Error>> {
        let store = open_temp_store();
        let authority = BudgetEventAuthority {
            authority_id: "kernel-authority".to_string(),
            lease_id: "hold-lease".to_string(),
            lease_epoch: 0,
        };
        authorize_with_authority(&store, "hold-snap", "cap-snap", Some(authority.clone()));
        assert_eq!(store.budget_hold_snapshot("hold-missing")?, None);
        assert_eq!(
            store.budget_hold_snapshot("hold-snap")?,
            Some(BudgetHoldSnapshot {
                hold_id: "hold-snap".to_string(),
                capability_id: "cap-snap".to_string(),
                grant_index: 0,
                authorized_exposure_units: 100,
                remaining_exposure_units: 100,
                disposition: BudgetHoldDispositionView::Open,
                authority: Some(authority),
            })
        );
        Ok(())
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

    #[test]
    fn reaper_forfeits_captured_orphan_at_worst_case() {
        let store = open_temp_store();
        authorize(&store, "hold-captured", "cap-captured");
        capture_invocation(&store, "hold-captured", "cap-captured");

        let summary = store.reap_holds_by_map(&HashMap::new()).unwrap();

        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.reversed, 0);
        assert_eq!(
            store
                .get_usage("cap-captured", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-captured")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
    }

    #[test]
    fn reaper_reclaims_kernel_authored_holds_bearing_authority() {
        // Kernel-authored holds carry a BudgetEventAuthority lease. A crash after
        // authorize leaves them open; the reaper must load and present each hold's
        // stored authority so the store's authority check passes and the orphaned
        // holds are reclaimed rather than left reserved indefinitely.
        let store = open_temp_store();
        let authority = BudgetEventAuthority {
            authority_id: "kernel-authority".to_string(),
            lease_id: "lease-1".to_string(),
            lease_epoch: 0,
        };
        authorize_with_authority(&store, "hold-admitted", "cap-a", Some(authority.clone()));
        authorize_with_authority(&store, "hold-orphan", "cap-b", Some(authority));

        let mut realized = HashMap::new();
        realized.insert("hold-admitted".to_string(), 40u64);
        let summary = store.reap_holds_by_map(&realized).unwrap();
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.reversed, 1);

        // cap-a reconciled to realized 40; cap-b orphan reversed to 0.
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
