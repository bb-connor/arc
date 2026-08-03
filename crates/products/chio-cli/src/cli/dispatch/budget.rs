// Dispatch handlers for the `chio budget` command group.

use super::*;

use chio_kernel::budget_store::{BudgetStore, OpenHoldSummary};

pub(crate) fn dispatch_budget(
    command: BudgetCommands,
    json_output: bool,
    budget_db: Option<PathBuf>,
) -> Result<(), CliError> {
    match command {
        BudgetCommands::Holds { command } => match command {
            BudgetHoldsCommands::List {
                store,
                older_than_secs,
                json,
            } => {
                let path = resolve_store(store, budget_db)?;
                let cutoff_unix_ms = older_than_secs
                    .map(|secs| now_unix_ms().saturating_sub(secs.saturating_mul(1_000)))
                    .unwrap_or(u64::MAX);
                let holds = list_open_holds(&path, cutoff_unix_ms)?;
                if json || json_output {
                    let value = serde_json::json!({
                        "schema": "chio.cli.budget.holds.list.v1",
                        "openHolds": holds.iter().map(|hold| serde_json::json!({
                            "holdId": hold.hold_id,
                            "capabilityId": hold.capability_id,
                            "grantIndex": hold.grant_index,
                            "remainingExposureUnits": hold.remaining_exposure_units,
                            "createdAtUnixMs": hold.created_at_unix_ms,
                        })).collect::<Vec<_>>(),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&value)
                            .map_err(|error| CliError::Other(format!("budget holds: {error}")))?
                    );
                } else {
                    for hold in &holds {
                        println!(
                            "{}  capability={} grant={} remaining={} created_ms={}",
                            hold.hold_id,
                            hold.capability_id,
                            hold.grant_index,
                            hold.remaining_exposure_units,
                            hold.created_at_unix_ms
                        );
                    }
                    println!("{} open hold(s)", holds.len());
                }
                Ok(())
            }
        },
    }
}

fn resolve_store(
    explicit: Option<PathBuf>,
    budget_db: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    explicit.or(budget_db).ok_or_else(|| {
        CliError::Other(
            "no budget store path (pass --store or the global --budget-db)".to_string(),
        )
    })
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn list_open_holds(
    path: &std::path::Path,
    cutoff_unix_ms: u64,
) -> Result<Vec<OpenHoldSummary>, CliError> {
    let store = chio_store_sqlite::SqliteBudgetStore::open(path)
        .map_err(|error| CliError::Other(format!("open budget store: {error}")))?;
    store
        .list_open_holds_older_than(cutoff_unix_ms, 10_000)
        .map_err(|error| CliError::Other(format!("list open holds: {error}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "chio-{prefix}-{}-{nonce}.sqlite3",
            std::process::id()
        ))
    }

    #[test]
    fn holds_list_preserves_the_open_hold() {
        use chio_kernel::budget_store::BudgetAuthorizeHoldRequest;

        let path = unique_db_path("cli-holds");
        {
            let store = chio_store_sqlite::SqliteBudgetStore::open(&path).unwrap();
            store
                .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                    "cap".to_string(),
                    0,
                    Some(5),
                    30,
                    Some(30),
                    Some(300),
                    Some("cli-hold-1".to_string()),
                    Some("cli-hold-1:authorize".to_string()),
                    None,
                ))
                .unwrap();
        }
        // List returns the open hold.
        let listed = list_open_holds(&path, u64::MAX).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hold_id, "cli-hold-1");
        // Inspection cannot mutate ambiguous capacity.
        assert_eq!(list_open_holds(&path, u64::MAX).unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
