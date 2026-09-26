use rusqlite::{params, TransactionBehavior};
use serde::Serialize;

use super::*;

#[derive(Serialize)]
struct Outcome {
    process: String,
    state: String,
    attempts: u32,
    outcome: Option<String>,
}

impl Service {
    pub(super) fn settle(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        active: &ActiveRun,
        parent: &str,
    ) -> Result<Value, ProcessError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wait {
            children: Vec<String>,
        }
        let wait: Wait = serde_json::from_value(arguments)?;
        let work = self.registry.child_work()?;
        if wait.children.iter().any(|id| {
            !work
                .iter()
                .any(|child| child.process == *id && child.parent == parent)
        }) {
            return Err(ProcessError::Invalid(
                "settlement requires your direct dynamically spawned children",
            ));
        }
        // Acquire no runner write transaction while holding the process store.
        // Wait ownership, cancellation and cycles are checked atomically there.
        let mut db =
            SqliteConnection::open_with_flags(&self.journal, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.pragma_update(None, "synchronous", "FULL")?;
        if worker_state(&db, parent)?.as_deref() != Some("running") {
            return Err(ProcessError::Invalid(
                "caller has no running worker attempt",
            ));
        }
        self.registry
            .wait_for_settled_children(context, &wait.children, |_, proposed| {
                validate_wait(active, proposed)
            })?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if worker_state(&tx, parent)?.as_deref() != Some("running") {
            return Err(ProcessError::Invalid(
                "caller has no running worker attempt",
            ));
        }
        let mut outcomes = Vec::new();
        for child in &wait.children {
            let row = tx
                .query_row(
                    "SELECT state,attempts,outcome FROM run_workers WHERE process=?1",
                    [child],
                    |row| {
                        Ok(Outcome {
                            process: child.clone(),
                            state: row.get(0)?,
                            attempts: row.get(1)?,
                            outcome: row.get(2)?,
                        })
                    },
                )
                .optional()?;
            // A committed submission may not yet have been discovered by the runner.
            let outcome = row.unwrap_or_else(|| Outcome {
                process: child.clone(),
                state: "pending".to_owned(),
                attempts: 0,
                outcome: None,
            });
            if !matches!(
                outcome.state.as_str(),
                "pending" | "running" | "completed" | "failed"
            ) {
                return Err(ProcessError::Invalid("invalid child worker state"));
            }
            outcomes.push(outcome);
        }
        let complete = outcomes
            .iter()
            .all(|o| matches!(o.state.as_str(), "completed" | "failed"));
        if complete {
            for outcome in outcomes.iter().filter(|o| o.state == "failed") {
                // This is a committed tool effect, not a claim about response
                // delivery. Retain the first settlement's kernel request identity.
                tx.execute("INSERT OR IGNORE INTO run_child_settlements(parent,child,request_id) VALUES(?1,?2,?3)",
                    params![parent, outcome.process, context.request_id()])?;
            }
        }
        tx.commit()?;
        Ok(json!({
            "complete": complete,
            "successful": outcomes.iter().all(|o| o.state == "completed"),
            "children": wait.children,
            "outcomes": outcomes,
        }))
    }
}
