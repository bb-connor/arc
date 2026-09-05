use crate::{Error, Result, Run, RunStatus, TaskStatus};
use rusqlite::{params, Connection};
use std::{path::Path, sync::Mutex};

pub(crate) struct Store(Mutex<Connection>);

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS workbench_runs (
                id TEXT PRIMARY KEY, started_at INTEGER NOT NULL, body TEXT NOT NULL);",
        )?;
        let store = Self(Mutex::new(connection));
        for mut run in store.list()? {
            if matches!(run.status, RunStatus::Running | RunStatus::Stopping) {
                run.status = RunStatus::Interrupted;
                run.finished_at = Some(crate::now());
                run.error = Some("Workbench restarted. Review pending actions before starting a new task; their effects may have completed.".into());
                for task in &mut run.tasks {
                    if matches!(task.status, TaskStatus::Running | TaskStatus::Queued) {
                        task.status = TaskStatus::Interrupted;
                    }
                    for action in &mut task.actions {
                        if action.state == "running" {
                            action.state = "unknown".into();
                        }
                    }
                }
                store.save(&run)?;
            }
        }
        Ok(store)
    }
    pub fn save(&self, run: &Run) -> Result<()> {
        self.0.lock().map_err(|_| Error::Lock)?.execute(
            "INSERT INTO workbench_runs VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET body=excluded.body",
            params![
                run.id,
                i64::try_from(run.started_at)
                    .map_err(|_| Error::Invalid("run timestamp exceeds storage range".into()))?,
                serde_json::to_string(run)?
            ],
        )?;
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<Run>> {
        let connection = self.0.lock().map_err(|_| Error::Lock)?;
        let mut statement = connection
            .prepare("SELECT body FROM workbench_runs ORDER BY started_at DESC, id DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }
    pub fn get(&self, id: &str) -> Result<Run> {
        let connection = self.0.lock().map_err(|_| Error::Lock)?;
        let body: String = connection
            .query_row("SELECT body FROM workbench_runs WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Error::NotFound,
                other => Error::Sqlite(other),
            })?;
        Ok(serde_json::from_str(&body)?)
    }
}
