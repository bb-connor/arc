//! Health of the durable SQLite stores a deployment names.
//!
//! Every store the launch names is checked the way the runtime will open it:
//! a regular file that is not a symlink, readable, and a SQLite database whose
//! `quick_check` answers `ok`. A store that does not exist yet is reported,
//! not failed, because a first launch creates it.

use std::path::{Path, PathBuf};

use super::super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

/// One named store the deployment depends on.
#[derive(Debug, Clone)]
pub struct NamedStore {
    pub label: &'static str,
    pub path: PathBuf,
}

/// What one store looks like on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreState {
    Absent,
    NotARegularFile,
    Symlink,
    Unreadable(String),
    Corrupt(String),
    Healthy { journal_mode: String },
}

/// Inspect one store without changing it.
pub fn inspect_store(path: &Path) -> StoreState {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return StoreState::Absent;
    };
    if metadata.file_type().is_symlink() {
        return StoreState::Symlink;
    }
    if !metadata.file_type().is_file() {
        return StoreState::NotARegularFile;
    }
    let connection = match rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => connection,
        Err(error) => return StoreState::Unreadable(error.to_string()),
    };
    let check: Result<String, rusqlite::Error> =
        connection.query_row("PRAGMA quick_check", [], |row| row.get(0));
    match check {
        Ok(verdict) if verdict == "ok" => {}
        Ok(verdict) => return StoreState::Corrupt(verdict),
        Err(error) => return StoreState::Corrupt(error.to_string()),
    }
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap_or_else(|_| "unknown".to_string());
    StoreState::Healthy { journal_mode }
}

/// Reports whether the named stores can be opened and pass SQLite's check.
pub struct DurableStoreProbe {
    stores: Vec<NamedStore>,
}

impl DurableStoreProbe {
    pub fn new(stores: Vec<NamedStore>) -> Self {
        Self { stores }
    }
}

impl Probe for DurableStoreProbe {
    fn name(&self) -> &'static str {
        "security.durable_stores"
    }

    fn run(&self, _config: &ProbeConfig) -> ProbeReport {
        if self.stores.is_empty() {
            return ProbeReport::fail(
                self.name(),
                ProbeSeverity::Info,
                "urn:chio:error:cli:other",
                "no durable store was named, so store health was not checked",
            )
            .with_help("pass --receipt-db, --session-db and --authority-db as the launch would");
        }
        let mut failures = Vec::new();
        let mut absent = Vec::new();
        let mut contexts = Vec::new();
        for store in &self.stores {
            let state = inspect_store(&store.path);
            let value = match &state {
                StoreState::Absent => {
                    absent.push(store.label);
                    "absent".to_string()
                }
                StoreState::NotARegularFile => {
                    failures.push(format!("{} is not a regular file", store.label));
                    "not a regular file".to_string()
                }
                StoreState::Symlink => {
                    failures.push(format!("{} is a symlink", store.label));
                    "symlink".to_string()
                }
                StoreState::Unreadable(reason) => {
                    failures.push(format!("{} cannot be opened: {reason}", store.label));
                    "unreadable".to_string()
                }
                StoreState::Corrupt(reason) => {
                    failures.push(format!("{} fails quick_check: {reason}", store.label));
                    "corrupt".to_string()
                }
                StoreState::Healthy { journal_mode } => format!("healthy, journal {journal_mode}"),
            };
            contexts.push((store.label, format!("{} ({value})", store.path.display())));
        }
        let mut report = if !failures.is_empty() {
            ProbeReport::fail(
                self.name(),
                ProbeSeverity::Error,
                "urn:chio:error:cli:other",
                format!("durable stores are not healthy: {}", failures.join("; ")),
            )
            .with_help("the runtime refuses symlinked or damaged stores; restore them from the last verified checkpoint")
        } else if absent.is_empty() {
            ProbeReport::ok(
                self.name(),
                format!("{} durable stores open and pass quick_check", self.stores.len()),
            )
        } else {
            ProbeReport::fail(
                self.name(),
                ProbeSeverity::Info,
                "urn:chio:error:cli:other",
                format!("stores not created yet: {}", absent.join(", ")),
            )
            .with_help("a first launch creates them; rerun the preflight after it")
        };
        for (key, value) in contexts {
            report = report.with_context(key, value);
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_database(directory: &Path) -> PathBuf {
        let path = directory.join("healthy.sqlite3");
        let connection = rusqlite::Connection::open(&path).unwrap_or_else(|error| panic!("{error}"));
        connection
            .execute_batch("CREATE TABLE probe (id INTEGER PRIMARY KEY); INSERT INTO probe (id) VALUES (1);")
            .unwrap_or_else(|error| panic!("{error}"));
        path
    }

    #[test]
    fn a_healthy_store_passes_and_an_absent_one_is_informational() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let healthy = healthy_database(directory.path());
        assert!(matches!(inspect_store(&healthy), StoreState::Healthy { .. }));
        assert_eq!(inspect_store(&directory.path().join("missing.sqlite3")), StoreState::Absent);
        let report = DurableStoreProbe::new(vec![
            NamedStore { label: "receipts", path: healthy },
            NamedStore { label: "sessions", path: directory.path().join("missing.sqlite3") },
        ])
        .run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Info);
        assert!(report.message.contains("sessions"));
    }

    #[test]
    fn a_damaged_or_linked_store_fails() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let damaged = directory.path().join("damaged.sqlite3");
        std::fs::write(&damaged, b"not a sqlite database at all, just bytes").unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(inspect_store(&damaged), StoreState::Unreadable(_) | StoreState::Corrupt(_)));
        let healthy = healthy_database(directory.path());
        let link = directory.path().join("link.sqlite3");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&healthy, &link).unwrap_or_else(|error| panic!("{error}"));
        #[cfg(unix)]
        assert_eq!(inspect_store(&link), StoreState::Symlink);
        let report = DurableStoreProbe::new(vec![NamedStore { label: "receipts", path: damaged }])
            .run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Error);
    }

    #[test]
    fn no_store_is_informational() {
        let report = DurableStoreProbe::new(Vec::new()).run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Info);
    }
}
