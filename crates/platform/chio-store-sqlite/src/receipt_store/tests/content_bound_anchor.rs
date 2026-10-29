//! A qualified receipt store binds the content of every anchored commit, so a
//! database that reaches the anchored generation with different content is
//! refused.

use super::super::*;
use super::support::*;
use std::path::{Path, PathBuf};

struct World {
    directory: tempfile::TempDir,
    anchors: tempfile::TempDir,
}

struct Snapshot {
    database: PathBuf,
    anchors: PathBuf,
}

fn copy_files(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            std::fs::copy(entry.path(), to.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn clear_files(directory: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

impl World {
    fn new(prefix: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let anchors = rollback_anchor_tempdir(prefix)?;
        #[cfg(unix)]
        for root in [directory.path(), anchors.path()] {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { directory, anchors })
    }

    fn database(&self) -> PathBuf {
        self.directory.path().join("fork.sqlite3")
    }

    fn open(&self) -> Result<SqliteReceiptStore, ReceiptStoreError> {
        SqliteReceiptStore::open_for_finding_pool(&self.database(), self.anchors.path())
    }

    fn checkpoint_wal(&self) -> Result<(), Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open(self.database())?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    fn snapshot(&self, name: &str) -> Result<Snapshot, Box<dyn std::error::Error>> {
        self.checkpoint_wal()?;
        let root = self.directory.path().join(format!("snapshot-{name}"));
        let snapshot = Snapshot {
            database: root.join("database.sqlite3"),
            anchors: root.join("anchors"),
        };
        std::fs::create_dir_all(&root)?;
        std::fs::copy(self.database(), &snapshot.database)?;
        copy_files(self.anchors.path(), &snapshot.anchors)?;
        Ok(snapshot)
    }

    fn restore_database(&self, snapshot: &Snapshot) -> std::io::Result<()> {
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.database().display()));
        }
        std::fs::copy(&snapshot.database, self.database())?;
        Ok(())
    }

    fn restore_anchors(&self, snapshot: &Snapshot) -> std::io::Result<()> {
        clear_files(self.anchors.path())?;
        copy_files(&snapshot.anchors, self.anchors.path())
    }
}

fn keypair() -> chio_core::crypto::Keypair {
    chio_core::crypto::Keypair::from_seed(&[7u8; 32])
}

fn seed(store: &SqliteReceiptStore) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = keypair();
    store.enable_background_checkpoints(signer(&keypair, 2))?;
    for index in 0..2u64 {
        let receipt = sample_receipt_with_keypair_and_timestamp(
            &format!("fork-aged-{index}"),
            index + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    for index in 2..6u64 {
        let receipt = sample_receipt_with_keypair_and_timestamp(
            &format!("fork-fresh-{index}"),
            index + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    Ok(())
}

type Operation = fn(&SqliteReceiptStore, &Path, &str) -> Result<(), Box<dyn std::error::Error>>;

fn append_receipt(
    store: &SqliteReceiptStore,
    _: &Path,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = sample_receipt_with_keypair_and_timestamp(
        &format!("fork-extra-{label}"),
        7,
        600,
        &keypair(),
    );
    store.append_chio_receipt_returning_seq(&receipt)?;
    Ok(())
}

fn writer_closure(
    store: &SqliteReceiptStore,
    _: &Path,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    store.record_receipt_lineage_statement_record(
        "fork-aged-0",
        Some("fork-request"),
        Some("fork-session"),
        None,
        None,
        None,
        Some(label),
        1_000,
        &serde_json::json!({ "fork": label }),
    )?;
    Ok(())
}

fn retention_delete(
    store: &SqliteReceiptStore,
    archives: &Path,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let archive = archives.join(format!("archive-{label}.sqlite3"));
    let archived = store.archive_receipts_before(150, archive.to_str().ok_or("archive path")?)?;
    assert_eq!(archived, 2);
    Ok(())
}

fn assert_equal_generation_fork_is_refused(
    name: &str,
    operation: Operation,
) -> Result<(), Box<dyn std::error::Error>> {
    let world = World::new(&format!("chio-fork-{name}"))?;
    {
        let store = world.open()?;
        seed(&store)?;
    }
    let base = world.snapshot("base")?;

    {
        let store = world.open()?;
        operation(&store, world.directory.path(), "a")?;
        store.flush_receipt_writes()?;
    }
    let branch_a = world.snapshot("a")?;

    world.restore_database(&base)?;
    world.restore_anchors(&base)?;
    {
        let store = world.open()?;
        operation(&store, world.directory.path(), "b")?;
        store.flush_receipt_writes()?;
    }
    let branch_b = world.snapshot("b")?;

    world.restore_anchors(&branch_a)?;
    world.restore_database(&branch_a)?;
    world
        .open()
        .map(drop)
        .map_err(|error| format!("the anchored branch itself must open: {error}"))?;

    world.restore_anchors(&branch_a)?;
    world.restore_database(&branch_b)?;
    let error = world
        .open()
        .err()
        .ok_or("a database that forked at the anchored generation was accepted")?;
    assert!(
        matches!(&error, ReceiptStoreError::Conflict(message) if message.contains("rollback head")),
        "unexpected fork error: {error}"
    );
    Ok(())
}

#[test]
fn a_batch_append_fork_at_the_anchored_generation_is_refused(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_equal_generation_fork_is_refused("append", append_receipt)
}

#[test]
fn a_writer_closure_fork_at_the_anchored_generation_is_refused(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_equal_generation_fork_is_refused("closure", writer_closure)
}

#[test]
fn a_retention_fork_at_the_anchored_generation_is_refused() -> Result<(), Box<dyn std::error::Error>>
{
    assert_equal_generation_fork_is_refused("retention", retention_delete)
}

#[test]
fn flipping_the_head_in_the_database_alone_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let world = World::new("chio-fork-head-flip")?;
    {
        let store = world.open()?;
        seed(&store)?;
    }
    world.checkpoint_wal()?;
    let connection = rusqlite::Connection::open(world.database())?;
    connection.execute(
        "UPDATE chio_receipt_sink_generation SET head_sha256 = ?1",
        [format!("{:064x}", 1)],
    )?;
    drop(connection);
    let error = world
        .open()
        .err()
        .ok_or("a database with a rewritten head was accepted")?;
    assert!(
        matches!(&error, ReceiptStoreError::Conflict(message) if message.contains("rollback head")),
        "unexpected head-flip error: {error}"
    );
    Ok(())
}

#[test]
fn distinct_writer_closures_at_one_generation_leave_distinct_heads(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut heads = Vec::new();
    for label in ["one", "two"] {
        let world = World::new("chio-fork-closure-heads")?;
        {
            let store = world.open()?;
            seed(&store)?;
        }
        let base = world.snapshot("base")?;
        world.restore_anchors(&base)?;
        world.restore_database(&base)?;
        {
            let store = world.open()?;
            writer_closure(&store, world.directory.path(), label)?;
            store.flush_receipt_writes()?;
        }
        world.checkpoint_wal()?;
        let connection = rusqlite::Connection::open(world.database())?;
        heads.push(connection.query_row(
            "SELECT head_sha256 FROM chio_receipt_sink_generation",
            [],
            |row| row.get::<_, String>(0),
        )?);
    }
    assert_ne!(heads[0], heads[1]);
    Ok(())
}
