//! Probe the documented process-local file ledger, using the pinned upstream API.
//! Synthetic bytes only; this does not launch a coding agent or a confined process.
use appa_engine::label::{Audience, Label, ReaderId, Trust};
use appa_engine::value::{DispatchId, TrajectoryId};
use appa_eventlog::files::{FileOperation, FileOutcome, FileStore, PinnedBasis};
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = PathBuf::from(env::args().nth(1).expect("scratch workspace argument"));
    fs::create_dir_all(&workspace)?;
    let file = workspace.join("example.txt");
    fs::write(&file, b"initial synthetic bytes")?;
    let initial = Label::top();
    let restricted = Label::new(
        Trust::new(1),
        Audience::restricted([ReaderId::new("hr@company.test")]),
    );
    let store = FileStore::new(&workspace, &initial)?;
    store.prepare("probe", "replace", FileOperation::Replace, "example.txt")?;
    let dispatch = DispatchId::new(
        TrajectoryId::new("probe"),
        serde_json::from_value(serde_json::json!("ab".repeat(32)))?,
        0,
    );
    store.bind("probe", "replace", &dispatch, &restricted)?;
    fs::write(&file, b"synthetic HR-only value")?;
    let before = match store.finish("probe", "replace", true)?.outcome {
        FileOutcome::Succeeded { version: Some(version) } => version,
        other => panic!("replace did not publish: {other:?}"),
    };
    assert_eq!(before.label, restricted);
    drop(store);

    let reopened = FileStore::new(&workspace, &initial)?;
    let after = match reopened.prepare("probe", "read", FileOperation::Read, "example.txt")?.basis {
        PinnedBasis::Read(version) => version,
        other => panic!("read did not pin: {other:?}"),
    };
    assert_eq!(before.digest, after.digest, "bytes must be identical");
    assert_eq!(after.label, initial, "fresh ledger adopts its initial label");
    assert_ne!(before.label, after.label, "the recorded restriction was forgotten");
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "experiment": "file-ledger-recreation",
        "passed": true,
        "scope": "FileStore API; recreation of the in-memory ledger, not a full runtime restart",
        "unchanged_digest": before.digest,
        "label_before": before.label,
        "label_after": after.label,
        "interpretation": "A fresh FileStore forgets the recorded label and adopts configured initial classification. This confirms a documented experimental limitation."
    }))?);
    Ok(())
}
