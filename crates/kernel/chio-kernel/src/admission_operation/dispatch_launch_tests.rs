use super::*;
use crate::admission_operation::{
    AdmissionDispatchCommitBindingV1, ATTEMPT_SCOPED_RECEIPT_METADATA_PATHS,
};

fn native(id: char) -> serde_json::Value {
    serde_json::json!({"receipt_id": id.to_string().repeat(64), "receipt_sha256": "d".repeat(64)})
}

fn worker(attempt: u32) -> serde_json::Value {
    serde_json::json!({
        "kind": "container",
        "launch_attempt": attempt,
        "launch_ref": {"record_id": "a".repeat(64), "record_sha256": "e".repeat(64)},
    })
}

fn metadata(
    native_launch: serde_json::Value,
    worker_profile: serde_json::Value,
) -> AdmittedReceiptMetadata {
    let value = serde_json::json!({
        "native_launch": native_launch,
        "chio_process": {"process_id": "worker", "attempt": 1, "worker_profile": worker_profile},
        "route": {"selectedRoute": "mcp:tools"},
    });
    value.as_object().cloned().unwrap_or_default()
}

#[test]
fn dispatch_launch_carries_exactly_the_attempt_scoped_metadata_entries() {
    let paths: [&[&str]; 2] = [&["native_launch"], &["chio_process", "worker_profile"]];
    assert_eq!(ATTEMPT_SCOPED_RECEIPT_METADATA_PATHS, paths);
}

#[test]
fn dispatch_launch_is_read_from_the_presenting_metadata() -> Result<(), AdmissionOperationError> {
    let launch =
        AdmissionDispatchLaunchV1::from_admitted_metadata(Some(&metadata(native('b'), worker(2))))?;
    assert_eq!(launch.native_launch(), Some(&native('b')));
    assert_eq!(launch.worker_profile(), Some(&worker(2)));
    assert_eq!(
        AdmissionDispatchLaunchV1::from_admitted_metadata(None)?,
        AdmissionDispatchLaunchV1::default()
    );
    Ok(())
}

#[test]
fn malformed_dispatch_launch_entries_are_refused() {
    let mut malformed_native = metadata(native('b'), worker(1));
    malformed_native.insert(
        "native_launch".into(),
        serde_json::json!({"receipt_id": "x"}),
    );
    assert!(matches!(
        AdmissionDispatchLaunchV1::from_admitted_metadata(Some(&malformed_native)),
        Err(AdmissionOperationError::InvalidDispatchLaunch {
            entry: "native_launch"
        })
    ));
    let malformed_worker = metadata(native('b'), serde_json::json!({"kind": "direct"}));
    assert!(matches!(
        AdmissionDispatchLaunchV1::from_admitted_metadata(Some(&malformed_worker)),
        Err(AdmissionOperationError::InvalidDispatchLaunch {
            entry: "worker_profile"
        })
    ));
}

#[test]
fn dispatch_launch_names_both_entries_when_persisted() -> Result<(), serde_json::Error> {
    let launch: AdmissionDispatchLaunchV1 = serde_json::from_value(
        serde_json::json!({"native_launch": native('b'), "worker_profile": null}),
    )?;
    assert_eq!(launch.native_launch(), Some(&native('b')));
    assert_eq!(launch.worker_profile(), None);
    assert_eq!(
        serde_json::to_value(&launch)?,
        serde_json::json!({"native_launch": native('b'), "worker_profile": null})
    );
    for persisted in [
        serde_json::json!({"native_launch": null}),
        serde_json::json!({"native_launch": null, "worker_profile": null, "extra": 1}),
    ] {
        let error = serde_json::from_value::<AdmissionDispatchLaunchV1>(persisted)
            .err()
            .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("dispatch launch must name exactly native_launch and worker_profile")
        );
    }
    let error = serde_json::from_value::<AdmissionDispatchLaunchV1>(
        serde_json::json!({"native_launch": {"receipt_id": "x"}, "worker_profile": null}),
    )
    .err()
    .map(|error| error.to_string());
    assert_eq!(
        error.as_deref(),
        Some("native_launch dispatch launch evidence is malformed")
    );
    Ok(())
}

#[test]
fn refusal_metadata_names_the_dispatching_launches() -> Result<(), AdmissionOperationError> {
    let dispatching =
        AdmissionDispatchLaunchV1::from_admitted_metadata(Some(&metadata(native('b'), worker(2))))?;
    let mut admitted = metadata(native('a'), worker(1));
    dispatching.apply_to(&mut admitted);
    assert_eq!(admitted, metadata(native('b'), worker(2)));

    let mut admitted = metadata(native('a'), worker(1));
    AdmissionDispatchLaunchV1::default().apply_to(&mut admitted);
    assert_eq!(admitted.get("native_launch"), None);
    assert_eq!(
        admitted
            .get("chio_process")
            .and_then(|process| process.get("worker_profile")),
        None
    );
    assert_eq!(
        admitted.get("route"),
        Some(&serde_json::json!({"selectedRoute": "mcp:tools"}))
    );
    Ok(())
}

#[test]
fn a_dispatch_commit_without_its_launch_is_refused() {
    let persisted = serde_json::json!({
        "committed_version": 8,
        "coordinator_lease_id": "lease",
        "coordinator_lease_epoch": 1,
        "store_fence": {"store_uuid": "store", "lease_id": "lease", "owner_epoch": 1},
        "provider_attempt": null,
    });
    let error = serde_json::from_value::<AdmissionDispatchCommitBindingV1>(persisted)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error.as_deref(), Some("missing field `dispatch_launch`"));
}
