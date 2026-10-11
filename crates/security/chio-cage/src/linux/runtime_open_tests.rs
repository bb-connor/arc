use super::*;
use chio_test_support::prelude::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const FIFO_PROBE_PATH: &str = "CHIO_CAGE_REVIEW2_FIFO_PROBE_PATH";
const FIFO_PROBE_ROLE: &str = "CHIO_CAGE_REVIEW2_FIFO_PROBE_ROLE";
const FIFO_PROBE_TEST: &str =
    "linux::runtime_open_tests::runtime_artifacts_reject_fifo_without_waiting_for_writer";

fn wait_for_probe(child: &mut Child) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                child.wait().test_unwrap();
                return false;
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("unable to supervise owned FIFO probe: {error}");
            }
        }
    }
}

#[test]
fn runtime_artifacts_reject_fifo_without_waiting_for_writer() {
    if let Some(path) = std::env::var_os(FIFO_PROBE_PATH) {
        let path = PathBuf::from(path);
        let role = match std::env::var(FIFO_PROBE_ROLE).test_unwrap().as_str() {
            "helper" => RuntimeArtifactRole::CageInitHelper,
            "target" => RuntimeArtifactRole::TargetExecutable,
            "runtime" => RuntimeArtifactRole::RuntimeFile,
            other => panic!("unexpected FIFO probe role: {other}"),
        };
        let result = retain_runtime_artifact(&path, role, 64);
        assert!(
            matches!(&result, Err(CageError::UnsupportedResourceKind(rejected)) if rejected == &path),
            "FIFO was not refused at descriptor-kind validation: {result:?}"
        );
        return;
    }

    let tree = chio_test_support::private_tempdir().test_unwrap();
    let fifo = tree.path().join("artifact.fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .test_unwrap()
        .success());
    let mut outcomes = Vec::new();
    for role in ["helper", "target", "runtime"] {
        let mut child = Command::new(std::env::current_exe().test_unwrap())
            .args(["--exact", FIFO_PROBE_TEST, "--nocapture"])
            .env(FIFO_PROBE_PATH, &fifo)
            .env(FIFO_PROBE_ROLE, role)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .test_unwrap();
        let completed = wait_for_probe(&mut child);
        let output = child.wait_with_output().test_unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for line in stdout.lines().chain(stderr.lines()) {
            eprintln!("FIFO probe {role}: {line}");
        }
        outcomes.push((role, completed));
    }
    assert_eq!(
        outcomes,
        vec![("helper", true), ("target", true), ("runtime", true)]
    );
}

#[test]
fn regular_runtime_artifact_retains_original_descriptor_after_path_replacement() {
    let tree = chio_test_support::private_tempdir().test_unwrap();
    let path = tree.path().join("runtime.data");
    let previous = tree.path().join("previous.data");
    std::fs::write(&path, b"old").test_unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).test_unwrap();
    let retained =
        retain_runtime_artifact(&path, RuntimeArtifactRole::RuntimeFile, 64).test_unwrap();
    let original_identity = retained.resource.identity;

    std::fs::rename(&path, &previous).test_unwrap();
    std::fs::write(&path, b"replacement").test_unwrap();
    assert_ne!(
        std::fs::metadata(&path).test_unwrap().ino(),
        original_identity.inode()
    );
    assert_eq!(
        descriptor_identity(&retained.resource.file, Some(&path)).test_unwrap(),
        original_identity
    );
    assert_eq!(
        read_stable_content(&retained.resource.file, &path, 64)
            .test_unwrap()
            .0,
        b"old"
    );
}
