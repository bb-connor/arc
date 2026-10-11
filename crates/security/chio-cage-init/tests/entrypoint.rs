//! The packaged bootstrap must reject invocation without its authenticated control FD.
#![cfg(target_os = "linux")]
use chio_test_support::prelude::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn standalone_helper_rejects_missing_control_descriptor() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_chio-cage-init"))
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .test_expect("spawn packaged helper");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().test_expect("observe helper") {
            assert_eq!(status.code(), Some(127));
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("unauthenticated helper invocation did not terminate");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
