//! Receipt persistence is unsupported by wrap and must never be silently ignored.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn assert_receipt_db_refused(output: &Output, database: &Path) {
    assert!(
        !output.status.success(),
        "wrap silently accepted --receipt-db"
    );
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostic.contains("mcp wrap does not support --receipt-db"),
        "expected the unsupported persistence reason before any launch: {diagnostic}"
    );
    assert!(
        !database.exists(),
        "refusal must not create a receipt database"
    );
    assert!(!diagnostic.contains("Chio-verified"));
}

fn reject_fixture_receipt_db(strict: bool) -> TestResult {
    let root = tempfile::tempdir()?;
    let database = root.path().join("receipts.sqlite3");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp/echo_server_fixture.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .arg("--receipt-db")
        .arg(&database)
        .args(["mcp", "wrap"]);
    if strict {
        command.arg("--strict-execution-nonce");
    }
    let mut child = command
        .arg("--e2e-fixture")
        .arg(fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("wrap stdin missing")?;
    // An early refusal can close stdin before this write. The exit reason is
    // the assertion; the baseline instead dispatches this allowed call.
    let write = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"hello"}}}}}}"#
    );
    if let Err(error) = write {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(error.into());
        }
    }
    drop(stdin);
    assert_receipt_db_refused(&child.wait_with_output()?, &database);
    Ok(())
}

#[test]
fn wrap_refuses_receipt_db_before_allowed_fixture_call() -> TestResult {
    reject_fixture_receipt_db(false)
}

#[test]
fn strict_wrap_refuses_receipt_db_before_allowed_fixture_call() -> TestResult {
    reject_fixture_receipt_db(true)
}

#[test]
fn wrap_refuses_global_receipt_db_before_reading_native_launch_inputs() -> TestResult {
    let root = tempfile::tempdir()?;
    for global_after_subcommand in [false, true] {
        let database = root.path().join("receipts.sqlite3");
        let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
        if !global_after_subcommand {
            command.arg("--receipt-db").arg(&database);
        }
        command.args(["mcp", "wrap"]);
        if global_after_subcommand {
            command.arg("--receipt-db").arg(&database);
        }
        let output = command
            .arg("--manifest")
            .arg(root.path().join("absent-manifest.json"))
            .arg("--")
            .arg(root.path().join("absent-native-child"))
            .output()?;
        assert_receipt_db_refused(&output, &database);
    }
    Ok(())
}
