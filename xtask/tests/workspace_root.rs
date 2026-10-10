use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);
const MANIFEST: &str = "tests/bindings/vectors/MANIFEST.sha256";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, Box<dyn Error>> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let counter = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "chio-xtask-root-{}-{timestamp}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn checkout(root: &Path, value: &str) -> Result<String, Box<dyn Error>> {
    fs::create_dir_all(root.join("xtask/src"))?;
    fs::create_dir_all(root.join("crates/core/chio-core/src"))?;
    fs::create_dir_all(root.join("tests/bindings/vectors"))?;
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"xtask\", \"crates/core/chio-core\"]\n",
    )?;
    fs::write(
        root.join("xtask/Cargo.toml"),
        "[package]\nname = \"xtask\"\n",
    )?;
    fs::write(
        root.join("crates/core/chio-core/Cargo.toml"),
        "[package]\nname = \"chio-core\"\n",
    )?;
    fs::write(root.join("tests/bindings/vectors/value.json"), value)?;
    let manifest = format!(
        "{:x}  tests/bindings/vectors/value.json\n",
        Sha256::digest(value.as_bytes())
    );
    fs::write(root.join(MANIFEST), &manifest)?;
    Ok(manifest)
}

fn run_from(directory: &Path, check: bool, stale_checkout: &Path) -> std::io::Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command
        .current_dir(directory)
        // Cargo and frozen-binary callers can retain unrelated environment
        // values. Neither may redirect the invocation to a different checkout.
        .env("CARGO_MANIFEST_DIR", stale_checkout.join("xtask"))
        .env(
            "CARGO_MANIFEST_PATH",
            stale_checkout.join("xtask/Cargo.toml"),
        )
        .arg("freeze-vectors");
    if check {
        command.arg("--check");
    }
    command.output()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_refused(output: &Output, reason: &str) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn reused_binary_checks_and_updates_only_the_invocation_checkout() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::new()?;
    let first = scratch.0.join("first");
    let second = scratch.0.join("second");
    let first_manifest = checkout(&first, "1")?;
    let second_manifest = checkout(&second, "2")?;

    // The binary was compiled outside either fixture. Verify the paths it
    // actually selected before permitting this test to invoke a writing task.
    for (root, stale) in [(&first, &second), (&second, &first)] {
        let output = run_from(root, true, stale)?;
        assert_success(&output);
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains(root.join(MANIFEST).to_string_lossy().as_ref()));
    }

    fs::write(second.join("tests/bindings/vectors/value.json"), "3")?;
    assert!(!run_from(&second, true, &first)?.status.success());
    assert_success(&run_from(&second, false, &first)?);
    assert_ne!(fs::read_to_string(second.join(MANIFEST))?, second_manifest);
    assert_eq!(fs::read_to_string(first.join(MANIFEST))?, first_manifest);
    assert_success(&run_from(&second, true, &first)?);
    Ok(())
}

#[test]
fn member_and_plain_subdirectories_find_their_checkout() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::new()?;
    checkout(&scratch.0, "1")?;
    for relative in [
        "xtask",
        "xtask/src",
        "crates/core/chio-core/src",
        "tests/bindings",
    ] {
        assert_success(&run_from(&scratch.0.join(relative), true, &scratch.0)?);
    }
    Ok(())
}

#[test]
fn outside_checkout_refuses_a_stale_manifest_environment() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::new()?;
    let source = scratch.0.join("source");
    let original = checkout(&source, "1")?;
    let output = run_from(&scratch.0, true, &source)?;
    assert_refused(&output, "no Chio workspace found");
    assert_eq!(fs::read_to_string(source.join(MANIFEST))?, original);
    Ok(())
}

#[test]
fn nested_unrelated_boundaries_refuse_the_containing_checkout() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::new()?;
    let original = checkout(&scratch.0, "1")?;
    for (name, marker, contents, reason) in [
        (
            "cargo-workspace",
            "Cargo.toml",
            "[workspace]\nmembers = []\n",
            "is not a Chio workspace",
        ),
        (
            "cargo-package",
            "Cargo.toml",
            "[package]\nname = \"unrelated\"\n",
            "is not a member of",
        ),
        (
            "git-worktree",
            ".git",
            "gitdir: /irrelevant/path\n",
            "no Chio workspace found",
        ),
        ("malformed", "Cargo.toml", "[workspace\n", "cannot parse"),
    ] {
        let nested = scratch.0.join(name);
        fs::create_dir_all(nested.join("child"))?;
        fs::write(nested.join(marker), contents)?;
        assert_refused(&run_from(&nested.join("child"), true, &scratch.0)?, reason);
    }
    let nested = scratch.0.join("git-checkout");
    fs::create_dir_all(nested.join(".git"))?;
    assert_refused(
        &run_from(&nested, true, &scratch.0)?,
        "no Chio workspace found",
    );
    let bare = scratch.0.join("bare.git");
    fs::create_dir_all(bare.join("objects"))?;
    fs::write(bare.join("HEAD"), "ref: refs/heads/main\n")?;
    fs::write(bare.join("config"), "[core]\nbare = true\n")?;
    assert_refused(
        &run_from(&bare.join("objects"), true, &scratch.0)?,
        "no Chio workspace found",
    );
    let metadata = scratch.0.join(".git/worktrees/another");
    fs::create_dir_all(&metadata)?;
    assert_refused(
        &run_from(&metadata, true, &scratch.0)?,
        "no Chio workspace found",
    );
    assert_eq!(fs::read_to_string(scratch.0.join(MANIFEST))?, original);
    Ok(())
}

#[test]
fn incomplete_or_misidentified_chio_workspaces_fail_closed() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::new()?;
    let original = checkout(&scratch.0, "1")?;
    let core_manifest = scratch.0.join("crates/core/chio-core/Cargo.toml");
    fs::write(&core_manifest, "[package]\nname = \"unrelated\"\n")?;
    assert_refused(
        &run_from(&scratch.0, true, &scratch.0)?,
        "is not a Chio workspace",
    );
    fs::remove_file(&core_manifest)?;
    assert_refused(
        &run_from(&scratch.0, true, &scratch.0)?,
        "is not a Chio workspace",
    );
    assert_eq!(fs::read_to_string(scratch.0.join(MANIFEST))?, original);
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_working_directory_resolves_the_physical_checkout() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::new()?;
    let source = scratch.0.join("source");
    let other = scratch.0.join("other");
    checkout(&source, "1")?;
    checkout(&other, "2")?;
    let alias = other.join("source-alias");
    std::os::unix::fs::symlink(&source, &alias)?;
    let output = run_from(&alias.join("xtask/src"), true, &other)?;
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains(source.join(MANIFEST).to_string_lossy().as_ref()));
    Ok(())
}
