use std::path::{Path, PathBuf};
use std::process::Command;

use chio_runtime_core::computer::branches::{
    BranchError, BranchState, ChangeStatus, Limits, ManagedBranches, PublicationState,
    UnsupportedKind,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn git_binary() -> Result<PathBuf, &'static str> {
    let path = std::env::var_os("PATH").ok_or("PATH is unset")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|candidate| candidate.is_file())
        .ok_or("git is not on PATH")
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: PathBuf,
    source: PathBuf,
}

fn fixture() -> Result<Fixture, std::io::Error> {
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("store.git");
    let source = dir.path().join("source");
    std::fs::create_dir_all(source.join("src"))?;
    std::fs::write(source.join("README.md"), "project\n")?;
    std::fs::write(source.join("src/lib.rs"), "pub fn one() -> u8 { 1 }\n")?;
    Ok(Fixture {
        _dir: dir,
        store,
        source,
    })
}

fn open(fixture: &Fixture) -> Result<ManagedBranches, Box<dyn std::error::Error>> {
    Ok(ManagedBranches::open(
        &git_binary()?,
        &fixture.store,
        Limits::default(),
    )?)
}

fn read_tree_file(
    store: &Path,
    tree: &str,
    path: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let output = Command::new(git_binary()?)
        .env("GIT_DIR", store)
        .args(["cat-file", "blob", &format!("{tree}:{path}")])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8(output.stdout)?))
}

fn raw_git(
    store: &Path,
    args: &[&str],
    stdin: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut child = Command::new(git_binary()?)
        .env("GIT_DIR", store)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!("git {args:?} failed").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn sealed_branch(
    branches: &ManagedBranches,
    project: &str,
    branch: &str,
    path: &str,
    body: &str,
) -> Result<(), BranchError> {
    let snapshot = branches.snapshot(project)?;
    let lease = branches.create_branch(&snapshot, branch)?;
    branches.stage_write(&lease, path, body.as_bytes(), false)?;
    branches.freeze(branch)?;
    branches.seal(branch, "operation-1")
}

#[test]
fn branches_are_isolated_from_each_other_and_from_the_project() -> TestResult {
    let fixture = fixture()?;
    let branches = open(&fixture)?;
    let snapshot = branches.import_project("demo", &fixture.source)?;
    assert_eq!(snapshot.entries().len(), 2);

    let a = branches.create_branch(&snapshot, "branch-a")?;
    let b = branches.create_branch(&snapshot, "branch-b")?;
    let a_tree = branches.stage_write(&a, "src/lib.rs", b"pub fn one() -> u8 { 2 }\n", false)?;
    branches.stage_remove(&a, "README.md")?;

    assert_eq!(branches.branch_tree("branch-b")?, snapshot.tree());
    assert_eq!(branches.project_head("demo")?, snapshot.tree());
    assert_eq!(
        read_tree_file(&fixture.store, snapshot.tree(), "src/lib.rs")?.as_deref(),
        Some("pub fn one() -> u8 { 1 }\n")
    );
    assert_eq!(
        read_tree_file(&fixture.store, &a_tree, "src/lib.rs")?.as_deref(),
        Some("pub fn one() -> u8 { 2 }\n")
    );
    assert_eq!(b.generation(), 0);

    branches.freeze("branch-a")?;
    branches.seal("branch-a", "operation-a")?;
    let changes = branches.diff("branch-a", &|_| true)?;
    let summary: Vec<_> = changes
        .iter()
        .map(|c| (c.path.as_str(), c.status))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("README.md", ChangeStatus::Deleted),
            ("src/lib.rs", ChangeStatus::Modified)
        ]
    );
    assert_eq!(
        branches.diff("branch-a", &|path| path != "README.md"),
        Err(BranchError::ReleaseWithheld)
    );
    assert_eq!(
        branches.diff("branch-b", &|_| true),
        Err(BranchError::BranchNotSealed)
    );
    Ok(())
}

#[test]
fn interrupted_publication_recovers_only_by_original_identity() -> TestResult {
    let fixture = fixture()?;
    let snapshot = {
        let branches = open(&fixture)?;
        let snapshot = branches.import_project("demo", &fixture.source)?;
        sealed_branch(&branches, "demo", "branch-a", "NOTES.md", "accepted\n")?;
        branches.begin_publication("branch-a", "publication-1")?;
        snapshot
    };

    let branches = open(&fixture)?;
    assert_eq!(branches.project_head("demo")?, snapshot.tree());
    assert_eq!(
        branches.publication_state("branch-a")?,
        PublicationState::Intent
    );
    assert_eq!(
        branches.apply("branch-a", "publication-2"),
        Err(BranchError::PublicationPending("publication-1".to_owned()))
    );
    assert_eq!(
        branches.apply("branch-a", "publication-1"),
        Err(BranchError::PublicationPending("publication-1".to_owned()))
    );

    let head = branches.reconcile("branch-a")?;
    assert_eq!(branches.project_head("demo")?, head);
    assert_eq!(
        read_tree_file(&fixture.store, &head, "NOTES.md")?.as_deref(),
        Some("accepted\n")
    );
    assert_eq!(
        branches.publication_state("branch-a")?,
        PublicationState::Published
    );
    assert_eq!(branches.reconcile("branch-a")?, head);
    Ok(())
}

#[test]
fn a_moved_base_is_a_conflict_and_never_overwrites() -> TestResult {
    let fixture = fixture()?;
    let branches = open(&fixture)?;
    let snapshot = branches.import_project("demo", &fixture.source)?;
    sealed_branch(&branches, "demo", "branch-a", "A.md", "a\n")?;
    let snapshot_b = branches.snapshot("demo")?;
    assert_eq!(snapshot_b, snapshot);
    let lease_b = branches.create_branch(&snapshot_b, "branch-b")?;
    branches.stage_write(&lease_b, "B.md", b"b\n", false)?;
    branches.freeze("branch-b")?;
    branches.seal("branch-b", "operation-b")?;

    let after_a = branches.apply("branch-a", "publication-a")?;
    assert_eq!(
        branches.apply("branch-b", "publication-b"),
        Err(BranchError::BaseConflict {
            expected: snapshot.tree().to_owned(),
            actual: after_a.clone(),
        })
    );
    assert_eq!(branches.project_head("demo")?, after_a);
    assert_eq!(
        branches.publication_state("branch-b")?,
        PublicationState::Conflict {
            actual: after_a.clone()
        }
    );
    assert_eq!(
        branches.reconcile("branch-b"),
        Err(BranchError::BaseConflict {
            expected: snapshot.tree().to_owned(),
            actual: after_a,
        })
    );
    Ok(())
}

#[test]
fn freezing_fences_stale_writers() -> TestResult {
    let fixture = fixture()?;
    let branches = open(&fixture)?;
    let snapshot = branches.import_project("demo", &fixture.source)?;
    let lease = branches.create_branch(&snapshot, "branch-a")?;
    branches.stage_write(&lease, "A.md", b"draft\n", false)?;
    let output = branches.freeze("branch-a")?;

    assert_eq!(
        branches.stage_write(&lease, "A.md", b"late\n", false),
        Err(BranchError::StaleWriter {
            presented: 0,
            current: 1
        })
    );
    assert_eq!(
        branches.stage_remove(&lease, "A.md"),
        Err(BranchError::StaleWriter {
            presented: 0,
            current: 1
        })
    );
    assert_eq!(branches.branch_tree("branch-a")?, output);
    assert_eq!(branches.branch_state("branch-a")?, BranchState::Frozen);
    assert_eq!(branches.freeze("branch-a"), Err(BranchError::BranchFrozen));
    assert_eq!(
        branches.apply("branch-a", "publication-1"),
        Err(BranchError::BranchNotSealed)
    );
    Ok(())
}

#[test]
fn unsupported_entries_and_unsafe_paths_are_refused() -> TestResult {
    let fixture = fixture()?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", fixture.source.join("escape"))?;
    let branches = open(&fixture)?;
    #[cfg(unix)]
    assert_eq!(
        branches.import_project("demo", &fixture.source),
        Err(BranchError::UnsupportedEntry {
            path: "escape".to_owned(),
            kind: UnsupportedKind::Symlink
        })
    );
    #[cfg(unix)]
    std::fs::remove_file(fixture.source.join("escape"))?;

    std::fs::write(
        fixture.source.join("large.bin"),
        b"version https://git-lfs.github.com/spec/v1\noid sha256:00\nsize 1\n",
    )?;
    assert_eq!(
        branches.import_project("demo", &fixture.source),
        Err(BranchError::UnsupportedEntry {
            path: "large.bin".to_owned(),
            kind: UnsupportedKind::LfsPointer
        })
    );
    std::fs::remove_file(fixture.source.join("large.bin"))?;

    let snapshot = branches.import_project("demo", &fixture.source)?;
    let lease = branches.create_branch(&snapshot, "branch-a")?;
    for (path, reason) in [
        ("../outside", "traversal"),
        ("src/../../outside", "traversal"),
        ("/etc/passwd", "empty_component"),
        (".git/config", "git_metadata"),
        ("src/.GIT/hooks", "git_metadata"),
        ("a\\b", "character"),
        ("", "empty"),
    ] {
        assert_eq!(
            branches.stage_write(&lease, path, b"x", false),
            Err(BranchError::PathRefused {
                path: path.to_owned(),
                reason
            }),
            "{path}"
        );
    }
    assert_eq!(
        branches.create_branch(&snapshot, "Branch_A"),
        Err(BranchError::InvalidIdentifier("Branch_A".to_owned()))
    );
    assert_eq!(
        branches.create_branch(&snapshot, "branch-a"),
        Err(BranchError::BranchExists("branch-a".to_owned()))
    );
    assert_eq!(
        branches.import_project("demo", &fixture.source),
        Err(BranchError::ProjectExists("demo".to_owned()))
    );
    Ok(())
}

#[test]
fn snapshots_refuse_submodules_and_bounds() -> TestResult {
    let fixture = fixture()?;
    let branches = open(&fixture)?;
    branches.import_project("demo", &fixture.source)?;

    let gitlink = raw_git(
        &fixture.store,
        &["mktree"],
        Some("160000 commit 1111111111111111111111111111111111111111\tvendor\n"),
    )?;
    raw_git(
        &fixture.store,
        &["update-ref", "refs/chio/computer/projects/linked", &gitlink],
        None,
    )?;
    assert_eq!(
        branches.snapshot("linked"),
        Err(BranchError::UnsupportedEntry {
            path: "vendor".to_owned(),
            kind: UnsupportedKind::Submodule
        })
    );

    let small = ManagedBranches::open(
        &git_binary()?,
        &fixture.store,
        Limits {
            max_file_bytes: 4,
            ..Limits::default()
        },
    )?;
    assert_eq!(
        small.snapshot("demo"),
        Err(BranchError::BoundExceeded("file_bytes"))
    );

    std::fs::write(
        fixture.store.join("objects/info/alternates"),
        "/tmp/other\n",
    )?;
    assert_eq!(
        ManagedBranches::open(&git_binary()?, &fixture.store, Limits::default()).err(),
        Some(BranchError::AlternatesPresent)
    );
    assert_eq!(
        ManagedBranches::open(Path::new("git"), &fixture.store, Limits::default()).err(),
        Some(BranchError::PathNotAbsolute)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn store_hooks_and_local_configuration_never_run() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let fixture = fixture()?;
    let branches = open(&fixture)?;
    let marker = fixture.store.join("hook-ran");
    let hooks = fixture.store.join("hooks");
    std::fs::create_dir_all(&hooks)?;
    for hook in ["reference-transaction", "post-index-change"] {
        let script = hooks.join(hook);
        std::fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
    }
    raw_git(
        &fixture.store,
        &["config", "core.hooksPath", &hooks.display().to_string()],
        None,
    )?;

    let snapshot = branches.import_project("demo", &fixture.source)?;
    let lease = branches.create_branch(&snapshot, "branch-a")?;
    branches.stage_write(&lease, "A.md", b"a\n", false)?;
    branches.freeze("branch-a")?;
    branches.seal("branch-a", "operation-1")?;
    branches.apply("branch-a", "publication-1")?;

    assert!(!marker.exists());
    Ok(())
}

#[test]
fn a_partially_committed_publication_completes_from_the_moved_head() -> TestResult {
    let fixture = fixture()?;
    let branches = open(&fixture)?;
    let snapshot = branches.import_project("demo", &fixture.source)?;
    sealed_branch(&branches, "demo", "branch-a", "A.md", "a\n")?;
    branches.begin_publication("branch-a", "publication-1")?;
    let output = branches.branch_tree("branch-a")?;
    raw_git(
        &fixture.store,
        &[
            "update-ref",
            "refs/chio/computer/projects/demo",
            &output,
            snapshot.tree(),
        ],
        None,
    )?;

    assert_eq!(
        branches.publication_state("branch-a")?,
        PublicationState::Intent
    );
    assert_eq!(branches.reconcile("branch-a")?, output);
    assert_eq!(
        branches.publication_state("branch-a")?,
        PublicationState::Published
    );
    assert_eq!(branches.project_head("demo")?, output);
    Ok(())
}

#[test]
fn a_branch_publishes_only_against_its_own_base() -> TestResult {
    let fixture = fixture()?;
    let branches = open(&fixture)?;
    let base = branches.import_project("demo", &fixture.source)?;
    let stale = branches.create_branch(&base, "branch-old")?;
    branches.stage_write(&stale, "OLD.md", b"old\n", false)?;
    branches.freeze("branch-old")?;
    branches.seal("branch-old", "operation-old")?;
    sealed_branch(&branches, "demo", "branch-new", "NEW.md", "new\n")?;
    let moved = branches.apply("branch-new", "publication-new")?;

    assert_eq!(
        branches.apply("branch-old", "publication-old"),
        Err(BranchError::BaseConflict {
            expected: base.tree().to_owned(),
            actual: moved.clone(),
        })
    );
    assert_eq!(branches.project_head("demo")?, moved);
    assert_eq!(read_tree_file(&fixture.store, &moved, "OLD.md")?, None);
    Ok(())
}

#[test]
fn stores_with_foreign_configuration_are_refused() -> TestResult {
    let fixture = fixture()?;
    open(&fixture)?;
    raw_git(
        &fixture.store,
        &["config", "core.sharedRepository", "world"],
        None,
    )?;
    assert_eq!(
        ManagedBranches::open(&git_binary()?, &fixture.store, Limits::default()).err(),
        Some(BranchError::UnsupportedStoreConfig(
            "core.sharedrepository=world".to_owned()
        ))
    );
    Ok(())
}

#[test]
fn ignorable_characters_cannot_spell_git_metadata() -> TestResult {
    let fixture = fixture()?;
    let branches = open(&fixture)?;
    let snapshot = branches.import_project("demo", &fixture.source)?;
    let lease = branches.create_branch(&snapshot, "branch-a")?;
    for path in [".g\u{200c}it/config", "src/.git\u{feff}/hooks"] {
        assert_eq!(
            branches.stage_write(&lease, path, b"x", false),
            Err(BranchError::PathRefused {
                path: path.to_owned(),
                reason: "character"
            })
        );
    }
    Ok(())
}
