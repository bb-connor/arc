use super::super::directory::{open_parents, StagedPrivateDirectory};
use super::*;

const PROBE_PARENT: &str = "CHIO_SNAPSHOT_CUSTODY_PROVISION_PROBE_PARENT";
const PROBE_SELECTOR: &str =
    "receipt_query_snapshot_backing::tests::provision::directory_open_exhaustion_probe";
const PROBE_COMPLETED: &str = "chio_snapshot_custody_emfile_completed_all_3";

#[derive(Debug, Eq, PartialEq)]
enum ProbeFailure {
    ChildFailed,
    MissingCompletion,
}

fn validate_probe_output(output: &std::process::Output) -> Result<(), ProbeFailure> {
    if !output.status.success() {
        return Err(ProbeFailure::ChildFailed);
    }
    if !String::from_utf8_lossy(&output.stdout).contains(PROBE_COMPLETED) {
        return Err(ProbeFailure::MissingCompletion);
    }
    Ok(())
}

fn run_probe(parent: &Path, selector: &str) -> std::io::Result<std::process::Output> {
    std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            selector,
            "--test-threads=1",
            "--nocapture",
        ])
        .env(PROBE_PARENT, parent)
        .output()
}

#[test]
fn directory_open_fd_exhaustion_cleans_exclusively_created_entries() -> TestResult {
    let root = private_tempdir()?;
    let output = run_probe(root.path(), PROBE_SELECTOR)?;
    assert_eq!(
        validate_probe_output(&output),
        Ok(()),
        "actual EMFILE subprocess failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        custody_entries(root.path())?,
        Vec::<std::path::PathBuf>::new()
    );
    Ok(())
}

#[test]
fn misspelled_probe_selector_cannot_satisfy_the_emfile_control() -> TestResult {
    let root = private_tempdir()?;
    let output = run_probe(root.path(), "receipt_query_snapshot_backing::tests::provision::directory_open_exhaustion_probe_misspelled")?;
    assert!(
        output.status.success(),
        "a zero-test selector should exit successfully"
    );
    assert_eq!(
        validate_probe_output(&output),
        Err(ProbeFailure::MissingCompletion)
    );
    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
#[ignore = "invoked in a separate process by directory_open_fd_exhaustion_cleans_exclusively_created_entries"]
fn directory_open_exhaustion_probe() -> TestResult {
    let parent = std::env::var_os(PROBE_PARENT).ok_or("probe parent is required")?;
    let parent = Path::new(&parent);
    assert_eq!(fs::read_dir(parent)?.count(), 0);
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    // stdin/stdout/stderr, the three held ancestor directories, the held
    // snapshot parent and its held reclaim cursor fill the actual descriptor
    // table. mkdirat still succeeds; opening its new child fails with EMFILE.
    // This limit applies only to this subprocess.
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(8),
            maximum: limit.maximum,
        },
    )?;
    for _ in 0..3 {
        let failure = SnapshotFileBacking::create_in(parent)
            .err()
            .ok_or("actual descriptor exhaustion must refuse")?;
        assert!(
            matches!(failure, SnapshotBackingError::Io(ref source)
                if source.raw_os_error() == Some(rustix::io::Errno::MFILE.raw_os_error())),
            "expected actual native EMFILE: {failure:?}"
        );
        assert_eq!(
            custody_entries(parent)?,
            Vec::<std::path::PathBuf>::new(),
            "failed directory open leaked an exclusively created custody entry"
        );
    }
    // Parent accepts this unique marker only with successful termination. A
    // misspelled exact selector executes zero tests and cannot print it.
    println!("{PROBE_COMPLETED}");
    Ok(())
}

#[test]
fn staged_cleanup_preserves_substituted_directory() -> TestResult {
    let root = private_tempdir()?;
    let parents = open_parents(root.path())?;
    let parent = parents.last().ok_or("held parent is required")?;
    rustix::fs::mkdirat(
        &parent.handle,
        "staged",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    )?;
    let mut staged = StagedPrivateDirectory::capture(parent, "staged")?;
    let path = root.path().join("staged");
    let original = root.path().join("original");
    fs::rename(&path, &original)?;
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    let replacement = fs::symlink_metadata(&path)?;
    require_refusal(
        staged.cleanup(),
        SnapshotCustodyRefusal::DirectoryEntryIdentity,
    )?;
    drop(staged);
    let after = fs::symlink_metadata(&path)?;
    assert_eq!(
        (after.dev(), after.ino()),
        (replacement.dev(), replacement.ino())
    );
    assert!(fs::symlink_metadata(original)?.is_dir());
    Ok(())
}

#[test]
fn staged_cleanup_preserves_substituted_symlink() -> TestResult {
    let root = private_tempdir()?;
    let parents = open_parents(root.path())?;
    let parent = parents.last().ok_or("held parent is required")?;
    rustix::fs::mkdirat(
        &parent.handle,
        "staged",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    )?;
    let mut staged = StagedPrivateDirectory::capture(parent, "staged")?;
    let path = root.path().join("staged");
    let original = root.path().join("original");
    fs::rename(&path, &original)?;
    symlink(&original, &path)?;
    require_refusal(
        staged.cleanup(),
        SnapshotCustodyRefusal::DirectoryEntryIdentity,
    )?;
    drop(staged);
    assert!(fs::symlink_metadata(&path)?.file_type().is_symlink());
    assert!(fs::symlink_metadata(original)?.is_dir());
    Ok(())
}

#[test]
fn directory_substituted_after_stage_capture_cannot_replace_the_created_inode() -> TestResult {
    let root = private_tempdir()?;
    let parents = open_parents(root.path())?;
    let parent = parents.last().ok_or("held parent is required")?;
    rustix::fs::mkdirat(
        &parent.handle,
        "staged",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    )?;
    let staged = StagedPrivateDirectory::capture(parent, "staged")?;
    let path = root.path().join("staged");
    fs::rename(&path, root.path().join("original"))?;
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    let replacement = std::fs::File::from(rustix::fs::openat(
        &parent.handle,
        "staged",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?);
    require_refusal(
        staged.validate_opened(&replacement),
        SnapshotCustodyRefusal::DirectoryEntryIdentity,
    )?;
    drop(staged);
    assert!(fs::symlink_metadata(path)?.is_dir());
    Ok(())
}
