//! Private provisioning artifacts are restricted through the descriptor that
//! was validated, never through a path that may name another file.

use super::*;
use std::os::unix::fs::PermissionsExt as _;

fn mode(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
}

fn victim(directory: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let victim = directory.join("victim");
    std::fs::write(&victim, b"outside the artifact set")?;
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644))?;
    Ok(victim)
}

#[test]
fn a_symlinked_artifact_path_does_not_chmod_its_target() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let victim = victim(root.path())?;
    let artifact = root.path().join("artifact");
    std::os::unix::fs::symlink(&victim, &artifact)?;

    assert!(set_private_file_permissions(&artifact).is_err());
    assert_eq!(mode(&victim)?, 0o644);
    Ok(())
}

#[test]
fn a_symlinked_migration_sidecar_does_not_chmod_its_target(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let victim = victim(root.path())?;
    let database = root.path().join(MIGRATION_DATABASE_FILE);
    std::fs::write(&database, b"database")?;
    let mut sidecar = database.as_os_str().to_os_string();
    sidecar.push("-wal");
    std::os::unix::fs::symlink(&victim, PathBuf::from(sidecar))?;

    assert!(secure_existing_migration_sidecars(&database).is_err());
    assert_eq!(mode(&victim)?, 0o644);
    Ok(())
}

#[test]
fn a_symlinked_staging_directory_does_not_chmod_its_target(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let elsewhere = root.path().join("elsewhere");
    std::fs::create_dir(&elsewhere)?;
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755))?;
    let staging = root.path().join("staging");
    std::os::unix::fs::symlink(&elsewhere, &staging)?;

    assert!(set_private_directory_permissions(&staging).is_err());
    assert_eq!(mode(&elsewhere)?, 0o755);
    Ok(())
}

#[test]
fn an_artifact_replaced_after_open_is_restricted_through_its_descriptor(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let victim = victim(root.path())?;
    let artifact = root.path().join("artifact");
    std::fs::write(&artifact, b"artifact")?;
    std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o644))?;
    let opened = File::open(&artifact)?;
    let original = root.path().join("artifact.opened");
    std::fs::rename(&artifact, &original)?;
    std::os::unix::fs::symlink(&victim, &artifact)?;

    restrict_private_file(&opened, &artifact, "artifact")?;
    assert_eq!(mode(&victim)?, 0o644);
    assert_eq!(mode(&original)?, 0o600);
    Ok(())
}

#[test]
fn a_hard_linked_artifact_is_refused_before_its_mode_changes(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let victim = victim(root.path())?;
    let artifact = root.path().join("artifact");
    std::fs::hard_link(&victim, &artifact)?;

    assert!(set_private_file_permissions(&artifact).is_err());
    assert_eq!(mode(&victim)?, 0o644);
    Ok(())
}

#[test]
fn a_private_directory_must_belong_to_the_provisioning_user(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt as _;

    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    validate_private_directory(root.path())?;
    let metadata = std::fs::symlink_metadata(root.path())?;
    let refused = private_files::require_private_directory_metadata(
        &metadata,
        metadata.uid().wrapping_add(1),
    )
    .err()
    .ok_or("a directory owned by another user must be refused")?;
    assert!(
        refused
            .to_string()
            .contains("not owned by the provisioning user"),
        "{refused}"
    );
    Ok(())
}
