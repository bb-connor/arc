//! Publish a fully verified generated Python tree.
//!
//! Preparation never changes the maintained tree. Linux and macOS commit a
//! completed sibling with one atomic directory operation. Publishers cooperate
//! through an exclusive parent-directory lock; this is not a compare-and-swap
//! against arbitrary writers. Unexpected exchanged directories are retained.

use std::path::Path;

use crate::XtaskError;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn publish(source: &Path, destination: &Path) -> Result<(), XtaskError> {
    atomic::publish(source, destination)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn publish(_source: &Path, _destination: &Path) -> Result<(), XtaskError> {
    Err(XtaskError::Validation(
        "atomic Python directory publication is unsupported on this platform".into(),
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod atomic {
    use std::{
        ffi::{CString, OsStr, OsString},
        fs::{self, File},
        io,
        os::{
            fd::AsRawFd,
            unix::{ffi::OsStrExt, fs::DirBuilderExt, fs::MetadataExt},
        },
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{support::copy_dir_recursive, support::display_path, XtaskError};

    static NEXT_SIBLING: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryIdentity {
        device: u64,
        inode: u64,
    }

    impl DirectoryIdentity {
        fn inspect(path: &Path) -> io::Result<Option<Self>> {
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    Ok(Some(Self {
                        device: metadata.dev(),
                        inode: metadata.ino(),
                    }))
                }
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "generated output must be a directory, without a symlink",
                )),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }

        fn require(path: &Path) -> io::Result<Self> {
            Self::inspect(path)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "generated directory is missing")
            })
        }
    }

    /// Owns only the directory created at this unique sibling name. A changed
    /// identity is preserved rather than deleted by preparation-error cleanup.
    struct PreparedTree {
        path: PathBuf,
        identity: DirectoryIdentity,
        clean_on_drop: bool,
    }

    impl PreparedTree {
        fn create(parent: &Path, destination_name: &OsStr) -> io::Result<Self> {
            for _ in 0..64 {
                let sequence = NEXT_SIBLING.fetch_add(1, Ordering::Relaxed);
                let mut name = OsString::from(".");
                name.push(destination_name);
                name.push(format!(".codegen-{}-{sequence}", std::process::id()));
                let path = parent.join(name);
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {
                        return Ok(Self {
                            identity: DirectoryIdentity::require(&path)?,
                            path,
                            clean_on_drop: true,
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "no unique generated-output sibling is available",
            ))
        }
    }

    impl Drop for PreparedTree {
        fn drop(&mut self) {
            if self.clean_on_drop {
                match DirectoryIdentity::inspect(&self.path) {
                    Ok(None) => {}
                    Ok(Some(identity)) if identity == self.identity => {
                        if let Err(error) = fs::remove_dir_all(&self.path) {
                            eprintln!(
                                "codegen python: retained preparation directory {}: {error}",
                                display_path(&self.path)
                            );
                        }
                    }
                    _ => eprintln!(
                        "codegen python: retained unexpected preparation directory {}",
                        display_path(&self.path)
                    ),
                }
            }
        }
    }

    pub(super) fn publish(source: &Path, destination: &Path) -> Result<(), XtaskError> {
        publish_with(source, destination, copy_dir_recursive)
    }

    fn publish_with(
        source: &Path,
        destination: &Path,
        copy: impl FnOnce(&Path, &Path) -> Result<(), XtaskError>,
    ) -> Result<(), XtaskError> {
        publish_with_operations(source, destination, copy, commit, remove_directory_tree)
    }

    fn remove_directory_tree(path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }

    fn publish_with_operations(
        source: &Path,
        destination: &Path,
        copy: impl FnOnce(&Path, &Path) -> Result<(), XtaskError>,
        exchange: impl FnOnce(&File, &OsStr, &OsStr, bool) -> io::Result<()>,
        cleanup: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), XtaskError> {
        DirectoryIdentity::require(source)
            .map_err(|error| XtaskError::Io(display_path(source), error))?;
        let parent = destination.parent().ok_or_else(|| {
            XtaskError::Validation("generated output requires a parent directory".into())
        })?;
        let name = destination.file_name().ok_or_else(|| {
            XtaskError::Validation("generated output requires a directory name".into())
        })?;
        // Reject names that cannot be passed to the atomic operation before
        // preparing any output. Both operation names are single components.
        c_name(name).map_err(|error| XtaskError::Io(display_path(destination), error))?;
        fs::create_dir_all(parent).map_err(|error| XtaskError::Io(display_path(parent), error))?;
        let parent = fs::canonicalize(parent)
            .map_err(|error| XtaskError::Io(display_path(parent), error))?;
        let directory =
            File::open(&parent).map_err(|error| XtaskError::Io(display_path(&parent), error))?;
        directory.try_lock().map_err(|error| {
            XtaskError::Validation(format!(
                "cannot acquire generated-output directory lock for {}: {error:?}",
                display_path(&parent)
            ))
        })?;
        let destination = parent.join(name);
        let previous = DirectoryIdentity::inspect(&destination)
            .map_err(|error| XtaskError::Io(display_path(&destination), error))?;
        let mut candidate = PreparedTree::create(&parent, name)
            .map_err(|error| XtaskError::Io(display_path(&parent), error))?;
        copy(source, &candidate.path)?;
        let source_permissions = fs::symlink_metadata(source)
            .map_err(|error| XtaskError::Io(display_path(source), error))?
            .permissions();
        fs::set_permissions(&candidate.path, source_permissions)
            .map_err(|error| XtaskError::Io(display_path(&candidate.path), error))?;

        if DirectoryIdentity::inspect(&destination)
            .map_err(|error| XtaskError::Io(display_path(&destination), error))?
            != previous
            || DirectoryIdentity::require(&candidate.path)
                .map_err(|error| XtaskError::Io(display_path(&candidate.path), error))?
                != candidate.identity
        {
            return Err(XtaskError::Validation(
                "generated directory identity changed during preparation".into(),
            ));
        }
        let candidate_name = candidate.path.file_name().ok_or_else(|| {
            XtaskError::Validation("prepared output requires a directory name".into())
        })?;
        exchange(&directory, candidate_name, name, previous.is_some())
            .map_err(|error| XtaskError::Io(display_path(&destination), error))?;

        // The atomic operation succeeded. Any cleanup issue preserves the old
        // sibling and reports success for the valid, committed candidate.
        candidate.clean_on_drop = false;
        if let Some(previous) = previous {
            match DirectoryIdentity::inspect(&candidate.path) {
                Ok(Some(identity)) if identity == previous => {
                    if let Err(error) = cleanup(&candidate.path) {
                        eprintln!(
                            "codegen python: published output; retained previous tree {}: {error}",
                            display_path(&candidate.path)
                        );
                    }
                }
                _ => eprintln!(
                    "codegen python: published output; retained unexpected exchanged tree {}",
                    display_path(&candidate.path)
                ),
            }
        }
        Ok(())
    }

    fn c_name(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    fn commit(
        parent: &File,
        candidate: &OsStr,
        destination: &OsStr,
        replace: bool,
    ) -> io::Result<()> {
        let candidate = c_name(candidate)?;
        let destination = c_name(destination)?;
        let descriptor = parent.as_raw_fd();
        #[cfg(target_os = "linux")]
        let flags = if replace {
            libc::RENAME_EXCHANGE
        } else {
            libc::RENAME_NOREPLACE
        };
        #[cfg(target_os = "macos")]
        let flags = if replace {
            libc::RENAME_SWAP
        } else {
            libc::RENAME_EXCL
        };
        // SAFETY: the borrowed parent descriptor remains open for the entire
        // call. Both CString buffers remain live and NUL-terminated; their
        // names are single path components under that same parent descriptor.
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                descriptor,
                candidate.as_ptr(),
                descriptor,
                destination.as_ptr(),
                flags,
            )
        };
        // SAFETY: the same descriptor and CString lifetime guarantees apply
        // to the macOS atomic directory operation.
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                descriptor,
                candidate.as_ptr(),
                descriptor,
                destination.as_ptr(),
                flags,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::support::TempDir;
        use std::os::unix::fs::symlink;

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        fn fixture() -> Result<(TempDir, PathBuf, PathBuf), Box<dyn std::error::Error>> {
            let directory = TempDir::new("chio-python-publish")?;
            let source = directory.path().join("candidate");
            let destination = directory.path().join("maintained");
            fs::create_dir(&source)?;
            fs::create_dir(&destination)?;
            fs::write(source.join("candidate.py"), b"verified candidate\n")?;
            fs::write(destination.join("retained.py"), b"retained bytes\n")?;
            Ok((directory, source, destination))
        }

        fn siblings(parent: &Path) -> io::Result<Vec<PathBuf>> {
            fs::read_dir(parent)?
                .filter_map(|entry| match entry {
                    Ok(entry) if entry.file_name().as_bytes().starts_with(b".maintained.") => {
                        Some(Ok(entry.path()))
                    }
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect()
        }

        #[test]
        fn failed_copy_preserves_the_complete_maintained_python_tree() -> TestResult {
            let (directory, source, destination) = fixture()?;
            let result = publish_with(&source, &destination, |_, target| {
                fs::write(target.join("partial.py"), b"incomplete\n")
                    .map_err(|error| XtaskError::Io(display_path(target), error))?;
                Err(XtaskError::Io(
                    display_path(target),
                    io::Error::other("injected copy failure after partial output"),
                ))
            });
            assert!(result.is_err());
            assert_eq!(
                fs::read(destination.join("retained.py"))?,
                b"retained bytes\n"
            );
            assert!(!destination.join("partial.py").exists());
            assert!(siblings(directory.path())?.is_empty());
            Ok(())
        }

        #[test]
        fn missing_candidate_preserves_the_maintained_python_tree() -> TestResult {
            let (directory, _source, destination) = fixture()?;
            assert!(publish(&directory.path().join("missing"), &destination).is_err());
            assert_eq!(
                fs::read(destination.join("retained.py"))?,
                b"retained bytes\n"
            );
            assert!(siblings(directory.path())?.is_empty());
            Ok(())
        }

        #[test]
        fn managed_output_symlinks_are_refused_without_replacing_them() -> TestResult {
            let (directory, source, retained) = fixture()?;
            let destination = directory.path().join("managed-link");
            symlink(&retained, &destination)?;
            assert!(publish(&source, &destination).is_err());
            assert!(fs::symlink_metadata(&destination)?.file_type().is_symlink());
            assert_eq!(fs::read(retained.join("retained.py"))?, b"retained bytes\n");
            Ok(())
        }

        #[test]
        fn first_publication_commits_a_complete_tree_exclusively() -> TestResult {
            let (directory, source, _retained) = fixture()?;
            let destination = directory.path().join("initial");
            publish(&source, &destination).map_err(|error| io::Error::other(error.to_string()))?;
            assert_eq!(
                fs::read(destination.join("candidate.py"))?,
                b"verified candidate\n"
            );
            Ok(())
        }

        #[test]
        fn replacement_commits_the_candidate_and_removes_only_the_old_tree() -> TestResult {
            let (directory, source, destination) = fixture()?;
            publish(&source, &destination).map_err(|error| io::Error::other(error.to_string()))?;
            assert_eq!(
                fs::read(destination.join("candidate.py"))?,
                b"verified candidate\n"
            );
            assert!(!destination.join("retained.py").exists());
            assert!(siblings(directory.path())?.is_empty());
            Ok(())
        }

        #[test]
        fn failed_atomic_commit_preserves_the_maintained_tree() -> TestResult {
            let (directory, source, destination) = fixture()?;
            for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Unsupported] {
                let result = publish_with_operations(
                    &source,
                    &destination,
                    copy_dir_recursive,
                    |_, _, _, _| Err(io::Error::new(kind, "injected atomic operation failure")),
                    remove_directory_tree,
                );
                assert!(result.is_err());
                assert_eq!(
                    fs::read(destination.join("retained.py"))?,
                    b"retained bytes\n"
                );
                assert!(!destination.join("candidate.py").exists());
                assert!(siblings(directory.path())?.is_empty());
            }
            Ok(())
        }

        #[test]
        fn managed_regular_files_are_preserved_on_refusal() -> TestResult {
            let (directory, source, _retained) = fixture()?;
            let destination = directory.path().join("managed-file");
            fs::write(&destination, b"preserve this file\n")?;
            assert!(publish(&source, &destination).is_err());
            assert_eq!(fs::read(destination)?, b"preserve this file\n");
            Ok(())
        }

        #[test]
        fn a_busy_publication_lock_refuses_without_mutating_the_managed_tree() -> TestResult {
            let (directory, source, destination) = fixture()?;
            let other_publisher = File::open(directory.path())?;
            other_publisher.lock()?;
            assert!(publish(&source, &destination).is_err());
            assert_eq!(
                fs::read(destination.join("retained.py"))?,
                b"retained bytes\n"
            );
            assert!(siblings(directory.path())?.is_empty());
            Ok(())
        }

        #[test]
        fn a_changed_managed_identity_is_preserved_before_commit() -> TestResult {
            let (directory, source, destination) = fixture()?;
            let displaced = directory.path().join("displaced");
            let result = publish_with(&source, &destination, |from, target| {
                copy_dir_recursive(from, target)?;
                fs::rename(&destination, &displaced)
                    .and_then(|()| fs::create_dir(&destination))
                    .and_then(|()| fs::write(destination.join("unexpected.py"), b"unexpected\n"))
                    .map_err(|error| XtaskError::Io(display_path(&destination), error))
            });
            assert!(result.is_err());
            assert_eq!(
                fs::read(displaced.join("retained.py"))?,
                b"retained bytes\n"
            );
            assert_eq!(
                fs::read(destination.join("unexpected.py"))?,
                b"unexpected\n"
            );
            assert!(siblings(directory.path())?.is_empty());
            Ok(())
        }

        #[test]
        fn initial_publication_refuses_a_target_appearing_at_commit() -> TestResult {
            let (directory, source, _retained) = fixture()?;
            let destination = directory.path().join("initial");
            let result = publish_with_operations(
                &source,
                &destination,
                copy_dir_recursive,
                |parent, candidate, name, replace| {
                    assert!(!replace);
                    fs::create_dir(&destination)?;
                    fs::write(
                        destination.join("unexpected.py"),
                        b"preserve appeared target\n",
                    )?;
                    commit(parent, candidate, name, replace)
                },
                remove_directory_tree,
            );
            assert!(result.is_err());
            assert_eq!(
                fs::read(destination.join("unexpected.py"))?,
                b"preserve appeared target\n"
            );
            assert!(!destination.join("candidate.py").exists());
            Ok(())
        }

        #[test]
        fn cleanup_failure_preserves_the_old_sibling_and_reports_committed_success() -> TestResult {
            let (directory, source, destination) = fixture()?;
            publish_with_operations(&source, &destination, copy_dir_recursive, commit, |_| {
                Err(io::Error::other("injected previous-tree cleanup failure"))
            })
            .map_err(|error| io::Error::other(error.to_string()))?;
            assert_eq!(
                fs::read(destination.join("candidate.py"))?,
                b"verified candidate\n"
            );
            let retained = siblings(directory.path())?;
            assert_eq!(retained.len(), 1);
            assert_eq!(
                fs::read(retained[0].join("retained.py"))?,
                b"retained bytes\n"
            );
            Ok(())
        }

        #[test]
        fn unexpected_exchanged_bytes_are_preserved_after_success() -> TestResult {
            let (directory, source, destination) = fixture()?;
            let displaced = directory.path().join("displaced");
            publish_with_operations(
                &source,
                &destination,
                copy_dir_recursive,
                |parent, candidate, name, replace| {
                    commit(parent, candidate, name, replace)?;
                    let old_sibling = directory.path().join(candidate);
                    fs::rename(&old_sibling, &displaced)?;
                    fs::create_dir(&old_sibling)?;
                    fs::write(
                        old_sibling.join("unexpected.py"),
                        b"unexpected exchanged bytes\n",
                    )
                },
                remove_directory_tree,
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
            assert_eq!(
                fs::read(destination.join("candidate.py"))?,
                b"verified candidate\n"
            );
            let retained = siblings(directory.path())?;
            assert_eq!(retained.len(), 1);
            assert_eq!(
                fs::read(retained[0].join("unexpected.py"))?,
                b"unexpected exchanged bytes\n"
            );
            assert_eq!(
                fs::read(displaced.join("retained.py"))?,
                b"retained bytes\n"
            );
            Ok(())
        }
    }
}
