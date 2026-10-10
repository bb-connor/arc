use super::{require_owned_unaliased_file, security_state_file_entry, SecurityStateFileEntry};
use super::{FileType, SecurityStateDatabaseFileIdentity};
use chio_security_types::ports::PortErrorKind;
use std::os::unix::fs::MetadataExt;

fn entry(file_type: FileType, link_count: u64, owner: u32) -> SecurityStateFileEntry {
    SecurityStateFileEntry {
        file_type,
        link_count,
        owner,
        mode: 0o600,
        identity: SecurityStateDatabaseFileIdentity {
            device: 1,
            inode: 2,
        },
    }
}

// Another user's file cannot be planted without privilege, so the owner rule
// is exercised on the decision itself.
#[test]
fn only_an_owned_singly_linked_regular_file_is_accepted() {
    let owner = 1000;
    assert!(require_owned_unaliased_file(&entry(FileType::RegularFile, 1, owner), owner).is_ok());
    let refused = [
        ("another user", entry(FileType::RegularFile, 1, owner + 1)),
        ("root", entry(FileType::RegularFile, 1, 0)),
        ("hard link", entry(FileType::RegularFile, 2, owner)),
        ("symlink", entry(FileType::Symlink, 1, owner)),
        ("directory", entry(FileType::Directory, 1, owner)),
        ("fifo", entry(FileType::Fifo, 1, owner)),
        ("socket", entry(FileType::Socket, 1, owner)),
    ];
    for (description, candidate) in refused {
        assert_eq!(
            require_owned_unaliased_file(&candidate, owner).map_err(|error| error.kind()),
            Err(PortErrorKind::InvalidData),
            "{description}"
        );
    }
}

#[test]
fn a_file_entry_reports_what_the_filesystem_reports() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("entry");
    std::fs::write(&path, b"entry").unwrap_or_else(|error| panic!("write: {error}"));
    let metadata = std::fs::metadata(&path).unwrap_or_else(|error| panic!("metadata: {error}"));
    let stat = rustix::fs::stat(&path).unwrap_or_else(|error| panic!("stat: {error}"));
    assert_eq!(
        security_state_file_entry(&stat),
        SecurityStateFileEntry {
            file_type: FileType::RegularFile,
            link_count: metadata.nlink(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            identity: SecurityStateDatabaseFileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        }
    );
}

#[test]
fn sqlite_identity_native_io_maps_unavailable_with_actual_enoent_source(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::error::Error;
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("absent-native-identity-probe");
    let native = std::fs::File::open(&path)
        .err()
        .ok_or("real missing file must refuse")?;
    assert_eq!(native.kind(), std::io::ErrorKind::NotFound);
    let errno = native.raw_os_error().ok_or("native ENOENT code")?;
    let mapped = super::security_state_file_identity_error(
        chio_sqlite_file_identity::SqliteFileIdentityInspectionError::Io(native),
    );
    assert_eq!(
        mapped.kind(),
        PortErrorKind::Unavailable,
        "native inspection IO is operational unavailability"
    );
    let cause = mapped
        .source()
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .ok_or("native caller IO cause must survive")?;
    assert_eq!(cause.raw_os_error(), Some(errno));
    assert_eq!(mapped.code().as_str(), "store.unavailable");
    assert!(!mapped.to_string().contains("absent-native-identity-probe"));
    assert!(!format!("{mapped:?}").contains("absent-native-identity-probe"));
    Ok(())
}

#[test]
fn sqlite_identity_actual_unsupported_main_maps_invalid_data(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = rusqlite::Connection::open_in_memory()?;
    let unsupported = chio_sqlite_file_identity::inspect_main_database_file_identity(&connection)
        .err()
        .ok_or("unsupported main must refuse")?;
    assert!(matches!(
        &unsupported,
        chio_sqlite_file_identity::SqliteFileIdentityInspectionError::Validation(_)
    ));
    assert_eq!(
        super::security_state_file_identity_error(unsupported).kind(),
        PortErrorKind::InvalidData
    );
    Ok(())
}
