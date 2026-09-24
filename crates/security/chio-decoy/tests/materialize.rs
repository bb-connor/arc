#[path = "../src/materialize.rs"]
pub mod materialize;

#[cfg(unix)]
use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

use chio_test_support::prelude::*;
#[cfg(unix)]
use materialize::{
    CleanupOutcome, CleanupRequest, MaterializationIdentity, MaterializationRequest, PathViolation,
};
use materialize::{FileMaterializer, MaterializeError, OwnershipKey};

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

#[cfg(unix)]
fn identity(operation_id: &str) -> MaterializationIdentity {
    MaterializationIdentity {
        operation_id: operation_id.to_string(),
        tenant_id: "tenant-materialize".to_string(),
        artifact_id: "artifact-materialize".to_string(),
        version_hash: [7_u8; 32],
    }
}

#[cfg(unix)]
fn materializer(root: &Path) -> FileMaterializer {
    FileMaterializer::open(root, OwnershipKey::from_bytes([23_u8; 32]))
        .unwrap_or_else(|error| panic!("open materializer: {error}"))
}

#[cfg(unix)]
fn materialize<'a>(
    materializer: &FileMaterializer,
    identity: &'a MaterializationIdentity,
    relative_path: &'a Path,
    content: &'a [u8],
) -> materialize::MaterializationReceipt {
    materializer
        .materialize(&MaterializationRequest {
            identity,
            relative_path,
            content,
        })
        .unwrap_or_else(|error| panic!("materialize file: {error}"))
}

#[cfg(unix)]
#[test]
fn materialize_creates_restrictive_tree_and_exact_retry_is_idempotent() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = identity("operation-create");
    let path = Path::new("nested/private/credential.txt");
    let content = b"credential-shaped decoy material";

    let first = materialize(&materializer, &identity, path, content);
    let second = materialize(&materializer, &identity, path, content);

    assert_eq!(second, first);
    assert_eq!(first.identity, identity);
    assert_eq!(first.proof.relative_path, path);
    assert_eq!(first.proof.size, content.len() as u64);
    assert_eq!(first.proof.link_count, 1);
    assert_eq!(first.proof.mode, 0o600);
    assert_ne!(first.proof.ownership_tag, [0_u8; 32]);
    assert_eq!(
        fs::read(directory.path().join(path))
            .unwrap_or_else(|error| panic!("read materialized file: {error}")),
        content
    );
    assert_eq!(
        fs::metadata(directory.path().join("nested"))
            .unwrap_or_else(|error| panic!("nested metadata: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(directory.path().join("nested/private"))
            .unwrap_or_else(|error| panic!("private metadata: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(directory.path().join(path))
            .unwrap_or_else(|error| panic!("file metadata: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn materialize_rejects_unsafe_relative_paths_before_mutation() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = identity("operation-invalid-path");
    let nul = PathBuf::from(std::ffi::OsString::from_vec(b"bad\0name".to_vec()));
    let paths = [
        PathBuf::new(),
        PathBuf::from("/absolute"),
        PathBuf::from("."),
        PathBuf::from("./file"),
        PathBuf::from("parent/../file"),
        PathBuf::from("double//separator"),
        PathBuf::from("trailing/"),
        PathBuf::from(".chio-decoy-quarantine/foreign"),
        nul,
    ];

    for path in paths {
        let error = materializer
            .materialize(&MaterializationRequest {
                identity: &identity,
                relative_path: &path,
                content: b"decoy",
            })
            .test_expect_err("unsafe path must fail");
        assert!(
            matches!(error, MaterializeError::InvalidPath(_)),
            "unexpected error for {path:?}: {error}"
        );
    }
    assert!(fs::read_dir(directory.path())
        .unwrap_or_else(|error| panic!("read root: {error}"))
        .next()
        .is_none());
}

#[cfg(unix)]
#[test]
fn materialize_rejects_empty_or_nul_operation_identity() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    for operation_id in ["", "bad\0operation"] {
        let mut identity = identity("operation-valid");
        identity.operation_id = operation_id.to_string();
        assert!(matches!(
            materializer.materialize(&MaterializationRequest {
                identity: &identity,
                relative_path: Path::new("identity.txt"),
                content: b"decoy",
            }),
            Err(MaterializeError::InvalidIdentity)
        ));
    }
}

#[cfg(unix)]
#[test]
fn foreign_existing_file_is_never_adopted_even_when_content_matches() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("foreign.txt");
    fs::write(&path, b"same bytes").unwrap_or_else(|error| panic!("seed foreign file: {error}"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("chmod foreign file: {error}"));
    let materializer = materializer(directory.path());

    let error = materializer
        .materialize(&MaterializationRequest {
            identity: &identity("operation-foreign"),
            relative_path: Path::new("foreign.txt"),
            content: b"same bytes",
        })
        .test_expect_err("foreign file must not be adopted");
    assert!(matches!(
        error,
        MaterializeError::ForeignExisting | MaterializeError::OwnershipMismatch
    ));
    assert_eq!(
        fs::read(path).unwrap_or_else(|error| panic!("read foreign file: {error}")),
        b"same bytes"
    );
}

#[cfg(unix)]
#[test]
fn identity_or_key_rebinding_cannot_adopt_an_existing_file() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let first = materializer(directory.path());
    let first_identity = identity("operation-owner");
    let path = Path::new("owned.txt");
    materialize(&first, &first_identity, path, b"owned bytes");

    let mut operation_rebound = first_identity.clone();
    operation_rebound.operation_id = "operation-rebound".to_string();
    let mut tenant_rebound = first_identity.clone();
    tenant_rebound.tenant_id = "tenant-rebound".to_string();
    let mut artifact_rebound = first_identity.clone();
    artifact_rebound.artifact_id = "artifact-rebound".to_string();
    let mut version_rebound = first_identity.clone();
    version_rebound.version_hash = [8_u8; 32];
    for rebound_identity in [
        operation_rebound,
        tenant_rebound,
        artifact_rebound,
        version_rebound,
    ] {
        assert!(matches!(
            first.materialize(&MaterializationRequest {
                identity: &rebound_identity,
                relative_path: path,
                content: b"owned bytes",
            }),
            Err(MaterializeError::ForeignExisting | MaterializeError::OwnershipMismatch)
        ));
    }

    let wrong_key = FileMaterializer::open(directory.path(), OwnershipKey::from_bytes([24_u8; 32]))
        .unwrap_or_else(|error| panic!("open wrong-key materializer: {error}"));
    assert!(matches!(
        wrong_key.materialize(&MaterializationRequest {
            identity: &first_identity,
            relative_path: path,
            content: b"owned bytes",
        }),
        Err(MaterializeError::OwnershipMismatch | MaterializeError::ForeignExisting)
    ));
}

#[cfg(unix)]
#[test]
fn symlink_root_component_and_final_entry_are_rejected() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let outside = tempfile::tempdir().unwrap_or_else(|error| panic!("outside tempdir: {error}"));
    let root_link = directory.path().join("root-link");
    symlink(outside.path(), &root_link).unwrap_or_else(|error| panic!("root symlink: {error}"));
    assert!(matches!(
        FileMaterializer::open(&root_link, OwnershipKey::from_bytes([23_u8; 32])),
        Err(MaterializeError::InvalidRoot | MaterializeError::Symlink)
    ));

    let materializer = materializer(directory.path());
    symlink(outside.path(), directory.path().join("component"))
        .unwrap_or_else(|error| panic!("component symlink: {error}"));
    let component_error = materializer
        .materialize(&MaterializationRequest {
            identity: &identity("operation-component-link"),
            relative_path: Path::new("component/escaped.txt"),
            content: b"must stay inside",
        })
        .test_expect_err("component symlink must fail");
    assert!(matches!(
        component_error,
        MaterializeError::Symlink | MaterializeError::InvalidPath(PathViolation::Symlink)
    ));
    assert!(!outside.path().join("escaped.txt").exists());

    let outside_file = outside.path().join("outside.txt");
    fs::write(&outside_file, b"outside")
        .unwrap_or_else(|error| panic!("write outside file: {error}"));
    symlink(&outside_file, directory.path().join("final-link"))
        .unwrap_or_else(|error| panic!("final symlink: {error}"));
    let final_error = materializer
        .materialize(&MaterializationRequest {
            identity: &identity("operation-final-link"),
            relative_path: Path::new("final-link"),
            content: b"replacement",
        })
        .test_expect_err("final symlink must fail");
    assert!(matches!(
        final_error,
        MaterializeError::Symlink
            | MaterializeError::ForeignExisting
            | MaterializeError::OwnershipMismatch
    ));
    assert_eq!(
        fs::read(outside_file).unwrap_or_else(|error| panic!("read outside file: {error}")),
        b"outside"
    );
}

#[cfg(unix)]
#[test]
fn hardlink_invalidates_retry_and_cleanup() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = identity("operation-hardlink");
    let path = Path::new("hardlink-owned.txt");
    let receipt = materialize(&materializer, &identity, path, b"hardlink bytes");
    fs::hard_link(
        directory.path().join(path),
        directory.path().join("second-link.txt"),
    )
    .unwrap_or_else(|error| panic!("create hardlink: {error}"));

    assert!(matches!(
        materializer.materialize(&MaterializationRequest {
            identity: &identity,
            relative_path: path,
            content: b"hardlink bytes",
        }),
        Err(MaterializeError::Hardlink)
    ));
    assert!(matches!(
        materializer.cleanup(&CleanupRequest {
            cleanup_operation_id: "cleanup-hardlink",
            receipt: &receipt,
        }),
        Err(MaterializeError::Hardlink)
    ));
    assert_eq!(
        fs::metadata(directory.path().join(path))
            .unwrap_or_else(|error| panic!("hardlink metadata: {error}"))
            .nlink(),
        2
    );
}

#[cfg(unix)]
#[test]
fn cleanup_rejects_changed_or_replaced_content_without_removal() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());

    let changed_identity = identity("operation-changed");
    let changed_path = Path::new("changed.txt");
    let changed_receipt = materialize(
        &materializer,
        &changed_identity,
        changed_path,
        b"original content",
    );
    fs::write(directory.path().join(changed_path), b"modified content")
        .unwrap_or_else(|error| panic!("modify owned file: {error}"));
    assert!(matches!(
        materializer.cleanup(&CleanupRequest {
            cleanup_operation_id: "cleanup-changed",
            receipt: &changed_receipt,
        }),
        Err(MaterializeError::ContentMismatch | MaterializeError::MetadataMismatch)
    ));
    assert!(directory.path().join(changed_path).exists());

    let replaced_identity = identity("operation-replaced");
    let replaced_path = Path::new("replaced.txt");
    let replaced_receipt = materialize(
        &materializer,
        &replaced_identity,
        replaced_path,
        b"replacement target",
    );
    fs::remove_file(directory.path().join(replaced_path))
        .unwrap_or_else(|error| panic!("remove owned file: {error}"));
    fs::write(directory.path().join(replaced_path), b"replacement target")
        .unwrap_or_else(|error| panic!("replace owned file: {error}"));
    fs::set_permissions(
        directory.path().join(replaced_path),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap_or_else(|error| panic!("chmod replacement: {error}"));
    assert!(matches!(
        materializer.cleanup(&CleanupRequest {
            cleanup_operation_id: "cleanup-replaced",
            receipt: &replaced_receipt,
        }),
        Err(MaterializeError::OwnershipMismatch | MaterializeError::MetadataMismatch)
    ));
    assert!(directory.path().join(replaced_path).exists());
}

#[cfg(unix)]
#[test]
fn cleanup_rejects_symlink_replacement_and_preserves_target() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let outside = tempfile::tempdir().unwrap_or_else(|error| panic!("outside tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = identity("operation-cleanup-symlink");
    let path = Path::new("cleanup-link.txt");
    let receipt = materialize(&materializer, &identity, path, b"owned content");
    fs::remove_file(directory.path().join(path))
        .unwrap_or_else(|error| panic!("remove owned file: {error}"));
    let outside_file = outside.path().join("outside.txt");
    fs::write(&outside_file, b"outside content")
        .unwrap_or_else(|error| panic!("write outside file: {error}"));
    symlink(&outside_file, directory.path().join(path))
        .unwrap_or_else(|error| panic!("replace with symlink: {error}"));

    assert!(matches!(
        materializer.cleanup(&CleanupRequest {
            cleanup_operation_id: "cleanup-symlink",
            receipt: &receipt,
        }),
        Err(MaterializeError::Symlink | MaterializeError::OwnershipMismatch)
    ));
    assert_eq!(
        fs::read(outside_file).unwrap_or_else(|error| panic!("read outside file: {error}")),
        b"outside content"
    );
}

#[cfg(unix)]
#[test]
fn cleanup_rejects_forged_registry_identity_and_metadata_proof() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = identity("operation-forged-cleanup");
    let path = Path::new("forged-cleanup.txt");
    let receipt = materialize(&materializer, &identity, path, b"owned content");

    let mut forged_identity = receipt.clone();
    forged_identity.identity.tenant_id = "forged-tenant".to_string();
    assert!(matches!(
        materializer.cleanup(&CleanupRequest {
            cleanup_operation_id: "cleanup-forged-identity",
            receipt: &forged_identity,
        }),
        Err(MaterializeError::OwnershipMismatch)
    ));

    let mut forged_metadata = receipt.clone();
    forged_metadata.proof.inode ^= 1;
    assert!(matches!(
        materializer.cleanup(&CleanupRequest {
            cleanup_operation_id: "cleanup-forged-metadata",
            receipt: &forged_metadata,
        }),
        Err(MaterializeError::OwnershipMismatch)
    ));
    assert_eq!(
        fs::read(directory.path().join(path))
            .unwrap_or_else(|error| panic!("read preserved owned file: {error}")),
        b"owned content"
    );
}

#[cfg(unix)]
#[test]
fn cleanup_is_idempotent_and_recovers_after_quarantine_rename() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = identity("operation-cleanup");
    let path = Path::new("cleanup/owned.txt");
    let receipt = materialize(&materializer, &identity, path, b"cleanup content");
    let request = CleanupRequest {
        cleanup_operation_id: "cleanup-operation",
        receipt: &receipt,
    };

    materializer
        .quarantine_without_unlink_for_test(&request)
        .unwrap_or_else(|error| panic!("quarantine test file: {error}"));
    assert!(!directory.path().join(path).exists());
    assert_eq!(
        materializer
            .cleanup(&request)
            .unwrap_or_else(|error| panic!("recover cleanup: {error}")),
        CleanupOutcome::Removed
    );
    assert_eq!(
        materializer
            .cleanup(&request)
            .unwrap_or_else(|error| panic!("retry cleanup: {error}")),
        CleanupOutcome::AlreadyRemoved
    );
}

#[cfg(unix)]
#[test]
fn ordinary_cleanup_removes_only_the_proven_owned_file() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = identity("operation-ordinary-cleanup");
    let path = Path::new("ordinary.txt");
    let receipt = materialize(&materializer, &identity, path, b"ordinary content");
    let request = CleanupRequest {
        cleanup_operation_id: "cleanup-ordinary",
        receipt: &receipt,
    };

    assert_eq!(
        materializer
            .cleanup(&request)
            .unwrap_or_else(|error| panic!("cleanup file: {error}")),
        CleanupOutcome::Removed
    );
    assert!(!directory.path().join(path).exists());
    assert_eq!(
        materializer
            .cleanup(&request)
            .unwrap_or_else(|error| panic!("retry cleanup file: {error}")),
        CleanupOutcome::AlreadyRemoved
    );
}

#[cfg(unix)]
#[test]
fn ownership_receipt_round_trips_non_utf8_paths_and_remains_authoritative() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = identity("operation-persisted-receipt");
    let path = Path::new("persisted-receipt.txt");
    let receipt = materialize(&materializer, &identity, path, b"persisted receipt content");

    let non_utf8_path = PathBuf::from(std::ffi::OsString::from_vec(
        b"persisted-non-utf8-\xff.txt".to_vec(),
    ));
    let mut non_utf8_receipt = receipt.clone();
    non_utf8_receipt.proof.relative_path = non_utf8_path;
    let encoded_non_utf8 = serde_json::to_vec(&non_utf8_receipt)
        .unwrap_or_else(|error| panic!("serialize non-UTF-8 receipt: {error}"));
    let decoded_non_utf8: materialize::MaterializationReceipt =
        serde_json::from_slice(&encoded_non_utf8)
            .unwrap_or_else(|error| panic!("deserialize non-UTF-8 receipt: {error}"));
    assert_eq!(decoded_non_utf8, non_utf8_receipt);
    assert!(matches!(
        materializer.cleanup(&CleanupRequest {
            cleanup_operation_id: "cleanup-forged-non-utf8-receipt",
            receipt: &decoded_non_utf8,
        }),
        Err(MaterializeError::OwnershipMismatch)
    ));
    assert!(directory.path().join(path).exists());

    let encoded = serde_json::to_vec(&receipt)
        .unwrap_or_else(|error| panic!("serialize materialization receipt: {error}"));
    let decoded: materialize::MaterializationReceipt = serde_json::from_slice(&encoded)
        .unwrap_or_else(|error| panic!("deserialize materialization receipt: {error}"));
    assert_eq!(decoded, receipt);

    assert_eq!(
        materializer
            .cleanup(&CleanupRequest {
                cleanup_operation_id: "cleanup-persisted-receipt",
                receipt: &decoded,
            })
            .unwrap_or_else(|error| panic!("cleanup from persisted receipt: {error}")),
        CleanupOutcome::Removed
    );
}

#[cfg(unix)]
#[test]
fn ownership_key_debug_never_exposes_secret_bytes() {
    let key = OwnershipKey::from_bytes([0x5a_u8; 32]);
    let rendered = format!("{key:?}");
    assert_eq!(rendered, "OwnershipKey(<redacted>)");
    assert!(!rendered.contains("5a"));
}

#[cfg(unix)]
#[test]
fn debug_output_redacts_identity_path_content_digest_and_tag() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let materializer = materializer(directory.path());
    let identity = MaterializationIdentity {
        operation_id: "secret-operation".to_string(),
        tenant_id: "secret-tenant".to_string(),
        artifact_id: "secret-artifact".to_string(),
        version_hash: [0x4d_u8; 32],
    };
    let path = Path::new("secret-path.txt");
    let content = b"secret decoy content";
    let request = MaterializationRequest {
        identity: &identity,
        relative_path: path,
        content,
    };
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains("secret-operation"));
    assert!(!request_debug.contains("secret-tenant"));
    assert!(!request_debug.contains("secret-artifact"));
    assert!(!request_debug.contains("secret-path"));
    assert!(!request_debug.contains("secret decoy content"));

    let receipt = materializer
        .materialize(&request)
        .unwrap_or_else(|error| panic!("materialize redaction test file: {error}"));
    let receipt_debug = format!("{receipt:?}");
    assert!(!receipt_debug.contains("secret-operation"));
    assert!(!receipt_debug.contains("secret-tenant"));
    assert!(!receipt_debug.contains("secret-artifact"));
    assert!(!receipt_debug.contains("secret-path"));
    assert!(!receipt_debug.contains(&format!("{:?}", receipt.proof.content_digest)));
    assert!(!receipt_debug.contains(&format!("{:?}", receipt.proof.ownership_tag)));
}

#[cfg(not(unix))]
#[test]
fn non_unix_materializer_is_explicitly_unsupported() {
    assert!(matches!(
        FileMaterializer::open(
            Path::new("unsupported"),
            OwnershipKey::from_bytes([23_u8; 32])
        ),
        Err(MaterializeError::Unsupported)
    ));
}
