// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializationIdentity {
    pub operation_id: String,
    pub tenant_id: String,
    pub artifact_id: String,
    pub version_hash: [u8; 32],
}

impl fmt::Debug for MaterializationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializationIdentity")
            .field("operation_id", &"<redacted>")
            .field("tenant_id", &"<redacted>")
            .field("artifact_id", &"<redacted>")
            .field("version_hash", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistedFileType {
    RegularFile,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOwnershipProof {
    #[cfg_attr(unix, serde(with = "unix_path_serde"))]
    pub relative_path: PathBuf,
    pub root_device_id: u64,
    pub root_inode: u64,
    pub device_id: u64,
    pub inode: u64,
    pub file_type: PersistedFileType,
    pub link_count: u64,
    pub mode: u32,
    pub owner_user_id: u32,
    pub owner_group_id: u32,
    pub size: u64,
    pub content_digest: [u8; 32],
    pub ownership_tag: [u8; 32],
}

impl fmt::Debug for FileOwnershipProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileOwnershipProof")
            .field("relative_path", &"<redacted>")
            .field("root_device_id", &self.root_device_id)
            .field("root_inode", &self.root_inode)
            .field("device_id", &self.device_id)
            .field("inode", &self.inode)
            .field("file_type", &self.file_type)
            .field("link_count", &self.link_count)
            .field("mode", &self.mode)
            .field("owner_user_id", &self.owner_user_id)
            .field("owner_group_id", &self.owner_group_id)
            .field("size", &self.size)
            .field("content_digest", &"<redacted>")
            .field("ownership_tag", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializationReceipt {
    pub identity: MaterializationIdentity,
    pub proof: FileOwnershipProof,
}

impl fmt::Debug for MaterializationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializationReceipt")
            .field("identity", &self.identity)
            .field("proof", &self.proof)
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct MaterializationRequest<'a> {
    pub identity: &'a MaterializationIdentity,
    pub relative_path: &'a Path,
    pub content: &'a [u8],
}

impl fmt::Debug for MaterializationRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializationRequest")
            .field("identity", &"<redacted>")
            .field("relative_path", &"<redacted>")
            .field("content_len", &self.content.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct CleanupRequest<'a> {
    pub cleanup_operation_id: &'a str,
    pub receipt: &'a MaterializationReceipt,
}

impl fmt::Debug for CleanupRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanupRequest")
            .field("cleanup_operation_id", &"<redacted>")
            .field("receipt", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanupOutcome {
    Removed,
    AlreadyRemoved,
}

pub struct OwnershipKey(Zeroizing<[u8; 32]>);

impl OwnershipKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[cfg(unix)]
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OwnershipKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnershipKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathViolation {
    Empty,
    Absolute,
    EmptyComponent,
    CurrentDirectory,
    ParentDirectory,
    Nul,
    Reserved,
    Symlink,
}

impl fmt::Display for PathViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "empty path",
            Self::Absolute => "absolute path",
            Self::EmptyComponent => "empty path component",
            Self::CurrentDirectory => "current-directory path component",
            Self::ParentDirectory => "parent-directory path component",
            Self::Nul => "NUL byte in path",
            Self::Reserved => "reserved path component",
            Self::Symlink => "symlink path component",
        };
        formatter.write_str(message)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializeError {
    Unsupported,
    InvalidRoot,
    InvalidIdentity,
    InvalidPath(PathViolation),
    Symlink,
    ForeignExisting,
    OwnershipMismatch,
    MetadataMismatch,
    ContentMismatch,
    Hardlink,
    QuarantineConflict,
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for MaterializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("file materialization is unsupported"),
            Self::InvalidRoot => formatter.write_str("invalid materialization root"),
            Self::InvalidIdentity => formatter.write_str("invalid operation identity"),
            Self::InvalidPath(violation) => {
                write!(formatter, "invalid materialization path: {violation}")
            }
            Self::Symlink => formatter.write_str("symlink traversal rejected"),
            Self::ForeignExisting => formatter.write_str("foreign existing entry rejected"),
            Self::OwnershipMismatch => formatter.write_str("ownership proof mismatch"),
            Self::MetadataMismatch => formatter.write_str("file metadata mismatch"),
            Self::ContentMismatch => formatter.write_str("file content mismatch"),
            Self::Hardlink => formatter.write_str("hardlinked file rejected"),
            Self::QuarantineConflict => formatter.write_str("cleanup quarantine conflict"),
            Self::Io { operation, kind } => {
                write!(formatter, "{operation} failed with I/O kind {kind:?}")
            }
        }
    }
}

impl std::error::Error for MaterializeError {}

#[cfg(unix)]
mod unix_path_serde {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(path.as_os_str().as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;

    use hmac::{Hmac, Mac};
    use rustix::fs::{
        fchmod, fgetxattr, fsetxattr, mkdirat, open, openat, renameat_with, statat, unlinkat,
        AtFlags, FileType, Mode, OFlags, RenameFlags, XattrFlags,
    };
    use sha2::{Digest, Sha256};

    use super::{
        CleanupOutcome, CleanupRequest, FileOwnershipProof, MaterializationIdentity,
        MaterializationReceipt, MaterializationRequest, MaterializeError, OwnershipKey,
        PathViolation, PersistedFileType,
    };

    type HmacSha256 = Hmac<Sha256>;

    const DIRECTORY_MODE: u32 = 0o700;
    const FILE_MODE: u32 = 0o600;
    const PERMISSION_MASK: u32 = 0o7777;
    const OWNERSHIP_DOMAIN: &[u8] = b"chio-decoy-file-ownership-v1";
    const QUARANTINE_DOMAIN: &[u8] = b"chio-decoy-quarantine-name-v1";
    const OWNERSHIP_XATTR: &str = "user.chio.decoy.owner.v1";
    const QUARANTINE_DIRECTORY: &[u8] = b".chio-decoy-quarantine";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RootIdentity {
        device_id: u64,
        inode: u64,
        owner_user_id: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FileMetadata {
        device_id: u64,
        inode: u64,
        file_type: PersistedFileType,
        link_count: u64,
        mode: u32,
        owner_user_id: u32,
        owner_group_id: u32,
        size: u64,
    }

    struct ParsedPath<'a> {
        components: Vec<&'a OsStr>,
    }

    enum EntryState {
        Missing,
        Present(File),
    }

    pub struct FileMaterializer {
        root: File,
        root_identity: RootIdentity,
        ownership_key: OwnershipKey,
    }

    impl FileMaterializer {
        pub fn open(
            root: &std::path::Path,
            ownership_key: OwnershipKey,
        ) -> Result<Self, MaterializeError> {
            let descriptor = match open(
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::LOOP => {
                    return Err(MaterializeError::Symlink);
                }
                Err(error) if error == rustix::io::Errno::NOTDIR => {
                    return Err(MaterializeError::InvalidRoot);
                }
                Err(_) => return Err(MaterializeError::InvalidRoot),
            };
            let root = File::from(descriptor);
            let metadata = root
                .metadata()
                .map_err(|error| io_error("inspect materialization root", error))?;
            if !metadata.file_type().is_dir() {
                return Err(MaterializeError::InvalidRoot);
            }
            let root_identity = RootIdentity {
                device_id: metadata.dev(),
                inode: metadata.ino(),
                owner_user_id: metadata.uid(),
            };
            Ok(Self {
                root,
                root_identity,
                ownership_key,
            })
        }

        pub fn materialize(
            &self,
            request: &MaterializationRequest<'_>,
        ) -> Result<MaterializationReceipt, MaterializeError> {
            validate_identity(request.identity)?;
            let parsed = parse_relative_path(request.relative_path)?;
            let (parent, basename) = self
                .walk_parent(&parsed, true)?
                .ok_or(MaterializeError::MetadataMismatch)?;
            let content_digest = digest_bytes(request.content);

            match openat(
                &parent,
                basename,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(descriptor) => self.finish_created_file(
                    &parent,
                    File::from(descriptor),
                    request,
                    content_digest,
                ),
                Err(error) if error == rustix::io::Errno::EXIST => {
                    let file = match open_file_at(&parent, basename)? {
                        EntryState::Present(file) => file,
                        EntryState::Missing => return Err(MaterializeError::MetadataMismatch),
                    };
                    self.verify_retry(file, request, content_digest)
                }
                Err(error) if error == rustix::io::Errno::LOOP => Err(MaterializeError::Symlink),
                Err(error) => Err(errno_error("create materialized file", error)),
            }
        }

        pub fn cleanup(
            &self,
            request: &CleanupRequest<'_>,
        ) -> Result<CleanupOutcome, MaterializeError> {
            self.validate_cleanup_request(request)?;
            let parsed = parse_relative_path(&request.receipt.proof.relative_path)?;
            let quarantine_name = self.quarantine_name(request.receipt)?;
            let parent = self.walk_parent(&parsed, false)?;

            match parent {
                Some((parent, basename)) => match open_file_at(&parent, basename)? {
                    EntryState::Present(file) => {
                        self.verify_receipt_file(&file, request.receipt)?;
                        let quarantine = self
                            .open_quarantine(true)?
                            .ok_or(MaterializeError::MetadataMismatch)?;
                        if entry_exists(&quarantine, &quarantine_name)? {
                            return Err(MaterializeError::QuarantineConflict);
                        }
                        self.rename_to_quarantine(
                            &parent,
                            basename,
                            &quarantine,
                            &quarantine_name,
                        )?;
                        sync_file(&parent, "sync materialization parent")?;
                        sync_file(&quarantine, "sync cleanup quarantine")?;
                        self.verify_and_unlink_quarantine(
                            &quarantine,
                            &quarantine_name,
                            request.receipt,
                        )?;
                        Ok(CleanupOutcome::Removed)
                    }
                    EntryState::Missing => {
                        self.recover_quarantined_cleanup(&quarantine_name, request.receipt)
                    }
                },
                None => self.recover_quarantined_cleanup(&quarantine_name, request.receipt),
            }
        }

        #[cfg(test)]
        pub fn quarantine_without_unlink_for_test(
            &self,
            request: &CleanupRequest<'_>,
        ) -> Result<(), MaterializeError> {
            self.validate_cleanup_request(request)?;
            let parsed = parse_relative_path(&request.receipt.proof.relative_path)?;
            let quarantine_name = self.quarantine_name(request.receipt)?;
            let Some((parent, basename)) = self.walk_parent(&parsed, false)? else {
                let quarantine = self
                    .open_quarantine(false)?
                    .ok_or(MaterializeError::MetadataMismatch)?;
                return self.verify_receipt_entry(&quarantine, &quarantine_name, request.receipt);
            };
            match open_file_at(&parent, basename)? {
                EntryState::Present(file) => {
                    self.verify_receipt_file(&file, request.receipt)?;
                    let quarantine = self
                        .open_quarantine(true)?
                        .ok_or(MaterializeError::MetadataMismatch)?;
                    if entry_exists(&quarantine, &quarantine_name)? {
                        return Err(MaterializeError::QuarantineConflict);
                    }
                    self.rename_to_quarantine(&parent, basename, &quarantine, &quarantine_name)?;
                    sync_file(&parent, "sync materialization parent")?;
                    sync_file(&quarantine, "sync cleanup quarantine")?;
                    self.verify_receipt_entry(&quarantine, &quarantine_name, request.receipt)
                }
                EntryState::Missing => {
                    let quarantine = self
                        .open_quarantine(false)?
                        .ok_or(MaterializeError::MetadataMismatch)?;
                    self.verify_receipt_entry(&quarantine, &quarantine_name, request.receipt)
                }
            }
        }

        fn finish_created_file(
            &self,
            parent: &File,
            mut file: File,
            request: &MaterializationRequest<'_>,
            content_digest: [u8; 32],
        ) -> Result<MaterializationReceipt, MaterializeError> {
            fchmod(&file, Mode::RUSR | Mode::WUSR)
                .map_err(|error| errno_error("set materialized file mode", error))?;
            file.write_all(request.content)
                .map_err(|error| io_error("write materialized file", error))?;

            let metadata = regular_file_metadata(&file, MaterializeError::MetadataMismatch)?;
            validate_owned_file_metadata(&metadata)?;
            if metadata.size != usize_as_u64(request.content.len())? {
                return Err(MaterializeError::MetadataMismatch);
            }

            let mut proof = self.proof_from_metadata(
                request.relative_path,
                metadata,
                content_digest,
                [0_u8; 32],
            );
            proof.ownership_tag = self.ownership_tag(request.identity, &proof)?;
            fsetxattr(
                &file,
                OWNERSHIP_XATTR,
                &proof.ownership_tag,
                XattrFlags::CREATE,
            )
            .map_err(|error| errno_error("set materialized ownership proof", error))?;
            sync_file(&file, "sync materialized file")?;
            sync_file(parent, "sync materialization parent")?;

            let parsed = parse_relative_path(request.relative_path)?;
            let (rooted_parent, rooted_basename) = self
                .walk_parent(&parsed, false)?
                .ok_or(MaterializeError::MetadataMismatch)?;
            let reopened = match open_file_at(&rooted_parent, rooted_basename)? {
                EntryState::Present(reopened) => reopened,
                EntryState::Missing => return Err(MaterializeError::MetadataMismatch),
            };
            let receipt = MaterializationReceipt {
                identity: request.identity.clone(),
                proof,
            };
            self.verify_receipt_file(&reopened, &receipt)?;
            Ok(receipt)
        }

        fn verify_retry(
            &self,
            file: File,
            request: &MaterializationRequest<'_>,
            content_digest: [u8; 32],
        ) -> Result<MaterializationReceipt, MaterializeError> {
            let metadata = regular_file_metadata(&file, MaterializeError::ForeignExisting)?;
            validate_owned_file_metadata(&metadata)?;
            if metadata.size != usize_as_u64(request.content.len())? {
                return Err(MaterializeError::MetadataMismatch);
            }

            let mut proof = self.proof_from_metadata(
                request.relative_path,
                metadata,
                content_digest,
                [0_u8; 32],
            );
            let expected_tag = self.ownership_tag(request.identity, &proof)?;
            let stored_tag = read_ownership_tag(&file)?;
            self.verify_ownership_tag(request.identity, &proof, &stored_tag)?;
            let observed_digest = digest_file(&file)?;
            if observed_digest != content_digest {
                return Err(MaterializeError::ContentMismatch);
            }
            let observed_metadata =
                regular_file_metadata(&file, MaterializeError::MetadataMismatch)?;
            if observed_metadata != metadata {
                return Err(MaterializeError::MetadataMismatch);
            }
            proof.ownership_tag = expected_tag;
            Ok(MaterializationReceipt {
                identity: request.identity.clone(),
                proof,
            })
        }

        fn validate_cleanup_request(
            &self,
            request: &CleanupRequest<'_>,
        ) -> Result<(), MaterializeError> {
            validate_identifier(request.cleanup_operation_id)?;
            validate_identity(&request.receipt.identity)?;
            parse_relative_path(&request.receipt.proof.relative_path)?;
            let proof = &request.receipt.proof;
            if proof.root_device_id != self.root_identity.device_id
                || proof.root_inode != self.root_identity.inode
                || proof.file_type != PersistedFileType::RegularFile
                || proof.mode != FILE_MODE
            {
                return Err(MaterializeError::MetadataMismatch);
            }
            if proof.link_count != 1 {
                return Err(MaterializeError::Hardlink);
            }
            self.verify_ownership_tag(&request.receipt.identity, proof, &proof.ownership_tag)
        }

        fn verify_receipt_file(
            &self,
            file: &File,
            receipt: &MaterializationReceipt,
        ) -> Result<(), MaterializeError> {
            let observed = regular_file_metadata(file, MaterializeError::MetadataMismatch)?;
            if observed.link_count != 1 {
                return Err(MaterializeError::Hardlink);
            }
            if !metadata_matches_proof(&observed, &receipt.proof) {
                return Err(MaterializeError::MetadataMismatch);
            }

            let stored_tag = read_ownership_tag(file)?;
            self.verify_ownership_tag(&receipt.identity, &receipt.proof, &stored_tag)?;
            self.verify_ownership_tag(
                &receipt.identity,
                &receipt.proof,
                &receipt.proof.ownership_tag,
            )?;
            let observed_digest = digest_file(file)?;
            if observed_digest != receipt.proof.content_digest {
                return Err(MaterializeError::ContentMismatch);
            }
            let final_metadata = regular_file_metadata(file, MaterializeError::MetadataMismatch)?;
            if final_metadata != observed {
                return Err(MaterializeError::MetadataMismatch);
            }
            Ok(())
        }

        fn verify_receipt_entry(
            &self,
            directory: &File,
            name: &OsStr,
            receipt: &MaterializationReceipt,
        ) -> Result<(), MaterializeError> {
            match open_file_at(directory, name)? {
                EntryState::Present(file) => self.verify_receipt_file(&file, receipt),
                EntryState::Missing => Err(MaterializeError::MetadataMismatch),
            }
        }

        fn proof_from_metadata(
            &self,
            relative_path: &std::path::Path,
            metadata: FileMetadata,
            content_digest: [u8; 32],
            ownership_tag: [u8; 32],
        ) -> FileOwnershipProof {
            FileOwnershipProof {
                relative_path: relative_path.to_path_buf(),
                root_device_id: self.root_identity.device_id,
                root_inode: self.root_identity.inode,
                device_id: metadata.device_id,
                inode: metadata.inode,
                file_type: metadata.file_type,
                link_count: metadata.link_count,
                mode: metadata.mode,
                owner_user_id: metadata.owner_user_id,
                owner_group_id: metadata.owner_group_id,
                size: metadata.size,
                content_digest,
                ownership_tag,
            }
        }

        fn ownership_tag(
            &self,
            identity: &MaterializationIdentity,
            proof: &FileOwnershipProof,
        ) -> Result<[u8; 32], MaterializeError> {
            let mac = self.ownership_mac(identity, proof)?;
            let output = mac.finalize().into_bytes();
            let mut tag = [0_u8; 32];
            tag.copy_from_slice(&output);
            Ok(tag)
        }

        fn ownership_mac(
            &self,
            identity: &MaterializationIdentity,
            proof: &FileOwnershipProof,
        ) -> Result<HmacSha256, MaterializeError> {
            let mut mac = new_mac(&self.ownership_key)?;
            update_frame(&mut mac, OWNERSHIP_DOMAIN)?;
            update_frame(&mut mac, identity.operation_id.as_bytes())?;
            update_frame(&mut mac, identity.tenant_id.as_bytes())?;
            update_frame(&mut mac, identity.artifact_id.as_bytes())?;
            update_frame(&mut mac, &identity.version_hash)?;
            update_frame(&mut mac, proof.relative_path.as_os_str().as_bytes())?;
            update_u64(&mut mac, proof.root_device_id)?;
            update_u64(&mut mac, proof.root_inode)?;
            update_u64(&mut mac, proof.device_id)?;
            update_u64(&mut mac, proof.inode)?;
            update_frame(&mut mac, b"regular-file")?;
            update_u64(&mut mac, proof.link_count)?;
            update_u32(&mut mac, proof.mode)?;
            update_u32(&mut mac, proof.owner_user_id)?;
            update_u32(&mut mac, proof.owner_group_id)?;
            update_u64(&mut mac, proof.size)?;
            update_frame(&mut mac, &proof.content_digest)?;
            Ok(mac)
        }

        fn verify_ownership_tag(
            &self,
            identity: &MaterializationIdentity,
            proof: &FileOwnershipProof,
            tag: &[u8],
        ) -> Result<(), MaterializeError> {
            let mac = self.ownership_mac(identity, proof)?;
            mac.verify_slice(tag)
                .map_err(|_| MaterializeError::OwnershipMismatch)
        }

        fn quarantine_name(
            &self,
            receipt: &MaterializationReceipt,
        ) -> Result<OsString, MaterializeError> {
            let mut mac = new_mac(&self.ownership_key)?;
            update_frame(&mut mac, QUARANTINE_DOMAIN)?;
            update_frame(&mut mac, &receipt.proof.ownership_tag)?;
            update_u64(&mut mac, receipt.proof.root_device_id)?;
            update_u64(&mut mac, receipt.proof.root_inode)?;
            let digest = mac.finalize().into_bytes();
            let mut name = Vec::with_capacity(2 + digest.len() * 2);
            name.extend_from_slice(b"q-");
            for byte in digest {
                name.push(lower_hex(byte >> 4));
                name.push(lower_hex(byte & 0x0f));
            }
            Ok(OsString::from_vec(name))
        }

        fn walk_parent<'a>(
            &self,
            path: &ParsedPath<'a>,
            create_directories: bool,
        ) -> Result<Option<(File, &'a OsStr)>, MaterializeError> {
            let (basename, parents) = path
                .components
                .split_last()
                .ok_or(MaterializeError::InvalidPath(PathViolation::Empty))?;
            let descriptor = rustix::io::dup(&self.root)
                .map_err(|error| errno_error("duplicate materialization root", error))?;
            let mut current = File::from(descriptor);

            for component in parents {
                match open_directory_at(&current, component) {
                    Ok(next) => {
                        self.validate_private_directory(&next)?;
                        current = next;
                    }
                    Err(error) if error == rustix::io::Errno::NOENT && create_directories => {
                        let created = match mkdirat(&current, *component, Mode::RWXU) {
                            Ok(()) => true,
                            Err(mkdir_error) if mkdir_error == rustix::io::Errno::EXIST => false,
                            Err(mkdir_error) => {
                                return Err(errno_error(
                                    "create materialization directory",
                                    mkdir_error,
                                ));
                            }
                        };
                        let next =
                            open_directory_at(&current, component).map_err(|open_error| {
                                path_entry_error(&current, component, open_error)
                            })?;
                        if created {
                            fchmod(&next, Mode::RWXU).map_err(|chmod_error| {
                                errno_error("set materialization directory mode", chmod_error)
                            })?;
                            sync_file(&next, "sync materialization directory")?;
                            sync_file(&current, "sync materialization parent")?;
                        }
                        self.validate_private_directory(&next)?;
                        current = next;
                    }
                    Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
                    Err(error) => {
                        return Err(path_entry_error(&current, component, error));
                    }
                }
            }
            Ok(Some((current, basename)))
        }

        fn validate_private_directory(&self, directory: &File) -> Result<(), MaterializeError> {
            let metadata = directory
                .metadata()
                .map_err(|error| io_error("inspect materialization directory", error))?;
            if !metadata.file_type().is_dir()
                || metadata.dev() != self.root_identity.device_id
                || metadata.uid() != self.root_identity.owner_user_id
                || metadata.mode() & PERMISSION_MASK != DIRECTORY_MODE
            {
                return Err(MaterializeError::MetadataMismatch);
            }
            Ok(())
        }

        fn open_quarantine(&self, create: bool) -> Result<Option<File>, MaterializeError> {
            let name = OsStr::from_bytes(QUARANTINE_DIRECTORY);
            match open_directory_at(&self.root, name) {
                Ok(directory) => {
                    self.validate_private_directory(&directory)?;
                    Ok(Some(directory))
                }
                Err(error) if error == rustix::io::Errno::NOENT && !create => Ok(None),
                Err(error) if error == rustix::io::Errno::NOENT => {
                    let created = match mkdirat(&self.root, name, Mode::RWXU) {
                        Ok(()) => true,
                        Err(mkdir_error) if mkdir_error == rustix::io::Errno::EXIST => false,
                        Err(mkdir_error) => {
                            return Err(errno_error("create cleanup quarantine", mkdir_error));
                        }
                    };
                    let directory = open_directory_at(&self.root, name)
                        .map_err(|open_error| path_entry_error(&self.root, name, open_error))?;
                    if created {
                        fchmod(&directory, Mode::RWXU).map_err(|chmod_error| {
                            errno_error("set cleanup quarantine mode", chmod_error)
                        })?;
                        sync_file(&directory, "sync cleanup quarantine")?;
                        sync_file(&self.root, "sync materialization root")?;
                    }
                    self.validate_private_directory(&directory)?;
                    Ok(Some(directory))
                }
                Err(error) => Err(path_entry_error(&self.root, name, error)),
            }
        }

        fn rename_to_quarantine(
            &self,
            parent: &File,
            basename: &OsStr,
            quarantine: &File,
            quarantine_name: &OsStr,
        ) -> Result<(), MaterializeError> {
            match renameat_with(
                parent,
                basename,
                quarantine,
                quarantine_name,
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) => Ok(()),
                Err(error) if error == rustix::io::Errno::EXIST => {
                    Err(MaterializeError::QuarantineConflict)
                }
                Err(error) if error == rustix::io::Errno::NOENT => {
                    Err(MaterializeError::MetadataMismatch)
                }
                Err(error) => Err(errno_error("quarantine materialized file", error)),
            }
        }

        fn recover_quarantined_cleanup(
            &self,
            quarantine_name: &OsStr,
            receipt: &MaterializationReceipt,
        ) -> Result<CleanupOutcome, MaterializeError> {
            let Some(quarantine) = self.open_quarantine(false)? else {
                return Ok(CleanupOutcome::AlreadyRemoved);
            };
            match open_file_at(&quarantine, quarantine_name)? {
                EntryState::Missing => Ok(CleanupOutcome::AlreadyRemoved),
                EntryState::Present(file) => {
                    self.verify_receipt_file(&file, receipt)?;
                    self.unlink_verified_quarantine(&quarantine, quarantine_name)?;
                    Ok(CleanupOutcome::Removed)
                }
            }
        }

        fn verify_and_unlink_quarantine(
            &self,
            quarantine: &File,
            quarantine_name: &OsStr,
            receipt: &MaterializationReceipt,
        ) -> Result<(), MaterializeError> {
            self.verify_receipt_entry(quarantine, quarantine_name, receipt)?;
            self.unlink_verified_quarantine(quarantine, quarantine_name)
        }

        fn unlink_verified_quarantine(
            &self,
            quarantine: &File,
            quarantine_name: &OsStr,
        ) -> Result<(), MaterializeError> {
            unlinkat(quarantine, quarantine_name, AtFlags::empty())
                .map_err(|error| errno_error("unlink quarantined file", error))?;
            sync_file(quarantine, "sync cleanup quarantine")
        }
    }

    fn validate_identity(identity: &MaterializationIdentity) -> Result<(), MaterializeError> {
        validate_identifier(&identity.operation_id)?;
        validate_identifier(&identity.tenant_id)?;
        validate_identifier(&identity.artifact_id)
    }

    fn validate_identifier(value: &str) -> Result<(), MaterializeError> {
        if value.is_empty() || value.as_bytes().contains(&0) {
            return Err(MaterializeError::InvalidIdentity);
        }
        Ok(())
    }

    fn parse_relative_path(path: &std::path::Path) -> Result<ParsedPath<'_>, MaterializeError> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() {
            return Err(MaterializeError::InvalidPath(PathViolation::Empty));
        }
        if bytes.first() == Some(&b'/') {
            return Err(MaterializeError::InvalidPath(PathViolation::Absolute));
        }
        if bytes.contains(&0) {
            return Err(MaterializeError::InvalidPath(PathViolation::Nul));
        }

        let mut components = Vec::new();
        for component in bytes.split(|byte| *byte == b'/') {
            if component.is_empty() {
                return Err(MaterializeError::InvalidPath(PathViolation::EmptyComponent));
            }
            if component == b"." {
                return Err(MaterializeError::InvalidPath(
                    PathViolation::CurrentDirectory,
                ));
            }
            if component == b".." {
                return Err(MaterializeError::InvalidPath(
                    PathViolation::ParentDirectory,
                ));
            }
            if components.is_empty() && component == QUARANTINE_DIRECTORY {
                return Err(MaterializeError::InvalidPath(PathViolation::Reserved));
            }
            components.push(OsStr::from_bytes(component));
        }
        Ok(ParsedPath { components })
    }

    fn open_directory_at(parent: &File, name: &OsStr) -> Result<File, rustix::io::Errno> {
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
    }

    fn open_file_at(parent: &File, name: &OsStr) -> Result<EntryState, MaterializeError> {
        match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) if FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile => {}
            Ok(metadata) if FileType::from_raw_mode(metadata.st_mode) == FileType::Symlink => {
                return Err(MaterializeError::Symlink);
            }
            Ok(_) => return Err(MaterializeError::ForeignExisting),
            Err(error) if error == rustix::io::Errno::NOENT => {
                return Ok(EntryState::Missing);
            }
            Err(error) => return Err(errno_error("inspect materialized entry", error)),
        }
        match openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => Ok(EntryState::Present(File::from(descriptor))),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(EntryState::Missing),
            Err(error) if error == rustix::io::Errno::LOOP => Err(MaterializeError::Symlink),
            Err(error) => Err(errno_error("open materialized entry", error)),
        }
    }

    fn entry_exists(parent: &File, name: &OsStr) -> Result<bool, MaterializeError> {
        match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
            Err(error) => Err(errno_error("inspect cleanup quarantine entry", error)),
        }
    }

    fn path_entry_error(parent: &File, name: &OsStr, error: rustix::io::Errno) -> MaterializeError {
        if error == rustix::io::Errno::LOOP {
            return MaterializeError::Symlink;
        }
        if error == rustix::io::Errno::NOTDIR {
            if let Ok(metadata) = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                if FileType::from_raw_mode(metadata.st_mode) == FileType::Symlink {
                    return MaterializeError::InvalidPath(PathViolation::Symlink);
                }
            }
            return MaterializeError::MetadataMismatch;
        }
        errno_error("open materialization path component", error)
    }

    fn regular_file_metadata(
        file: &File,
        wrong_type_error: MaterializeError,
    ) -> Result<FileMetadata, MaterializeError> {
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect materialized file", error))?;
        if !metadata.file_type().is_file() {
            return Err(wrong_type_error);
        }
        Ok(FileMetadata {
            device_id: metadata.dev(),
            inode: metadata.ino(),
            file_type: PersistedFileType::RegularFile,
            link_count: metadata.nlink(),
            mode: metadata.mode() & PERMISSION_MASK,
            owner_user_id: metadata.uid(),
            owner_group_id: metadata.gid(),
            size: metadata.size(),
        })
    }

    fn validate_owned_file_metadata(metadata: &FileMetadata) -> Result<(), MaterializeError> {
        if metadata.link_count != 1 {
            return Err(MaterializeError::Hardlink);
        }
        if metadata.file_type != PersistedFileType::RegularFile || metadata.mode != FILE_MODE {
            return Err(MaterializeError::MetadataMismatch);
        }
        Ok(())
    }

    fn metadata_matches_proof(metadata: &FileMetadata, proof: &FileOwnershipProof) -> bool {
        metadata.device_id == proof.device_id
            && metadata.inode == proof.inode
            && metadata.file_type == proof.file_type
            && metadata.link_count == proof.link_count
            && metadata.mode == proof.mode
            && metadata.owner_user_id == proof.owner_user_id
            && metadata.owner_group_id == proof.owner_group_id
            && metadata.size == proof.size
    }

    fn read_ownership_tag(file: &File) -> Result<[u8; 32], MaterializeError> {
        let mut value = vec![0_u8; 33];
        let initialized = fgetxattr(file, OWNERSHIP_XATTR, &mut value)
            .map_err(|_| MaterializeError::OwnershipMismatch)?;
        if initialized != 32 {
            return Err(MaterializeError::OwnershipMismatch);
        }
        let mut tag = [0_u8; 32];
        tag.copy_from_slice(&value[..initialized]);
        Ok(tag)
    }

    fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, bytes);
        let output = hasher.finalize();
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&output);
        digest
    }

    fn digest_file(file: &File) -> Result<[u8; 32], MaterializeError> {
        let mut reader = file
            .try_clone()
            .map_err(|error| io_error("duplicate materialized file", error))?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|error| io_error("seek materialized file", error))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| io_error("read materialized file", error))?;
            if count == 0 {
                break;
            }
            Digest::update(&mut hasher, &buffer[..count]);
        }
        let output = hasher.finalize();
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&output);
        Ok(digest)
    }

    fn new_mac(key: &OwnershipKey) -> Result<HmacSha256, MaterializeError> {
        HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| MaterializeError::OwnershipMismatch)
    }

    fn update_frame(mac: &mut HmacSha256, value: &[u8]) -> Result<(), MaterializeError> {
        let length = usize_as_u64(value.len())?;
        Mac::update(mac, &length.to_be_bytes());
        Mac::update(mac, value);
        Ok(())
    }

    fn update_u64(mac: &mut HmacSha256, value: u64) -> Result<(), MaterializeError> {
        update_frame(mac, &value.to_be_bytes())
    }

    fn update_u32(mac: &mut HmacSha256, value: u32) -> Result<(), MaterializeError> {
        update_frame(mac, &value.to_be_bytes())
    }

    fn usize_as_u64(value: usize) -> Result<u64, MaterializeError> {
        u64::try_from(value).map_err(|_| MaterializeError::MetadataMismatch)
    }

    fn lower_hex(nibble: u8) -> u8 {
        match nibble {
            0..=9 => b'0' + nibble,
            _ => b'a' + (nibble - 10),
        }
    }

    fn sync_file(file: &File, operation: &'static str) -> Result<(), MaterializeError> {
        file.sync_all().map_err(|error| io_error(operation, error))
    }

    fn io_error(operation: &'static str, error: std::io::Error) -> MaterializeError {
        MaterializeError::Io {
            operation,
            kind: error.kind(),
        }
    }

    fn errno_error(operation: &'static str, error: rustix::io::Errno) -> MaterializeError {
        MaterializeError::Io {
            operation,
            kind: error.kind(),
        }
    }
}

#[cfg(unix)]
pub use unix::FileMaterializer;

#[cfg(not(unix))]
pub enum FileMaterializer {}

#[cfg(not(unix))]
impl FileMaterializer {
    pub fn open(_root: &Path, _ownership_key: OwnershipKey) -> Result<Self, MaterializeError> {
        Err(MaterializeError::Unsupported)
    }

    pub fn materialize(
        &self,
        _request: &MaterializationRequest<'_>,
    ) -> Result<MaterializationReceipt, MaterializeError> {
        Err(MaterializeError::Unsupported)
    }

    pub fn cleanup(
        &self,
        _request: &CleanupRequest<'_>,
    ) -> Result<CleanupOutcome, MaterializeError> {
        Err(MaterializeError::Unsupported)
    }
}
