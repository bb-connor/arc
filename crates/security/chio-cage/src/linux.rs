//! Audited Linux descriptor-resolution boundary.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::linux::fs::MetadataExt;
use std::os::raw::{c_int, c_long, c_uint};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::{
    digest, AdmittedManifest, BrokerIpc, CageError, ExpectedAccess, FileIdentity, FileRevision,
    ResourceKind, RetainedResource, RetainedRuntimeArtifact, RetainedRuntimeResources,
    RuntimeArtifactRole,
};

const O_WRONLY: u64 = libc::O_WRONLY as u64;
const O_RDONLY: u64 = libc::O_RDONLY as u64;
const O_CREAT: u64 = libc::O_CREAT as u64;
const O_EXCL: u64 = libc::O_EXCL as u64;
const O_CLOEXEC: u64 = libc::O_CLOEXEC as u64;
const O_DIRECTORY: u64 = libc::O_DIRECTORY as u64;
const O_NOFOLLOW: u64 = libc::O_NOFOLLOW as u64;
const O_PATH: u64 = libc::O_PATH as u64;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const SYS_OPENAT2: c_long = libc::SYS_openat2;
const ENOENT: i32 = 2;
const SOL_SOCKET: c_int = 1;
const SO_PEERCRED: c_int = 17;
const MAX_FDINFO_BYTES: u64 = 64 * 1024;
const DIRECTORY_SCAN_BUFFER_BYTES: usize = 64 * 1024;
const LINUX_DIRENT64_NAME_OFFSET: usize = 19;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[repr(C)]
struct UCred {
    pid: c_int,
    uid: c_uint,
    gid: c_uint,
}

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn geteuid() -> u32;
    fn getegid() -> u32;
    fn fchmod(fd: c_int, mode: c_uint) -> c_int;
    fn fchown(fd: c_int, owner: c_uint, group: c_uint) -> c_int;
    fn fgetxattr(
        fd: c_int,
        name: *const std::os::raw::c_char,
        value: *mut std::ffi::c_void,
        size: usize,
    ) -> isize;
    fn getsockopt(
        fd: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *mut std::ffi::c_void,
        option_length: *mut c_uint,
    ) -> c_int;
}

pub(crate) fn current_process_identity() -> crate::BrokerPeerIdentity {
    // SAFETY: these process-identity queries take no pointers and mutate no
    // Rust-owned memory.
    let uid = unsafe { geteuid() };
    // SAFETY: this process-identity query has the same contract as `geteuid`.
    let gid = unsafe { getegid() };
    crate::BrokerPeerIdentity::new(std::process::id(), uid, gid)
}

pub(crate) fn broker_peer_identity(file: &File) -> Result<crate::BrokerPeerIdentity, CageError> {
    let mut credentials = UCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = u32::try_from(std::mem::size_of::<UCred>())
        .map_err(|_| CageError::InvalidBrokerDescriptor)?;
    // SAFETY: `file` owns a live descriptor, the output points to an initialized
    // UCred buffer, and the length pointer is valid for the call.
    if unsafe {
        getsockopt(
            file.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credentials as *mut UCred).cast(),
            &mut length,
        )
    } != 0
        || usize::try_from(length).ok() != Some(std::mem::size_of::<UCred>())
    {
        return Err(CageError::InvalidBrokerDescriptor);
    }
    let pid = u32::try_from(credentials.pid).map_err(|_| CageError::InvalidBrokerDescriptor)?;
    Ok(crate::BrokerPeerIdentity::new(
        pid,
        credentials.uid,
        credentials.gid,
    ))
}

pub(crate) fn retain_forbidden(
    paths: &BTreeSet<PathBuf>,
) -> Result<Vec<RetainedResource>, CageError> {
    let root = open_root()?;
    paths
        .iter()
        .map(|path| retain_existing_from_root(&root, path, ExpectedAccess::Read))
        .collect()
}

pub(crate) fn retain_read_grants(
    paths: &BTreeSet<PathBuf>,
) -> Result<Vec<RetainedResource>, CageError> {
    let root = open_root()?;
    let mut resources = Vec::new();
    let mut visited_directories = BTreeSet::new();
    for path in paths {
        let resource = retain_existing_from_root(&root, path, ExpectedAccess::Read)?;
        retain_read_closure(resource, &mut resources, &mut visited_directories)?;
    }
    resources.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(resources)
}

fn retain_read_closure(
    resource: RetainedResource,
    resources: &mut Vec<RetainedResource>,
    visited_directories: &mut BTreeSet<(u64, u64)>,
) -> Result<(), CageError> {
    if resources.len() >= crate::MAX_READ_GRANTS {
        return Err(CageError::ResourceLimitExceeded("read grants"));
    }
    if resource.identity.kind != ResourceKind::Directory {
        resources.push(resource);
        return Ok(());
    }

    let directory_identity = (resource.identity.device, resource.identity.inode);
    let first_visit = visited_directories.insert(directory_identity);
    let directory_path = resource.path.clone();
    let traversal = open_directory_for_scan(&resource)?;
    resources.push(resource);
    if !first_visit {
        return Ok(());
    }

    for name in directory_entry_names(&traversal, &directory_path)? {
        let child_path = directory_path.join(&name);
        if let Some(child) = retain_directory_entry(&traversal, &child_path, &name)? {
            retain_read_closure(child, resources, visited_directories)?;
        }
    }
    Ok(())
}

fn open_directory_for_scan(resource: &RetainedResource) -> Result<File, CageError> {
    let file = openat2(
        resource.file.as_raw_fd(),
        b".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC,
        0,
        strict_resolution(),
    )
    .map_err(|source| CageError::RetainPath {
        path: resource.path.clone(),
        source,
    })?;
    let identity = descriptor_identity(&file, Some(&resource.path))?;
    if identity != resource.identity {
        return Err(CageError::DescriptorIdentityChanged(resource.path.clone()));
    }
    Ok(file)
}

fn directory_entry_names(
    directory: &File,
    path: &Path,
) -> Result<Vec<std::ffi::OsString>, CageError> {
    let mut names = Vec::new();
    let mut buffer = vec![0_u8; DIRECTORY_SCAN_BUFFER_BYTES];
    loop {
        // SAFETY: directory owns a live directory descriptor and buffer is a
        // writable allocation whose exact length is passed to the kernel.
        let count = unsafe {
            syscall(
                libc::SYS_getdents64,
                directory.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count < 0 {
            return Err(CageError::DirectoryEnumeration {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        let count = usize::try_from(count).map_err(|_| CageError::DirectoryEnumeration {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "invalid getdents64 length"),
        })?;
        if count == 0 {
            break;
        }
        let mut offset = 0_usize;
        while offset < count {
            let record = buffer.get(offset..count).ok_or_else(|| {
                invalid_directory_record(path, "directory record offset exceeds buffer")
            })?;
            let record_length_bytes: [u8; 2] = record
                .get(16..18)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| invalid_directory_record(path, "directory record is truncated"))?;
            let record_length = usize::from(u16::from_ne_bytes(record_length_bytes));
            if record_length <= LINUX_DIRENT64_NAME_OFFSET || record_length > record.len() {
                return Err(invalid_directory_record(
                    path,
                    "directory record length is invalid",
                ));
            }
            let name_field = &record[LINUX_DIRENT64_NAME_OFFSET..record_length];
            let terminator = name_field
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| {
                    invalid_directory_record(path, "directory entry name is not terminated")
                })?;
            let name = &name_field[..terminator];
            if name != b"." && name != b".." {
                if name.is_empty() || name.contains(&b'/') {
                    return Err(invalid_directory_record(
                        path,
                        "directory entry name is invalid",
                    ));
                }
                names.push(std::ffi::OsString::from_vec(name.to_vec()));
            }
            offset = offset.checked_add(record_length).ok_or_else(|| {
                invalid_directory_record(path, "directory record offset overflowed")
            })?;
        }
    }
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_directory_record(
            path,
            "directory enumeration returned a duplicate entry",
        ));
    }
    Ok(names)
}

fn invalid_directory_record(path: &Path, message: &'static str) -> CageError {
    CageError::DirectoryEnumeration {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, message),
    }
}

fn retain_directory_entry(
    directory: &File,
    path: &Path,
    name: &std::ffi::OsStr,
) -> Result<Option<RetainedResource>, CageError> {
    let file = match openat2(
        directory.as_raw_fd(),
        name.as_bytes(),
        O_PATH | O_CLOEXEC | O_NOFOLLOW,
        0,
        strict_resolution(),
    ) {
        Ok(file) => file,
        Err(source)
            if matches!(
                source.raw_os_error(),
                Some(libc::ENOENT) | Some(libc::ELOOP)
            ) =>
        {
            return Ok(None);
        }
        Err(source) => {
            return Err(CageError::RetainPath {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let metadata = file
        .metadata()
        .map_err(|source| CageError::DescriptorMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Ok(None);
    }
    if !(metadata.file_type().is_file() || metadata.file_type().is_dir()) {
        return Err(CageError::UnsupportedResourceKind(path.to_path_buf()));
    }
    let identity = descriptor_identity(&file, Some(path))?;
    Ok(Some(RetainedResource {
        path: path.to_path_buf(),
        identity,
        expected_access: ExpectedAccess::Read,
        creation_parent: None,
        file,
    }))
}

pub(crate) fn retain_write_grants(
    paths: &BTreeSet<PathBuf>,
) -> Result<Vec<RetainedResource>, CageError> {
    let root = open_root()?;
    paths
        .iter()
        .map(|path| retain_or_create_write_from_root(&root, path))
        .collect()
}

fn open_root() -> Result<File, CageError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags((O_PATH | O_CLOEXEC) as i32);
    options.open("/").map_err(|source| CageError::RetainPath {
        path: PathBuf::from("/"),
        source,
    })
}

fn retain_existing_from_root(
    root: &File,
    path: &Path,
    expected_access: ExpectedAccess,
) -> Result<RetainedResource, CageError> {
    let relative = relative_to_root(path)?;
    let file = openat2(
        root.as_raw_fd(),
        relative,
        O_PATH | O_CLOEXEC,
        0,
        strict_resolution(),
    )
    .map_err(|source| map_open_error(path, source))?;
    let identity = descriptor_identity(&file, Some(path))?;
    if matches!(expected_access, ExpectedAccess::WriteExactFile)
        && identity.kind != ResourceKind::RegularFile
    {
        return Err(CageError::WritableDirectory(path.to_path_buf()));
    }
    Ok(RetainedResource {
        path: path.to_path_buf(),
        identity,
        expected_access,
        creation_parent: None,
        file,
    })
}

fn retain_or_create_write_from_root(
    root: &File,
    path: &Path,
) -> Result<RetainedResource, CageError> {
    match retain_existing_from_root(root, path, ExpectedAccess::WriteExactFile) {
        Ok(resource) => Ok(resource),
        Err(CageError::RetainPath { source, .. }) if source.raw_os_error() == Some(ENOENT) => {
            create_exact_write(root, path)
        }
        Err(error) => Err(error),
    }
}

fn create_exact_write(root: &File, path: &Path) -> Result<RetainedResource, CageError> {
    let parent = path
        .parent()
        .filter(|parent| *parent != Path::new("/"))
        .ok_or_else(|| CageError::MissingWriteParent(path.to_path_buf()))?;
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| CageError::MissingWriteParent(path.to_path_buf()))?;
    let parent_resource = retain_existing_from_root(root, parent, ExpectedAccess::Read)?;
    if parent_resource.identity.kind != ResourceKind::Directory {
        return Err(CageError::MissingWriteParent(path.to_path_buf()));
    }
    let created = openat2(
        parent_resource.file.as_raw_fd(),
        file_name.as_bytes(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        0o600,
        strict_resolution(),
    )
    .map_err(|source| map_open_error(path, source))?;
    // SAFETY: these process-identity queries take no pointers and mutate no
    // Rust-owned memory.
    let effective_uid = unsafe { geteuid() };
    // SAFETY: this process-identity query has the same contract as `geteuid`.
    let effective_gid = unsafe { getegid() };
    // SAFETY: `created` owns a live descriptor and both IDs are the current
    // effective process identities.
    if unsafe { fchown(created.as_raw_fd(), effective_uid, effective_gid) } != 0 {
        return Err(CageError::RetainPath {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `created` owns a live descriptor and 0600 is a valid file mode.
    if unsafe { fchmod(created.as_raw_fd(), 0o600) } != 0 {
        return Err(CageError::RetainPath {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    let created_identity = descriptor_identity(&created, Some(path))?;
    if created_identity.kind != ResourceKind::RegularFile
        || created_identity.uid != effective_uid
        || created_identity.gid != effective_gid
        || created_identity.mode & 0o777 != 0o600
    {
        return Err(CageError::UnsafeCreatedFile(path.to_path_buf()));
    }
    let retained = openat2(
        parent_resource.file.as_raw_fd(),
        file_name.as_bytes(),
        O_PATH | O_CLOEXEC | O_NOFOLLOW,
        0,
        strict_resolution(),
    )
    .map_err(|source| map_open_error(path, source))?;
    let retained_identity = descriptor_identity(&retained, Some(path))?;
    if !created_identity.same_object(retained_identity) {
        return Err(CageError::DescriptorIdentityChanged(path.to_path_buf()));
    }
    Ok(RetainedResource {
        path: path.to_path_buf(),
        identity: retained_identity,
        expected_access: ExpectedAccess::WriteExactFile,
        creation_parent: Some(Box::new(parent_resource)),
        file: retained,
    })
}

pub(crate) fn retain_runtime_artifact(
    path: &Path,
    role: RuntimeArtifactRole,
    max_artifact_bytes: u64,
) -> Result<RetainedRuntimeArtifact, CageError> {
    let root = open_root()?;
    let relative = relative_to_root(path)?;
    let flags = match role {
        RuntimeArtifactRole::WorkingDirectory => O_PATH | O_DIRECTORY | O_CLOEXEC,
        RuntimeArtifactRole::CageInitHelper
        | RuntimeArtifactRole::TargetExecutable
        | RuntimeArtifactRole::RuntimeFile => O_CLOEXEC,
    };
    let file = openat2(root.as_raw_fd(), relative, flags, 0, strict_resolution())
        .map_err(|source| map_open_error(path, source))?;
    let identity = descriptor_identity(&file, Some(path))?;
    let expected_kind = match role {
        RuntimeArtifactRole::WorkingDirectory => ResourceKind::Directory,
        RuntimeArtifactRole::CageInitHelper
        | RuntimeArtifactRole::TargetExecutable
        | RuntimeArtifactRole::RuntimeFile => ResourceKind::RegularFile,
    };
    if identity.kind != expected_kind {
        return Err(CageError::UnsupportedResourceKind(path.to_path_buf()));
    }
    let required_executable = matches!(
        role,
        RuntimeArtifactRole::CageInitHelper | RuntimeArtifactRole::TargetExecutable
    );
    let executable_runtime = role == RuntimeArtifactRole::RuntimeFile && identity.mode & 0o111 != 0;
    if (required_executable && identity.mode & 0o111 == 0)
        || ((required_executable || executable_runtime) && identity.mode & 0o6022 != 0)
    {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    if required_executable || executable_runtime {
        reject_file_capabilities(&file, path)?;
    }

    let (binding_digest, revision) = if role == RuntimeArtifactRole::WorkingDirectory {
        (digest(&identity)?, None)
    } else {
        let (content, revision) = read_stable_content(&file, path, max_artifact_bytes)?;
        if matches!(
            role,
            RuntimeArtifactRole::CageInitHelper | RuntimeArtifactRole::TargetExecutable
        ) {
            validate_native_executable(&content, path, role)?;
        }
        (chio_core::sha256_hex(&content), Some(revision))
    };
    Ok(RetainedRuntimeArtifact {
        role,
        resource: RetainedResource {
            path: path.to_path_buf(),
            identity,
            expected_access: ExpectedAccess::Read,
            creation_parent: None,
            file,
        },
        binding_digest,
        revision,
    })
}

fn validate_native_executable(
    content: &[u8],
    path: &Path,
    role: RuntimeArtifactRole,
) -> Result<(), CageError> {
    const ELF_HEADER_BYTES: usize = 64;
    const ELF_HEADER_SIZE: u16 = 64;
    const ELF_PROGRAM_HEADER_SIZE: u16 = 56;
    const ELF_CLASS_64: u8 = 2;
    const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
    const ELF_TYPE_EXECUTABLE: u16 = 2;
    const ELF_TYPE_SHARED_OBJECT: u16 = 3;
    const ELF_MACHINE_X86_64: u16 = 62;
    const ELF_MACHINE_AARCH64: u16 = 183;
    const EXTENDED_PROGRAM_HEADER_COUNT: u16 = u16::MAX;

    if content.len() < ELF_HEADER_BYTES
        || &content[..4] != b"\x7fELF"
        || content[4] != ELF_CLASS_64
        || content[5] != ELF_DATA_LITTLE_ENDIAN
        || content[6] != 1
    {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    let image_type = read_elf_u16(content, 16)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let machine = read_elf_u16(content, 18)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let image_version = read_elf_u32(content, 20)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let entry_point = read_elf_u64(content, 24)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let program_header_offset = read_elf_u64(content, 32)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let header_size = read_elf_u16(content, 52)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let program_header_size = read_elf_u16(content, 54)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let program_header_count = read_elf_u16(content, 56)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let expected_machine = match std::env::consts::ARCH {
        "x86_64" => ELF_MACHINE_X86_64,
        "aarch64" => ELF_MACHINE_AARCH64,
        _ => return Err(CageError::InvalidExecutable(path.to_path_buf())),
    };
    if image_version != 1
        || header_size != ELF_HEADER_SIZE
        || !matches!(image_type, ELF_TYPE_EXECUTABLE | ELF_TYPE_SHARED_OBJECT)
        || role == RuntimeArtifactRole::CageInitHelper && image_type != ELF_TYPE_SHARED_OBJECT
        || machine != expected_machine
        || program_header_count == EXTENDED_PROGRAM_HEADER_COUNT
    {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    if program_header_count == 0
        || program_header_size != ELF_PROGRAM_HEADER_SIZE
        || program_header_offset < u64::from(ELF_HEADER_SIZE)
    {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    validate_program_headers(
        content,
        path,
        role,
        program_header_offset,
        program_header_size,
        program_header_count,
        entry_point,
    )
}

fn validate_program_headers(
    content: &[u8],
    path: &Path,
    role: RuntimeArtifactRole,
    table_offset: u64,
    entry_size: u16,
    entry_count: u16,
    entry_point: u64,
) -> Result<(), CageError> {
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const PF_X: u32 = 1;

    let table_size = u64::from(entry_size)
        .checked_mul(u64::from(entry_count))
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    checked_elf_range(content, table_offset, table_size)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;

    let mut interpreter_seen = false;
    let mut dynamic_seen = false;
    let mut load_seen = false;
    let mut executable_entry_seen = false;
    for index in 0..entry_count {
        let entry_offset = table_offset
            .checked_add(
                u64::from(index)
                    .checked_mul(u64::from(entry_size))
                    .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?,
            )
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        let entry = checked_elf_range(content, entry_offset, u64::from(entry_size))
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        let segment_type = read_elf_u32(entry, 0)
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        let segment_flags = read_elf_u32(entry, 4)
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        let segment_offset = read_elf_u64(entry, 8)
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        let virtual_address = read_elf_u64(entry, 16)
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        let file_size = read_elf_u64(entry, 32)
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        let memory_size = read_elf_u64(entry, 40)
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        let alignment = read_elf_u64(entry, 48)
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        if file_size > memory_size
            || file_size > 0 && checked_elf_range(content, segment_offset, file_size).is_none()
            || alignment > 1
                && (!alignment.is_power_of_two()
                    || virtual_address % alignment != segment_offset % alignment)
        {
            return Err(CageError::InvalidExecutable(path.to_path_buf()));
        }

        match segment_type {
            PT_LOAD => {
                load_seen = true;
                let file_backed_end = virtual_address
                    .checked_add(file_size)
                    .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
                if segment_flags & PF_X != 0
                    && file_size > 0
                    && entry_point >= virtual_address
                    && entry_point < file_backed_end
                {
                    executable_entry_seen = true;
                }
            }
            PT_INTERP => {
                if interpreter_seen {
                    return Err(CageError::InvalidExecutable(path.to_path_buf()));
                }
                interpreter_seen = true;
                validate_interpreter_segment(content, segment_offset, file_size, path)?;
                if role == RuntimeArtifactRole::CageInitHelper {
                    return Err(CageError::InvalidExecutable(path.to_path_buf()));
                }
            }
            PT_DYNAMIC => {
                if dynamic_seen {
                    return Err(CageError::InvalidExecutable(path.to_path_buf()));
                }
                dynamic_seen = true;
                validate_dynamic_segment(
                    content,
                    segment_offset,
                    file_size,
                    path,
                    role == RuntimeArtifactRole::CageInitHelper,
                )?;
            }
            _ => {}
        }
    }
    if !load_seen || !executable_entry_seen {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    Ok(())
}

fn validate_interpreter_segment(
    content: &[u8],
    offset: u64,
    size: u64,
    path: &Path,
) -> Result<(), CageError> {
    let segment = checked_elf_range(content, offset, size)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let Some((&terminator, interpreter)) = segment.split_last() else {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    };
    if terminator != 0 || interpreter.is_empty() || interpreter.contains(&0) {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    Ok(())
}

fn validate_dynamic_segment(
    content: &[u8],
    offset: u64,
    size: u64,
    path: &Path,
    cage_init: bool,
) -> Result<(), CageError> {
    const ELF_DYNAMIC_ENTRY_SIZE: u64 = 16;
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_RPATH: u64 = 15;
    const DT_RUNPATH: u64 = 29;

    if size == 0 || size % ELF_DYNAMIC_ENTRY_SIZE != 0 {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    let segment = checked_elf_range(content, offset, size)
        .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
    let mut terminated = false;
    for entry in segment.chunks_exact(ELF_DYNAMIC_ENTRY_SIZE as usize) {
        let tag = read_elf_u64(entry, 0)
            .ok_or_else(|| CageError::InvalidExecutable(path.to_path_buf()))?;
        if tag == DT_NULL {
            terminated = true;
        } else if terminated || cage_init && matches!(tag, DT_NEEDED | DT_RPATH | DT_RUNPATH) {
            return Err(CageError::InvalidExecutable(path.to_path_buf()));
        }
    }
    if !terminated {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    Ok(())
}

fn checked_elf_range(content: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let end = offset.checked_add(size)?;
    let start = usize::try_from(offset).ok()?;
    let end = usize::try_from(end).ok()?;
    content.get(start..end)
}

fn read_elf_u16(content: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = content
        .get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_elf_u32(content: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = content
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_elf_u64(content: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = content
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()?;
    Some(u64::from_le_bytes(bytes))
}

pub(crate) fn verify_runtime_resources(
    runtime: &RetainedRuntimeResources,
) -> Result<(), CageError> {
    for artifact in std::iter::once(&runtime.helper)
        .chain(std::iter::once(&runtime.target))
        .chain(std::iter::once(&runtime.working_directory))
        .chain(&runtime.runtime_files)
    {
        let current = descriptor_identity(&artifact.resource.file, Some(&artifact.resource.path))?;
        if current != artifact.resource.identity {
            return Err(CageError::DescriptorIdentityChanged(
                artifact.resource.path.clone(),
            ));
        }
        if matches!(
            artifact.role,
            RuntimeArtifactRole::CageInitHelper | RuntimeArtifactRole::TargetExecutable
        ) || artifact.role == RuntimeArtifactRole::RuntimeFile
            && artifact.resource.identity.mode & 0o111 != 0
        {
            reject_file_capabilities(&artifact.resource.file, &artifact.resource.path)?;
        }
        if let Some(revision) = artifact.revision {
            let (content, _) = read_stable_content(
                &artifact.resource.file,
                &artifact.resource.path,
                revision.size,
            )?;
            if chio_core::sha256_hex(&content) != artifact.binding_digest {
                return Err(CageError::ArtifactDigestMismatch(
                    artifact.resource.path.clone(),
                ));
            }
        } else if digest(&current)? != artifact.binding_digest {
            return Err(CageError::ArtifactDigestMismatch(
                artifact.resource.path.clone(),
            ));
        }
    }
    Ok(())
}

fn reject_file_capabilities(file: &File, path: &Path) -> Result<(), CageError> {
    let name = c"security.capability";
    // SAFETY: the descriptor and NUL-terminated attribute name are live. A
    // null output with size zero queries only the attribute length.
    let size = unsafe { fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size > 0
        || size < 0
            && !matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODATA) | Some(libc::ENOTSUP)
            )
    {
        return Err(CageError::InvalidExecutable(path.to_path_buf()));
    }
    Ok(())
}

pub(crate) fn verify_admitted_resources(admitted: &AdmittedManifest) -> Result<(), CageError> {
    for resource in admitted
        .forbidden_resources
        .iter()
        .chain(&admitted.read_resources)
        .chain(&admitted.write_resources)
    {
        verify_resource(resource)?;
    }
    Ok(())
}

pub(crate) fn verify_broker_ipc(broker: &BrokerIpc) -> Result<(), CageError> {
    let current = descriptor_identity(&broker.file, None)?;
    if current != broker.identity || current.kind != ResourceKind::UnixSocket {
        return Err(CageError::InvalidBrokerDescriptor);
    }
    if broker_peer_identity(&broker.file)? != broker.peer_identity {
        return Err(CageError::BrokerPeerIdentityMismatch);
    }
    Ok(())
}

fn verify_resource(resource: &RetainedResource) -> Result<(), CageError> {
    let current = descriptor_identity(&resource.file, Some(&resource.path))?;
    if !retained_resource_identity_matches(resource.identity, current) {
        return Err(CageError::DescriptorIdentityChanged(resource.path.clone()));
    }
    if let Some(parent) = resource.creation_parent.as_deref() {
        verify_resource(parent)?;
    }
    Ok(())
}

fn retained_resource_identity_matches(expected: FileIdentity, current: FileIdentity) -> bool {
    expected == current
}

pub(crate) fn descriptor_identity(
    file: &File,
    path: Option<&Path>,
) -> Result<FileIdentity, CageError> {
    let display_path = path.unwrap_or_else(|| Path::new("<descriptor>"));
    let metadata = file
        .metadata()
        .map_err(|source| CageError::DescriptorMetadata {
            path: display_path.to_path_buf(),
            source,
        })?;
    let file_type = metadata.file_type();
    let kind = if file_type.is_file() {
        ResourceKind::RegularFile
    } else if file_type.is_dir() {
        ResourceKind::Directory
    } else if file_type.is_socket() {
        ResourceKind::UnixSocket
    } else if file_type.is_symlink() {
        return Err(CageError::SymbolicLink(display_path.to_path_buf()));
    } else {
        return Err(CageError::UnsupportedResourceKind(
            display_path.to_path_buf(),
        ));
    };
    Ok(FileIdentity {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
        mount_id: mount_id(file, display_path)?,
        mode: metadata.st_mode(),
        uid: metadata.st_uid(),
        gid: metadata.st_gid(),
        kind,
    })
}

fn mount_id(file: &File, path: &Path) -> Result<u64, CageError> {
    let fdinfo_path = format!("/proc/self/fdinfo/{}", file.as_raw_fd());
    let fdinfo_file = File::open(&fdinfo_path).map_err(|source| CageError::DescriptorMetadata {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fdinfo_file
        .metadata()
        .map_err(|source| CageError::DescriptorMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.len() > MAX_FDINFO_BYTES {
        return Err(CageError::MissingMountIdentity(path.to_path_buf()));
    }
    let mut bytes = Vec::new();
    fdinfo_file
        .take(MAX_FDINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CageError::DescriptorMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    let byte_count = u64::try_from(bytes.len())
        .map_err(|_| CageError::MissingMountIdentity(path.to_path_buf()))?;
    if byte_count > MAX_FDINFO_BYTES {
        return Err(CageError::MissingMountIdentity(path.to_path_buf()));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CageError::MissingMountIdentity(path.to_path_buf()))?;
    text.lines()
        .find_map(|line| line.strip_prefix("mnt_id:\t"))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| CageError::MissingMountIdentity(path.to_path_buf()))
}

fn read_stable_content(
    file: &File,
    path: &Path,
    max_bytes: u64,
) -> Result<(Vec<u8>, FileRevision), CageError> {
    let before = file_revision(file, path)?;
    if before.size > max_bytes {
        return Err(CageError::ArtifactTooLarge(path.to_path_buf()));
    }
    let capacity = usize::try_from(before.size)
        .map_err(|_| CageError::ArtifactTooLarge(path.to_path_buf()))?;
    let mut content = Vec::with_capacity(capacity);
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read_at(&mut buffer, offset)
            .map_err(|source| CageError::RetainPath {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        let read_u64 =
            u64::try_from(read).map_err(|_| CageError::ArtifactTooLarge(path.to_path_buf()))?;
        offset = offset
            .checked_add(read_u64)
            .ok_or_else(|| CageError::ArtifactTooLarge(path.to_path_buf()))?;
        if offset > max_bytes {
            return Err(CageError::ArtifactTooLarge(path.to_path_buf()));
        }
        content.extend_from_slice(&buffer[..read]);
    }
    let after = file_revision(file, path)?;
    if before != after || offset != before.size {
        return Err(CageError::ArtifactChanged(path.to_path_buf()));
    }
    Ok((content, after))
}

fn file_revision(file: &File, path: &Path) -> Result<FileRevision, CageError> {
    let metadata = file
        .metadata()
        .map_err(|source| CageError::DescriptorMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(FileRevision {
        size: metadata.st_size(),
        modified_seconds: metadata.st_mtime(),
        modified_nanoseconds: metadata.st_mtime_nsec(),
        changed_seconds: metadata.st_ctime(),
        changed_nanoseconds: metadata.st_ctime_nsec(),
    })
}

fn relative_to_root(path: &Path) -> Result<&[u8], CageError> {
    path.as_os_str()
        .as_bytes()
        .strip_prefix(b"/")
        .filter(|relative| !relative.is_empty())
        .ok_or_else(|| CageError::InvalidPath(path.to_path_buf()))
}

const fn strict_resolution() -> u64 {
    RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
}

fn openat2(
    directory_fd: RawFd,
    path: &[u8],
    flags: u64,
    mode: u64,
    resolve: u64,
) -> io::Result<File> {
    let path = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let how = OpenHow {
        flags,
        mode,
        resolve,
    };
    // SAFETY: `path` is NUL terminated, `how` is initialized for the full
    // kernel ABI size, and both pointers remain live for the syscall.
    let result = unsafe {
        syscall(
            SYS_OPENAT2,
            c_long::from(directory_fd),
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw_fd = i32::try_from(result)
        .map_err(|_| io::Error::other("openat2 returned an invalid descriptor"))?;
    // SAFETY: a successful openat2 result is a new owned descriptor. This is
    // its single conversion into a Rust owner.
    let file = unsafe { File::from_raw_fd(raw_fd) };
    Ok(file)
}

fn map_open_error(path: &Path, source: io::Error) -> CageError {
    match source.raw_os_error() {
        Some(38) => CageError::UnsupportedKernelFeature("openat2 strict resolution"),
        Some(40) => CageError::SymbolicLink(path.to_path_buf()),
        _ => CageError::RetainPath {
            path: path.to_path_buf(),
            source,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(inode: u64) -> FileIdentity {
        FileIdentity {
            device: 1,
            inode,
            mount_id: 2,
            mode: 0o100600,
            uid: 1000,
            gid: 1000,
            kind: ResourceKind::RegularFile,
        }
    }

    #[test]
    fn path_identity_control_rejects_changed_retained_resource_identity() {
        let retained = identity(41);
        let replacement = identity(42);

        assert!(!retained_resource_identity_matches(retained, replacement));
        assert!(retained_resource_identity_matches(retained, retained));
    }
}
