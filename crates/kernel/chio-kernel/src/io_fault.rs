//! Closed filesystem fault vocabulary for the kernel store ports.
//!
//! Store adapters fold every `std::io::Error` into an [`IoFault`] at the
//! adapter boundary. The port error then carries only the fault kind: no OS
//! error object, path, or message crosses into the kernel.

use std::io::ErrorKind;

/// The filesystem fault a store adapter observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum IoFault {
    #[error("not found")]
    NotFound,
    #[error("permission denied")]
    PermissionDenied,
    #[error("already exists")]
    AlreadyExists,
    #[error("not a directory")]
    NotADirectory,
    #[error("is a directory")]
    IsADirectory,
    #[error("directory not empty")]
    DirectoryNotEmpty,
    #[error("read-only filesystem")]
    ReadOnlyFilesystem,
    #[error("storage full")]
    StorageFull,
    #[error("file too large")]
    FileTooLarge,
    #[error("resource busy")]
    ResourceBusy,
    #[error("crosses devices")]
    CrossesDevices,
    #[error("would block")]
    WouldBlock,
    #[error("interrupted")]
    Interrupted,
    #[error("timed out")]
    TimedOut,
    #[error("invalid input")]
    InvalidInput,
    #[error("invalid data")]
    InvalidData,
    #[error("unexpected end of file")]
    UnexpectedEof,
    #[error("write returned zero bytes")]
    WriteZero,
    #[error("unsupported")]
    Unsupported,
    #[error("out of memory")]
    OutOfMemory,
    /// Any kind the store ports do not distinguish.
    #[error("other io fault")]
    Other,
}

impl From<ErrorKind> for IoFault {
    fn from(kind: ErrorKind) -> Self {
        // `ErrorKind` is non-exhaustive, so kinds the ports do not
        // distinguish fold into `Other`.
        match kind {
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            ErrorKind::AlreadyExists => Self::AlreadyExists,
            ErrorKind::NotADirectory => Self::NotADirectory,
            ErrorKind::IsADirectory => Self::IsADirectory,
            ErrorKind::DirectoryNotEmpty => Self::DirectoryNotEmpty,
            ErrorKind::ReadOnlyFilesystem => Self::ReadOnlyFilesystem,
            ErrorKind::StorageFull => Self::StorageFull,
            ErrorKind::FileTooLarge => Self::FileTooLarge,
            ErrorKind::ResourceBusy => Self::ResourceBusy,
            ErrorKind::CrossesDevices => Self::CrossesDevices,
            ErrorKind::WouldBlock => Self::WouldBlock,
            ErrorKind::Interrupted => Self::Interrupted,
            ErrorKind::TimedOut => Self::TimedOut,
            ErrorKind::InvalidInput => Self::InvalidInput,
            ErrorKind::InvalidData => Self::InvalidData,
            ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            ErrorKind::WriteZero => Self::WriteZero,
            ErrorKind::Unsupported => Self::Unsupported,
            ErrorKind::OutOfMemory => Self::OutOfMemory,
            _ => Self::Other,
        }
    }
}

impl From<&std::io::Error> for IoFault {
    fn from(error: &std::io::Error) -> Self {
        Self::from(error.kind())
    }
}

impl From<std::io::Error> for IoFault {
    fn from(error: std::io::Error) -> Self {
        Self::from(error.kind())
    }
}
