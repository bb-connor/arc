use std::fmt;
use std::io;

/// The custody rule that refused an operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Refusal {
    /// A path or entry name does not have the required shape.
    InvalidPath,
    /// A requested creation mode carries more than permission bits.
    InvalidMode,
    /// The object is not a regular file.
    NotRegularFile,
    /// The object is owned by a user the policy does not trust.
    Owner,
    /// The object carries a permission bit the policy forbids.
    Mode,
    /// A regular file has more than one hard link.
    LinkCount,
    /// The object carries an extended ACL, or its ACL cannot be inspected.
    Acl,
    /// A directory above the target is owned by an untrusted user.
    AncestorOwner,
    /// A directory above the target is writable by others and not sticky.
    AncestorWritable,
    /// An entry in a sticky directory above the target is owned by an
    /// untrusted user.
    StickyEntryOwner,
    /// The pathname no longer names the pinned directory.
    PathReplaced,
    /// The file changed between its path check and its open.
    ChangedWhileOpening,
    /// The file changed while it was read.
    ChangedWhileReading,
    /// The file holds more bytes than the caller's limit.
    TooLarge,
    /// A publish destination exists although it was expected to be absent.
    DestinationExists,
    /// A publish destination is missing or no longer has its expected identity.
    DestinationChanged,
}

/// A custody refusal carried inside an [`std::io::Error`].
#[derive(Debug)]
pub struct Refused {
    refusal: Refusal,
    message: String,
}

impl Refused {
    /// The rule that refused the operation.
    #[must_use]
    pub fn refusal(&self) -> Refusal {
        self.refusal
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Refused {}

/// Names the custody rule behind `error`, or `None` for an operating-system
/// failure.
#[must_use]
pub fn refusal(error: &io::Error) -> Option<Refusal> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Refused>())
        .map(Refused::refusal)
}

pub(crate) fn refuse(
    kind: io::ErrorKind,
    refusal: Refusal,
    message: impl Into<String>,
) -> io::Error {
    io::Error::new(
        kind,
        Refused {
            refusal,
            message: message.into(),
        },
    )
}

pub(crate) fn invalid_path(message: impl Into<String>) -> io::Error {
    refuse(io::ErrorKind::InvalidInput, Refusal::InvalidPath, message)
}
