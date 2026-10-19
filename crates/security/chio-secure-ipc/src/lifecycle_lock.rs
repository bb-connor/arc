use std::fs::File;

use rustix::fs::{flock, FlockOperation};

/// An exclusive `flock` on a lifecycle lock file, held until drop.
///
/// A child forked but not yet exec'd holds a duplicate of every descriptor,
/// and closing alone cannot release the open file description's lock while
/// that duplicate exists. Drop therefore unlocks before closing.
pub struct LifecycleLock(File);

impl LifecycleLock {
    pub fn try_exclusive(file: File) -> rustix::io::Result<Self> {
        flock(&file, FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self(file))
    }

    #[must_use]
    pub fn file(&self) -> &File {
        &self.0
    }
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        while let Err(rustix::io::Errno::INTR) = flock(&self.0, FlockOperation::Unlock) {}
    }
}
