use std::fs::File;

use rustix::fs::{flock, FlockOperation};

/// An exclusive `flock` on a socket lifecycle lock file, held until drop.
///
/// A child forked but not yet exec'd holds a duplicate of every descriptor,
/// and closing alone cannot release the open file description's lock while
/// that duplicate exists. Drop therefore unlocks before closing.
pub(crate) struct LifecycleLock(File);

impl LifecycleLock {
    pub(crate) fn try_exclusive(file: File) -> rustix::io::Result<Self> {
        flock(&file, FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self(file))
    }
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        while let Err(rustix::io::Errno::INTR) = flock(&self.0, FlockOperation::Unlock) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn open(path: &std::path::Path) -> File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .test_expect("open lifecycle lock file")
    }

    #[test]
    fn drop_releases_the_lock_while_a_duplicate_descriptor_stays_open() {
        let directory = crate::private_tempdir().test_expect("lock directory");
        let path = directory.path().join("broker.sock.lifecycle.lock");
        let held = LifecycleLock::try_exclusive(open(&path)).test_expect("acquire lock");
        let inherited = held.0.try_clone().test_expect("duplicate lock descriptor");

        assert_eq!(
            LifecycleLock::try_exclusive(open(&path)).err(),
            Some(rustix::io::Errno::WOULDBLOCK)
        );
        drop(held);
        let reacquired =
            LifecycleLock::try_exclusive(open(&path)).test_expect("released lock is reacquired");
        drop(reacquired);
        drop(inherited);
    }
}
