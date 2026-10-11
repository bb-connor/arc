//! Private local custody established before SQLite can write signing material.

use chio_kernel::AuthorityStoreError;

#[cfg(target_os = "linux")]
mod filesystem;
#[cfg(target_os = "linux")]
mod path;

#[cfg(target_os = "linux")]
pub(super) use filesystem::AuthorityCustody;

fn refused(message: &str) -> AuthorityStoreError {
    AuthorityStoreError::Fence(format!("authority file custody: {message}"))
}

// A permissive fallback would silently expose the same plaintext seed on a
// platform whose ACL and descriptor identity semantics are not qualified.
#[cfg(not(target_os = "linux"))]
pub(super) struct AuthorityCustody;

#[cfg(not(target_os = "linux"))]
impl AuthorityCustody {
    pub(super) fn prepare(_path: &std::path::Path) -> Result<Self, AuthorityStoreError> {
        Err(refused("requires qualified Linux file custody"))
    }

    pub(super) fn open_connection(&self) -> Result<rusqlite::Connection, AuthorityStoreError> {
        Err(refused("requires qualified Linux file custody"))
    }

    pub(super) fn inspect_existing(
        _path: &std::path::Path,
    ) -> Result<Option<Self>, AuthorityStoreError> {
        Err(refused("requires qualified Linux file custody"))
    }

    pub(super) fn open_read_only_connection(
        &self,
    ) -> Result<rusqlite::Connection, AuthorityStoreError> {
        Err(refused("requires qualified Linux file custody"))
    }

    pub(super) fn validate(
        &self,
        _connection: &rusqlite::Connection,
    ) -> Result<(), AuthorityStoreError> {
        Err(refused("requires qualified Linux file custody"))
    }
}
