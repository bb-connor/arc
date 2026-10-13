//! Connection pools for SQLite stores.

use r2d2::{Builder, ManageConnection, Pool};

/// A pool builder without the idle reaper. SQLite connections are local file
/// handles that never go stale, and a scheduled reaper keeps a dropped pool's
/// worker threads alive until its next tick, so every store pool ends with
/// its owner.
pub(crate) fn sqlite_pool_builder<M: ManageConnection>() -> Builder<M> {
    Pool::builder().idle_timeout(None).max_lifetime(None)
}
