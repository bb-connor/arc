pub mod treaty;

/// Runtime stores in these suites read the shared fixture clock.
#[allow(
    dead_code,
    reason = "The treaty suite shares this module but opens no runtime store."
)]
pub fn open_store(
    path: impl AsRef<std::path::Path>,
) -> Result<chio_runtime_core::SqliteRuntimeOrchestrationStore, chio_runtime_core::ChioRuntimeError>
{
    chio_runtime_core::SqliteRuntimeOrchestrationStore::open_with_clock(
        path,
        chio_test_support::clock::clock(),
    )
}
