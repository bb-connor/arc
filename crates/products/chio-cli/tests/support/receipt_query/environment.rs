use super::*;

pub(crate) fn unique_dir(prefix: &str) -> PathBuf {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    // These fixtures retain paths across child processes. Keep the directory
    // with its existing caller-owned lifetime, but establish custody at creation.
    builder
        .tempdir()
        .expect("private receipt-query fixture")
        .keep()
}

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

pub(crate) fn build_test_client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(120))
        .build()
        .expect("build reqwest client")
}
