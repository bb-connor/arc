use super::*;

pub(super) fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
}
