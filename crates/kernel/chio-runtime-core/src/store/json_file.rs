use crate::bounded_read::read_bounded_file;
use crate::*;

/// Bounds a runtime JSON store file on both read and write, so every written store reopens.
const MAX_JSON_STORE_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn read_json_store<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<T, ChioRuntimeError> {
    let json = read_bounded_file(path, MAX_JSON_STORE_BYTES)?;
    chio_core_types::canonical::UntrustedJsonText::from_wire(&json, MAX_JSON_STORE_BYTES)
        .and_then(|input| input.decode_signed())
        .map_err(ChioRuntimeError::from)
}

/// Serializes the complete file image and refuses it before touching `path`
/// when it would not reopen.
pub(super) fn write_json_store<T: Serialize>(
    path: &Path,
    state: &T,
) -> Result<(), ChioRuntimeError> {
    let mut json = serde_json::to_vec_pretty(state).map_err(ChioRuntimeError::Json)?;
    json.push(b'\n');
    if json.len() > MAX_JSON_STORE_BYTES {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_json_store_too_large",
            detail: format!(
                "runtime JSON store {} would hold {} bytes, above the {MAX_JSON_STORE_BYTES} byte limit",
                path.display(),
                json.len()
            ),
        });
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(ChioRuntimeError::Io)?;
        }
    }
    fs::write(path, json).map_err(ChioRuntimeError::Io)
}
