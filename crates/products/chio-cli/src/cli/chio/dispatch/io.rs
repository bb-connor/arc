use crate::CliError;
use std::fs;
use std::path::Path;

pub(crate) fn read_utf8_json_file(path: &Path, label: &str) -> Result<String, CliError> {
    let _ = label;
    crate::input::read_text(path)
}

pub(crate) fn write_json_string(path: &Path, json: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create Chio output directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    fs::write(path, json).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to write Chio JSON {}: {error}",
            path.display()
        ))
    })
}
