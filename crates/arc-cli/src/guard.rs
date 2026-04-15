use std::path::Path;

use crate::CliError;

pub(crate) fn cmd_guard_new(_name: &str) -> Result<(), CliError> {
    Err(CliError::Other("not yet implemented".to_string()))
}

pub(crate) fn cmd_guard_build() -> Result<(), CliError> {
    Err(CliError::Other("not yet implemented".to_string()))
}

pub(crate) fn cmd_guard_inspect(_path: &Path) -> Result<(), CliError> {
    Err(CliError::Other("not yet implemented".to_string()))
}
