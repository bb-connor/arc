//! Optional retained terminal facts remain part of the resolution lifecycle digest.

use super::*;

pub(super) const MAX_TERMINAL_SNAPSHOT_BYTES: usize = 8_192;

pub(super) fn validate(snapshot: Option<&Value>) -> Result<(), ToolOutcomeError> {
    if let Some(value) = snapshot {
        if !value.is_object() {
            return Err(ToolOutcomeError::Invalid("resolution.terminal_snapshot"));
        }
        bounded(
            "resolution.terminal_snapshot",
            value,
            MAX_TERMINAL_SNAPSHOT_BYTES,
        )?;
    }
    Ok(())
}
