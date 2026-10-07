//! Apply decoded UTF-8 schema bounds without changing generated model identities.

use std::{path::Path, process::Command};

use crate::{support::display_path, XtaskError};

const HELPER: &str = "xtask/src/codegen/python_utf8_bounds.py";

pub(super) struct ModelInputs<'a> {
    pub schemas: &'a Path,
    pub models: &'a Path,
    pub raw: &'a Path,
    pub oracle: &'a Path,
    pub bindings: &'a Path,
    pub report: &'a Path,
}

pub(super) fn harden(root: &Path, inputs: ModelInputs<'_>) -> Result<(), XtaskError> {
    let helper = root.join(HELPER);
    if !helper.is_file() {
        return Err(XtaskError::ToolMissing(format!(
            "Python UTF-8 model helper missing: {}",
            display_path(&helper)
        )));
    }
    let output = Command::new("python3")
        .arg(&helper)
        .arg("--schema-dir")
        .arg(inputs.schemas)
        .arg("--models-dir")
        .arg(inputs.models)
        .arg("--raw-dir")
        .arg(inputs.raw)
        .arg("--oracle-dir")
        .arg(inputs.oracle)
        .arg("--name-plan")
        .arg(inputs.bindings)
        .arg("--report")
        .arg(inputs.report)
        .current_dir(root)
        .output()
        .map_err(|error| XtaskError::Io(display_path(&helper), error))?;
    if !output.status.success() {
        let detail = if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        };
        return Err(XtaskError::ToolFailed(format!(
            "Python UTF-8 model validation refused ({})\n{}",
            output.status,
            String::from_utf8_lossy(detail).trim()
        )));
    }
    Ok(())
}
