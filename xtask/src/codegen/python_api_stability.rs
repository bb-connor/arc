//! Stage stable model identities and refuse unapproved public API changes.

use std::{fs, path::Path, process::Command};

use crate::{support::display_path, XtaskError};

const HELPER: &str = "xtask/src/codegen/python_api_stability.py";
const API_LOCK: &str = "sdks/python/chio-sdk-python/generated-api.lock.json";
const COMPATIBILITY: &str = "sdks/python/chio-sdk-python/generated-api-compatibility.json";

pub(super) fn annotate(root: &Path, input: &Path, output: &Path) -> Result<(), XtaskError> {
    let mut command = helper(root)?;
    command
        .arg("annotate")
        .arg("--input-dir")
        .arg(input)
        .arg("--output-dir")
        .arg(output);
    run(command, "annotate stable Python model identities")
}

pub(super) fn plan(
    root: &Path,
    raw: &Path,
    oracle: &Path,
    output: &Path,
) -> Result<(), XtaskError> {
    let mut command = helper(root)?;
    command
        .arg("plan")
        .arg("--raw-dir")
        .arg(raw)
        .arg("--oracle-dir")
        .arg(oracle)
        .arg("--baseline")
        .arg(root.join(API_LOCK))
        .arg("--output")
        .arg(output);
    run(command, "plan stable Python model bindings")
}

pub(super) fn apply(root: &Path, models: &Path, plan: &Path) -> Result<(), XtaskError> {
    let mut command = helper(root)?;
    command
        .arg("apply")
        .arg("--models-dir")
        .arg(models)
        .arg("--plan")
        .arg(plan)
        .arg("--baseline")
        .arg(root.join(API_LOCK))
        .arg("--compatibility")
        .arg(root.join(COMPATIBILITY))
        .arg("--sdk-version")
        .arg(sdk_version(root)?)
        .arg("--sdk-root")
        .arg(root.join("sdks/python/chio-sdk-python/src/chio_sdk"));
    run(command, "verify and apply stable Python public API")
}

fn helper(root: &Path) -> Result<Command, XtaskError> {
    let path = root.join(HELPER);
    if !path.is_file() {
        return Err(XtaskError::ToolMissing(format!(
            "Python API stability helper missing: {}",
            display_path(&path)
        )));
    }
    // Identity analysis uses Python's public standard-library AST API. It never
    // imports the generated models or reaches a package index during analysis.
    let mut command = Command::new("python3");
    command.arg(path).current_dir(root);
    Ok(command)
}

fn sdk_version(root: &Path) -> Result<String, XtaskError> {
    let path = root.join("sdks/python/chio-sdk-python/pyproject.toml");
    let source =
        fs::read_to_string(&path).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    let manifest: toml::Value = source
        .parse()
        .map_err(|error| XtaskError::Usage(format!("cannot parse Python SDK manifest: {error}")))?;
    manifest
        .get("project")
        .and_then(|project| project.get("version"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| XtaskError::Usage("Python SDK manifest has no fixed project version".into()))
}

fn run(mut command: Command, action: &str) -> Result<(), XtaskError> {
    let output = command
        .output()
        .map_err(|error| XtaskError::Io(action.into(), error))?;
    if !output.status.success() {
        return Err(XtaskError::ToolFailed(format!(
            "{action} refused ({})\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}
