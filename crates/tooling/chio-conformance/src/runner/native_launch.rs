//! Explicit operator inputs for the conformance runner's enforced tool launch.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use super::RunnerError;

const MAX_READ_GRANTS_BYTES: u64 = 64 * 1024;

pub(super) fn configured_cage_arguments() -> Result<Vec<OsString>, RunnerError> {
    cage_arguments(|name| std::env::var_os(name))
}

fn cage_arguments(
    setting: impl Fn(&str) -> Option<OsString>,
) -> Result<Vec<OsString>, RunnerError> {
    let mut arguments = vec![OsString::from("--stage"), OsString::from("enforced")];
    for (variable, flag) in [
        ("CHIO_CAGE_INIT", "--cage-init"),
        ("CHIO_RECEIPT_ANCHOR_ROOT", "--receipt-rollback-anchor-root"),
    ] {
        arguments.push(flag.into());
        arguments.push(required_path(&setting, variable)?);
    }
    let grants_file = required_path(&setting, "CHIO_CAGE_READ_PATHS_FILE")?;
    let mut grants = String::new();
    File::open(grants_file)?
        .take(MAX_READ_GRANTS_BYTES + 1)
        .read_to_string(&mut grants)?;
    if grants.len() as u64 > MAX_READ_GRANTS_BYTES {
        return Err(RunnerError::InvalidSecurityMaterial(
            "native read grants exceed 64 KiB".into(),
        ));
    }
    for path in grants.lines().filter(|line| !line.is_empty()) {
        if !Path::new(path).is_absolute() {
            return Err(RunnerError::InvalidSecurityMaterial(
                "native read grants must be absolute paths".into(),
            ));
        }
        arguments.push("--read-path".into());
        arguments.push(path.into());
    }
    Ok(arguments)
}

fn required_path(
    setting: &impl Fn(&str) -> Option<OsString>,
    name: &str,
) -> Result<OsString, RunnerError> {
    setting(name)
        .filter(|path| Path::new(path).is_absolute())
        .ok_or_else(|| {
            RunnerError::InvalidSecurityMaterial(format!(
                "{name} must name an absolute path on the enforcing host"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_enforcement_configuration_is_refused() {
        let error = cage_arguments(|_| None);
        assert!(
            matches!(error, Err(RunnerError::InvalidSecurityMaterial(message)) if message.contains("CHIO_CAGE_INIT"))
        );
    }

    #[test]
    fn enforced_arguments_preserve_exact_read_paths() -> Result<(), RunnerError> {
        let root = tempfile::tempdir()?;
        let grants = root.path().join("read-paths.txt");
        std::fs::write(&grants, "/usr/lib\n/reviewed path\n")?;
        let arguments = cage_arguments(|name| match name {
            "CHIO_CAGE_INIT" => Some("/helper".into()),
            "CHIO_RECEIPT_ANCHOR_ROOT" => Some("/anchor".into()),
            "CHIO_CAGE_READ_PATHS_FILE" => Some(grants.clone().into_os_string()),
            _ => None,
        })?;
        let expected: Vec<OsString> = [
            "--stage",
            "enforced",
            "--cage-init",
            "/helper",
            "--receipt-rollback-anchor-root",
            "/anchor",
            "--read-path",
            "/usr/lib",
            "--read-path",
            "/reviewed path",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(arguments, expected);
        Ok(())
    }

    #[test]
    fn malformed_or_oversized_read_grants_are_refused() -> Result<(), RunnerError> {
        let root = tempfile::tempdir()?;
        let grants = root.path().join("read-paths.txt");
        for input in ["relative/path".to_string(), "a".repeat(65_537)] {
            std::fs::write(&grants, input)?;
            let result = cage_arguments(|name| {
                Some(if name == "CHIO_CAGE_READ_PATHS_FILE" {
                    grants.clone().into_os_string()
                } else {
                    "/configured".into()
                })
            });
            assert!(matches!(
                result,
                Err(RunnerError::InvalidSecurityMaterial(_))
            ));
        }
        Ok(())
    }
}
