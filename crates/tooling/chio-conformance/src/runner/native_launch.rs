//! Explicit operator inputs for the conformance runner's enforced tool launch.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use super::RunnerError;

const MAX_READ_GRANTS_BYTES: u64 = 64 * 1024;

/// The wrapped server must use the interpreter whose runtime files were
/// reviewed. The peer keeps its SDK-capable interpreter from the run options.
pub(super) fn configured_upstream_python(peer_python: &OsString) -> Result<OsString, RunnerError> {
    select_upstream_python(peer_python, std::env::var_os("CHIO_DEMO_PYTHON"))
}

fn select_upstream_python(
    peer_python: &OsString,
    packaged_python: Option<OsString>,
) -> Result<OsString, RunnerError> {
    match packaged_python {
        Some(program) if Path::new(&program).is_absolute() => Ok(program),
        Some(_) => Err(RunnerError::InvalidSecurityMaterial(
            "CHIO_DEMO_PYTHON must name an absolute interpreter path".into(),
        )),
        None => Ok(peer_python.clone()),
    }
}

pub(super) fn upstream_launch_arguments(target: &Path, script: &Path) -> Vec<OsString> {
    vec![
        "--target".into(),
        target.as_os_str().to_owned(),
        "--target-arg".into(),
        script.as_os_str().to_owned(),
        "--read-path".into(),
        script.as_os_str().to_owned(),
        "--runtime-file".into(),
        script.as_os_str().to_owned(),
    ]
}

pub(super) fn configured_cage_arguments() -> Result<Vec<OsString>, RunnerError> {
    cage_arguments(|name| std::env::var_os(name))
}

fn cage_arguments(
    setting: impl Fn(&str) -> Option<OsString>,
) -> Result<Vec<OsString>, RunnerError> {
    let mut arguments = vec![
        OsString::from("--stage"),
        OsString::from("enforced"),
        OsString::from("--max-artifact-bytes"),
        OsString::from("67108864"),
    ];
    for (variable, flag) in [
        ("CHIO_CAGE_INIT", "--cage-init"),
        ("CHIO_RECEIPT_ANCHOR_ROOT", "--receipt-rollback-anchor-root"),
    ] {
        arguments.push(flag.into());
        arguments.push(required_path(&setting, variable)?);
    }
    let grants_file = required_path(&setting, "CHIO_CAGE_READ_PATHS_FILE")?;
    path_arguments(&mut arguments, &grants_file, "--read-path")?;
    if setting("CHIO_CAGE_RUNTIME_FILES_FILE").is_some() {
        let runtime_file = required_path(&setting, "CHIO_CAGE_RUNTIME_FILES_FILE")?;
        path_arguments(&mut arguments, &runtime_file, "--runtime-file")?;
    }
    if let Some(profile) = setting("CHIO_CAGE_SYSCALL_PROFILE") {
        if !matches!(
            profile.to_str(),
            Some("native-minimal-v1" | "native-standard-v1")
        ) {
            return Err(RunnerError::InvalidSecurityMaterial(
                "CHIO_CAGE_SYSCALL_PROFILE must select a reviewed native profile".into(),
            ));
        }
        arguments.extend(["--syscall-profile".into(), profile]);
    }
    let uid = identity_id(&setting, "CHIO_CAGE_EXECUTION_UID")?;
    let gid = identity_id(&setting, "CHIO_CAGE_EXECUTION_GID")?;
    arguments.extend([
        "--execution-uid".into(),
        uid.to_string().into(),
        "--execution-gid".into(),
        gid.to_string().into(),
    ]);
    let groups = setting("CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS")
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| {
            RunnerError::InvalidSecurityMaterial(
                "explicit supplementary groups are required".into(),
            )
        })?;
    if groups.len() > 1024 || (!groups.is_empty() && groups.split(',').count() > 64) {
        return Err(RunnerError::InvalidSecurityMaterial(
            "supplementary groups exceed the bound".into(),
        ));
    }
    let mut previous = None;
    for group in groups.split(',').filter(|_| !groups.is_empty()) {
        let group = group
            .parse::<u32>()
            .ok()
            .filter(|group| *group != 0 && *group != u32::MAX && *group != gid)
            .ok_or_else(|| {
                RunnerError::InvalidSecurityMaterial("invalid supplementary group".into())
            })?;
        if previous.is_some_and(|value| value >= group) {
            return Err(RunnerError::InvalidSecurityMaterial(
                "supplementary groups must be sorted and unique".into(),
            ));
        }
        previous = Some(group);
        arguments.extend([
            "--execution-supplementary-gid".into(),
            group.to_string().into(),
        ]);
    }
    Ok(arguments)
}

fn path_arguments(
    arguments: &mut Vec<OsString>,
    source: &OsString,
    flag: &str,
) -> Result<(), RunnerError> {
    let mut paths = String::new();
    File::open(source)?
        .take(MAX_READ_GRANTS_BYTES + 1)
        .read_to_string(&mut paths)?;
    if paths.len() as u64 > MAX_READ_GRANTS_BYTES {
        return Err(RunnerError::InvalidSecurityMaterial(
            "native path declarations exceed 64 KiB".into(),
        ));
    }
    for path in paths.lines().filter(|line| !line.is_empty()) {
        if !Path::new(path).is_absolute() {
            return Err(RunnerError::InvalidSecurityMaterial(
                "native path declarations must be absolute paths".into(),
            ));
        }
        arguments.push(flag.into());
        arguments.push(path.into());
    }
    Ok(())
}

fn identity_id(
    setting: &impl Fn(&str) -> Option<OsString>,
    name: &str,
) -> Result<u32, RunnerError> {
    setting(name)
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0 && *value != u32::MAX)
        .ok_or_else(|| {
            RunnerError::InvalidSecurityMaterial(format!(
                "{name} must identify a non-root execution identity"
            ))
        })
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
    fn configured_native_python_preserves_the_sdk_peer_interpreter() -> Result<(), RunnerError> {
        let peer_python = OsString::from("/sdk virtualenv/bin/python");
        let packaged_python = OsString::from("/reviewed runtime/python");
        assert_eq!(
            select_upstream_python(&peer_python, Some(packaged_python.clone()))?,
            packaged_python
        );
        assert_eq!(peer_python, OsString::from("/sdk virtualenv/bin/python"));
        assert_eq!(select_upstream_python(&peer_python, None)?, peer_python);
        for invalid in ["", "python3", "relative/python"] {
            assert!(matches!(
                select_upstream_python(&peer_python, Some(invalid.into())),
                Err(RunnerError::InvalidSecurityMaterial(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn upstream_script_is_bound_as_an_argument_and_retained_runtime_file() {
        let target = Path::new("/reviewed runtime/python");
        let script = Path::new("/private run/mock server.py");
        assert_eq!(
            upstream_launch_arguments(target, script),
            [
                "--target",
                "/reviewed runtime/python",
                "--target-arg",
                "/private run/mock server.py",
                "--read-path",
                "/private run/mock server.py",
                "--runtime-file",
                "/private run/mock server.py",
            ]
            .map(OsString::from)
        );
    }

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
            "CHIO_CAGE_EXECUTION_UID" | "CHIO_CAGE_EXECUTION_GID" => Some("10001".into()),
            "CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS" => Some("".into()),
            "CHIO_CAGE_INIT" => Some("/helper".into()),
            "CHIO_RECEIPT_ANCHOR_ROOT" => Some("/anchor".into()),
            "CHIO_CAGE_READ_PATHS_FILE" => Some(grants.clone().into_os_string()),
            _ => None,
        })?;
        let expected: Vec<OsString> = [
            "--stage",
            "enforced",
            "--max-artifact-bytes",
            "67108864",
            "--cage-init",
            "/helper",
            "--receipt-rollback-anchor-root",
            "/anchor",
            "--read-path",
            "/usr/lib",
            "--read-path",
            "/reviewed path",
            "--execution-uid",
            "10001",
            "--execution-gid",
            "10001",
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

    #[test]
    fn dynamic_runtime_files_are_explicit_bounded_paths() -> Result<(), RunnerError> {
        let root = tempfile::tempdir()?;
        let paths = root.path().join("paths");
        for (input, valid) in [("/lib/loader.so\n", true), ("relative.so\n", false)] {
            std::fs::write(&paths, input)?;
            let result = cage_arguments(|name| match name {
                "CHIO_CAGE_EXECUTION_UID" | "CHIO_CAGE_EXECUTION_GID" => Some("10001".into()),
                "CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS" => Some("".into()),
                "CHIO_CAGE_SYSCALL_PROFILE" => Some("native-standard-v1".into()),
                "CHIO_CAGE_READ_PATHS_FILE" | "CHIO_CAGE_RUNTIME_FILES_FILE" => {
                    Some(paths.clone().into_os_string())
                }
                _ => Some("/configured".into()),
            });
            if valid {
                let arguments = result?;
                assert!(arguments.windows(2).any(|pair| {
                    pair == [
                        OsString::from("--runtime-file"),
                        OsString::from("/lib/loader.so"),
                    ]
                }));
            } else {
                assert!(matches!(
                    result,
                    Err(RunnerError::InvalidSecurityMaterial(_))
                ));
            }
        }
        Ok(())
    }
    #[test]
    fn identities_and_group_sets_are_explicit_and_bounded() -> Result<(), RunnerError> {
        let root = tempfile::tempdir()?;
        let grants = root.path().join("grants");
        std::fs::write(&grants, "/usr\n")?;
        for (uid, groups) in [
            ("0", "".to_owned()),
            ("4294967295", "".to_owned()),
            ("1001", "0".to_owned()),
            ("1001", "1002".to_owned()),
            ("1001", "3,,4".to_owned()),
            ("1001", "4,3".to_owned()),
            ("1001", "3,3".to_owned()),
            (
                "1001",
                (3..68)
                    .map(|group| group.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ] {
            let result = cage_arguments(|name| {
                if matches!(
                    name,
                    "CHIO_CAGE_RUNTIME_FILES_FILE" | "CHIO_CAGE_SYSCALL_PROFILE"
                ) {
                    return None;
                }
                Some(match name {
                    "CHIO_CAGE_EXECUTION_UID" => uid.into(),
                    "CHIO_CAGE_EXECUTION_GID" => "1002".into(),
                    "CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS" => groups.clone().into(),
                    "CHIO_CAGE_READ_PATHS_FILE" => grants.clone().into_os_string(),
                    _ => "/configured".into(),
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
