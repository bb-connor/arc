use super::*;
use crate::capability::{CapabilitySource, FsCapability};
use tempfile::tempdir;

fn make_test_caps() -> CapabilitySet {
    let mut caps = CapabilitySet::new().block_network();
    caps.add_fs(FsCapability {
        original: PathBuf::from("/test/project"),
        resolved: PathBuf::from("/test/project"),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::User,
    });
    caps
}

fn make_mixed_caps() -> CapabilitySet {
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: PathBuf::from("/home/user/project"),
        resolved: PathBuf::from("/home/user/project"),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::User,
    });
    caps.add_fs(FsCapability {
        original: PathBuf::from("/usr/bin"),
        resolved: PathBuf::from("/usr/bin"),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::Group("base_read".to_string()),
    });
    caps.add_fs(FsCapability {
        original: PathBuf::from("/usr/lib"),
        resolved: PathBuf::from("/usr/lib"),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::Group("base_read".to_string()),
    });
    caps.add_fs(FsCapability {
        original: PathBuf::from("/tmp"),
        resolved: PathBuf::from("/tmp"),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::System,
    });
    caps
}

// --- Standard mode tests ---

#[test]
fn test_standard_footer_contains_exit_code() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("Command exited with code 1."));
}

#[test]
fn test_standard_footer_uses_may_not_was() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(!output.contains("may be due to sandbox restrictions"));
    assert!(!output.contains("was caused by"));
}

#[test]
fn test_standard_footer_has_block_header() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(!output.starts_with("nono diagnostic"));
    assert!(!output.contains("[nono]"));
}

#[test]
fn test_standard_footer_shows_user_paths() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("/test/project"));
    assert!(output.contains("read+write"));
}

#[test]
fn test_standard_footer_summarizes_group_paths() {
    let caps = make_mixed_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    // User path shown explicitly
    assert!(output.contains("/home/user/project"));
    // Group/system paths summarized, not listed individually
    assert!(output.contains("3 system/group path(s)"));
    assert!(!output.contains("/usr/bin"));
    assert!(!output.contains("/usr/lib"));
}

#[test]
fn test_standard_footer_shows_network_blocked() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("Network: blocked"));
}

#[test]
fn test_standard_footer_shows_network_allowed() {
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: PathBuf::from("/test/project"),
        resolved: PathBuf::from("/test/project"),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::User,
    });
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("Network: allowed"));
}

#[test]
fn test_standard_footer_shows_network_proxy() {
    use crate::NetworkMode;
    let mut caps = CapabilitySet::new().block_network();
    caps.set_network_mode_mut(NetworkMode::ProxyOnly {
        port: 12345,
        bind_ports: vec![],
    });
    caps.add_fs(FsCapability {
        original: PathBuf::from("/test/project"),
        resolved: PathBuf::from("/test/project"),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::User,
    });
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("Network: proxy (localhost:12345)"));
}

#[test]
fn test_standard_footer_shows_help() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("--allow <path>"));
    assert!(output.contains("--read <path>"));
    assert!(output.contains("--write <path>"));
}

#[test]
fn test_standard_footer_shows_network_help_when_blocked() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("--allow-net"));
}

#[test]
fn test_standard_footer_no_network_help_when_allowed() {
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: PathBuf::from("/test/project"),
        resolved: PathBuf::from("/test/project"),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::User,
    });
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(!output.contains("--allow-net"));
}

#[test]
fn test_analyze_error_output_detects_read_path() {
    let observation = analyze_error_output(
        "/bin/sh: /Users/alice/.profile: Operation not permitted\n",
        &[],
        None,
    );

    assert_eq!(
        observation.path_hints,
        vec![ObservedPathHint {
            path: PathBuf::from("/Users/alice/.profile"),
            access: AccessMode::Read,
        }]
    );
}

#[test]
fn test_analyze_error_output_detects_write_path_with_spaces() {
    let observation = analyze_error_output(
        "sh: cannot create '/tmp/file with spaces.txt': Operation not permitted\n",
        &[],
        None,
    );

    assert_eq!(
        observation.path_hints,
        vec![ObservedPathHint {
            path: PathBuf::from("/tmp/file with spaces.txt"),
            access: AccessMode::Write,
        }]
    );
}

#[test]
fn test_analyze_error_output_detects_node_eperm_mkdir_as_write() {
    let observation = analyze_error_output(
        "Failed to extract bundled package: Error: EPERM: operation not permitted, mkdir '/Users/luke/Library/Caches/copilot/pkg/darwin-arm64'\n",
        &[],
        None,
    );

    let hint = ObservedPathHint {
        path: PathBuf::from("/Users/luke/Library/Caches/copilot/pkg/darwin-arm64"),
        access: AccessMode::Write,
    };
    assert_eq!(observation.path_hints, vec![hint.clone()]);
    assert_eq!(
        observation.primary_verdict,
        Some(ErrorVerdict::LikelySandbox(hint))
    );
}

#[test]
fn test_analyze_error_output_detects_structured_node_eperm_mkdir_path() {
    let observation = analyze_error_output(
        "Error: EPERM: operation not permitted\n  code: 'EPERM',\n  syscall: 'mkdir',\n  path: '/Users/luke/Library/Caches/copilot/pkg/darwin-arm64'\n",
        &[],
        None,
    );

    assert_eq!(
        observation.path_hints,
        vec![ObservedPathHint {
            path: PathBuf::from("/Users/luke/Library/Caches/copilot/pkg/darwin-arm64"),
            access: AccessMode::Write,
        }]
    );
}

#[test]
fn test_analyze_error_output_detects_structured_path_with_escaped_quote() {
    let observation = analyze_error_output(
        "Error: EPERM: operation not permitted\n  code: 'EPERM',\n  syscall: 'mkdir',\n  path: '/Users/luke/Library/Caches/it\\'s/pkg'\n",
        &[],
        None,
    );

    assert_eq!(
        observation.path_hints,
        vec![ObservedPathHint {
            path: PathBuf::from("/Users/luke/Library/Caches/it's/pkg"),
            access: AccessMode::Write,
        }]
    );
}

#[test]
fn test_analyze_error_output_merges_access_modes() {
    let observation = analyze_error_output(
        "cat: /tmp/shared.txt: Permission denied\ntee: /tmp/shared.txt: Operation not permitted\n",
        &[],
        None,
    );

    assert_eq!(
        observation.path_hints,
        vec![ObservedPathHint {
            path: PathBuf::from("/tmp/shared.txt"),
            access: AccessMode::ReadWrite,
        }]
    );
}

#[test]
fn test_analyze_error_output_detects_missing_path() {
    let observation = analyze_error_output(
        "sh: /tmp/missing/file.txt: No such file or directory\n",
        &[],
        None,
    );

    assert_eq!(observation.path_hints, Vec::<ObservedPathHint>::new());
    assert_eq!(
        observation.missing_paths,
        vec![PathBuf::from("/tmp/missing/file.txt")]
    );
}

#[test]
fn test_analyze_error_output_handles_quoted_execvp_path() {
    // Regression: "sandbox-exec: execvp() of '/bin/ls' failed: Permission denied"
    // must extract /bin/ls, not "/bin/ls' failed".
    let observation = analyze_error_output(
        "sandbox-exec: execvp() of '/bin/ls' failed: Permission denied\n",
        &[],
        None,
    );

    assert_eq!(
        observation.path_hints,
        vec![ObservedPathHint {
            path: PathBuf::from("/bin/ls"),
            access: AccessMode::ReadWrite,
        }]
    );
}

#[test]
fn test_analyze_error_output_handles_double_quoted_path() {
    let observation = analyze_error_output(
        "error: cannot open \"/etc/shadow\" for reading: Permission denied\n",
        &[],
        None,
    );

    assert_eq!(
        observation.path_hints,
        vec![ObservedPathHint {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
        }]
    );
}

#[test]
fn test_analyze_error_output_infers_relative_write_path_from_cwd() {
    let cwd = Path::new("/Users/luke/project");
    let observation = analyze_error_output(
        "Creating empty tessl.json...\nPermission denied. Please check file permissions and try again.\n",
        &[],
        Some(cwd),
    );

    assert_eq!(
        observation.path_hints,
        vec![ObservedPathHint {
            path: PathBuf::from("/Users/luke/project/tessl.json"),
            access: AccessMode::Write,
        }]
    );
    assert_eq!(
        observation.primary_verdict,
        Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
            path: PathBuf::from("/Users/luke/project/tessl.json"),
            access: AccessMode::Write,
        }))
    );
}

#[test]
fn test_analyze_error_output_detects_non_sandbox_failure() {
    let observation = analyze_error_output(
        "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'\n",
        &[],
        None,
    );

    assert_eq!(
        observation.non_sandbox_failure.as_deref(),
        Some("EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'")
    );
    assert_eq!(
        observation.primary_verdict,
        Some(ErrorVerdict::NonSandboxFailure(
            "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                .to_string(),
        ))
    );
    assert!(observation.path_hints.is_empty());
    assert!(observation.missing_paths.is_empty());
}

#[test]
fn test_standard_footer_empty_caps() {
    let caps = CapabilitySet::new();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("(none)"));
}

#[test]
fn test_standard_footer_file_vs_dir() {
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: PathBuf::from("/test/file.txt"),
        resolved: PathBuf::from("/test/file.txt"),
        access: AccessMode::Read,
        is_file: true,
        source: CapabilitySource::User,
    });
    caps.add_fs(FsCapability {
        original: PathBuf::from("/test/dir"),
        resolved: PathBuf::from("/test/dir"),
        access: AccessMode::Write,
        is_file: false,
        source: CapabilitySource::User,
    });

    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("file.txt (read, file)"));
    assert!(output.contains("dir (write, dir)"));
}

#[test]
fn test_format_summary() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let summary = formatter.format_summary();

    assert!(summary.contains("1 path(s)"));
    assert!(summary.contains("network blocked"));
}

#[test]
fn test_standard_footer_shows_observed_path_hint_suggestions() {
    let temp = match tempdir() {
        Ok(dir) => dir,
        Err(e) => panic!("tempdir failed: {e}"),
    };
    let denied = temp.path().join("denied.txt");
    if let Err(e) = std::fs::write(&denied, "secret") {
        panic!("write failed: {e}");
    }
    let caps = make_test_caps();

    let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
        primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
            path: denied.clone(),
            access: AccessMode::Read,
        })),
        blocked_protected_file: None,
        path_hints: vec![ObservedPathHint {
            path: denied.clone(),
            access: AccessMode::Read,
        }],
        missing_paths: Vec::new(),
        non_sandbox_failure: None,
    });
    let output = formatter.format_footer(1);

    assert!(output.contains("Sandbox denial:"));
    assert!(output.contains(&denied.display().to_string()));
    assert!(output.contains(&format!("Try: --read-file {}", denied.display())));
    assert!(output.contains("Sandbox policy:"));
}

#[test]
fn test_standard_footer_exit_zero_with_observed_hint_still_surfaces_diagnostic() {
    let denied = PathBuf::from("/Users/alice/.profile");
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
        primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
            path: denied.clone(),
            access: AccessMode::Read,
        })),
        blocked_protected_file: None,
        path_hints: vec![ObservedPathHint {
            path: denied.clone(),
            access: AccessMode::Read,
        }],
        missing_paths: Vec::new(),
        non_sandbox_failure: None,
    });
    let output = formatter.format_footer(0);

    assert!(output.contains(
        "The command succeeded, but stderr showed a likely sandbox-related access issue."
    ));
    assert!(output.contains("Sandbox denial:"));
    assert!(output.contains(&denied.display().to_string()));
}

#[test]
fn test_standard_footer_surfaces_missing_path_before_policy() {
    let caps = make_test_caps();
    let missing = PathBuf::from("/tmp/missing/file.txt");
    let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
        primary_verdict: Some(ErrorVerdict::MissingPath(missing.clone())),
        blocked_protected_file: None,
        path_hints: Vec::new(),
        missing_paths: vec![missing.clone()],
        non_sandbox_failure: None,
    });
    let output = formatter.format_footer(1);
    let missing_idx = match output.find("Missing path:") {
        Some(idx) => idx,
        None => panic!("missing path block missing: {output}"),
    };
    let policy_idx = match output.find("Sandbox policy:") {
        Some(idx) => idx,
        None => panic!("policy block missing: {output}"),
    };

    assert!(
        output.contains("The command failed, but this does not look like a sandbox denial.")
    );
    assert!(output.contains(&missing.display().to_string()));
    assert!(output.contains("Path flags only apply to paths that already exist"));
    assert!(missing_idx < policy_idx);
    assert!(!output.contains("To grant additional access, re-run with:"));
    assert!(!output.contains("Why: nono why"));
}

#[test]
fn test_standard_footer_surfaces_non_sandbox_failure_before_policy() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
        primary_verdict: Some(ErrorVerdict::NonSandboxFailure(
            "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                .to_string(),
        )),
        blocked_protected_file: None,
        path_hints: Vec::new(),
        missing_paths: Vec::new(),
        non_sandbox_failure: Some(
            "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                .to_string(),
        ),
    });
    let output = formatter.format_footer(1);

    assert!(
        output.contains("The command failed, but this does not look like a sandbox denial.")
    );
    assert!(output.contains("Application error:"));
    assert!(output.contains("EEXIST: file already exists"));
    assert!(!output.contains("To grant additional access, re-run with:"));
    assert!(!output.contains("Why: nono why"));
}

#[test]
fn test_standard_footer_observed_hint_narrows_to_missing_write_access() {
    let temp = match tempdir() {
        Ok(dir) => dir,
        Err(e) => panic!("tempdir failed: {e}"),
    };
    let denied = temp.path().join("denied.txt");
    if let Err(e) = std::fs::write(&denied, "secret") {
        panic!("write failed: {e}");
    }

    let canonical_temp = match temp.path().canonicalize() {
        Ok(path) => path,
        Err(e) => panic!("canonicalize failed: {e}"),
    };

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: temp.path().to_path_buf(),
        resolved: canonical_temp.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::User,
    });

    let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
        primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
            path: denied.clone(),
            access: AccessMode::ReadWrite,
        })),
        blocked_protected_file: None,
        path_hints: vec![ObservedPathHint {
            path: denied.clone(),
            access: AccessMode::ReadWrite,
        }],
        missing_paths: Vec::new(),
        non_sandbox_failure: None,
    });
    let output = formatter.format_footer(1);

    assert!(output.contains(&format!("{} (write)", denied.display())));
    assert!(output.contains(&format!("--write {}", canonical_temp.display())));
    assert!(!output.contains(&format!("--allow-file {}", denied.display())));
}

#[test]
fn test_standard_footer_prefers_explicit_write_upgrade_for_read_only_cwd_write() {
    let cwd = PathBuf::from("/Users/luke/project");
    let denied = cwd.join("tessl.json");
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: cwd.clone(),
        resolved: cwd.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::User,
    });

    let formatter = DiagnosticFormatter::new(&caps)
        .with_current_dir(&cwd)
        .with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Write,
            })),
            blocked_protected_file: None,
            path_hints: vec![ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Write,
            }],
            missing_paths: Vec::new(),
            non_sandbox_failure: None,
        });
    let output = formatter.format_footer(1);

    assert!(output.contains("current working directory is read-only"));
    assert!(output.contains(&format!("Try: --write {}", cwd.display())));
    assert!(!output.contains("Try: --allow-cwd"));
}

#[test]
fn test_standard_footer_skips_observed_hint_already_covered() {
    let temp = match tempdir() {
        Ok(dir) => dir,
        Err(e) => panic!("tempdir failed: {e}"),
    };
    let denied = temp.path().join("denied.txt");
    if let Err(e) = std::fs::write(&denied, "secret") {
        panic!("write failed: {e}");
    }

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: temp.path().to_path_buf(),
        resolved: match temp.path().canonicalize() {
            Ok(path) => path,
            Err(e) => panic!("canonicalize failed: {e}"),
        },
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::User,
    });

    let formatter = DiagnosticFormatter::new(&caps).with_error_observation(ErrorObservation {
        primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
            path: denied.clone(),
            access: AccessMode::Read,
        })),
        blocked_protected_file: None,
        path_hints: vec![ObservedPathHint {
            path: denied.clone(),
            access: AccessMode::Read,
        }],
        missing_paths: Vec::new(),
        non_sandbox_failure: None,
    });
    let output = formatter.format_footer(1);

    assert!(!output.contains("Likely blocked paths seen in the command output"));
    assert!(!output.contains(&denied.display().to_string()));
    assert!(!output.contains("--read-file"));
}

// --- Supervised mode tests ---

#[test]
fn test_supervised_no_denials_no_extensions() {
    let caps = make_test_caps(); // extensions_enabled defaults to false
    let formatter = DiagnosticFormatter::new(&caps).with_mode(DiagnosticMode::Supervised);
    let output = formatter.format_footer(1);

    assert!(output.contains("No path denials were observed during this session."));
    assert!(output.contains("The failure may be unrelated to sandbox restrictions."));
    assert!(output.contains("To grant additional access, re-run with:"));
    assert!(output.contains("--allow <path>"));
    assert!(!output.contains("Sandbox policy:"));
}

#[test]
fn test_supervised_no_denials_no_extensions_uses_observed_hints() {
    let temp = match tempdir() {
        Ok(dir) => dir,
        Err(e) => panic!("tempdir failed: {e}"),
    };
    let denied = temp.path().join("startup.txt");
    if let Err(e) = std::fs::write(&denied, "secret") {
        panic!("write failed: {e}");
    }
    let caps = make_test_caps();

    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            })),
            blocked_protected_file: None,
            path_hints: vec![ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            }],
            missing_paths: Vec::new(),
            non_sandbox_failure: None,
        });
    let output = formatter.format_footer(1);

    assert!(output.contains("Sandbox denial:"));
    assert!(output.contains(&format!("Try: --read-file {}", denied.display())));
    assert!(output.contains("No path denials were observed during this session."));
    assert!(output.contains("Discover paths: nono learn -- <your command>"));
    assert!(!output.contains("Sandbox policy:"));
}

#[test]
fn test_supervised_exit_zero_with_observed_hint_still_surfaces_diagnostic() {
    let denied = PathBuf::from("/Users/alice/.profile");
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            })),
            blocked_protected_file: None,
            path_hints: vec![ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Read,
            }],
            missing_paths: Vec::new(),
            non_sandbox_failure: None,
        });
    let output = formatter.format_footer(0);

    assert!(output.contains(
        "The command succeeded, but stderr showed a likely sandbox-related access issue."
    ));
    assert!(output.contains("Sandbox denial:"));
    assert!(output.contains(&denied.display().to_string()));
    assert!(output.contains("Discover paths: nono learn -- <your command>"));
}

#[test]
fn test_supervised_no_denials_no_extensions_surfaces_missing_path() {
    let caps = make_test_caps();
    let missing = PathBuf::from("/tmp/missing/file.txt");
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::MissingPath(missing.clone())),
            blocked_protected_file: None,
            path_hints: Vec::new(),
            missing_paths: vec![missing.clone()],
            non_sandbox_failure: None,
        });
    let output = formatter.format_footer(1);

    assert!(
        output.contains("The command failed, but this does not look like a sandbox denial.")
    );
    assert!(output.contains(&missing.display().to_string()));
    assert!(output.contains("To grant additional access, re-run with:"));
    assert!(output.contains("Query policy: nono why --path <path> --op <read|write|readwrite>"));
}

#[test]
fn test_supervised_no_denials_no_extensions_surfaces_non_sandbox_failure() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::NonSandboxFailure(
                "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                    .to_string(),
            )),
            blocked_protected_file: None,
            path_hints: Vec::new(),
            missing_paths: Vec::new(),
            non_sandbox_failure: Some(
                "EEXIST: file already exists, mkdir '/Users/luke/.local/share/opencode'"
                    .to_string(),
            ),
        });
    let output = formatter.format_footer(1);

    assert!(
        output.contains("The command failed, but this does not look like a sandbox denial.")
    );
    assert!(output.contains("Application error:"));
    assert!(output.contains("EEXIST: file already exists"));
    assert!(output.contains("To grant additional access, re-run with:"));
    assert!(output.contains("Discover paths: nono learn -- <your command>"));
}

#[test]
fn test_supervised_no_denials_extensions_active() {
    let mut caps = make_test_caps();
    caps.set_extensions_enabled(true);
    let formatter = DiagnosticFormatter::new(&caps).with_mode(DiagnosticMode::Supervised);
    let output = formatter.format_footer(1);

    assert!(output.contains("No path denials were observed during this session."));
    assert!(output.contains("may be unrelated"));
    assert!(output.contains("--allow <path>"));
}

#[test]
fn test_supervised_uses_sandbox_violations_when_available() {
    let caps = make_test_caps();
    let violations = vec![
        SandboxViolation {
            operation: "file-read-data".to_string(),
            target: Some("/Users/alice/.ssh/id_rsa".to_string()),
        },
        SandboxViolation {
            operation: "mach-lookup".to_string(),
            target: Some("com.apple.logd".to_string()),
        },
    ];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_sandbox_violations(&violations);
    let output = formatter.format_footer(1);

    assert!(output.contains("Sandbox denial:"));
    assert!(output.contains("/Users/alice/.ssh/id_rsa (read)"));
    assert!(output.contains("Also blocked (system services):"));
    assert!(output.contains("mach-lookup (com.apple.logd)"));
    assert!(output.contains("System logging"));
}

#[test]
fn test_supervised_merges_mkdir_error_hint_with_logged_read_denial() {
    let temp = tempdir().expect("tempdir should be created");
    let pkg = temp.path().join("Library/Caches/copilot/pkg");
    std::fs::create_dir_all(&pkg).expect("pkg fixture should be created");
    let denied = pkg.join("darwin-arm64");

    let caps = CapabilitySet::new();
    let violations = vec![SandboxViolation {
        operation: "file-read-data".to_string(),
        target: Some(denied.display().to_string()),
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_sandbox_violations(&violations)
        .with_error_observation(ErrorObservation {
            primary_verdict: Some(ErrorVerdict::LikelySandbox(ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Write,
            })),
            blocked_protected_file: None,
            path_hints: vec![ObservedPathHint {
                path: denied.clone(),
                access: AccessMode::Write,
            }],
            missing_paths: Vec::new(),
            non_sandbox_failure: None,
        })
        .with_policy_explanations(vec![PolicyExplanation {
            path: denied.clone(),
            access: AccessMode::Read,
            reason: "path_not_granted".to_string(),
            details: None,
            policy_source: None,
            suggested_flag: Some(format!("--read {}", denied.display())),
        }]);
    let output = formatter.format_footer(1);

    assert!(output.contains(&format!("{} (read+write)", denied.display())));
    assert!(output.contains(&format!("Fix: --allow {}", pkg.display())));
    assert!(!output.contains(&format!("Fix: --read {}", denied.display())));
}

#[test]
fn test_keychain_guidance_uses_file_flag_for_file_targets() {
    let dir = tempdir().expect("tempdir should be created");
    let keychain = dir.path().join("login.keychain-db");
    std::fs::write(&keychain, "db").expect("keychain fixture should be written");

    let guidance =
        keychain_grant_guidance_for_path(&keychain, "~/Library/Keychains/login.keychain-db");

    assert_eq!(
        guidance,
        "[nono]   --read-file ~/Library/Keychains/login.keychain-db"
    );
}

#[test]
fn test_keychain_guidance_uses_directory_flag_for_directory_targets() {
    let dir = tempdir().expect("tempdir should be created");

    let guidance =
        keychain_grant_guidance_for_path(dir.path(), "~/Library/Keychains/login.keychain-db");

    assert_eq!(
        guidance,
        "[nono]   --read ~/Library/Keychains/login.keychain-db"
    );
}

#[test]
fn test_keychain_guidance_recognizes_keychain_mach_services() {
    let caps = make_test_caps();
    let violations = vec![SandboxViolation {
        operation: "mach-lookup".to_string(),
        target: Some("com.apple.secd".to_string()),
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_sandbox_violations(&violations);
    let output = formatter.format_footer(1);

    assert!(output.contains("Keychain access requires granting the login keychain path:"));
    assert!(output.contains("--read-file ~/Library/Keychains/login.keychain-db"));
}

#[test]
fn test_preference_guidance_recognizes_any_application_domain() {
    let caps = make_test_caps();
    let violations = vec![SandboxViolation {
        operation: "user-preference-read".to_string(),
        target: Some("kcfpreferencesanyapplication".to_string()),
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_sandbox_violations(&violations);
    let output = formatter.format_footer(1);

    assert!(output.contains("user-preference-read (kcfpreferencesanyapplication)"));
    assert!(output.contains("Global preferences"));
    assert!(output.contains("CFPreferences / NSUserDefaults"));
    assert!(output.contains("unsafe_macos_seatbelt_rules"));
    assert!(output.contains("(allow user-preference-read)"));
}

#[test]
fn test_forbidden_exec_sugid_guidance_is_not_saveable() {
    let caps = make_test_caps();
    let violations = vec![SandboxViolation {
        operation: "forbidden-exec-sugid".to_string(),
        target: None,
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_sandbox_violations(&violations);
    let output = formatter.format_footer(0);

    assert!(output.contains("forbidden-exec-sugid"));
    assert!(output.contains("Setuid/setgid executable blocked"));
    assert!(output.contains("not a path grant"));
    assert!(output.contains("does not save this automatically"));
    assert!(!output.contains("unsafe_macos_seatbelt_rules"));
}

#[test]
fn test_supervised_policy_blocked_denial() {
    let caps = make_test_caps();
    let denials = vec![DenialRecord {
        path: PathBuf::from("/etc/shadow"),
        access: AccessMode::Read,
        reason: DenialReason::PolicyBlocked,
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    assert!(output.contains("Sandbox denial: 1 path blocked."));
    assert!(output.contains("/etc/shadow (read)  [permanently restricted]"));
    assert!(output.contains("permanently restricted — override via a user profile"));
    // Policy-blocked paths cannot be fixed with a path flag.
    assert!(!output.contains("Fix: --read /etc/shadow"));
    assert!(!output.contains("--allow <path>"));
}

#[test]
fn test_supervised_user_denied() {
    let caps = make_test_caps();
    let dir = tempdir().expect("tempdir should be created");
    let denied_path = dir.path().join("secret.txt");
    std::fs::write(&denied_path, "secret").expect("denied file should be created");
    let denials = vec![DenialRecord {
        path: denied_path.clone(),
        access: AccessMode::Read,
        reason: DenialReason::UserDenied,
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    assert!(output.contains("Sandbox denial: 1 path blocked."));
    assert!(output.contains(&denied_path.display().to_string()));
    assert!(output.contains(&format!("Fix: --read-file {}", denied_path.display())));
    // User-denied paths are actionable, not policy-blocked.
    assert!(!output.contains("[permanently restricted]"));
}

#[test]
fn test_supervised_mixed_denials() {
    let caps = make_test_caps();
    let denials = vec![
        DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        },
        DenialRecord {
            path: PathBuf::from("/home/user/data.txt"),
            access: AccessMode::Read,
            reason: DenialReason::UserDenied,
        },
    ];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    assert!(output.contains("Sandbox denial: 2 paths blocked."));
    // Policy-blocked path gets the marker.
    assert!(output.contains("/etc/shadow (read)  [permanently restricted]"));
    // Actionable path is listed without the marker.
    assert!(output.contains("/home/user/data.txt (read)"));
    assert!(!output.contains("/home/user/data.txt (read)  [permanently restricted]"));
    // Consolidated Fix line covers only the actionable path. The suggested
    // target falls back to the nearest existing parent directory since the
    // path itself doesn't exist in the test environment.
    assert!(output.contains("Fix: --read "));
    assert!(!output.contains("Fix: --read /etc/shadow"));
    // The permanent-restriction note appears once for the policy-blocked path.
    assert!(output.contains("1 path is permanently restricted"));
}

#[test]
fn test_supervised_deduplicates_paths() {
    let caps = make_test_caps();
    let denials = vec![
        DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        },
        DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        },
    ];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    let count = output.matches("/etc/shadow").count();
    assert_eq!(count, 1, "Path should be deduplicated");
    assert!(!output.contains("Denied paths during this session:"));
}

#[test]
fn test_supervised_consolidated_fix_combines_all_actionable() {
    let caps = make_test_caps();
    let dir = tempdir().expect("tempdir should be created");
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    std::fs::write(&a, "a").expect("write a");
    std::fs::write(&b, "b").expect("write b");
    let denials = vec![
        DenialRecord {
            path: a.clone(),
            access: AccessMode::Read,
            reason: DenialReason::UserDenied,
        },
        DenialRecord {
            path: b.clone(),
            access: AccessMode::Write,
            reason: DenialReason::InsufficientAccess,
        },
    ];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    // Single Fix line covers both paths.
    let fix_lines: Vec<&str> = output
        .lines()
        .filter(|line| line.contains("Fix: "))
        .collect();
    assert_eq!(
        fix_lines.len(),
        1,
        "expected one consolidated Fix line: {output}"
    );
    assert!(fix_lines[0].contains(&format!("--read-file {}", a.display())));
    assert!(fix_lines[0].contains(&format!("--write-file {}", b.display())));
    assert!(!output.contains("[permanently restricted]"));
}

#[test]
fn test_supervised_consolidated_list_truncates_beyond_cap() {
    // Zero-pad the index so paths sort in numeric order.
    let caps = make_test_caps();
    let denials: Vec<DenialRecord> = (0..15)
        .map(|i| DenialRecord {
            path: PathBuf::from(format!("/tmp/denied-{i:02}")),
            access: AccessMode::Read,
            reason: DenialReason::UserDenied,
        })
        .collect();
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    assert!(output.contains("Sandbox denial: 15 paths blocked."));
    // First 10 paths listed, remaining 5 collapsed.
    assert!(output.contains("/tmp/denied-00 "));
    assert!(output.contains("/tmp/denied-09 "));
    assert!(!output.contains("/tmp/denied-10 "));
    assert!(output.contains("… and 5 more"));
    // Fix line still covers all 15 paths.
    assert_eq!(
        output.lines().filter(|l| l.contains("Fix: ")).count(),
        1,
        "expected one consolidated Fix line"
    );
}

#[test]
fn test_supervised_has_block_header() {
    let caps = make_test_caps();
    let denials = vec![DenialRecord {
        path: PathBuf::from("/etc/shadow"),
        access: AccessMode::Read,
        reason: DenialReason::PolicyBlocked,
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    assert!(!output.starts_with("nono diagnostic"));
    assert!(!output.contains("[nono]"));
}

#[test]
fn test_supervised_rate_limited_denial() {
    let caps = make_test_caps();
    let denials = vec![DenialRecord {
        path: PathBuf::from("/tmp/flood"),
        access: AccessMode::Read,
        reason: DenialReason::RateLimited,
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    assert!(output.contains("Sandbox denial: 1 path blocked."));
    assert!(output.contains("/tmp/flood (read)"));
    // Rate-limited denials are still actionable via a path flag. The
    // suggested target falls back to the nearest existing parent since
    // /tmp/flood itself doesn't exist.
    assert!(output.contains("Fix: --read "));
    assert!(!output.contains("[permanently restricted]"));
}

#[test]
fn test_supervised_insufficient_access_shows_closest_grant_and_fix() {
    let dir = tempdir().expect("tempdir should be created");
    let denied_path = dir.path().join("output.txt");
    std::fs::write(&denied_path, "output").expect("output file should be created");
    let dir_path = dir
        .path()
        .canonicalize()
        .expect("tempdir should canonicalize");

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: dir.path().to_path_buf(),
        resolved: dir_path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::Group("project_read".to_string()),
    });

    let denials = vec![DenialRecord {
        path: denied_path.clone(),
        access: AccessMode::Write,
        reason: DenialReason::InsufficientAccess,
    }];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_denials(&denials);
    let output = formatter.format_footer(1);

    // The "Closest grant" hint moved out of the consolidated footer;
    // users can recover it with `nono why` if they want the detail.
    assert!(!output.contains("Closest grant:"));
    assert!(output.contains(&format!("Fix: --write-file {}", denied_path.display())));
    assert!(!output.contains("Denied paths during this session:"));
}

// --- Protected paths tests ---

#[test]
fn test_protected_paths_shown_in_footer() {
    let caps = make_test_caps();
    let protected = vec![
        PathBuf::from("/project/SKILLS.md"),
        PathBuf::from("/project/helper.py"),
    ];
    let formatter = DiagnosticFormatter::new(&caps).with_protected_paths(&protected);
    let output = formatter.format_footer(1);

    assert!(output.contains("Write-protected"));
    assert!(output.contains("SKILLS.md"));
    assert!(output.contains("helper.py"));
}

#[test]
fn test_protected_paths_empty_no_section() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps).with_protected_paths(&[]);
    let output = formatter.format_footer(1);

    assert!(!output.contains("Write-protected"));
}

#[test]
fn test_protected_paths_shown_in_supervised_macos_fallback() {
    let caps = make_test_caps(); // extensions_enabled defaults to false
    let protected = vec![PathBuf::from("/project/config.json")];
    let formatter = DiagnosticFormatter::new(&caps)
        .with_mode(DiagnosticMode::Supervised)
        .with_protected_paths(&protected);
    let output = formatter.format_footer(1);

    assert!(!output.contains("Write-protected"));
}

// --- Exit code explanation tests ---

fn make_command_context(program: &str, path: &str) -> CommandContext {
    CommandContext {
        program: program.to_string(),
        resolved_path: PathBuf::from(path),
        args: vec![program.to_string()],
    }
}

#[test]
fn test_exit_127_binary_not_readable() {
    // Binary resolved to /opt/bin/foo but sandbox has no read access there
    let caps = make_test_caps(); // only /test/project
    let cmd = make_command_context("foo", "/opt/bin/foo");
    let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
    let output = formatter.format_footer(127);

    assert!(output.contains("Failed to execute command (exit code 127)"));
    assert!(output.contains("The executable 'foo' was resolved at:"));
    assert!(output.contains("/opt/bin/foo"));
    assert!(output.contains("not readable inside the sandbox"));
    assert!(output.contains("nono run --read /opt/bin"));
}

#[test]
fn test_exit_127_binary_readable_but_exec_fails() {
    // Binary at /usr/bin/ps, sandbox has /usr/bin readable
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: PathBuf::from("/usr/bin"),
        resolved: PathBuf::from("/usr/bin"),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::Group("system_read".to_string()),
    });
    let cmd = make_command_context("ps", "/usr/bin/ps");
    let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
    let output = formatter.format_footer(127);

    assert!(output.contains("'ps' resolved to /usr/bin/ps and is readable"));
    assert!(output.contains("execution still failed. Common causes:"));
    assert!(output.contains("shared library"));
    assert!(output.contains("Run with -v"));
}

#[test]
fn test_exit_127_file_level_grant_dir_not_readable() {
    // Binary granted as a file-level read, but parent dir not readable
    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: PathBuf::from("/opt/custom/mybin"),
        resolved: PathBuf::from("/opt/custom/mybin"),
        access: AccessMode::Read,
        is_file: true,
        source: CapabilitySource::User,
    });
    let cmd = make_command_context("mybin", "/opt/custom/mybin");
    let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
    let output = formatter.format_footer(127);

    // is_binary_path_readable returns true (file-level match)
    // is_binary_dir_readable returns false (/opt/custom not granted)
    assert!(output.contains("'mybin' resolved to /opt/custom/mybin but the directory"));
    assert!(output.contains("read access to"));
}

#[test]
fn test_exit_127_no_command_context() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(127);

    assert!(output.contains("Command not found (exit code 127)"));
    assert!(output.contains("could not be found or executed"));
}

#[test]
fn test_exit_126_permission_denied() {
    let caps = make_test_caps();
    let cmd = make_command_context("script.sh", "/test/project/script.sh");
    let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
    let output = formatter.format_footer(126);

    assert!(output.contains("Permission denied (exit code 126)"));
    assert!(output.contains("'script.sh' was found at /test/project/script.sh"));
    assert!(output.contains("execute permission"));
}

#[test]
fn test_exit_126_no_command_context() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(126);

    assert!(output.contains("Permission denied (exit code 126)"));
    assert!(output.contains("found but could not be executed"));
}

#[test]
fn test_exit_1_generic() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(1);

    assert!(output.contains("Command exited with code 1."));
}

#[test]
fn test_exit_sigkill() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(128 + 9);

    assert!(output.contains("SIGKILL"));
    assert!(output.contains("forcefully terminated"));
    assert!(output.contains("usually not"));
}

#[test]
fn test_exit_sigsys_platform_correct() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(128 + libc::SIGSYS);

    assert!(output.contains("SIGSYS"));
    assert!(output.contains("blocked system call"));
}

#[test]
fn test_exit_sigterm() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(128 + 15);

    assert!(output.contains("SIGTERM"));
    // SIGTERM gets the generic signal line, not a special explanation
    assert!(!output.contains("blocked system call"));
    assert!(!output.contains("forcefully terminated"));
}

#[test]
fn test_exit_unknown_signal() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(128 + 33);

    assert!(output.contains("killed by signal 33"));
    assert!(!output.contains("SIGKILL"));
    assert!(!output.contains("SIGSYS"));
}

#[test]
fn test_exit_other_code() {
    let caps = make_test_caps();
    let formatter = DiagnosticFormatter::new(&caps);
    let output = formatter.format_footer(42);

    assert!(output.contains("Command exited with code 42."));
}
