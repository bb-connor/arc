use super::*;

// -- FsGuard tests --

#[test]
fn fs_guard_allows_path_under_prefix() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    assert!(guard.check_read("/home/user/project/src/main.rs").is_ok());
    assert!(guard.check_write("/home/user/project/README.md").is_ok());
}

#[test]
fn fs_guard_blocks_path_outside_prefix() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    assert_eq!(
        guard_error(guard.check_read("/etc/passwd")),
        AcpGuardError::PathOutsideScope
    );
    assert_eq!(
        guard_error(guard.check_write("/tmp/evil.sh")),
        AcpGuardError::PathOutsideScope
    );
    assert_eq!(
        guard_error(guard.check_cwd("/tmp")),
        AcpGuardError::PathOutsideScope
    );
}

#[test]
fn fs_guard_blocks_path_traversal() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    assert_eq!(
        guard_error(guard.check_read("/home/user/project/../../../etc/passwd")),
        AcpGuardError::PathTraversal
    );
    assert_eq!(
        guard_error(guard.check_write("/home/user/project/../../evil")),
        AcpGuardError::PathTraversal
    );
    assert_eq!(
        guard_error(guard.check_read("/home/user/project/src/..")),
        AcpGuardError::PathTraversal
    );
}

#[test]
fn fs_guard_traversal_is_refused_before_the_allowlist_is_consulted() {
    let guard = FsGuard::new(vec![]);
    assert_eq!(
        guard_error(guard.check_read("/any/../path")),
        AcpGuardError::PathTraversal
    );
}

#[test]
fn fs_guard_denies_when_no_prefixes_configured() {
    let guard = FsGuard::new(vec![]);
    assert_eq!(
        guard_error(guard.check_read("/any/path")),
        AcpGuardError::EmptyAllowlist
    );
    assert_eq!(
        guard_error(guard.check_write("/any/path")),
        AcpGuardError::EmptyAllowlist
    );
}

#[test]
fn fs_guard_skips_unusable_prefixes_and_refuses_outside_scope() {
    let guard = FsGuard::new(vec![String::new(), "/home/user/../root".to_string()]);
    assert_eq!(
        guard_error(guard.check_read("/root/secret")),
        AcpGuardError::PathOutsideScope
    );
}

#[test]
fn fs_guard_multiple_prefixes() {
    let guard = FsGuard::new(vec![
        "/home/user/project".to_string(),
        "/tmp/workspace".to_string(),
    ]);
    assert!(guard.check_read("/home/user/project/file.txt").is_ok());
    assert!(guard.check_read("/tmp/workspace/output.log").is_ok());
    assert_eq!(
        guard_error(guard.check_read("/var/log/system.log")),
        AcpGuardError::PathOutsideScope
    );
}

#[test]
fn fs_guard_blocks_prefix_substring_attack() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    assert_eq!(
        guard_error(guard.check_read("/home/user/project_evil/secret.txt")),
        AcpGuardError::PathOutsideScope
    );
    assert!(guard.check_read("/home/user/project").is_ok());
    assert!(guard.check_read("/home/user/project/file.txt").is_ok());
}

#[test]
fn fs_guard_rejects_relative_paths() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    assert_eq!(
        guard_error(guard.check_read("relative/path/file.txt")),
        AcpGuardError::RelativePath
    );
    assert_eq!(
        guard_error(guard.check_write("../escape")),
        AcpGuardError::RelativePath
    );
    assert_eq!(
        guard_error(guard.check_read("file.txt")),
        AcpGuardError::RelativePath
    );
}

#[test]
fn fs_guard_handles_empty_path() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
    assert_eq!(guard_error(guard.check_read("")), AcpGuardError::EmptyPath);
    assert_eq!(guard_error(guard.check_write("")), AcpGuardError::EmptyPath);
    assert_eq!(guard_error(guard.check_cwd("")), AcpGuardError::EmptyPath);
}

#[test]
fn fs_guard_with_resolve_symlinks_flag() {
    let guard = FsGuard::new(vec!["/home/user/project".to_string()]).with_resolve_symlinks(true);
    // A non-existent path falls back to textual canonicalization.
    assert!(guard
        .check_read("/home/user/project/nonexistent.txt")
        .is_ok());
}

#[cfg(unix)]
#[test]
fn fs_guard_blocks_symlink_escape_by_default() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("chio-acp-root-{nonce}"));
    let outside = std::env::temp_dir().join(format!("chio-acp-outside-{nonce}"));
    let link = root.join("link");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let secret = outside.join("secret.txt");
    std::fs::write(&secret, "secret").unwrap();
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let guard = FsGuard::new(vec![root.to_string_lossy().into_owned()]);
    let escaped_path = link.join("secret.txt");
    let escaped_write = link.join("new.txt");

    assert_eq!(
        guard_error(guard.check_read(escaped_path.to_string_lossy().as_ref())),
        AcpGuardError::PathOutsideScope
    );
    assert_eq!(
        guard_error(guard.check_write(escaped_write.to_string_lossy().as_ref())),
        AcpGuardError::PathOutsideScope
    );

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

// -- TerminalGuard tests --

#[test]
fn terminal_guard_allows_listed_command() {
    let guard = TerminalGuard::new(vec!["cargo".to_string(), "npm".to_string()]);
    assert!(guard.check_command("cargo", &["build".to_string()]).is_ok());
    assert!(guard.check_command("npm", &["install".to_string()]).is_ok());
}

#[test]
fn terminal_guard_blocks_unlisted_command() {
    let guard = TerminalGuard::new(vec!["cargo".to_string()]);
    assert_eq!(
        guard_error(guard.check_command("rm", &["-rf".to_string()])),
        AcpGuardError::CommandOutsideScope
    );
}

#[test]
fn terminal_guard_denies_when_no_commands_configured() {
    let guard = TerminalGuard::new(vec![]);
    assert_eq!(
        guard_error(guard.check_command("ls", &[])),
        AcpGuardError::EmptyAllowlist
    );
    assert_eq!(
        guard_error(guard.check_command("", &[])),
        AcpGuardError::EmptyAllowlist
    );
}

#[test]
fn terminal_guard_refuses_an_empty_command() {
    let guard = TerminalGuard::new(vec!["cargo".to_string()]);
    assert_eq!(
        guard_error(guard.check_command("", &["build".to_string()])),
        AcpGuardError::EmptyCommand
    );
}

#[test]
fn terminal_guard_blocks_shell_injection_in_args() {
    let guard = TerminalGuard::new(vec!["echo".to_string()]);
    for argument in [
        "$(rm -rf /)",
        "hello; rm -rf /",
        "`evil`",
        "hello | cat /etc/passwd",
        "hello\nrm -rf /",
        "hello\rrm -rf /",
    ] {
        assert_eq!(
            guard_error(guard.check_command("echo", &["ok".to_string(), argument.to_string()])),
            AcpGuardError::ShellArgument,
            "argument {argument:?}"
        );
    }
}

#[test]
fn terminal_guard_checks_scope_before_arguments() {
    let guard = TerminalGuard::new(vec!["echo".to_string()]);
    assert_eq!(
        guard_error(guard.check_command("sh", &["-c; evil".to_string()])),
        AcpGuardError::CommandOutsideScope
    );
}

#[test]
fn terminal_guard_allows_clean_args() {
    let guard = TerminalGuard::new(vec!["cargo".to_string()]);
    assert!(guard
        .check_command(
            "cargo",
            &[
                "build".to_string(),
                "--release".to_string(),
                "--target".to_string(),
                "x86_64-unknown-linux-gnu".to_string(),
            ]
        )
        .is_ok());
}

#[test]
fn terminal_guard_requires_exact_path_allowlist_for_path_commands() {
    let guard = TerminalGuard::new(vec!["cargo".to_string()]);
    assert_eq!(
        guard_error(guard.check_command("/usr/bin/cargo", &["test".to_string()])),
        AcpGuardError::CommandOutsideScope
    );

    let guard = TerminalGuard::new(vec!["/usr/bin/cargo".to_string()]);
    assert!(guard
        .check_command("/usr/bin/cargo", &["test".to_string()])
        .is_ok());
}

#[test]
fn terminal_guard_rejects_path_command_by_basename_only() {
    let guard = TerminalGuard::new(vec!["git".to_string()]);
    assert_eq!(
        guard_error(guard.check_command("/tmp/attacker/git", &["status".to_string()])),
        AcpGuardError::CommandOutsideScope
    );
}

// -- PermissionMapper tests --

#[test]
fn permission_mapper_maps_known_kinds() {
    let mapper = PermissionMapper::new(3600);

    let allow_once = PermissionOption {
        option_id: "opt-1".to_string(),
        name: "Allow".to_string(),
        kind: "allow_once".to_string(),
    };
    let mapped = mapper.map_option(&allow_once);
    assert_eq!(mapped.chio_decision, PermissionDecision::AllowOnce);

    let allow_always = PermissionOption {
        option_id: "opt-2".to_string(),
        name: "Always allow".to_string(),
        kind: "allow_always".to_string(),
    };
    let mapped = mapper.map_option(&allow_always);
    assert_eq!(
        mapped.chio_decision,
        PermissionDecision::AllowScoped {
            duration_secs: 3600
        }
    );

    let reject_once = PermissionOption {
        option_id: "opt-3".to_string(),
        name: "Deny".to_string(),
        kind: "reject_once".to_string(),
    };
    let mapped = mapper.map_option(&reject_once);
    assert_eq!(mapped.chio_decision, PermissionDecision::Deny);

    let reject_always = PermissionOption {
        option_id: "opt-4".to_string(),
        name: "Never allow".to_string(),
        kind: "reject_always".to_string(),
    };
    let mapped = mapper.map_option(&reject_always);
    assert_eq!(mapped.chio_decision, PermissionDecision::DenyPermanent);
}

#[test]
fn permission_mapper_denies_unknown_kind() {
    let mapper = PermissionMapper::new(3600);
    let unknown = PermissionOption {
        option_id: "opt-x".to_string(),
        name: "Mystery".to_string(),
        kind: "unknown_kind".to_string(),
    };
    let mapped = mapper.map_option(&unknown);
    assert_eq!(mapped.chio_decision, PermissionDecision::Deny);
}

// -- ReceiptLogger tests --
