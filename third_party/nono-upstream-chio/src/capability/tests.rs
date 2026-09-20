use super::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_fs_capability_new_dir() {
    let dir = tempdir().unwrap();
    let path = dir.path();

    let cap = FsCapability::new_dir(path, AccessMode::Read).unwrap();
    assert_eq!(cap.access, AccessMode::Read);
    assert!(cap.resolved.is_absolute());
    assert!(!cap.is_file);
}

#[test]
fn test_fs_capability_new_file() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "test").unwrap();

    let cap = FsCapability::new_file(&file_path, AccessMode::Read).unwrap();
    assert_eq!(cap.access, AccessMode::Read);
    assert!(cap.resolved.is_absolute());
    assert!(cap.is_file);
}

#[test]
fn test_fs_capability_nonexistent() {
    let result = FsCapability::new_dir("/nonexistent/path/12345", AccessMode::Read);
    assert!(matches!(result, Err(NonoError::PathNotFound(_))));
}

#[test]
fn test_fs_capability_file_as_dir_error() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, "test").unwrap();

    let result = FsCapability::new_dir(&file_path, AccessMode::Read);
    assert!(matches!(result, Err(NonoError::ExpectedDirectory(_))));
}

#[test]
fn test_fs_capability_dir_as_file_error() {
    let dir = tempdir().unwrap();
    let path = dir.path();

    let result = FsCapability::new_file(path, AccessMode::Read);
    assert!(matches!(result, Err(NonoError::ExpectedFile(_))));
}

#[test]
fn test_capability_set_builder() {
    let dir = tempdir().unwrap();

    let caps = CapabilitySet::new()
        .allow_path(dir.path(), AccessMode::ReadWrite)
        .unwrap()
        .block_network()
        .allow_command("allowed_cmd")
        .block_command("blocked_cmd");

    assert_eq!(caps.fs_capabilities().len(), 1);
    assert!(caps.is_network_blocked());
    assert_eq!(caps.allowed_commands(), &["allowed_cmd"]);
    assert_eq!(caps.blocked_commands(), &["blocked_cmd"]);
}

#[test]
fn test_capability_set_deduplicate() {
    let dir = tempdir().unwrap();

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).unwrap());
    caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).unwrap());

    assert_eq!(caps.fs_capabilities().len(), 2);
    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    // Should keep ReadWrite (higher access)
    assert_eq!(caps.fs_capabilities()[0].access, AccessMode::ReadWrite);
}

#[test]
fn test_deduplicate_user_wins_over_system() {
    // User says --read /path, system says ReadWrite for same path.
    // User intent must win: surviving entry should be Read.
    let path = PathBuf::from("/some/path");

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::User,
    });
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::System,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    assert_eq!(surviving.access, AccessMode::Read);
    assert!(matches!(surviving.source, CapabilitySource::User));
}

#[test]
fn test_deduplicate_user_wins_over_system_reverse_order() {
    // Same as above but system entry added first.
    let path = PathBuf::from("/some/path");

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::System,
    });
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::User,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    assert_eq!(surviving.access, AccessMode::Read);
    assert!(matches!(surviving.source, CapabilitySource::User));
}

#[test]
fn test_deduplicate_merges_read_and_write_to_readwrite() {
    // Two system/group entries for the same path with Read and Write
    // should merge to ReadWrite (e.g., /dev from system_read + system_write).
    let path = PathBuf::from("/some/path");

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::System,
    });
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Write,
        is_file: false,
        source: CapabilitySource::System,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    assert_eq!(surviving.access, AccessMode::ReadWrite);
}

#[test]
fn test_deduplicate_merges_write_then_read_to_readwrite() {
    // Same merge but with Write added first, Read second.
    let path = PathBuf::from("/some/path");

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Write,
        is_file: false,
        source: CapabilitySource::System,
    });
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::System,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    assert_eq!(surviving.access, AccessMode::ReadWrite);
}

#[test]
fn test_deduplicate_symlink_and_direct_are_kept_separately() {
    // macOS only: Seatbelt enforces on literal (pre-resolution) paths.
    // A symlink entry (original=/symlink/path → resolved=/real/path) and a
    // direct entry (original=/real/path, resolved=/real/path) have different
    // original paths.  Dedup keys on `original` on macOS, so both entries
    // survive and each gets its own Seatbelt allow rule.
    #[cfg(target_os = "macos")]
    {
        let symlink_path = PathBuf::from("/symlink/path");
        let real_path = PathBuf::from("/real/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: real_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        // Both entries survive because they have different original paths.
        assert_eq!(caps.fs_capabilities().len(), 2);
        let originals: Vec<&PathBuf> =
            caps.fs_capabilities().iter().map(|c| &c.original).collect();
        assert!(originals.contains(&&symlink_path));
        assert!(originals.contains(&&real_path));
    }

    // Linux: dedup keys on `resolved`, so a symlink entry and its direct
    // counterpart collapse to one entry.  User-intent wins.
    #[cfg(target_os = "linux")]
    {
        let symlink_path = PathBuf::from("/symlink/path");
        let real_path = PathBuf::from("/real/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: real_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        // Collapsed to one entry; User/Read beats System/ReadWrite.
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
        // Symlink original preserved into the surviving entry.
        assert_eq!(surviving.original, symlink_path);
        assert_eq!(surviving.resolved, real_path);
    }
}

/// macOS only: the concrete bug that prompted this fix.
/// Two distinct symlinks resolving to the same canonical path
/// (e.g. ~/.local/state/nix/profile and ~/.local/state/nix/profiles
/// both pointing into the nix store) must each survive dedup so that
/// Seatbelt emits allow rules for both literal symlink paths.
///
/// On Linux the Landlock sandbox uses resolved paths; having both
/// entries would union the Landlock rules, which is harmless when both
/// have the same access level but could bypass a user-intent restriction
/// if they differed.  The resolved-path key already prevents that.
#[cfg(target_os = "macos")]
#[test]
fn test_deduplicate_two_symlinks_same_target_both_kept() {
    {
        let link1 = PathBuf::from("/Users/me/.local/state/nix/profiles");
        let link2 = PathBuf::from("/Users/me/.local/state/nix/profile");
        let real_path = PathBuf::from("/nix/var/nix/profiles/per-user/me/profile");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: link1.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: link2.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        caps.deduplicate();
        assert_eq!(
            caps.fs_capabilities().len(),
            2,
            "both symlink entries must survive"
        );
        let originals: Vec<&PathBuf> =
            caps.fs_capabilities().iter().map(|c| &c.original).collect();
        assert!(originals.contains(&&link1), "link1 (profiles) must be kept");
        assert!(originals.contains(&&link2), "link2 (profile) must be kept");
    }
}

/// Linux-only: when a direct-path entry (original == resolved) survives
/// dedup over a discarded symlink entry, the surviving entry should adopt
/// the symlink's original so that `original` stays meaningful for logging
/// and any future consumers.
///
/// Exercises the `original_updates` branch:
///   `existing.original == existing.resolved && cap.original != cap.resolved`
/// (keep_new = false path — existing wins, discarded entry is the symlink).
#[cfg(target_os = "linux")]
#[test]
fn test_deduplicate_linux_surviving_direct_entry_inherits_symlink_original() {
    let symlink_path = PathBuf::from("/symlink/path");
    let real_path = PathBuf::from("/real/path");

    let mut caps = CapabilitySet::new();
    // Direct entry added first — becomes `existing` in the dedup loop.
    // User source so it wins over the incoming System entry.
    caps.add_fs(FsCapability {
        original: real_path.clone(),
        resolved: real_path.clone(),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::User,
    });
    // Symlink entry added second — same resolved path, System source.
    // keep_new = false: User direct entry survives, symlink entry is discarded.
    caps.add_fs(FsCapability {
        original: symlink_path.clone(),
        resolved: real_path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::System,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    // User wins with its access level.
    assert_eq!(surviving.access, AccessMode::ReadWrite);
    assert!(matches!(surviving.source, CapabilitySource::User));
    // The surviving entry must have adopted the discarded symlink's original.
    assert_eq!(
        surviving.original, symlink_path,
        "surviving direct entry must inherit the discarded symlink's original"
    );
    assert_eq!(surviving.resolved, real_path);
}

/// Linux-only: mirror of the above but with insertion order reversed —
/// the symlink entry is `existing` and is discarded in favour of the
/// incoming direct User entry.  Exercises the `original_updates` branch:
///   `cap.original == cap.resolved && existing.original != existing.resolved`
/// (keep_new = true path — new direct entry wins, discarded entry is the symlink).
#[cfg(target_os = "linux")]
#[test]
fn test_deduplicate_linux_incoming_direct_entry_inherits_symlink_original_from_existing() {
    let symlink_path = PathBuf::from("/symlink/path");
    let real_path = PathBuf::from("/real/path");

    let mut caps = CapabilitySet::new();
    // Symlink entry added first — becomes `existing` in the dedup loop.
    // System source so it loses to the incoming User entry.
    caps.add_fs(FsCapability {
        original: symlink_path.clone(),
        resolved: real_path.clone(),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::System,
    });
    // Direct entry added second — same resolved path, User source.
    // keep_new = true: User direct entry survives, symlink entry is discarded.
    caps.add_fs(FsCapability {
        original: real_path.clone(),
        resolved: real_path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::User,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    // User wins with its access level.
    assert_eq!(surviving.access, AccessMode::Read);
    assert!(matches!(surviving.source, CapabilitySource::User));
    // The surviving entry must have adopted the discarded symlink's original.
    assert_eq!(
        surviving.original, symlink_path,
        "surviving direct entry must inherit the discarded symlink's original"
    );
    assert_eq!(surviving.resolved, real_path);
}

#[test]
fn test_deduplicate_identical_symlink_entries_collapsed() {
    // Two entries with the *same* original symlink path are true duplicates
    // and should still be collapsed to one.
    let symlink_path = PathBuf::from("/symlink/path");
    let real_path = PathBuf::from("/real/path");

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability {
        original: symlink_path.clone(),
        resolved: real_path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::User,
    });
    caps.add_fs(FsCapability {
        original: symlink_path.clone(),
        resolved: real_path.clone(),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::System,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    // User wins: Read is kept, not the system's ReadWrite
    assert_eq!(surviving.access, AccessMode::Read);
    assert!(matches!(surviving.source, CapabilitySource::User));
    assert_eq!(surviving.original, symlink_path);
    assert_eq!(surviving.resolved, real_path);
}

#[test]
fn test_deduplicate_user_upgrades_group_read_to_readwrite() {
    // Group sets ~/.npm as Read, user passes --allow ~/.npm (ReadWrite).
    // User intent must win: surviving entry should be ReadWrite with User source.
    let path = PathBuf::from("/some/path");

    let mut caps = CapabilitySet::new();
    // Group entry first (e.g., from node_runtime security group)
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::Group("node_runtime".to_string()),
    });
    // User entry second (e.g., from --allow CLI flag)
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::User,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    assert_eq!(surviving.access, AccessMode::ReadWrite);
    assert!(matches!(surviving.source, CapabilitySource::User));
}

#[test]
fn test_deduplicate_user_write_remains_write_over_group_read() {
    // Group sets a path as Read, user passes --write for same path.
    // The explicit User permission must win without inheriting Group reads.
    let path = PathBuf::from("/some/path");

    let mut caps = CapabilitySet::new();
    // Group entry first (e.g., from profile security group)
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::Group("node_runtime".to_string()),
    });
    // User entry second (e.g., from --write CLI flag)
    caps.add_fs(FsCapability {
        original: path.clone(),
        resolved: path.clone(),
        access: AccessMode::Write,
        is_file: false,
        source: CapabilitySource::User,
    });

    caps.deduplicate();
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    // User wins with its exact Write permission.
    assert_eq!(surviving.access, AccessMode::Write);
    assert!(matches!(surviving.source, CapabilitySource::User));
}

/// Linux-only: verify that two different symlinks pointing to the same
/// resolved path with different access levels are collapsed to one entry
/// so that the user-intent Read restriction is not bypassed by a system
/// ReadWrite rule for the same inode.
///
/// On macOS both entries would survive (Seatbelt needs literal-path rules
/// for each symlink), but on Linux Landlock unions all rules for the same
/// resolved path, so we must dedup by `resolved` to uphold the policy.
#[cfg(target_os = "linux")]
#[test]
fn test_deduplicate_linux_two_symlinks_same_resolved_user_intent_wins() {
    let link1 = PathBuf::from("/link1");
    let link2 = PathBuf::from("/link2");
    let real_path = PathBuf::from("/real");

    let mut caps = CapabilitySet::new();
    // User grants Read via one symlink
    caps.add_fs(FsCapability {
        original: link1.clone(),
        resolved: real_path.clone(),
        access: AccessMode::Read,
        is_file: false,
        source: CapabilitySource::User,
    });
    // System grants ReadWrite via a different symlink to the same target
    caps.add_fs(FsCapability {
        original: link2.clone(),
        resolved: real_path.clone(),
        access: AccessMode::ReadWrite,
        is_file: false,
        source: CapabilitySource::System,
    });

    caps.deduplicate();
    // Must collapse to one entry so Landlock only sees one rule (Read).
    // If both survived, Landlock would union them to ReadWrite, bypassing
    // the user-intent Read restriction.
    assert_eq!(caps.fs_capabilities().len(), 1);
    let surviving = &caps.fs_capabilities()[0];
    assert_eq!(
        surviving.access,
        AccessMode::Read,
        "user-intent Read must not be widened to ReadWrite by a system grant"
    );
    assert!(matches!(surviving.source, CapabilitySource::User));
}

#[cfg(unix)]
#[test]
fn test_fs_capability_symlink_resolution() {
    let dir = tempdir().unwrap();
    let real_dir = dir.path().join("real");
    let symlink = dir.path().join("link");

    fs::create_dir(&real_dir).unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink).unwrap();

    let cap = FsCapability::new_dir(&symlink, AccessMode::Read).unwrap();
    // Symlink should be resolved to real path
    assert_eq!(cap.resolved, real_dir.canonicalize().unwrap());
}

#[test]
fn test_extensions_flag() {
    let caps = CapabilitySet::new();
    assert!(!caps.extensions_enabled());

    let caps = caps.enable_extensions();
    assert!(caps.extensions_enabled());
}

#[test]
fn test_extensions_flag_mutable() {
    let mut caps = CapabilitySet::new();
    assert!(!caps.extensions_enabled());

    caps.set_extensions_enabled(true);
    assert!(caps.extensions_enabled());

    caps.set_extensions_enabled(false);
    assert!(!caps.extensions_enabled());
}

#[test]
fn test_platform_rule_validation_valid_deny() {
    let mut caps = CapabilitySet::new();
    assert!(caps.add_platform_rule("(deny file-write-unlink)").is_ok());
    assert!(caps
        .add_platform_rule("(deny file-read-data (subpath \"/secret\"))")
        .is_ok());
}

#[test]
fn test_platform_rule_validation_rejects_malformed() {
    let mut caps = CapabilitySet::new();
    assert!(caps.add_platform_rule("not an s-expression").is_err());
    assert!(caps.add_platform_rule("").is_err());
}

#[test]
fn test_platform_rule_validation_rejects_root_access() {
    let mut caps = CapabilitySet::new();
    assert!(caps
        .add_platform_rule("(allow file-read* (subpath \"/\"))")
        .is_err());
    assert!(caps
        .add_platform_rule("(allow file-write* (subpath \"/\"))")
        .is_err());
    // Specific subpaths should be fine
    assert!(caps
        .add_platform_rule("(allow file-read* (subpath \"/usr\"))")
        .is_ok());
}

#[test]
fn test_platform_rule_validation_rejects_whitespace_bypass() {
    let mut caps = CapabilitySet::new();
    // Tab-separated
    assert!(caps
        .add_platform_rule("(allow\tfile-read*\t(subpath\t\"/\"))")
        .is_err());
    // Extra spaces
    assert!(caps
        .add_platform_rule("(allow  file-read*  (subpath  \"/\"))")
        .is_err());
    // Mixed whitespace
    assert!(caps
        .add_platform_rule("(allow \t file-write* \t (subpath \"/\"))")
        .is_err());
}

#[test]
fn test_platform_rule_validation_rejects_comment_bypass() {
    let mut caps = CapabilitySet::new();
    // Block comment between tokens
    assert!(caps
        .add_platform_rule("(allow file-read* #| comment |# (subpath \"/\"))")
        .is_err());
    // Block comment inside nested expression
    assert!(caps
        .add_platform_rule("(allow #| sneaky |# file-write* (subpath \"/\"))")
        .is_err());
}

#[test]
fn test_platform_rule_validation_rejects_unbalanced_parens() {
    let mut caps = CapabilitySet::new();
    assert!(caps.add_platform_rule("(deny file-read*").is_err());
    assert!(caps.add_platform_rule("(deny file-read*))").is_err());
}

#[test]
fn test_platform_rule_validation_rejects_unterminated_constructs() {
    let mut caps = CapabilitySet::new();
    assert!(caps
        .add_platform_rule("(deny file-read* #| unterminated comment")
        .is_err());
    assert!(caps
        .add_platform_rule("(deny file-read* (subpath \"/usr))")
        .is_err());
}

#[test]
fn test_platform_rule_validation_accepts_gpu_iokit_rules() {
    let mut caps = CapabilitySet::new();
    // Minimal IOKit surface: AGXDeviceUserClient is the only class required
    // for Metal compute on Apple Silicon. IOSurfaceRootUserClient is tried
    // opportunistically but Metal continues without it when denied.
    assert!(caps
        .add_platform_rule(
            "(allow iokit-open \
                (iokit-user-client-class \
                    \"AGXDeviceUserClient\"))"
        )
        .is_ok());
    assert!(caps
        .add_platform_rule("(allow iokit-get-properties)")
        .is_ok());
    assert_eq!(caps.platform_rules().len(), 2);
}

// NetworkMode tests

#[test]
fn test_network_mode_default_is_allow_all() {
    let caps = CapabilitySet::new();
    assert_eq!(*caps.network_mode(), NetworkMode::AllowAll);
    assert!(!caps.is_network_blocked());
}

#[test]
fn test_block_network_sets_blocked_mode() {
    let caps = CapabilitySet::new().block_network();
    assert_eq!(*caps.network_mode(), NetworkMode::Blocked);
    assert!(caps.is_network_blocked());
}

#[test]
fn test_proxy_only_mode() {
    let caps = CapabilitySet::new().proxy_only(8080);
    assert_eq!(
        *caps.network_mode(),
        NetworkMode::ProxyOnly {
            port: 8080,
            bind_ports: vec![]
        }
    );
    // ProxyOnly counts as blocked for general network access
    assert!(caps.is_network_blocked());
}

#[test]
fn test_proxy_only_with_bind_ports() {
    let caps = CapabilitySet::new().proxy_only_with_bind(8080, vec![18789, 3000]);
    assert_eq!(
        *caps.network_mode(),
        NetworkMode::ProxyOnly {
            port: 8080,
            bind_ports: vec![18789, 3000]
        }
    );
    assert!(caps.is_network_blocked());
}

#[test]
fn test_set_network_mode_builder() {
    let caps = CapabilitySet::new().set_network_mode(NetworkMode::ProxyOnly {
        port: 54321,
        bind_ports: vec![],
    });
    assert_eq!(
        *caps.network_mode(),
        NetworkMode::ProxyOnly {
            port: 54321,
            bind_ports: vec![]
        }
    );
}

#[test]
fn test_set_network_blocked_backward_compat() {
    let mut caps = CapabilitySet::new();
    caps.set_network_blocked(true);
    assert_eq!(*caps.network_mode(), NetworkMode::Blocked);
    assert!(caps.is_network_blocked());

    caps.set_network_blocked(false);
    assert_eq!(*caps.network_mode(), NetworkMode::AllowAll);
    assert!(!caps.is_network_blocked());
}

#[test]
fn test_tcp_connect_ports() {
    let caps = CapabilitySet::new()
        .allow_tcp_connect(443)
        .allow_tcp_connect(8443);
    assert_eq!(caps.tcp_connect_ports(), &[443, 8443]);
}

#[test]
fn test_tcp_bind_ports() {
    let caps = CapabilitySet::new()
        .allow_tcp_bind(8080)
        .allow_tcp_bind(3000);
    assert_eq!(caps.tcp_bind_ports(), &[8080, 3000]);
}

#[test]
fn test_allow_https_convenience() {
    let caps = CapabilitySet::new().allow_https();
    assert_eq!(caps.tcp_connect_ports(), &[443, 8443]);
}

#[test]
fn test_tcp_ports_mutable() {
    let mut caps = CapabilitySet::new();
    caps.add_tcp_connect_port(443);
    caps.add_tcp_bind_port(8080);
    assert_eq!(caps.tcp_connect_ports(), &[443]);
    assert_eq!(caps.tcp_bind_ports(), &[8080]);
}

#[test]
fn test_localhost_port_builder() {
    let caps = CapabilitySet::new()
        .allow_localhost_port(3000)
        .allow_localhost_port(5000);
    assert_eq!(caps.localhost_ports(), &[3000, 5000]);
}

#[test]
fn test_localhost_port_mutable() {
    let mut caps = CapabilitySet::new();
    caps.add_localhost_port(8080);
    caps.add_localhost_port(9090);
    assert_eq!(caps.localhost_ports(), &[8080, 9090]);
}

#[test]
fn test_network_mode_display() {
    assert_eq!(format!("{}", NetworkMode::Blocked), "blocked");
    assert_eq!(format!("{}", NetworkMode::AllowAll), "allowed");
    assert_eq!(
        format!(
            "{}",
            NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![]
            }
        ),
        "proxy-only (localhost:8080)"
    );
    assert_eq!(
        format!(
            "{}",
            NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![18789]
            }
        ),
        "proxy-only (localhost:8080, bind: 18789)"
    );
    assert_eq!(
        format!(
            "{}",
            NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![18789, 3000]
            }
        ),
        "proxy-only (localhost:8080, bind: 18789, 3000)"
    );
}

#[test]
fn test_network_mode_serialization() {
    let mode = NetworkMode::ProxyOnly {
        port: 54321,
        bind_ports: vec![],
    };
    let json = serde_json::to_string(&mode).unwrap();
    let deserialized: NetworkMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, deserialized);
}

#[test]
fn test_network_mode_serialization_with_bind_ports() {
    let mode = NetworkMode::ProxyOnly {
        port: 54321,
        bind_ports: vec![18789, 3000],
    };
    let json = serde_json::to_string(&mode).unwrap();
    let deserialized: NetworkMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, deserialized);
}

#[test]
fn test_summary_includes_network_mode() {
    let caps = CapabilitySet::new().proxy_only(8080);
    let summary = caps.summary();
    assert!(summary.contains("proxy-only (localhost:8080)"));
}

#[test]
fn test_summary_includes_tcp_ports() {
    let caps = CapabilitySet::new()
        .allow_tcp_connect(443)
        .allow_tcp_bind(8080);
    let summary = caps.summary();
    assert!(summary.contains("tcp connect ports: 443"));
    assert!(summary.contains("tcp bind ports: 8080"));
}

#[test]
fn test_signal_mode_allow_same_sandbox_roundtrip() {
    let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
    assert_eq!(caps.signal_mode(), SignalMode::AllowSameSandbox);
}

#[test]
fn test_process_info_mode_default_is_isolated() {
    let caps = CapabilitySet::new();
    assert_eq!(caps.process_info_mode(), ProcessInfoMode::Isolated);
}

#[test]
fn test_process_info_mode_allow_same_sandbox() {
    let caps = CapabilitySet::new().set_process_info_mode(ProcessInfoMode::AllowSameSandbox);
    assert_eq!(caps.process_info_mode(), ProcessInfoMode::AllowSameSandbox);
}

#[test]
fn test_process_info_mode_allow_all() {
    let caps = CapabilitySet::new().set_process_info_mode(ProcessInfoMode::AllowAll);
    assert_eq!(caps.process_info_mode(), ProcessInfoMode::AllowAll);
}

#[test]
fn test_ipc_mode_default_is_shared_memory_only() {
    let caps = CapabilitySet::new();
    assert_eq!(caps.ipc_mode(), IpcMode::SharedMemoryOnly);
}

#[test]
fn test_ipc_mode_full() {
    let caps = CapabilitySet::new().set_ipc_mode(IpcMode::Full);
    assert_eq!(caps.ipc_mode(), IpcMode::Full);
}

#[test]
fn test_ipc_mode_mutable_setter() {
    let mut caps = CapabilitySet::new();
    assert_eq!(caps.ipc_mode(), IpcMode::SharedMemoryOnly);
    caps.set_ipc_mode_mut(IpcMode::Full);
    assert_eq!(caps.ipc_mode(), IpcMode::Full);
}

#[test]
fn test_access_mode_contains() {
    // ReadWrite subsumes everything
    assert!(AccessMode::ReadWrite.contains(AccessMode::Read));
    assert!(AccessMode::ReadWrite.contains(AccessMode::Write));
    assert!(AccessMode::ReadWrite.contains(AccessMode::ReadWrite));

    // Read only subsumes Read
    assert!(AccessMode::Read.contains(AccessMode::Read));
    assert!(!AccessMode::Read.contains(AccessMode::Write));
    assert!(!AccessMode::Read.contains(AccessMode::ReadWrite));

    // Write only subsumes Write
    assert!(AccessMode::Write.contains(AccessMode::Write));
    assert!(!AccessMode::Write.contains(AccessMode::Read));
    assert!(!AccessMode::Write.contains(AccessMode::ReadWrite));
}

#[test]
fn test_path_covered_basic() {
    let dir = tempdir().unwrap();
    let parent = dir.path();
    let child = parent.join("subdir");
    fs::create_dir(&child).unwrap();

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_dir(parent, AccessMode::Read).unwrap());

    assert!(caps.path_covered(&child.canonicalize().unwrap()));
}

#[test]
fn test_path_covered_not_matching() {
    let dir1 = tempdir().unwrap();
    let dir2 = tempdir().unwrap();

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_dir(dir1.path(), AccessMode::Read).unwrap());

    assert!(!caps.path_covered(&dir2.path().canonicalize().unwrap()));
}

#[test]
fn test_path_covered_with_access_read_parent_does_not_satisfy_readwrite() {
    // Regression: a read-only parent (e.g. /Volumes from system_read_macos)
    // must not suppress a readwrite workdir grant for a child path.
    let dir = tempdir().unwrap();
    let parent = dir.path();
    let child = parent.join("project");
    fs::create_dir(&child).unwrap();
    let child_canonical = child.canonicalize().unwrap();

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_dir(parent, AccessMode::Read).unwrap());

    // path_covered (access-unaware) says yes
    assert!(caps.path_covered(&child_canonical));
    // path_covered_with_access correctly says no for write/readwrite
    assert!(caps.path_covered_with_access(&child_canonical, AccessMode::Read));
    assert!(!caps.path_covered_with_access(&child_canonical, AccessMode::Write));
    assert!(!caps.path_covered_with_access(&child_canonical, AccessMode::ReadWrite));
}

#[test]
fn test_path_covered_with_access_readwrite_parent_satisfies_all() {
    let dir = tempdir().unwrap();
    let parent = dir.path();
    let child = parent.join("project");
    fs::create_dir(&child).unwrap();
    let child_canonical = child.canonicalize().unwrap();

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_dir(parent, AccessMode::ReadWrite).unwrap());

    assert!(caps.path_covered_with_access(&child_canonical, AccessMode::Read));
    assert!(caps.path_covered_with_access(&child_canonical, AccessMode::Write));
    assert!(caps.path_covered_with_access(&child_canonical, AccessMode::ReadWrite));
}

#[test]
fn test_path_covered_with_access_file_caps_ignored() {
    // File capabilities should not count as covering a directory path.
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("file.txt");
    fs::write(&file_path, "data").unwrap();
    let file_canonical = file_path.canonicalize().unwrap();

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_file(&file_path, AccessMode::ReadWrite).unwrap());

    assert!(!caps.path_covered_with_access(&file_canonical, AccessMode::Read));
}

#[test]
fn test_remove_exact_file_caps_for_paths_matches_original_and_resolved() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target.txt");
    fs::write(&target, "secret").unwrap();
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let mut caps = CapabilitySet::new();
    caps.add_fs(FsCapability::new_file(&link, AccessMode::Read).unwrap());
    caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).unwrap());

    let removed = caps.remove_exact_file_caps_for_paths(&[link.clone(), target.clone()]);

    assert_eq!(removed, 1);
    assert_eq!(caps.fs_capabilities().len(), 1);
    assert!(!caps.fs_capabilities()[0].is_file);
}

// --- UnixSocketCapability / UnixSocketMode tests -------------------------

#[test]
fn test_unix_socket_mode_permits_bind() {
    assert!(!UnixSocketMode::Connect.permits_bind());
    assert!(UnixSocketMode::ConnectBind.permits_bind());
}

#[test]
fn test_unix_socket_connect_requires_existing_path() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("ghost.sock");

    let result = UnixSocketCapability::new_file(&missing, UnixSocketMode::Connect);
    assert!(
        matches!(result, Err(NonoError::PathNotFound(_))),
        "connect grant on non-existent path must fail: {result:?}"
    );
}

#[test]
fn test_unix_socket_connect_on_existing_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("existing.sock");
    fs::write(&path, b"").unwrap(); // stand-in for a real socket file

    let cap = UnixSocketCapability::new_file(&path, UnixSocketMode::Connect).unwrap();
    assert_eq!(cap.mode, UnixSocketMode::Connect);
    assert!(!cap.is_directory);
    assert!(cap.resolved.is_absolute());
}

#[test]
fn test_unix_socket_connect_bind_allows_nonexistent_path() {
    // The #685 use case: tsx grants `/tmp/tsx-1000/<pid>.pipe` before
    // the process has even started. Path doesn't exist yet; parent does.
    let dir = tempdir().unwrap();
    let missing = dir.path().join("pending.sock");

    let cap = UnixSocketCapability::new_file(&missing, UnixSocketMode::ConnectBind).unwrap();
    assert_eq!(cap.mode, UnixSocketMode::ConnectBind);
    assert!(!cap.is_directory);
    // Resolved path is canonical-parent + final component
    assert_eq!(cap.resolved.file_name().unwrap(), "pending.sock");
    assert!(cap.resolved.parent().unwrap().is_absolute());
}

#[test]
fn test_unix_socket_connect_bind_fails_when_parent_missing() {
    let result = UnixSocketCapability::new_file(
        "/definitely/does/not/exist/12345/x.sock",
        UnixSocketMode::ConnectBind,
    );
    assert!(
        matches!(result, Err(NonoError::PathNotFound(_))),
        "bind grant must fail when parent is missing: {result:?}"
    );
}

#[test]
fn test_unix_socket_file_rejects_directory_path() {
    let dir = tempdir().unwrap();

    let result = UnixSocketCapability::new_file(dir.path(), UnixSocketMode::Connect);
    assert!(
        matches!(result, Err(NonoError::ExpectedFile(_))),
        "new_file must reject a directory path: {result:?}"
    );
}

#[test]
fn test_unix_socket_dir_on_existing_directory() {
    let dir = tempdir().unwrap();

    let cap = UnixSocketCapability::new_dir(dir.path(), UnixSocketMode::Connect).unwrap();
    assert!(cap.is_directory);
    assert!(cap.resolved.is_absolute());
}

#[test]
fn test_unix_socket_dir_rejects_file_path() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("regular.txt");
    fs::write(&file, "not a dir").unwrap();

    let result = UnixSocketCapability::new_dir(&file, UnixSocketMode::Connect);
    assert!(
        matches!(result, Err(NonoError::ExpectedDirectory(_))),
        "new_dir must reject a file path: {result:?}"
    );
}

#[test]
fn test_unix_socket_dir_nonexistent() {
    let result = UnixSocketCapability::new_dir(
        "/nonexistent/dir/for/tests/99999",
        UnixSocketMode::Connect,
    );
    assert!(matches!(result, Err(NonoError::PathNotFound(_))));
}

#[test]
fn test_unix_socket_dir_rejects_filesystem_root() {
    let result = UnixSocketCapability::new_dir("/", UnixSocketMode::Connect);
    assert!(
        matches!(result, Err(NonoError::SandboxInit(_))),
        "filesystem root must be rejected as a directory grant: {result:?}"
    );
}

#[test]
fn test_unix_socket_covers_file_exact_match() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("a.sock");
    fs::write(&path, b"").unwrap();
    let cap = UnixSocketCapability::new_file(&path, UnixSocketMode::Connect).unwrap();

    // Exact match covers; anything else does not.
    assert!(cap.covers(&cap.resolved));
    assert!(!cap.covers(&dir.path().canonicalize().unwrap()));
    let sibling = dir.path().canonicalize().unwrap().join("b.sock");
    assert!(!cap.covers(&sibling));
}

#[test]
fn test_unix_socket_covers_directory_one_level() {
    let dir = tempdir().unwrap();
    let cap = UnixSocketCapability::new_dir(dir.path(), UnixSocketMode::Connect).unwrap();

    // Direct child is covered.
    let child = cap.resolved.join("x.sock");
    assert!(cap.covers(&child), "direct child should be covered");

    // Grandchild is NOT (non-recursive).
    let grandchild = cap.resolved.join("sub").join("x.sock");
    assert!(!cap.covers(&grandchild), "grandchild must not be covered");

    // The directory itself, with no filename component, isn't a socket.
    assert!(!cap.covers(&cap.resolved));
}

#[test]
fn test_unix_socket_covers_does_not_string_prefix() {
    // Regression: a directory grant for /tmp/foo must NOT cover
    // /tmp/foobar/x.sock, which a naive string starts_with would match.
    let dir = tempdir().unwrap();
    let foo = dir.path().join("foo");
    let foobar = dir.path().join("foobar");
    fs::create_dir(&foo).unwrap();
    fs::create_dir(&foobar).unwrap();

    let cap = UnixSocketCapability::new_dir(&foo, UnixSocketMode::Connect).unwrap();
    let evil = foobar.canonicalize().unwrap().join("x.sock");
    assert!(!cap.covers(&evil), "string-prefix match must not leak");
}

#[test]
fn test_unix_socket_display() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("a.sock");
    fs::write(&path, b"").unwrap();

    let file_cap = UnixSocketCapability::new_file(&path, UnixSocketMode::Connect).unwrap();
    let rendered = format!("{file_cap}");
    assert!(rendered.contains("connect"));
    assert!(!rendered.starts_with("dir"));

    let dir_cap =
        UnixSocketCapability::new_dir(dir.path(), UnixSocketMode::ConnectBind).unwrap();
    let rendered = format!("{dir_cap}");
    assert!(rendered.contains("connect+bind"));
    assert!(rendered.starts_with("dir "));
}

#[test]
fn test_capability_set_allow_unix_socket_accumulates() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.sock");
    let b = dir.path().join("b.sock");
    fs::write(&a, b"").unwrap();

    let caps = CapabilitySet::new()
        .allow_unix_socket(&a, UnixSocketMode::Connect)
        .unwrap()
        .allow_unix_socket(&b, UnixSocketMode::ConnectBind)
        .unwrap();

    assert_eq!(caps.unix_socket_capabilities().len(), 2);
    assert_eq!(
        caps.unix_socket_capabilities()[0].mode,
        UnixSocketMode::Connect
    );
    assert_eq!(
        caps.unix_socket_capabilities()[1].mode,
        UnixSocketMode::ConnectBind
    );
}

#[test]
fn test_capability_set_unix_socket_allowed_mode_split() {
    // Invariant `separate-read-write`: Connect entries must not
    // accidentally permit bind.
    let dir = tempdir().unwrap();
    let connect_sock = dir.path().join("connect-only.sock");
    let bind_sock = dir.path().join("bind.sock");
    fs::write(&connect_sock, b"").unwrap();
    // bind_sock deliberately does not exist — allow_unix_socket with
    // ConnectBind must accept that.

    let caps = CapabilitySet::new()
        .allow_unix_socket(&connect_sock, UnixSocketMode::Connect)
        .unwrap()
        .allow_unix_socket(&bind_sock, UnixSocketMode::ConnectBind)
        .unwrap();

    let resolved_connect = connect_sock.canonicalize().unwrap();
    let resolved_bind = dir.path().canonicalize().unwrap().join("bind.sock");

    // Connect-only entry: connect ok, bind denied.
    assert!(caps.unix_socket_allowed(&resolved_connect, UnixSocketOp::Connect));
    assert!(!caps.unix_socket_allowed(&resolved_connect, UnixSocketOp::Bind));

    // ConnectBind entry: both ok.
    assert!(caps.unix_socket_allowed(&resolved_bind, UnixSocketOp::Connect));
    assert!(caps.unix_socket_allowed(&resolved_bind, UnixSocketOp::Bind));

    // Unrelated path: nothing allowed.
    let other = dir.path().canonicalize().unwrap().join("other.sock");
    assert!(!caps.unix_socket_allowed(&other, UnixSocketOp::Connect));
    assert!(!caps.unix_socket_allowed(&other, UnixSocketOp::Bind));
}

#[test]
fn test_capability_set_unix_socket_allowed_directory_grant() {
    let dir = tempdir().unwrap();

    let caps = CapabilitySet::new()
        .allow_unix_socket_dir(dir.path(), UnixSocketMode::Connect)
        .unwrap();

    let resolved_dir = dir.path().canonicalize().unwrap();
    let direct_child = resolved_dir.join("x.sock");
    let grandchild = resolved_dir.join("sub").join("x.sock");

    assert!(caps.unix_socket_allowed(&direct_child, UnixSocketOp::Connect));
    assert!(!caps.unix_socket_allowed(&grandchild, UnixSocketOp::Connect));
    assert!(!caps.unix_socket_allowed(&direct_child, UnixSocketOp::Bind));
}

#[test]
fn test_deduplicate_unix_sockets_merges_identical_grants() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("a.sock");
    fs::write(&sock, b"").unwrap();

    let mut caps = CapabilitySet::new()
        .allow_unix_socket(&sock, UnixSocketMode::Connect)
        .unwrap()
        .allow_unix_socket(&sock, UnixSocketMode::Connect)
        .unwrap();
    assert_eq!(caps.unix_socket_capabilities().len(), 2);

    caps.deduplicate();
    assert_eq!(caps.unix_socket_capabilities().len(), 1);
}

#[test]
fn test_deduplicate_unix_sockets_promotes_connect_to_connect_bind() {
    // When Connect and ConnectBind grants collide on the same resolved
    // path, the retained entry ends up as ConnectBind (superset).
    let dir = tempdir().unwrap();
    let sock = dir.path().join("a.sock");
    fs::write(&sock, b"").unwrap();

    let mut caps = CapabilitySet::new()
        .allow_unix_socket(&sock, UnixSocketMode::Connect)
        .unwrap()
        .allow_unix_socket(&sock, UnixSocketMode::ConnectBind)
        .unwrap();

    caps.deduplicate();
    let socks = caps.unix_socket_capabilities();
    assert_eq!(socks.len(), 1);
    assert_eq!(socks[0].mode, UnixSocketMode::ConnectBind);
}

#[test]
fn test_deduplicate_unix_sockets_does_not_widen_user_intent() {
    // Security-critical: a user explicitly narrowing a path to
    // Connect must not be silently upgraded to ConnectBind just
    // because a group/default also covers it.
    let dir = tempdir().unwrap();
    let sock = dir.path().join("a.sock");
    fs::write(&sock, b"").unwrap();

    let group_cap = UnixSocketCapability {
        original: sock.clone(),
        resolved: sock.canonicalize().unwrap(),
        is_directory: false,
        mode: UnixSocketMode::ConnectBind,
        source: CapabilitySource::Group("example_group".to_string()),
    };
    let user_cap = UnixSocketCapability {
        original: sock.clone(),
        resolved: sock.canonicalize().unwrap(),
        is_directory: false,
        mode: UnixSocketMode::Connect,
        source: CapabilitySource::User,
    };

    let mut caps = CapabilitySet::new();
    caps.add_unix_socket(group_cap);
    caps.add_unix_socket(user_cap);
    caps.deduplicate();

    let socks = caps.unix_socket_capabilities();
    assert_eq!(socks.len(), 1);
    assert_eq!(
        socks[0].mode,
        UnixSocketMode::Connect,
        "user-intent Connect must not be upgraded to ConnectBind by dedup"
    );
    assert!(matches!(socks[0].source, CapabilitySource::User));
}

#[test]
fn test_deduplicate_unix_sockets_keeps_file_and_dir_grants_separate() {
    // File grant on /path/foo.sock and dir grant on /path/ are
    // different keys — both should survive.
    let dir = tempdir().unwrap();
    let sock = dir.path().join("a.sock");
    fs::write(&sock, b"").unwrap();

    let mut caps = CapabilitySet::new()
        .allow_unix_socket(&sock, UnixSocketMode::Connect)
        .unwrap()
        .allow_unix_socket_dir(dir.path(), UnixSocketMode::Connect)
        .unwrap();

    caps.deduplicate();
    assert_eq!(caps.unix_socket_capabilities().len(), 2);
}

#[test]
fn test_summary_includes_unix_sockets() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("a.sock");
    fs::write(&sock, b"").unwrap();

    let caps = CapabilitySet::new()
        .allow_unix_socket(&sock, UnixSocketMode::Connect)
        .unwrap()
        .allow_unix_socket_dir(dir.path(), UnixSocketMode::ConnectBind)
        .unwrap();

    let summary = caps.summary();
    assert!(
        summary.contains("Unix sockets:"),
        "summary must include unix socket section: {summary}"
    );
    assert!(summary.contains("connect"));
    assert!(summary.contains("connect+bind"));
    assert!(summary.contains("file"));
    assert!(summary.contains("dir"));
}
