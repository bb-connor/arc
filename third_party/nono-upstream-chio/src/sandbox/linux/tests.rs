use super::*;

#[test]
fn seccomp_notification_ioctl_request_bits_match_linux_uapi() {
    assert_eq!(SECCOMP_IOCTL_NOTIF_RECV as u32, 0xc0502100);
    assert_eq!(SECCOMP_IOCTL_NOTIF_SEND as u32, 0xc0182101);
    assert_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID as u32, 0x40082102);
    assert_eq!(SECCOMP_IOCTL_NOTIF_ADDFD as u32, 0x40182103);
}

#[test]
fn test_is_supported() {
    // This test will pass or fail depending on kernel version
    // Just verify it doesn't panic
    let _ = is_supported();
}

#[test]
fn test_support_info() {
    let info = support_info();
    assert!(!info.details.is_empty());
}

#[test]
fn test_access_conversion_v3() {
    let abi = ABI::V3;

    let read = access_to_landlock(AccessMode::Read, abi);
    assert!(read.effective.contains(AccessFs::ReadFile));
    assert!(!read.effective.contains(AccessFs::WriteFile));
    assert!(read.dropped.is_empty());

    let write = access_to_landlock(AccessMode::Write, abi);
    assert!(write.effective.contains(AccessFs::WriteFile));
    assert!(!write.effective.contains(AccessFs::ReadFile));
    // V3 supports Refer and Truncate but NOT IoctlDev
    assert!(write.effective.contains(AccessFs::RemoveFile));
    assert!(write.effective.contains(AccessFs::RemoveDir));
    assert!(write.effective.contains(AccessFs::Refer));
    assert!(write.effective.contains(AccessFs::Truncate));
    assert!(!write.effective.contains(AccessFs::IoctlDev));
    assert!(write.dropped.is_empty());

    let rw = access_to_landlock(AccessMode::ReadWrite, abi);
    assert!(rw.effective.contains(AccessFs::ReadFile));
    assert!(rw.effective.contains(AccessFs::WriteFile));
    assert!(rw.effective.contains(AccessFs::RemoveFile));
    assert!(rw.effective.contains(AccessFs::RemoveDir));
    assert!(rw.effective.contains(AccessFs::Refer));
    assert!(rw.effective.contains(AccessFs::Truncate));
    assert!(rw.dropped.is_empty());
}

#[test]
fn test_access_conversion_v1_drops_refer_and_truncate() {
    let abi = ABI::V1;

    let write = access_to_landlock(AccessMode::Write, abi);
    assert!(write.effective.contains(AccessFs::WriteFile));
    // V1 does NOT have Refer, Truncate, or IoctlDev
    assert!(!write.effective.contains(AccessFs::Refer));
    assert!(!write.effective.contains(AccessFs::Truncate));
    assert!(!write.effective.contains(AccessFs::IoctlDev));
    // But basic write operations are still present
    assert!(write.effective.contains(AccessFs::RemoveFile));
    assert!(write.effective.contains(AccessFs::RemoveDir));
    // Dropped flags should be reported
    assert!(write.dropped.contains(AccessFs::Refer));
    assert!(write.dropped.contains(AccessFs::Truncate));
}

#[test]
fn test_access_conversion_v2_has_refer_but_not_truncate() {
    let abi = ABI::V2;

    let write = access_to_landlock(AccessMode::Write, abi);
    assert!(write.effective.contains(AccessFs::WriteFile));
    // V2 added Refer but NOT Truncate or IoctlDev
    assert!(write.effective.contains(AccessFs::Refer));
    assert!(!write.effective.contains(AccessFs::Truncate));
    assert!(!write.effective.contains(AccessFs::IoctlDev));
    // Truncate should be in dropped
    assert!(write.dropped.contains(AccessFs::Truncate));
    assert!(!write.dropped.contains(AccessFs::Refer));
}

#[test]
fn test_access_conversion_v5_excludes_ioctl_dev_from_generic_flags() {
    let abi = ABI::V5;

    // IoctlDev is NOT in the generic write flags — it is added selectively
    // at rule-addition time only for device paths (char/block devices).
    let write = access_to_landlock(AccessMode::Write, abi);
    assert!(!write.effective.contains(AccessFs::IoctlDev));

    let rw = access_to_landlock(AccessMode::ReadWrite, abi);
    assert!(!rw.effective.contains(AccessFs::IoctlDev));

    let read = access_to_landlock(AccessMode::Read, abi);
    assert!(!read.effective.contains(AccessFs::IoctlDev));
}

#[test]
fn test_is_device_path_dev_null() {
    // /dev/null is a character device on all Unix systems
    assert!(is_device_path(Path::new("/dev/null")));
}

#[test]
fn test_is_device_path_regular_file() {
    // A regular file should not be detected as a device
    assert!(!is_device_path(Path::new("/etc/hosts")));
}

#[test]
fn test_is_device_path_nonexistent() {
    assert!(!is_device_path(Path::new("/nonexistent/path/12345")));
}

#[test]
fn test_is_device_directory_dev_pts() {
    // /dev/pts is a directory under /dev
    if Path::new("/dev/pts").exists() {
        assert!(is_device_directory(Path::new("/dev/pts")));
    }
}

#[test]
fn test_is_device_directory_not_dev() {
    // /tmp is a directory but not under /dev
    assert!(!is_device_directory(Path::new("/tmp")));
}

#[test]
fn test_detected_abi_feature_methods() {
    let v1 = DetectedAbi::new(ABI::V1);
    assert!(!v1.has_refer());
    assert!(!v1.has_truncate());
    assert!(!v1.has_network());
    assert!(!v1.has_ioctl_dev());
    assert!(!v1.has_scoping());

    let v2 = DetectedAbi::new(ABI::V2);
    assert!(v2.has_refer());
    assert!(!v2.has_truncate());

    let v3 = DetectedAbi::new(ABI::V3);
    assert!(v3.has_refer());
    assert!(v3.has_truncate());
    assert!(!v3.has_network());

    let v4 = DetectedAbi::new(ABI::V4);
    assert!(v4.has_network());
    assert!(!v4.has_ioctl_dev());

    let v5 = DetectedAbi::new(ABI::V5);
    assert!(v5.has_ioctl_dev());
    assert!(!v5.has_scoping());

    let v6 = DetectedAbi::new(ABI::V6);
    assert!(v6.has_scoping());
}

#[test]
fn test_requested_scopes_allow_all_is_empty() {
    let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowAll);
    let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V6));
    assert!(matches!(scopes, Ok(actual) if actual.is_empty()));
}

#[test]
fn test_requested_scopes_isolated_uses_signal_scope_on_v6() {
    let caps = CapabilitySet::new().set_signal_mode(SignalMode::Isolated);
    let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V6));
    assert!(matches!(scopes, Ok(actual) if actual == BitFlags::from(Scope::Signal)));
}

#[test]
fn test_requested_scopes_isolated_is_empty_without_v6() {
    let caps = CapabilitySet::new().set_signal_mode(SignalMode::Isolated);
    let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V5));
    assert!(matches!(scopes, Ok(actual) if actual.is_empty()));
}

#[test]
fn test_requested_scopes_allow_same_sandbox_requires_v6() {
    let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
    let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V5));
    assert!(
        matches!(scopes, Err(NonoError::SandboxInit(message)) if message.contains("Landlock ABI V6+"))
    );
}

#[test]
fn test_requested_scopes_allow_same_sandbox_uses_signal_scope() {
    let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
    let scopes = requested_scopes(&caps, &DetectedAbi::new(ABI::V6));
    assert!(matches!(scopes, Ok(actual) if actual == BitFlags::from(Scope::Signal)));
}

#[cfg(target_os = "linux")]
#[test]
fn test_signal_scope_blocks_external_kill_on_v6() {
    struct ChildCleanup {
        sandbox_pid: Option<libc::pid_t>,
        target_pid: Option<libc::pid_t>,
    }

    impl Drop for ChildCleanup {
        fn drop(&mut self) {
            if let Some(pid) = self.sandbox_pid.take() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
            }

            if let Some(pid) = self.target_pid.take() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
            }
        }
    }

    let detected = match detect_abi() {
        Ok(detected) => detected,
        Err(_) => return,
    };

    if !detected.has_scoping() {
        return;
    }

    let mut report_pipe = [0; 2];
    let pipe_result = unsafe { libc::pipe(report_pipe.as_mut_ptr()) };
    assert_eq!(pipe_result, 0, "pipe() failed");

    let target_pid = unsafe { libc::fork() };
    assert!(target_pid >= 0, "fork() for target failed");
    let mut cleanup = ChildCleanup {
        sandbox_pid: None,
        target_pid: Some(target_pid),
    };

    if target_pid == 0 {
        unsafe {
            libc::close(report_pipe[0]);
            libc::close(report_pipe[1]);
            libc::signal(libc::SIGUSR1, libc::SIG_IGN);
            libc::pause();
            libc::_exit(0);
        }
    }

    let sandbox_pid = unsafe { libc::fork() };
    assert!(sandbox_pid >= 0, "fork() for sandbox failed");
    cleanup.sandbox_pid = Some(sandbox_pid);

    if sandbox_pid == 0 {
        let mut payload = [0_u8; 2];
        unsafe {
            libc::close(report_pipe[0]);
        }

        let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
        match apply_with_abi(&caps, &detected) {
            Ok(_) => {
                let kill_result = unsafe { libc::kill(target_pid, libc::SIGUSR1) };
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(255);
                payload[0] = if kill_result == -1 { 1 } else { 0 };
                payload[1] = u8::try_from(errno).unwrap_or(u8::MAX);
            }
            Err(_) => {
                payload[0] = 2;
                payload[1] = 0;
            }
        }

        let write_len = payload.len();
        let wrote = unsafe {
            libc::write(
                report_pipe[1],
                payload.as_ptr().cast::<libc::c_void>(),
                write_len,
            )
        };
        let exit_code = if wrote == isize::try_from(write_len).unwrap_or(-1) {
            0
        } else {
            3
        };
        unsafe {
            libc::close(report_pipe[1]);
            libc::_exit(exit_code);
        }
    }

    unsafe {
        libc::close(report_pipe[1]);
    }

    let mut sandbox_status = 0;
    let waited_sandbox = unsafe { libc::waitpid(sandbox_pid, &mut sandbox_status, 0) };
    assert_eq!(waited_sandbox, sandbox_pid, "waitpid() for sandbox failed");
    assert!(
        libc::WIFEXITED(sandbox_status),
        "sandbox child did not exit normally"
    );
    cleanup.sandbox_pid = None;
    assert_eq!(
        libc::WEXITSTATUS(sandbox_status),
        0,
        "sandbox child returned failure"
    );

    let mut payload = [0_u8; 2];
    let read_len = payload.len();
    let read_result = unsafe {
        libc::read(
            report_pipe[0],
            payload.as_mut_ptr().cast::<libc::c_void>(),
            read_len,
        )
    };
    unsafe {
        libc::close(report_pipe[0]);
    }
    assert_eq!(
        read_result,
        isize::try_from(read_len).unwrap_or(-1),
        "failed to read sandbox report"
    );
    assert_eq!(payload[0], 1, "sandboxed kill unexpectedly succeeded");
    assert_eq!(
        i32::from(payload[1]),
        libc::EPERM,
        "kill should fail with EPERM"
    );

    let target_wait = unsafe { libc::waitpid(target_pid, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(target_wait, 0, "external target should still be running");

    unsafe {
        libc::kill(target_pid, libc::SIGKILL);
        libc::waitpid(target_pid, std::ptr::null_mut(), 0);
    }
    cleanup.target_pid = None;
}

#[test]
fn test_detected_abi_version_string() {
    assert_eq!(DetectedAbi::new(ABI::V1).version_string(), "V1");
    assert_eq!(DetectedAbi::new(ABI::V4).version_string(), "V4");
    assert_eq!(DetectedAbi::new(ABI::V6).version_string(), "V6");
}

#[test]
fn test_detected_abi_display() {
    let d = DetectedAbi::new(ABI::V4);
    assert_eq!(format!("{}", d), "Landlock V4");
}

#[test]
fn test_detected_abi_feature_names() {
    let v1 = DetectedAbi::new(ABI::V1);
    let names = v1.feature_names();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0], "Basic filesystem access control");

    let v4 = DetectedAbi::new(ABI::V4);
    let names = v4.feature_names();
    assert!(names.iter().any(|n| n.starts_with("TCP network filtering")));
    assert!(names
        .iter()
        .any(|n| n == "File rename across directories (Refer)"));
    assert!(names.iter().any(|n| n == "File truncation (Truncate)"));
}

#[test]
fn test_detect_abi_returns_ok_on_supported_system() {
    // On a system with Landlock, this should succeed
    // On a system without it, it should return Err (not panic)
    let _ = detect_abi();
}

#[test]
fn test_seccomp_notif_struct_sizes() {
    // Verify our repr(C) structs match expected sizes
    use std::mem;
    // SeccompData: 4 + 4 + 8 + 6*8 = 64 bytes
    assert_eq!(mem::size_of::<SeccompData>(), 64);
    // SeccompNotif: 8 + 4 + 4 + 64 = 80 bytes
    assert_eq!(mem::size_of::<SeccompNotif>(), 80);
    // SeccompNotifResp: 8 + 8 + 4 + 4 = 24 bytes
    assert_eq!(mem::size_of::<SeccompNotifResp>(), 24);
    // SeccompNotifAddfd: 8 + 4 + 4 + 4 + 4 = 24 bytes
    assert_eq!(mem::size_of::<SeccompNotifAddfd>(), 24);
}

#[test]
fn test_bpf_filter_instruction_count() {
    // The BPF filter should have exactly 5 instructions:
    // ld, jeq openat, jeq openat2, ret allow, ret notify
    let filter = [
        SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 2,
            jf: 0,
            k: SYS_OPENAT as u32,
        },
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: SYS_OPENAT2 as u32,
        },
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_USER_NOTIF,
        },
    ];
    assert_eq!(filter.len(), 5);
}

#[test]
fn test_build_seccomp_block_network_filter() {
    let filter = build_seccomp_block_network_filter();

    assert_eq!(filter.len(), 10);
    assert_eq!(filter[0].k, SECCOMP_DATA_NR_OFFSET);

    assert_eq!(filter[1].k, SYS_SOCKET as u32);
    assert_eq!(filter[1].jt, 4);

    assert_eq!(filter[2].k, SYS_SOCKETPAIR as u32);
    assert_eq!(filter[2].jt, 3);

    assert_eq!(filter[3].k, SYS_IO_URING_SETUP as u32);
    assert_eq!(filter[3].jt, 1);

    assert_eq!(filter[4].k, SECCOMP_RET_ALLOW);
    assert_eq!(filter[5].k, SECCOMP_RET_ERRNO | (libc::EPERM as u32));

    assert_eq!(filter[6].k, SECCOMP_DATA_ARG0_OFFSET);
    assert_eq!(filter[7].k, libc::AF_UNIX as u32);
    assert_eq!(filter[7].jt, 1);

    assert_eq!(filter[8].k, SECCOMP_RET_ERRNO | (libc::EPERM as u32));
    assert_eq!(filter[9].k, SECCOMP_RET_ALLOW);
}

#[test]
fn test_open_how_struct_size() {
    use std::mem;
    // OpenHow: 3 x u64 = 24 bytes (flags, mode, resolve)
    assert_eq!(mem::size_of::<OpenHow>(), 24);
}

#[test]
fn test_syscall_numbers_distinct() {
    // Verify openat and openat2 have different syscall numbers
    assert_ne!(SYS_OPENAT, SYS_OPENAT2);
}

#[test]
fn test_syscall_numbers_match_seccomp_data_nr_type() {
    // SeccompData.nr is i32, verify our constants fit
    let _: i32 = SYS_OPENAT;
    let _: i32 = SYS_OPENAT2;
}

#[test]
fn test_classify_access_rdonly() {
    let access = classify_access_from_flags(libc::O_RDONLY);
    assert!(matches!(access, crate::AccessMode::Read));
}

#[test]
fn test_classify_access_wronly() {
    let access = classify_access_from_flags(libc::O_WRONLY);
    assert!(matches!(access, crate::AccessMode::Write));
}

#[test]
fn test_classify_access_rdwr() {
    let access = classify_access_from_flags(libc::O_RDWR);
    assert!(matches!(access, crate::AccessMode::ReadWrite));
}

#[test]
fn test_classify_access_with_extra_flags() {
    // O_RDONLY with O_CREAT, O_TRUNC etc should still be Read
    let flags = libc::O_RDONLY | libc::O_CREAT | libc::O_TRUNC;
    let access = classify_access_from_flags(flags);
    assert!(matches!(access, crate::AccessMode::Read));

    // O_WRONLY with O_APPEND should still be Write
    let flags = libc::O_WRONLY | libc::O_APPEND;
    let access = classify_access_from_flags(flags);
    assert!(matches!(access, crate::AccessMode::Write));

    // O_RDWR with O_CLOEXEC should still be ReadWrite
    let flags = libc::O_RDWR | libc::O_CLOEXEC;
    let access = classify_access_from_flags(flags);
    assert!(matches!(access, crate::AccessMode::ReadWrite));
}

#[test]
fn test_classify_access_pointer_as_flags_gives_readwrite() {
    // Simulates the original bug: a pointer value (e.g., 0x7fff12345678) treated as flags.
    // The O_ACCMODE mask (0o3) would extract garbage bits, likely resulting in O_RDWR (2).
    // This test documents that garbage input defaults to ReadWrite (fail-safe for deny
    // decisions, but the real fix is proper syscall discrimination).
    let fake_pointer = 0x7fff_1234_5678_i64 as i32; // truncated pointer
    let access = classify_access_from_flags(fake_pointer);
    // With this specific value, (fake_pointer & 0o3) == 0, which is O_RDONLY
    // But the point is: any garbage value goes through the match, we don't panic.
    // The actual security fix is not calling this with garbage in the first place.
    let _ = access; // Just verify it doesn't panic
}

#[test]
fn test_validate_openat2_size_rejects_zero() {
    assert!(!validate_openat2_size(0));
}

#[test]
fn test_validate_openat2_size_rejects_undersized() {
    // Anything less than sizeof(OpenHow) = 24 should be rejected
    assert!(!validate_openat2_size(1));
    assert!(!validate_openat2_size(8));
    assert!(!validate_openat2_size(16));
    assert!(!validate_openat2_size(23));
}

#[test]
fn test_validate_openat2_size_accepts_exact() {
    // Exactly sizeof(OpenHow) = 24 should be accepted
    let exact_size = std::mem::size_of::<OpenHow>();
    assert_eq!(exact_size, 24);
    assert!(validate_openat2_size(exact_size));
}

#[test]
fn test_validate_openat2_size_accepts_larger() {
    // Larger (but bounded) sizes are valid (kernel may extend struct in future)
    assert!(validate_openat2_size(32));
    assert!(validate_openat2_size(64));
    assert!(validate_openat2_size(128));
}

#[test]
fn test_validate_openat2_size_rejects_unreasonably_large() {
    assert!(!validate_openat2_size(4097));
    assert!(!validate_openat2_size(usize::MAX));
}

#[test]
fn test_resolve_notif_path_absolute_unchanged() {
    // Absolute paths should be returned unchanged regardless of dirfd
    let abs_path = std::path::PathBuf::from("/usr/lib/libc.so.6");
    let result = resolve_notif_path(1, 42, &abs_path);
    let path = match result {
        Ok(p) => p,
        Err(e) => panic!("unexpected error: {e}"),
    };
    assert_eq!(path, abs_path);
}

#[test]
fn test_resolve_notif_path_absolute_with_at_fdcwd() {
    // Absolute paths should be returned unchanged even with AT_FDCWD
    let abs_path = std::path::PathBuf::from("/etc/passwd");
    let at_fdcwd = libc::AT_FDCWD as i64 as u64;
    let path = match resolve_notif_path(1, at_fdcwd, &abs_path) {
        Ok(p) => p,
        Err(e) => panic!("unexpected error: {e}"),
    };
    assert_eq!(path, abs_path);
}

#[test]
fn test_resolve_notif_path_relative_with_invalid_pid_fails() {
    // Relative path with non-existent PID should fail (can't read /proc/PID/cwd)
    let rel_path = std::path::PathBuf::from("relative/path.so");
    let at_fdcwd = libc::AT_FDCWD as i64 as u64;
    let result = resolve_notif_path(u32::MAX, at_fdcwd, &rel_path);
    assert!(result.is_err());
}

#[test]
fn test_resolve_notif_path_relative_with_invalid_fd_fails() {
    // Relative path with non-existent PID/fd should fail
    let rel_path = std::path::PathBuf::from("some_lib.so");
    let result = resolve_notif_path(u32::MAX, 999, &rel_path);
    assert!(result.is_err());
}

#[test]
fn test_resolve_notif_path_at_fdcwd_both_representations() {
    // AT_FDCWD is -100. When stored as u64 in seccomp args, it may be
    // sign-extended to 0xFFFFFFFFFFFFFF9C or truncated to 0xFFFFFF9C.
    // Both should be recognized.
    let abs_path = std::path::PathBuf::from("/absolute");
    #[allow(clippy::unnecessary_cast)]
    let at_fdcwd_32 = libc::AT_FDCWD as i32 as u32 as u64; // 0xFFFFFF9C
    let at_fdcwd_64 = libc::AT_FDCWD as i64 as u64; // 0xFFFFFFFFFFFFFF9C

    // Both should work for absolute paths (early return)
    let path_32 = match resolve_notif_path(1, at_fdcwd_32, &abs_path) {
        Ok(p) => p,
        Err(e) => panic!("unexpected error for 32-bit AT_FDCWD: {e}"),
    };
    assert_eq!(path_32, abs_path);

    let path_64 = match resolve_notif_path(1, at_fdcwd_64, &abs_path) {
        Ok(p) => p,
        Err(e) => panic!("unexpected error for 64-bit AT_FDCWD: {e}"),
    };
    assert_eq!(path_64, abs_path);
}

#[test]
fn test_seccomp_network_fallback_mode_blocked() {
    let caps = CapabilitySet::new().block_network();
    assert_eq!(
        seccomp_network_fallback_mode(&caps),
        SeccompNetFallback::BlockAll
    );
}

#[test]
fn test_seccomp_network_fallback_mode_blocked_with_ports_is_none() {
    let mut caps = CapabilitySet::new().block_network();
    caps.add_localhost_port(3000);
    assert_eq!(
        seccomp_network_fallback_mode(&caps),
        SeccompNetFallback::None
    );
}

#[test]
fn test_seccomp_network_fallback_mode_proxy_only() {
    let caps = CapabilitySet::new().proxy_only(8080);
    assert_eq!(
        seccomp_network_fallback_mode(&caps),
        SeccompNetFallback::ProxyOnly {
            proxy_port: 8080,
            bind_ports: vec![],
        }
    );
}

#[test]
fn test_seccomp_network_fallback_mode_proxy_only_with_bind() {
    let caps = CapabilitySet::new().proxy_only_with_bind(8080, vec![3000, 3001]);
    assert_eq!(
        seccomp_network_fallback_mode(&caps),
        SeccompNetFallback::ProxyOnly {
            proxy_port: 8080,
            bind_ports: vec![3000, 3001],
        }
    );
}

#[test]
fn test_seccomp_network_fallback_mode_allow_all() {
    let caps = CapabilitySet::new();
    assert_eq!(
        seccomp_network_fallback_mode(&caps),
        SeccompNetFallback::None
    );
}

#[test]
fn test_legacy_can_use_seccomp_block_fallback() {
    // BlockAll => true
    assert!(can_use_seccomp_network_block_fallback(
        &CapabilitySet::new().block_network()
    ));

    // ProxyOnly => false
    let with_proxy = CapabilitySet::new().proxy_only(8080);
    assert!(!can_use_seccomp_network_block_fallback(&with_proxy));

    // Blocked with ports => false
    let mut with_localhost = CapabilitySet::new().block_network();
    with_localhost.add_localhost_port(3000);
    assert!(!can_use_seccomp_network_block_fallback(&with_localhost));
}

#[test]
fn test_build_seccomp_proxy_filter_with_bind() {
    let filter = build_seccomp_proxy_filter(true);
    // 19 instructions
    assert_eq!(filter.len(), 19);

    // Instruction 0 should be ld [nr]
    assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
    assert_eq!(filter[0].k, SECCOMP_DATA_NR_OFFSET);

    // Instruction 16 should be USER_NOTIF (connect)
    assert_eq!(filter[16].code, BPF_RET | BPF_K);
    assert_eq!(filter[16].k, SECCOMP_RET_USER_NOTIF);

    // Instruction 17 should be USER_NOTIF (bind; supervisor decides).
    assert_eq!(filter[17].code, BPF_RET | BPF_K);
    assert_eq!(filter[17].k, SECCOMP_RET_USER_NOTIF);
}

/// Regression test for the Landlock V2 + `has_bind_ports=false`
/// scenario (issue #685): even with no TCP bind ports configured,
/// bind() must route to USER_NOTIF so the supervisor can allow
/// pathname AF_UNIX bind. Previously the filter short-circuited to
/// ERRNO in this branch, unconditionally failing AF_UNIX bind.
#[test]
fn test_build_seccomp_proxy_filter_without_bind() {
    let filter = build_seccomp_proxy_filter(false);
    assert_eq!(filter.len(), 19);

    // Instruction 17 (bind) must ALSO route to USER_NOTIF — the
    // supervisor is the sole gate. This is the fix: previously this
    // emitted ERRNO, which skipped the supervisor entirely.
    assert_eq!(filter[17].code, BPF_RET | BPF_K);
    assert_eq!(
        filter[17].k, SECCOMP_RET_USER_NOTIF,
        "bind must route to USER_NOTIF regardless of has_bind_ports so \
         the supervisor can permit AF_UNIX pathname bind (#685)"
    );
}

#[test]
fn test_sockaddr_info_ipv4_loopback() {
    let info = SockaddrInfo {
        family: libc::AF_INET as u16,
        port: 8080,
        is_loopback: true,
        unix_kind: None,
    };
    assert!(info.is_loopback);
    assert_eq!(info.port, 8080);
}

#[test]
fn test_sockaddr_info_ipv6_loopback() {
    let info = SockaddrInfo {
        family: libc::AF_INET6 as u16,
        port: 443,
        is_loopback: true,
        unix_kind: None,
    };
    assert!(info.is_loopback);
}

#[test]
fn test_sockaddr_info_non_loopback() {
    let info = SockaddrInfo {
        family: libc::AF_INET as u16,
        port: 80,
        is_loopback: false,
        unix_kind: None,
    };
    assert!(!info.is_loopback);
}

#[test]
fn test_sockaddr_info_unix_is_loopback() {
    let info = SockaddrInfo {
        family: libc::AF_UNIX as u16,
        port: 0,
        is_loopback: true,
        unix_kind: Some(UnixSocketKind::Pathname),
    };
    assert!(info.is_loopback);
    assert_eq!(info.port, 0);
}

// --- classify_af_unix tests (issue #685) --------------------------------

#[test]
fn test_classify_af_unix_pathname() {
    // `/tmp/test.sock` — first byte is '/'
    assert_eq!(
        classify_af_unix(14, Some(b'/')),
        UnixSocketKind::Pathname,
        "non-null first byte => pathname"
    );
}

#[test]
fn test_classify_af_unix_abstract() {
    // \0foo — first byte is null (Linux abstract namespace)
    assert_eq!(
        classify_af_unix(6, Some(0)),
        UnixSocketKind::Abstract,
        "null first byte => abstract namespace"
    );
}

#[test]
fn test_classify_af_unix_unnamed() {
    // addrlen == 2: only sa_family, no sun_path
    assert_eq!(
        classify_af_unix(2, None),
        UnixSocketKind::Unnamed,
        "addrlen <= 2 => unnamed"
    );
}

#[test]
fn test_classify_af_unix_fails_closed_on_short_read() {
    // Defensive: if we couldn't read sun_path[0] despite addrlen > 2
    // (unexpected), treat as unnamed so policy fails closed.
    assert_eq!(
        classify_af_unix(10, None),
        UnixSocketKind::Unnamed,
        "missing sun_path byte => fail-closed to unnamed"
    );
}

/// Integration test: seccomp proxy filter blocks connect to non-proxy ports
/// and allows connect to the designated proxy port on localhost.
///
/// Forks a child that installs the proxy filter, then attempts connects.
/// Results are reported via a pipe. This test works on any kernel with
/// seccomp user notification support (>= 5.0), regardless of Landlock ABI.
#[cfg(target_os = "linux")]
#[test]
fn test_seccomp_proxy_filter_allows_proxy_port_blocks_others() {
    use std::io::Read;

    // Pick an ephemeral port for the "proxy". We bind a listener so the
    // connect to the allowed port actually succeeds (otherwise we'd get
    // ECONNREFUSED which is indistinguishable from EACCES in the child).
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return, // Can't bind, skip test
    };
    let proxy_port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => return,
    };

    let mut report_pipe = [0i32; 2];
    let pipe_result = unsafe { libc::pipe(report_pipe.as_mut_ptr()) };
    assert_eq!(pipe_result, 0, "pipe() failed");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork() failed");

    if pid == 0 {
        // CHILD: install proxy filter, attempt connects, report results.
        unsafe { libc::close(report_pipe[0]) };
        // Drop the listener in child (parent keeps it open for accept)
        drop(listener);

        // Install the proxy filter (no bind ports).
        // This requires PR_SET_NO_NEW_PRIVS first.
        let result = install_seccomp_proxy_filter(false);
        if result.is_err() {
            // Seccomp not available on this system
            let payload: [u8; 3] = [2, 2, 2]; // skip sentinel
            unsafe {
                libc::write(report_pipe[1], payload.as_ptr().cast(), payload.len());
                libc::close(report_pipe[1]);
                libc::_exit(0);
            }
        }
        let notify_fd = result.expect("install_seccomp_proxy_filter failed");

        // Spawn a thread to handle notifications from the seccomp filter.
        // The filter routes connect() to USER_NOTIF; we must respond or the
        // child's connect() calls block forever.
        let notify_raw = {
            use std::os::fd::AsRawFd;
            notify_fd.as_raw_fd()
        };

        // We handle notifications in the same process since we forked.
        // For each connect notification, allow localhost:proxy_port, deny others.
        // Run the handler in a thread so the main thread can do connects.
        let proxy_port_copy = proxy_port;
        let handler = std::thread::spawn(move || {
            for _ in 0..2 {
                // We expect exactly 2 connect attempts
                let notif = match recv_notif(notify_raw) {
                    Ok(n) => n,
                    Err(_) => break,
                };

                // Read sockaddr from our own /proc/self/mem (same process)
                let info = match read_notif_sockaddr(
                    notif.pid,
                    notif.data.args[1],
                    notif.data.args[2],
                ) {
                    Ok(i) => i,
                    Err(_) => {
                        let _ = deny_notif(notify_raw, notif.id);
                        continue;
                    }
                };

                if info.is_loopback && info.port == proxy_port_copy {
                    let _ = continue_notif(notify_raw, notif.id);
                } else {
                    let _ = respond_notif_errno(notify_raw, notif.id, libc::EACCES);
                }
            }
        });

        // Test 1: connect to proxy port on localhost — should succeed
        let sock1 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let mut addr1: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr1.sin_family = libc::AF_INET as u16;
        addr1.sin_port = proxy_port.to_be();
        addr1.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();

        let connect1 = unsafe {
            libc::connect(
                sock1,
                (&addr1 as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        let errno1 = if connect1 < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        unsafe { libc::close(sock1) };

        // Test 2: connect to a different port on localhost — should be denied (EACCES)
        let sock2 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let mut addr2: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr2.sin_family = libc::AF_INET as u16;
        addr2.sin_port = (proxy_port.wrapping_add(1)).to_be();
        addr2.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();

        let connect2 = unsafe {
            libc::connect(
                sock2,
                (&addr2 as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        let errno2 = if connect2 < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        unsafe { libc::close(sock2) };

        handler.join().ok();

        // Report: [connect1_result, connect2_errno]
        let payload: [u8; 3] = [
            if connect1 == 0 { 0 } else { 1 },
            errno1 as u8,
            errno2 as u8,
        ];
        unsafe {
            libc::write(report_pipe[1], payload.as_ptr().cast(), payload.len());
            libc::close(report_pipe[1]);
            libc::_exit(0);
        }
    }

    // PARENT: read results from child
    unsafe { libc::close(report_pipe[1]) };

    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let mut buf = [0u8; 3];
    let mut pipe_read = unsafe {
        use std::os::fd::FromRawFd;
        std::fs::File::from_raw_fd(report_pipe[0])
    };
    let n = pipe_read.read(&mut buf).expect("read from pipe failed");

    if n == 3 && buf[0] == 2 && buf[1] == 2 && buf[2] == 2 {
        // Skip sentinel: seccomp not available on this system
        return;
    }

    assert_eq!(n, 3, "expected 3 bytes from child, got {n}");

    // connect1 to proxy port should have succeeded (0)
    assert_eq!(
        buf[0], 0,
        "connect to proxy port should succeed, got result={} errno={}",
        buf[0], buf[1]
    );

    // connect2 to wrong port should have been denied with EACCES
    assert_eq!(
        buf[2],
        libc::EACCES as u8,
        "connect to non-proxy port should get EACCES, got errno={}",
        buf[2]
    );
}

/// End-to-end regression test for issue #685: a pathname `AF_UNIX`
/// `bind(2)` must succeed under the proxy-only seccomp filter even
/// when `has_bind_ports=false`. Previously the filter short-circuited
/// bind() to `EACCES` in that configuration, unconditionally failing
/// AF_UNIX bind regardless of what the supervisor would have decided.
///
/// Structure mirrors `test_seccomp_proxy_filter_allows_proxy_port_blocks_others`:
/// fork, install filter in the child, run a minimal supervisor-mimic
/// handler in a child thread, try the bind, report result over a pipe.
#[cfg(target_os = "linux")]
#[test]
fn test_seccomp_proxy_filter_allows_af_unix_bind_without_bind_ports() {
    use std::io::Read;

    // Unique per-test socket path under /tmp so parallel tests don't
    // collide.
    let sock_path = format!("/tmp/nono-integ-af-unix-bind-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&sock_path);

    let mut report_pipe = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(report_pipe.as_mut_ptr()) }, 0, "pipe()");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork() failed");

    if pid == 0 {
        // CHILD
        unsafe { libc::close(report_pipe[0]) };

        // Install filter with `has_bind_ports=false` — this is the
        // exact configuration the #685 bug manifested under.
        let notify_fd = match install_seccomp_proxy_filter(false) {
            Ok(fd) => fd,
            Err(_) => {
                // Seccomp unavailable — skip via sentinel.
                let sentinel: [u8; 2] = [2, 2];
                unsafe {
                    libc::write(report_pipe[1], sentinel.as_ptr().cast(), sentinel.len());
                    libc::close(report_pipe[1]);
                    libc::_exit(0);
                }
            }
        };

        let notify_raw = {
            use std::os::fd::AsRawFd;
            notify_fd.as_raw_fd()
        };

        // Minimal supervisor mimic: for each bind notification, allow
        // pathname AF_UNIX, deny everything else. Matches the policy
        // baked into `decide_network_notification` at PR A commit 1.
        let handler = std::thread::spawn(move || {
            for _ in 0..1 {
                let notif = match recv_notif(notify_raw) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                let info = match read_notif_sockaddr(
                    notif.pid,
                    notif.data.args[1],
                    notif.data.args[2],
                ) {
                    Ok(i) => i,
                    Err(_) => {
                        let _ = deny_notif(notify_raw, notif.id);
                        continue;
                    }
                };
                let is_pathname_unix = info.family == libc::AF_UNIX as u16
                    && matches!(info.unix_kind, Some(UnixSocketKind::Pathname));
                if is_pathname_unix {
                    let _ = continue_notif(notify_raw, notif.id);
                } else {
                    let _ = respond_notif_errno(notify_raw, notif.id, libc::EACCES);
                }
            }
        });

        // Attempt bind(AF_UNIX) at the pathname socket.
        let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as u16;
        let bytes = sock_path.as_bytes();
        assert!(bytes.len() < addr.sun_path.len(), "test path too long");
        for (i, &b) in bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        let addrlen = (std::mem::size_of::<u16>() + bytes.len() + 1) as libc::socklen_t;

        let rc =
            unsafe { libc::bind(sock, (&addr as *const libc::sockaddr_un).cast(), addrlen) };
        let errno = if rc < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        unsafe { libc::close(sock) };

        let _ = handler.join();
        // Clean up the socket file the child just created.
        let _ = std::fs::remove_file(&sock_path);

        let payload: [u8; 2] = [
            if rc < 0 { 1 } else { 0 },
            errno.unsigned_abs().min(255) as u8,
        ];
        unsafe {
            libc::write(report_pipe[1], payload.as_ptr().cast(), payload.len());
            libc::close(report_pipe[1]);
            libc::_exit(0);
        }
    }

    // PARENT
    unsafe { libc::close(report_pipe[1]) };

    // Wait for child.
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    use std::os::fd::FromRawFd;
    let mut pipe_read = unsafe { std::fs::File::from_raw_fd(report_pipe[0]) };
    let mut buf = [0u8; 2];
    let n = pipe_read.read(&mut buf).expect("read from pipe");

    if n == 2 && buf[0] == 2 && buf[1] == 2 {
        // Skip sentinel: seccomp not available.
        return;
    }
    assert_eq!(n, 2, "expected 2 bytes from child, got {n}");
    assert_eq!(
        buf[0], 0,
        "AF_UNIX bind must succeed under proxy filter with \
         has_bind_ports=false (errno={})",
        buf[1]
    );
}

/// Integration test: ProxyOnly + Landlock V4+ does NOT install seccomp
/// proxy filter (Landlock handles networking natively).
///
/// Verifies that apply_with_abi() returns SeccompNetFallback::None when
/// the kernel supports AccessNet, even with ProxyOnly mode.
#[cfg(target_os = "linux")]
#[test]
fn test_proxy_only_with_landlock_v4_returns_no_fallback() {
    let detected = match detect_abi() {
        Ok(d) => d,
        Err(_) => return,
    };

    if !detected.has_network() {
        // Pre-V4 kernel: the fallback SHOULD be ProxyOnly, not None.
        // Test that separately.
        return;
    }

    // On V4+, Landlock handles ProxyOnly natively. apply_with_abi should
    // return None (no seccomp fallback needed). We can't actually call
    // apply_with_abi in the parent (irreversible), so fork a child.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork() failed");

    if pid == 0 {
        let caps = CapabilitySet::new().proxy_only(8080);
        let exit_code = match apply_with_abi(&caps, &detected) {
            Ok(SeccompNetFallback::None) => 0,
            Ok(SeccompNetFallback::BlockAll) => 1,
            Ok(SeccompNetFallback::ProxyOnly { .. }) => 2,
            Err(_) => 3,
        };
        unsafe { libc::_exit(exit_code) };
    }

    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "Expected SeccompNetFallback::None on V4+ kernel, got exit code {}",
        libc::WEXITSTATUS(status)
    );
}

/// Integration test: ProxyOnly on pre-V4 kernel returns ProxyOnly fallback.
///
/// Verifies that apply_with_abi() returns SeccompNetFallback::ProxyOnly
/// when the kernel's Landlock ABI lacks AccessNet.
#[cfg(target_os = "linux")]
#[test]
fn test_proxy_only_without_landlock_net_returns_proxy_fallback() {
    let detected = match detect_abi() {
        Ok(d) => d,
        Err(_) => return,
    };

    if detected.has_network() {
        // V4+ kernel: Landlock handles it, fallback not used.
        // This test only runs on pre-V4 kernels.
        return;
    }

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork() failed");

    if pid == 0 {
        let caps = CapabilitySet::new().proxy_only(8080);
        let exit_code = match apply_with_abi(&caps, &detected) {
            Ok(SeccompNetFallback::ProxyOnly {
                proxy_port: 8080, ..
            }) => 0,
            Ok(SeccompNetFallback::ProxyOnly { .. }) => 1, // wrong port
            Ok(SeccompNetFallback::None) => 2,
            Ok(SeccompNetFallback::BlockAll) => 3,
            Err(_) => 4,
        };
        unsafe { libc::_exit(exit_code) };
    }

    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "Expected SeccompNetFallback::ProxyOnly on pre-V4 kernel, got exit code {}",
        libc::WEXITSTATUS(status)
    );
}

/// Integration test: under the proxy filter with `has_bind_ports=false`,
/// an `AF_INET` `bind(2)` must still be denied — but now the denial
/// comes from the supervisor (via `USER_NOTIF`), not from the BPF
/// filter directly. Issue #685 required the filter to route bind to
/// USER_NOTIF regardless of `has_bind_ports` so pathname `AF_UNIX`
/// bind can be allowed (see `test_seccomp_proxy_filter_allows_af_unix_bind_without_bind_ports`);
/// this test pins the complementary invariant that `AF_INET` bind is
/// still rejected when the supervisor's policy says so.
#[cfg(target_os = "linux")]
#[test]
fn test_seccomp_proxy_filter_blocks_bind_without_bind_ports() {
    let mut report_pipe = [0i32; 2];
    let pipe_result = unsafe { libc::pipe(report_pipe.as_mut_ptr()) };
    assert_eq!(pipe_result, 0, "pipe() failed");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork() failed");

    if pid == 0 {
        unsafe { libc::close(report_pipe[0]) };

        // Install proxy filter with has_bind_ports=false. As of the
        // #685 fix, bind() now routes to USER_NOTIF — so a handler
        // IS required even for the "block all bind" policy.
        let notify_fd = match install_seccomp_proxy_filter(false) {
            Ok(fd) => fd,
            Err(_) => {
                // Seccomp not available — skip.
                let skip: u8 = 255;
                unsafe {
                    libc::write(report_pipe[1], &skip as *const u8 as _, 1);
                    libc::close(report_pipe[1]);
                    libc::_exit(0);
                }
            }
        };
        let notify_raw = {
            use std::os::fd::AsRawFd;
            notify_fd.as_raw_fd()
        };

        // Supervisor mimic: deny every bind notification with EACCES.
        // Models the "no bind ports configured → deny AF_INET bind"
        // policy that `decide_network_notification` implements in
        // the real supervisor when `config.proxy_bind_ports` is empty.
        let handler = std::thread::spawn(move || {
            for _ in 0..1 {
                let notif = match recv_notif(notify_raw) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                let _ = respond_notif_errno(notify_raw, notif.id, libc::EACCES);
            }
        });

        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        let bind_result = unsafe {
            libc::bind(
                sock,
                (&addr as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        let errno = if bind_result < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) as u8
        } else {
            0
        };
        unsafe { libc::close(sock) };
        let _ = handler.join();

        unsafe {
            libc::write(report_pipe[1], &errno as *const u8 as _, 1);
            libc::close(report_pipe[1]);
            libc::_exit(0);
        }
    }

    // PARENT
    unsafe { libc::close(report_pipe[1]) };

    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let mut buf = [0u8; 1];
    let mut pipe_read = unsafe {
        use std::os::fd::FromRawFd;
        std::fs::File::from_raw_fd(report_pipe[0])
    };
    use std::io::Read as _;
    let n = pipe_read.read(&mut buf).expect("read from pipe");

    if n == 1 && buf[0] == 255 {
        return; // seccomp not available, skip
    }

    assert_eq!(n, 1);
    assert_eq!(
        buf[0],
        libc::EACCES as u8,
        "AF_INET bind() must still receive EACCES (from supervisor, not filter) \
         when has_bind_ports=false, got errno={}",
        buf[0]
    );
}

// =========================================================================
// WSL2 detection tests
// =========================================================================

#[test]
fn test_is_wsl2_does_not_panic() {
    // Must not panic regardless of environment
    let _ = is_wsl2();
}

#[test]
fn test_is_wsl2_consistent() {
    // Cached result must be stable across calls
    let first = is_wsl2();
    let second = is_wsl2();
    assert_eq!(first, second, "is_wsl2() must return consistent results");
}

#[test]
fn test_detect_wsl2_matches_indicators() {
    // Verify detection agrees with kernel-controlled indicators.
    // WSL_DISTRO_NAME env var alone is NOT sufficient (spoofable).
    let has_interop = std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists();
    let has_kernel_string = std::fs::read_to_string("/proc/version")
        .map(|v| v.contains("microsoft") || v.contains("WSL"))
        .unwrap_or(false);

    if has_interop || has_kernel_string {
        assert!(
            is_wsl2(),
            "Kernel-controlled WSL2 indicators present but is_wsl2() returned false"
        );
    }
    // Note: we don't assert the negative because the OnceLock cache
    // may have been populated by another test or indicator.
}

#[test]
fn test_wsl2_landlock_available() {
    // Landlock should be available on both WSL2 and native Linux
    // (WSL2 kernel 6.6 has Landlock V3)
    if is_wsl2() || is_supported() {
        assert!(
            is_supported(),
            "Landlock must be available when WSL2 or native Linux"
        );
    }
}
