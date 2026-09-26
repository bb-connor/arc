# Miri crate list

Which crates' unit tests run under Miri, which tests Miri cannot execute and
why, and for every listed crate which unit tests reach its `unsafe` code. The
list itself is `.config/miri-crates.toml`; `scripts/run-miri-crates.sh` runs
it and `.github/workflows/miri.yml` schedules it nightly. This document is
the measurement behind the list.

Measured on `packet/k-gates` at base `07e963e8f5`, 2026-09-26, with
`nightly-2026-02-07` (Miri `0.1.0 (efc9e1b50c 2026-02-06)`),
`MIRIFLAGS=-Zmiri-disable-isolation`, on aarch64, unit tests only
(`cargo miri test -p <crate> --lib`). No source was edited. Each candidate
was run to its first Miri stop, the stopping test was set aside with
`--skip`, and the run repeated until it finished or nothing was left; the
skips that resulted are the `#[cfg_attr(miri, ignore = "...")]` annotations
each crate's owner should add, and they carry only the two reasons Miri's
limits allow: a call into C, or a syscall Miri does not implement.

Reach figures come from `scripts/miri-unsafe-reach.py <crate dir>`, a static,
name-based call-chain analysis from every `#[test]` function to the functions
containing `unsafe` sites. It over-approximates (same-named functions are
conflated), so "unreached" is the reliable direction: a site it reports
unreached has no chain from any unit test, and a crate with no reached site is
ineligible for the list however green Miri would be on it.

## Candidates

Thirty-three crates have the word `unsafe` in production source. After
blanking comments and strings, fourteen have `unsafe` blocks, functions or
impls: `chio-cli` (49 sites), `chio-cage` (101), `chio-secret-broker` (17),
`chio-guard-sdk` (9), `chio-control-plane` (8), `chio-secure-ipc` (7),
`chio-keyring` (6), `chio-sqlite-file-identity` (5), `chio-bindings-ffi` (4),
`chio-cpp-kernel-ffi` (3), `chio-active-response-authority` (3), `chio-kernel`
(1), `chio-guard-sdk-macros` (1) and `chio-commerce-order` (0 after blanking;
its `unsafe` is in a comment).

## Classification

| Crate | Unsafe sites, reached | Miri result | Class |
| --- | --- | --- | --- |
| `chio-guard-sdk` | 9, 8 | 31 passed, 0 skipped, 15 s | runs entirely |
| `chio-secure-ipc` | 7, 5 | 4 passed, 2 skipped | runs with named syscall and C-call tests ignored |
| `chio-cage` | 101, 16 | 15 passed, 5 skipped, 399 s | runs with named syscall tests ignored; the OS-boundary custody tests are the exclusions, as expected |
| `chio-keyring` | 6, 6 | 5 passed, 2 skipped | runs with named syscall tests ignored |
| `chio-cpp-kernel-ffi` | 3, 3 | **Undefined Behavior** in the first buffer-reading test | listed; red until fixed (finding below) |
| `chio-bindings-ffi` | 4, 4 | **Undefined Behavior** in the first buffer-reading test | listed; red until fixed (finding below) |
| `chio-active-response-authority` | 3, 2 | 12 passed with 6 tests set aside: 5 `chmod` C calls and 1 assertion Miri's emulated file metadata cannot satisfy | ineligible: the two reachable sites are reached only by the ignored process-boundary helper test, the third is in the daemon binary; under Miri none of its unsafe code runs |
| `chio-sqlite-file-identity` | 5, 5 | 0 passed once its 4 C-calling tests are set aside; 1 already `#[ignore]` | excluded: calls into C (every test opens SQLite) |
| `chio-secret-broker` | 17, 7 | 4 passed before the first stop (`socket`, a C call); 180 unit tests | unclassified: the remainder was not run within the time available |
| `chio-control-plane` | 8, 8 | compiled (195 crates), then the first unit test did not return within the 1,200 s box; 0 tests completed | unclassified: not measurable at a whole-crate box; the 8 reaching tests need per-test runs |
| `chio-kernel` | 1, 1 | not run after the control-plane result: same shape (SQLite-backed, 1,517 unit tests) | unclassified |
| `chio-cli` | 49, 48 | not run after the control-plane result: same shape (SQLite-backed, 699 unit tests) | unclassified |
| `chio-guard-sdk-macros` | 1, 0 | Miri does not run proc-macro crate tests | ineligible: no test reaches its unsafe site |
| `chio-commerce-order` | 0 | not run | ineligible: no unsafe code |

## Skips, for the owners

Each row is one `#[cfg_attr(miri, ignore = "<reason>")]`; the entry in
`.config/miri-crates.toml` is removed when the attribute lands.

| Test | Reason |
| --- | --- |
| `crates/security/chio-secure-ipc/src/credentials.rs:100` `anonymous_credentials_require_read_only_handles_and_all_seals` | syscall: `memfd_create` (aarch64 number 279) |
| `crates/security/chio-secure-ipc/src/tests.rs:71` `listener_refuses_same_process_and_non_private_parent` | calls into C: `chmod` through `std::fs::set_permissions` |
| `crates/security/chio-cage/src/launch.rs:1343` `acknowledged_child_reaper_handoff_reaps` | syscall: `pidfd_spawnp` (child spawned through `posix_spawn`) |
| `crates/security/chio-cage/src/launch.rs:1310` `child_reaper_send_failure_reaps_synchronously` | syscall: `pidfd_spawnp` |
| `crates/security/chio-cage/src/launch.rs:1299` `child_reaper_start_failure_reaps_synchronously` | syscall: `pidfd_spawnp` |
| `crates/security/chio-cage/src/launch.rs:1326` `child_supervisor_retries_sigkill_until_reaped` | syscall: `pidfd_spawnp` |
| `crates/security/chio-cage/src/launch/linux_parts/part_02.rs:693` `swapped_live_stdio_descriptors_fail_identity_verification` | syscall: `fstat` on a descriptor that is not file-backed |
| `crates/security/chio-keyring/src/lib.rs:700` `retained_sqlite_descriptor_detects_hardlinks_and_path_rebinding` | syscall: `openat` with `O_DIRECTORY` (flag `0x4000`) |
| `crates/security/chio-keyring/src/lib.rs:739` `trusted_parent_policy_requires_private_child_below_system_temp_directory` | syscall: `openat` with `O_DIRECTORY` (flag `0x4000`) |
| `crates/security/chio-active-response-authority/src/runtime.rs:475` `daemon_health_crosses_an_authenticated_process_boundary` | calls into C: `chmod` |
| `crates/security/chio-active-response-authority/src/runtime.rs:480` `daemon_worker_panic_stops_the_listener_and_joins_workers` | calls into C: `chmod` |
| `crates/security/chio-active-response-authority/src/runtime.rs:485` `daemon_stop_discards_queued_requests_and_joins_inflight_workers` | calls into C: `chmod` |
| `crates/security/chio-active-response-authority/src/store/tests.rs:72` `sqlite_snapshot_round_trips_canonical_metadata_and_rows` | calls into C: `chmod` |
| `crates/security/chio-active-response-authority/src/store/tests.rs:157` `decisions_use_the_verified_startup_image_not_later_database_writes` | calls into C: `chmod` |
| `crates/security/chio-active-response-authority/src/store/tests.rs:200` `cleanup_guard_never_removes_a_replacement_inode` | syscall: the file metadata Miri returns does not carry the inode identity `validate_exact()` compares, so the guard cannot observe the replaced inode; the test fails on its assertion under Miri only (it passes natively, and 12 of the crate's tests pass around it under Miri) |
| `crates/security/chio-secret-broker/src/authority_ipc.rs:968` `authority_rpc_requires_signed_exact_responses_and_full_capabilities` | calls into C: `socket` |
| `crates/platform/chio-sqlite-file-identity/src/lib.rs:155`, `:174`, `:198`, `:222` (all four tests) | calls into C: `sqlite3_threadsafe` through `rusqlite` |

## Findings

Miri stops both FFI crates at the same defect, in code that every buffer-
returning test reaches:

- `crates/sdk/chio-cpp-kernel-ffi/src/lib.rs:82` takes `boxed.as_mut_ptr()`
  on a `Box<[u8]>`, then `:84` moves the box into `std::mem::forget`. Under
  the aliasing model Miri enforces, moving the box retags it uniquely and
  invalidates the pointer taken two lines earlier; the first read through it
  (`src/tests.rs:493`, `take_result_string`) is reported as Undefined
  Behavior, and so is the next test's (`ffi_sign_receipt_recompute_accepts_matching_content`)
  once the first is skipped.
- `crates/sdk/chio-bindings-ffi/src/lib.rs:79` and `:81` are the same
  constructor (`from_bytes`); the report lands at `src/lib.rs:438`
  (`result_to_string`).

The sound shape is `Box::into_raw(boxed)`, taking the length first. Until the
SDK owner lands that, the Miri lane is red on these two crates by design:
skipping the tests would hide the finding the lane exists to make, and a UB
report is not one of the two reasons a skip may carry.

## Reach records for the listed crates

Sites reached by a name-based call chain from at least one unit test. The
full output, including the cage's 85 unreached sites (the seccomp, Landlock,
mount and fork boundary code that only the native process tests exercise), is
`python3 scripts/miri-unsafe-reach.py crates/security/chio-cage ...`.

`chio-guard-sdk` (8 of 9): `src/glue.rs:129` in `chio_deny_reason`;
`src/glue.rs:280`, `:289`, `:294` in the `read_request_rejects_*` tests;
`src/host.rs:84` `log`, `:112` `get_config`, `:146` `get_time`, `:168`
`fetch_blob`. Unreached: `src/glue.rs:46`, an `unsafe fn` no test calls.

`chio-secure-ipc` (5 of 7): `src/lib.rs:384`, `:392`, `:394` in `adopt`;
`src/tests.rs:43`, `:57` in the descriptor duplication test. Unreached:
`src/lib.rs:379` (`unsafe fn`) and `src/lib.rs:475` in
`harden_process_custody`.

`chio-keyring` (6 of 6): `src/lib.rs:550`, `:564`, `:570`, `:582`, `:588` in
`trusted_file_has_extended_acl` (3 tests); `src/lib.rs:623` in
`validate_sqlite_main_database_live_path_binding` (3 tests).

`chio-cage` (16 of 101): `src/launch.rs:1266`, `:1277` in
`live_child_custody`; `bootstrap.inc:717`, `:719` in `pidfd_is_reaped`;
`bootstrap.inc:754`, `:758`, `:774`, `:783` in `waitid_pidfd`;
`bootstrap.inc:820` in `send_pidfd_signal`; `src/linux.rs:197`
`directory_entry_names`; `src/linux.rs:407`, `:409`, `:412`, `:419` in
`create_exact_write`; `src/linux.rs:1035`, `:1051` in `openat2`. The custody
sites are reached only by the four `pidfd_spawnp` tests that Miri cannot run,
so under Miri the cage's executed unsafe code is the directory, exact-write
and `openat2` paths.

`chio-cpp-kernel-ffi` (3 of 3): `src/lib.rs:305` `read_c_str`,
`src/lib.rs:778` `chio_kernel_buffer_free`, `src/tests.rs:493`
`take_result_string`.

`chio-bindings-ffi` (4 of 4): `src/lib.rs:97` `chio_buffer_free`,
`src/lib.rs:183` `read_c_str`, `src/lib.rs:205` `read_bytes`,
`src/lib.rs:438` `result_to_string`.

## Red on mutation

A scratch crate with one test reading one byte past a three-byte slice
through `pointer.add(len)` fails under the same toolchain and flags with
`Undefined Behavior: memory access failed: attempting to access 1 byte, but
got alloc...+0x3 which is at or beyond the end of the allocation`, at the
deliberate line. The lane runs listed crates with exactly that command, so
the same defect in a listed crate's test fails the lane the same way.
