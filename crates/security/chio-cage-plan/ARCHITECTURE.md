# chio-cage-plan architecture

## Responsibility and boundary

This crate owns shared data contracts between native-tool admission,
the launcher, and the Linux bootstrap. `CageInitPlan` carries the exact target
argv, FD table, Landlock grants, seccomp plan, resource limits, execution
identity, selected environment, and broker authentication commitment.
`LaunchEnvelope` adds parent and trace-session bindings plus content digests.

`SeccompProfilePlan` keeps its fields private and validates construction and
wire decoding. `ExecutionIdentity` similarly validates its constructor.
Other plan and evidence structures expose serializable fields, so their
consumers must invoke the appropriate validation functions.

The crate exports canonical JSON and SHA-256 helpers from `chio-core-types`.
It supplies no publisher registry, sandbox installation, signing key, or
receipt persistence. Enforcement records describe reported observations and
must be produced and authenticated by the surrounding launcher.

## Structure

| Module | Responsibility |
| --- | --- |
| `model.rs` | Descriptor identities/roles, plan fields, platform selection, argv/digest/target-binding validation. |
| `seccomp_plan.rs` | Closed syscall vocabulary, argument constraints, validating construction and wire decoding. |
| `execution_identity.rs` | Non-root Unix identity and comparison with prepared evidence. |
| `enforcement.rs` | Prepared/exec/exit evidence, enforcement states, versions, and consistency checks. |
| `launch_protocol.rs` | Sealed-envelope/status schemas, FD constants, and transfer/read limits. |
| `environment.rs` | Credential and loader/interpreter injection-name classification. |
| `error.rs` | Admission, retention, plan, platform, and identity error vocabulary. |
| `linux.rs` | Kernel descriptor metadata, broker process identity, and bounded procfs mount-ID inspection. |

## Data and control flow

`chio-cage` builds a `CageInitPlan` after admitting a verified manifest and
retaining runtime resources. Plan construction combines grants with immutable
`FileIdentity` values, fixed descriptor purposes, and artifact digests.
Canonical bytes become the sealed launch envelope consumed by `chio-cage-init`.

Descriptor slots reserve 3 for the plan, 4 for status, 5 for helper, 6 for
working directory, and 8 for broker IPC. Linux stdio source slots are 7, 9,
and 10. Runtime/read/write slots begin at 16, 64, and 128 respectively.
The target uses slot 255 while `CHILD_NOFILE_LIMIT` is 192, so a closed target
slot cannot be recreated by an ordinary later descriptor allocation.

The helper emits `StatusRecord::Prepared` or `StatusRecord::Failure`.
`EnforcementPrepared` carries versions, observed Landlock/seccomp status,
artifact and trace bindings, applied identity, and preparation time.
The parent adds `ExecTransitionObserved` after checking the kernel exec event.
`FullyEnforcedEvidence::new` joins those records with status EOF.

`CageEnforcementRecord` represents unsupported, rejected, bootstrap-failed,
fully enforced, and exited states. Its constructors validate state shape;
`exited` binds a terminal code or signal to the previously observed process.

## Trust and invariants

`SeccompProfilePlan::validate` rejects repeated syscalls, direct network socket
creation/connection, peer signaling, unlisted constraint keys, empty or repeated
alternatives, and invalid or duplicate argument indexes. Constraints are OR
alternatives containing ANDed equality checks; each syscall has at most eight
alternatives. `prlimit64` must restrict its PID argument to zero in every rule.
The vocabulary cannot decode `clone`, `clone3`, `fork`, or `vfork`.

The validator accepts a caller-selected syscall subset; it does not certify
that subset as the full compiler-generated profile. Native architecture
selection accepts x86_64 only, although the serialized enum includes Aarch64.

`ExecutionIdentity` rejects UID/GID zero and sentinel values. Its supplementary
groups must be sorted, unique, distinct from the primary group, and at most 64.
`validate_cage_execution_identity_binding` compares both validated identities
exactly. `validate_target_argv` bounds count to 256, each argument to 16 KiB,
and the complete NUL-terminated representation to 128 KiB.

`validate_cage_target_fd_binding` requires the plan/compiler versions, target
slot, exactly one close-on-exec target entry, observed identity/content match,
and a target-FD equality in every `execveat` alternative. Other argument and
complete-plan checks belong to the consuming launcher/bootstrap.

Prepared evidence requires Landlock ABI at least 4, pinned nono 0.53.0 with
patch `chio.3`, seccompiler 0.5.0, x86_64, and full filesystem/network/seccomp
status. Evidence joins require matching process, trace, target identity/content,
ordered times, and observed status EOF. These validators check supplied data;
they do not observe the kernel themselves.

Launch protocol bounds are 192 transferred FDs, a 4 MiB envelope, a 64 KiB
status record, and 256 MiB artifacts. The Linux descriptor helper obtains
mount identity from procfs with a 64 KiB read bound.

## Dependencies

`chio-core-types` supplies canonical encoding, hashing, and its error type.
`serde` and `serde_json` encode plans and validate closed wire forms.
`thiserror` defines typed failures. Linux builds use `libc` for descriptor
and process metadata. No heavy sandbox implementation enters this crate.

## Verification

`cargo test -p chio-cage-plan` exercises identity canonicalization/root rejection,
seccomp constraint consistency, closed wire keys, empty alternatives,
self-only resource limits, and the absence of process-creation wire names.
The plan module's evidence validators are further exercised by
`chio-cage/tests/enforcement_evidence.rs` and the launch/compile suites.

`enforcement-mutants` exposes unchecked/test mutation helpers for those suites.
The crate explicitly rejects release builds with that feature enabled.
Actual Landlock/seccomp installation and target observation are verified by
the sibling crates' Linux enforcement probes.
