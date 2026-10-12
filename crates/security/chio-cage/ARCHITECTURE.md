# chio-cage architecture

## Responsibility and boundary

`admit` consumes `VerifiedCageManifest` issued by the manifest registry and
returns an `AdmittedManifest` that owns filesystem descriptors. `OperatorCeilings`
restrict publisher permissions and bind an explicit forbidden-path policy.
The admitted value retains manifest, signed-manifest, registry, authorization,
and operator-ceiling digests for later compilation.

`retain_runtime_resources` owns helper, target, working-directory, and runtime
artifacts through `RetainedRuntimeResources`. `compile` consumes admission and
runtime ownership into `CompiledCage`, including any authenticated `BrokerIpc`.
`prepare_launch` consumes that value into `PreparedCageLaunch`; `launch_prepared`
returns an `EnforcedChild` only after supervised target execution is observed.

The caller supplies registry authority, operator ceilings, runtime paths,
non-root execution identity, environment values, broker authentication, signing
backend, and persistence sink. Namespace and cgroup isolation are deployment
responsibilities. The configured process limit is `RLIMIT_NOFILE`.

## Structure

| Module | Responsibility |
| --- | --- |
| `lib.rs` | Admission, retained ownership, compilation, canonical commitments, and shared-type reexports. |
| `linux.rs` | Strict path resolution, bounded directory scans, file creation, descriptor inspection, hashing, and ELF validation. |
| `seccomp.rs` | Closed minimal, standard, and brokered syscall profiles with argument restrictions. |
| `launch.rs` | Preparation/launch API, child ownership, waits, termination, and bounded custody handoff. |
| `launch/linux.rs` | Sealed envelopes, helper authentication, ptrace handshake, prepared evidence, and target-image checks. |
| `launch/linux/supervisor.rs` | Lifetime trace supervision, pidfd signaling, and exit observation. |
| `receipt.rs` | Cage receipt bodies, signing preparation, signature/trust-root verification, and persistence callbacks. |

## Data and control flow

Admission validates permission subsets and path overlaps before retaining
forbidden objects and allowed resources with strict `openat2` resolution.
Directory read authority becomes a bounded closure of admitted descendant
inodes. Writes name exact regular files; a missing file retains its parent
without creating anything during admission.

Runtime retention validates executable ELF inputs and hashes stable artifact
content. The helper must be static PIE: `ET_DYN`, no `PT_INTERP`, and no dynamic
library, search-path, or run-path entries. Executable and runtime files reject set-ID or
group/world-writable modes. Executable inputs also reject file capabilities.

Compilation rechecks retained objects and requires each extra runtime file to
match signed read authority. It selects allowed environment values, builds
Landlock grants and syscall constraints, and then creates pending write files
for the selected identity. A failed compile can leave a created file in place.
The canonical profile and plan commit to the FD table, artifacts, environment,
argv, network declarations, and execution identity.

Preparation binds fresh authenticated stdio sockets, creates a random trace
session, and seals a canonical envelope in a memfd. It exposes preparation
bindings while the target launch count remains zero. Launch revalidates these
bindings and starts the retained helper on a dedicated supervisor thread.

The supervisor receives a helper-owned pidfd, verifies the live helper image,
and seizes it before descriptor transfer. It authenticates the initial stop,
then requires prepared status, the kernel exec event, a matching stopped target
image, and status EOF before resuming and returning the child handle.
Lifetime tracing kills later exec events before the new image runs.

## Trust and invariants

`admit` rejects missing permissions, ceilings, forbidden-path policy, forbidden
aliases, symlinks, and unsupported platforms. Read and forbidden directory scans
have entry and name-byte bounds; forbidden scans also limit depth to 64. Compilation caps runtime files at 48
and read/write grants at 64 each; artifact hashing is limited to 256 MiB.

`compile` starts with filesystem deny and blocked network creation. It requires
full Landlock, default-deny seccomp, and ptrace exec observation. Brokered
profiles require one preconnected Unix socket with matching peer credentials
and an authentication digest; network destinations become committed declarations
for the surrounding broker to enforce.

The target FD is close-on-exec at slot 255, above the nofile ceiling of 192.
`execveat` is restricted to that FD and `AT_EMPTY_PATH`. The helper applies the
exact non-root Unix identity, `no_new_privs`, and parent-death `SIGKILL`.
The supervisor uses `PTRACE_O_EXITKILL`; child handles terminate and reap on drop.

`CageReceiptBody` validates state-specific bindings and timestamps.
`sign_cage_receipt` uses an atomic signing backend over canonical content.
`verify_signed_cage_receipt` checks the embedded signer; its trusted-key variant
also requires the configured trust root. Persistence helpers verify before
calling the supplied sink. They provide no store implementation or append log.

## Dependencies

`chio-manifest` supplies registry-issued authority and typed permissions.
`chio-cage-plan` supplies shared contracts and validators. `chio-core` supplies
canonical hashing, receipt semantics, and signing. On Linux, `chio-cage-init`
provides shared bootstrap validation and descriptor transfer; `libc` supplies
pidfd, ptrace, socket, memfd, and filesystem interfaces.

## Verification

`linux_compile` exercises deterministic plans, registry commitments, pending
write creation, retained path replacement, aliases, argv bounds, broker sockets,
and executable/runtime rejection. Unit tests also cover bounded scans, stdio
roles, seccomp constraints, helper identity, and child-custody failure paths.
`enforcement_evidence` checks evidence joins, signed receipt semantics, tampering,
trusted-key persistence, and sink failures.

Run `cargo test -p chio-cage --lib`, `cargo test -p chio-cage --test linux_compile`,
and `cargo test -p chio-cage --test enforcement_evidence` for those scopes.
The `linux_enforcement` target requires Linux x86_64, `real-linux-enforcement`,
a separately built static PIE helper, probe artifacts, and permissive outer
ptrace/seccomp policy. Its runner is
`crates/security/chio-cage/scripts/check-linux-enforcement.sh` and requires a
64-character lowercase hexadecimal `CHIO_CAGE_EVIDENCE_CHALLENGE`.
Those real probes exercise filesystem/network denials, later exec, stdio,
signals, lifetime cleanup, and caught enforcement mutations.
