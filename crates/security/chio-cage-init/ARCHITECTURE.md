# chio-cage-init architecture

## Responsibility and boundary

`run_cage_init` is the single-threaded Linux process entrypoint. The binary
calls it and exits 127 on an error; it accepts no argument-based configuration.
Its input is the launcher's authenticated control socket at FD 0, selected by
`CHIO_CAGE_CONTROL_FD=0`, followed by a sealed plan memfd and retained resources.

The crate owns descriptor transfer, bootstrap validation, identity changes,
confinement installation, prepared status emission, and the final target
`execveat`. Its library also exports filter compilation/hashing and descriptor
validation for the launcher. It relies on `chio-cage` for manifest admission,
helper image admission, ptrace supervision, final evidence, and receipt signing.

The crate library is compiled only on Linux. Native architecture selection
currently permits x86_64. Aarch64 syscall-number mappings exist, but native
filter compilation refuses that architecture through the shared selector.

## Structure

| Module | Responsibility |
| --- | --- |
| `bootstrap.rs` | Entrypoint, self-pidfd transfer, ordered setup, prepared status, and retained-FD exec. |
| `descriptor_transfer.rs` | Bounded `SCM_RIGHTS` transfer with ownership and ancillary validation. |
| `validation.rs` | Envelope/seal/table checks, live helper binding, artifact hashing, and descriptor comparisons. |
| `descriptors.rs` | Collision-safe remapping, stdio setup, Unix peer credentials, status writes, and FD closure. |
| `identity.rs` | Exact UID/GID/group application, capability-retention cleanup, and parent-death signal. |
| `sandbox.rs` | Signal-mask reset, nofile limits, caller-FD Landlock rules, and seccomp installation. |
| `seccomp.rs` | Architecture-bound BPF compilation, syscall numbering, and canonical filter digest. |
| `exec.rs` | Bounded argv/environment validation and NUL-terminated pointer vectors. |
| `status.rs` | Failure record emission through an available status socket and Unix millisecond time. |

## Data and control flow

The entrypoint duplicates the control descriptor close-on-exec for early
failure reporting. It opens a pidfd for itself and transfers it to the parent,
then checks that the helper has exactly one thread and obtains socket peer
credentials. It receives the sealed envelope and resource descriptors.

The bootstrap bounds the envelope read, decodes `LaunchEnvelope`, reencodes it
canonically, and requires byte equality. `validate_envelope` checks schemas,
parent process/socket identity, plan and FD-table digests, argv, execution
identity, deny-by-default configuration, and descriptor-table shape.

`verify_descriptor_table` checks live resource identities, artifact hashes,
unprivileged executable attributes, broker peer credentials, and target FD
binding. `verify_helper_self` compares `/proc/self/exe` with the retained helper.
Only then does the helper raise the stop authenticated by its parent's tracer.

After the handshake, descriptors are remapped through temporary slots above
255. Target stdio is duplicated into 0, 1, and 2; unnamed descriptors are
closed with `close_range`. Setup resets the signal mask, applies nofile limits,
changes directory through the retained working-directory FD, and applies or
verifies the sealed execution identity.

The helper arms parent-death `SIGKILL`, verifies its parent still exists,
and sets `PR_SET_NO_NEW_PRIVS`. It enforces Landlock, compiles and hashes the
independent seccomp filter, validates prepared evidence, and builds exec vectors.
It installs the filter before sending the prepared record, then invokes
`execveat` on the target FD with `AT_EMPTY_PATH`. An exec failure emits the
prebuilt failure packet and exits 70.

## Trust and invariants

`receive_descriptors` limits count to 192, requires one `SCM_RIGHTS` control
message with matching payload count, and rejects truncated/invalid messages.
Received descriptors become owned close-on-exec handles. The sealed plan must
carry write, grow, shrink, and seal seals; its envelope is at most 4 MiB.

Table validation requires ordered unique slots and exactly one helper, target,
working directory, and each stdio role. Broker presence must match the brokered
profile and authentication digest. Descriptor verification separately obtains
kernel metadata and hashes executable/runtime content.

`read_bounded_file` checks nonzero metadata length against its supplied bound
before allocating and reading the exact region. `hash_file` caps artifacts at
256 MiB and compares size/mtime/ctime before and after hashing.
`helper_identity_and_binding_match` compares supplied identity/digest pairs;
`verify_helper_self` provides their live observations.

Root setup sets supplementary groups and every real/effective/saved UID/GID
slot. Unprivileged setup requires the current identity already match exactly.
The target identity is always non-root; namespace and cgroup controls are
outside this helper. The resource plan currently sets only `RLIMIT_NOFILE`.

Landlock grants use authenticated retained FDs through `nono-chio` 0.53.0,
patch `chio.3`. Prepared validation requires ABI 4 or newer and full independent
filesystem/network rulesets. `compile_seccomp_filter` validates the plan,
requires the native architecture, and uses seccompiler 0.5.0 with `KillProcess`
default and `Allow` for selected rules. Missing/partial enforcement denies exec.

The helper's prepared record precedes target exec. The supervisor must add
kernel-observed target identity, the exec event, and close-on-exec status EOF
before reporting full launch evidence. Failure status delivery is best effort
when its status socket has already become unavailable.

## Dependencies

`chio-cage-plan` provides shared schemas, validators, constants, identity, and
canonical hashing. `nono-chio` supplies the retained-FD Landlock adapter.
`seccompiler` produces and installs BPF. `libc` supplies Linux process,
credential, descriptor, socket, and exec interfaces. `serde`/`serde_json` encode
and decode the envelope and status records.

## Verification

`cargo test -p chio-cage-init --lib` checks exact target argv construction and
invalid argv mutation. `cargo test -p chio-cage-init --test entrypoint` runs the
packaged helper with an empty environment and checks that missing control
protocol terminates with code 127.

The sibling cage compilation and unit suites exercise shared helper validators,
FD identity, table shape, and BPF restrictions. Real Linux enforcement uses a
separately built static PIE helper and raw syscall probes through the cage
runner. It requires permitted parent-child ptrace and a suitable outer seccomp
policy. `enforcement-mutants` supplies caught failure cases and cannot be
compiled in release mode. The declared `real-linux-enforcement` feature has
no source conditionals in this crate.
