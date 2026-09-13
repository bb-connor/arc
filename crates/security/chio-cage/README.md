# chio-cage

`chio-cage` consumes a non-forgeable authorization from the live verified
manifest registry, converts filesystem permissions into retained Linux
descriptors, and compiles a deterministic cage-init plan. The authorization
binds the complete registry snapshot, exact signed envelope and manifest,
server and tool identities, and every authenticated runtime topology entry.
The compiled profile binds the authorization digest, and the sealed launch
plan binds that profile digest.

A compiled profile is configuration intent. Linux launch reports
`FullyEnforced` only after a fresh single-threaded helper installs Landlock and
an independent seccomp-BPF allowlist, the parent observes `PTRACE_EVENT_EXEC`,
the stopped post-exec image matches the retained target, and the close-on-exec
status channel reaches EOF.

## Linux admission requirements

Native minimal and standard profiles are cage-eligible only when every tool in
the verified manifest registry has authenticated local topology. A brokered
native profile is eligible only when every tool has authenticated brokered
topology and compilation receives the matching preconnected broker descriptor.
Remote, mixed, missing, provider-native server-tool, and profile-confused
topologies deny admission. A raw signed manifest, protocol discovery object,
or self-asserted flow predicate cannot authorize cage compilation.

- `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, and
  `RESOLVE_NO_SYMLINKS`
- `O_PATH` and `O_CLOEXEC`
- procfs mounted at `/proc` with `mnt_id` present in `/proc/self/fdinfo`
- canonical absolute UTF-8 paths that do not name `/`

Existing grants are opened once beneath a retained root descriptor. Missing
writable files are accepted only as exact files beneath an existing retained
parent. Admission creates them exclusively with mode 0600 and current effective
ownership, reopens them as `O_PATH`, and compares kernel object identity.
Writable directory grants are rejected.

Read-directory grants are closed over their existing regular-file and
directory descendants at admission, bounded by the 64-slot read-grant limit.
Every descendant is retained by descriptor, and any descendant identity that
aliases an operator-forbidden object rejects admission. Landlock grants
directories `ReadDir` only and grants `ReadFile` only to the exact retained
files. A hard link or file created after admission therefore receives no file
read authority. The default-deny Landlock layer and seccomp profile also deny
the target's link and directory-mutation operations.

The compiler always emits explicit filesystem deny-all and network-blocked
intent. Brokered profiles require one already-connected Unix-domain descriptor
and a SHA-256 authentication-artifact digest. The syscall plan has a fail-stop
default and does not include `socket`, `socketpair`, `connect`, `bind`, `listen`,
or `accept`. The one `execveat` rule is constrained to the retained target at FD
255 with `AT_EMPTY_PATH`. Cage-init sets `RLIMIT_NOFILE` to 192 after installing
that descriptor. Every grant slot remains below the limit, while the inherited
close-on-exec target remains usable for the initial transition and cannot be
recreated after exec.

## Linux enforcement requirements

- Linux 6.7 is the minimum supported kernel. This floor is bound to the pinned
  reviewed stack manifest at
  `third_party/provenance/linux-enforcement-stack.toml`; changing it requires
  updating and revalidating that manifest.
- x86_64 CPU architecture (other architectures fail closed until separately
  reviewed and added to the real-kernel gate)
- Landlock ABI 4 or newer, including TCP connect and bind mediation
- seccomp filter mode and `PR_SET_NO_NEW_PRIVS`
- sealed memfds and `SCM_RIGHTS` descriptor passing
- procfs image and descriptor identity data
- `pidfd_open`, `pidfd_send_signal`, and `waitid(P_PIDFD)`
- parent-child `PTRACE_TRACEME` with `PTRACE_O_TRACEEXEC` and
  `PTRACE_O_EXITKILL`
- `close_range` and `execveat` with `AT_EMPTY_PATH`
- a parent `RLIMIT_NOFILE` soft limit large enough for the collision-free
  bootstrap descriptor remap (the target limit is reduced to 192 afterwards)

The parent duplicates the admitted helper descriptor and launches
`/proc/self/fd/<duplicate>` through the normal process-spawn path, so no helper
pathname is reopened and no confinement code runs in a post-fork callback.
The helper first opens a pidfd for itself while it is live and transfers that
descriptor over the private control socket. The parent verifies the pidfd
identity before any retained resource is transferred,
then independently verifies the running helper through `/proc/<pid>/exe`.
Lifecycle signals use `pidfd_send_signal`, and terminal reaping uses
`waitid(P_PIDFD)` rather than a numeric PID. The helper authenticates its parent
with `SO_PEERCRED`,
verifies the sealed canonical plan and every received descriptor, remaps the
fixed FD table, closes unnamed descriptors, applies Landlock rules directly
from the retained FDs, and installs a separately compiled seccomp-BPF filter.
The reviewed enforcement stack is nono 0.53.0 through the `nono-chio` `chio.2`
caller-FD adapter, Landlock 0.4.4, and seccompiler 0.5.0. Nono starts with
network blocked. Independent filesystem and TCP network Landlock layers must
both report `FullyEnforced`; `PartiallyEnforced` and `NotEnforced` deny launch.
The seccompiler-generated filter is independently installed with
`KILL_PROCESS` as its mismatch action.

The parent treats the close-on-exec status EOF only as corroboration. A matching
prepared record, kernel `PTRACE_EVENT_EXEC`, and stopped post-exec target image
are all mandatory before it detaches the tracee and returns `FullyEnforced`.
Every unsupported, partial, malformed, timed-out, or identity-mismatched path
terminates and reaps the child.

## Signed cage receipts

`CageEnforcementRecord` is local evidence, not a release receipt. The cage
receipt API converts rejection, bootstrap failure, fully enforced launch, and
terminal exit records into a canonical `CageReceiptBody`, binds that body as
the content of a signed `chio.receipt.v1`, and verifies the signature, content
hash, state-specific semantics, bindings, and timestamps before persistence.
The closed wire schemas are `chio.cage.receipt-body.v1` and
`chio.cage.receipt-metadata.v1`. Signing accepts only an atomic
`SigningBackend`, so the embedded kernel identity and returned signature come
from one signing operation.
Failure and rejection receipts are mediated denials, fully enforced launch is
a mediated allow, and exit is a trace observation of a previously enforced
process. A bootstrap receipt without compiled manifest, profile, plan, FD
table, helper, target, and target-identity bindings is invalid.
`CageLaunchError::receipt_bindings` exposes the authenticated compiled bindings
for failure paths, including the final launch-time stdio FD-table digest when
stdio binding completed.

Runtime composition persists only the signed `ChioReceipt`, using
`persist_signed_cage_receipt_with_trusted_key` as the configured-trust-root
validation hook around the existing Chio receipt-store append call. The
unsigned enforcement record must never be written as the release artifact.

The real-kernel gate builds `chio-cage-init` in a separate target directory
with the static C runtime and PIE relocation model. It rejects the built helper
unless the ELF type is `ET_DYN`, no `PT_INTERP` segment exists, and no dynamic
entry names `DT_NEEDED`, `DT_RPATH`, or `DT_RUNPATH`. Admission independently
parses the retained helper's program headers and dynamic table with checked
bounds before accepting the same contract. The gate is:

```bash
crates/security/chio-cage/scripts/check-linux-enforcement.sh
```

It compiles static raw-syscall probes and a dynamically linked control, then
runs the complete cage test suite with `real-linux-enforcement` enabled. The
probes cover allowed controls; forbidden
read, write, create, remove, rename, hard-link, and symlink traversal; retained
path and executable replacement; IPv4 and IPv6 connect and bind; unreviewed
syscalls and process creation; inherited descriptors; parent and loader
environment; undeclared exec; and script-target rejection. Test-only caught
mutants prove that disabled or partial Landlock and disabled seccomp all deny
launch. Additional caught mutants cover an unsealed plan, a corrupt plan
digest, a missing descriptor, malformed status, a trace-session mismatch, and
helper exit after prepared evidence but before exec. The mutant feature cannot
be compiled in release mode.

The runner must permit the parent-child ptrace contract. Containerized runs
also require an unconfined outer seccomp profile; the independent inner filter
remains mandatory and is tested by SIGSYS probes.

Landlock is not a namespace, cgroup, UID, or hostname boundary. Deployments that
need those controls must add them outside this crate. Network creation remains
blocked by seccomp; brokered communication uses one preconnected authenticated
Unix-domain descriptor.

Any platform without the Linux admission primitives returns an error. There is
no best-effort or unconfined success path.

Dynamically linked ELF targets must list the resolved ELF interpreter and each
required shared object as retained runtime files. Runtime files with executable
mode receive the exact-file execute-and-read Landlock grant needed for the
kernel's `PT_INTERP` transition; other runtime files remain read-only. Seccomp
still permits `execveat` only for the retained target descriptor.
