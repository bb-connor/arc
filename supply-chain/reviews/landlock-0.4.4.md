# landlock 0.4.4 source review

Recorded September 16, 2026 by Codex. This is direct source review, not
independent human review. Confidence is high for the reviewed source and the
selected Linux confinement path.

## Source

- Registry archive SHA-256:
  `49fefd6652c57d68aaa32544a4c0e642929725bdc1fd929367cdeb673ab81088`.
- Upstream release commit: `89c56e2db04cf0a4d63e192e7b4371af516a1ccc`.
- Selected library: unmodified registry 0.4.4. Its enumflags dependency uses
  Chio's repaired derive source; see `enumflags2-0.7.12.md`.
- Reviewed manifest and production implementations in `access.rs`, `compat.rs`,
  `errors.rs`, `fs.rs`, `lib.rs`, `net.rs`, `ruleset.rs`, `scope.rs` and `uapi/`.
  There is no package build script. The checked-in bindings are compiled
  directly; the bindgen helper is not invoked by Cargo.

## Enforcement and ownership

The default compatibility policy is **best effort**. Successful construction or
`restrict_self()` alone does not establish complete enforcement. Compatibility
states accumulate missing access rights; partial state remains partial after a
successful kernel call. The result separately carries ruleset enforcement,
`no_new_privs` and observed Landlock support. Hard requirements reject missing
rights. Chio's owned nono adapter requires the designated ABI and a fully
enforced result instead of treating `Ok` as sufficient evidence.

Filesystem and TCP access masks are mapped explicitly to the supported ABI.
Scope restrictions require ABI 6. Future kernel versions are represented by the
latest known ABI while retaining the actual kernel ABI in `LandlockStatus`.
This is a compatibility limit, not a claim to handle unknown future rights.

Rulesets distinguish requested from effective rights. A rule cannot grant
rights outside its ruleset's requested set. Compatibility checks filter the
effective rights and record reductions before the kernel call. Empty rights
and missing handled-access declarations reject. Kernel create/add/restrict
errors propagate; `no_new_privs` is enabled by default. Explicitly disabling it
does not disable the kernel's own privilege checks.

`PathBeneath<F>` retains its `AsFd` owner until rule insertion. It obtains the
borrowed descriptor immediately before the syscall. Ruleset descriptors enter
`OwnedFd` only after successful creation, are duplicated through `try_clone`,
and close through ownership. `PathFd` opens with `O_PATH | O_CLOEXEC`. Its
pathname convenience API follows normal filesystem resolution; Chio supplies
already admitted descriptors at its stronger identity boundary.

`path_beneath_rules` deliberately omits paths that cannot be opened. For this
allowlist API that removes grants; it is not evidence that every requested path
was present. Chio's required-path admission cannot infer completeness from that
helper. Directory-only permissions on files are checked through `fstat` and
the compatibility policy.

## Unsafe boundaries

FFI is limited to the Landlock syscalls, `prctl` and `fstat`, using bounded,
live structures and descriptor borrows. Attributes contain integer fields and
use the kernel ABI layout; packed path attributes are passed by pointer without
creating unaligned field references. The x86 and x86_64 bindings include layout
tests. Kernel-owned descriptor creation is converted to Rust ownership once.

`access::full_negation` temporarily constructs a mask containing unknown bits.
Its safe-input uses immediately intersect that mask with an already valid set;
they do not iterate or format the temporary mask. The unknown-input error path
requires an invalid bitset previously manufactured by unsafe caller code.
This review does not endorse violating enumflags' unchecked-input contract.

## Qualification

The checksum-verified source and member inventory are retained in
`output/process-security-20260915/confinement-audit-471e91ef0/`. On Linux
x86_64, all 52 upstream unit tests and 12 documentation tests pass with the
selected enumflags derive repair. No tests failed or were ignored. Resolution,
commands and terminal results are retained in
`confinement-upstream-e271c26a6/`.

The repaired candidate's cage gate also passed all 69 first-party tests, 26
real kernel outcomes and 10 mutation probes with unchanged source and lockfile.
That run covered required Landlock enforcement and its fail-closed
compatibility checks. Evidence is retained in
`linux-x86-cage-enumflags-e271c26a6/`.

A direct `safe-to-deploy` audit covers the exact 0.4.4 registry bytes. It does
not certify Chio's separately owned enumflags derive fork, infer complete
enforcement from Landlock's best-effort default, or replace qualification of a
final frozen integration candidate.
