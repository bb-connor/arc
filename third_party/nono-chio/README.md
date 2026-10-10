# nono-chio

`nono-chio` is Chio's minimal descriptor-based Landlock adapter. Its ABI probe
comes from the reviewed nono 0.53.0 Linux backend. The broad upstream nono
package is not a runtime dependency.

- Filesystem rules take caller-owned `BorrowedFd` values and never reopen paths.
- Directory enumeration does not grant reads to descendant files.
- Filesystem and TCP network restrictions are separate hard-requirement layers.
  No network grant API exists: bind and connect remain denied.
- Success requires `FullyEnforced` for both layers and `no_new_privs`.
- ABI 4 is the minimum; every access right known to the observed ABI is handled.
- The probe tries ABI 6 through 1 with filesystem, network, and scope checks.
  Its result is cached; unsupported kernels fail closed before execution.

The caller retains every descriptor. This adapter neither closes nor duplicates
supplied descriptors. Provenance is in
`third_party/provenance/linux-enforcement-stack.toml`; `PATCHES.md` records the
extracted source and integration changes.
