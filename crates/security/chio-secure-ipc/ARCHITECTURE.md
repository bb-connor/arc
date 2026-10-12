# chio-secure-ipc architecture

## Responsibility and boundary

The crate owns local transport custody and bounded binary framing.
`SecureUnixListener` manages a Unix listener, expected peer identity, socket
inode, and lifecycle lock. `InheritedSecretFile` owns an adopted descriptor.
`read_bounded_frame` and `write_bounded_frame` operate on ordinary I/O traits.

Service code supplies trusted UID, expected PID/UID/GID, private socket paths,
frame limits, and message semantics. Authentication establishes the configured
kernel peer identity; application authorization and signed-artifact verification
remain with the service. Framing adds no encryption or signature.

## Structure

`lib.rs` implements peer identities, path validation, socket binding and cleanup,
lifecycle-lock checks, inherited descriptor adoption, process hardening, and
length-prefixed reads/writes. `credentials.rs` implements Linux descriptor-based
systemd credential and sealed-file recognition. `tests.rs` contains framing,
configuration, listener, and inherited-descriptor tests; credentials also have
Linux-specific unit tests.

The crate declares no Cargo features. Platform branches determine availability:
listener types are exported on Unix, authenticated binding requires Linux,
and non-Linux hardening returns a custody error. Framing is independent of sockets.

## Data and control flow

`SecureUnixListener::bind` validates a normalized absolute named socket path,
requires a distinct client process, checks private parent ownership, and obtains
a nonblocking exclusive lifecycle lock. It refuses an existing socket path,
binds, sets private permissions, and verifies the new socket identity.
A provisional cleanup guard handles failures after binding.

`accept_authenticated` accepts a stream and calls the kernel credential reader.
The observed PID, UID, and GID must exactly match `expected_peer`. It then
rechecks that the socket path names the retained device/inode. The nonblocking
variant returns `None` only when accept reports `WouldBlock`.

Dropping the listener removes the socket only if custody checks and retained
identity still match. The lifecycle lock file is retained on disk; its open
handle holds the lock for the listener lifetime. There is no stale-socket
reclamation API in this crate.

`InheritedSecretFile::adopt` accepts descriptor numbers 3 through 65,535 under
an unsafe exclusive-transfer contract. It atomically duplicates with close-on-exec
and closes the original number. `validate_private_regular_file` separately
checks file type, expected owner, private mode bits, and link count. A zero-link
anonymous file is accepted only when the sealed-credential check succeeds.

`read_bounded_frame` reads four big-endian length bytes, rejects zero and lengths
over the configured maximum, allocates exactly the accepted length, and reads
that body. `write_bounded_frame` checks body bounds, writes prefix/body, and
flushes. Readers must supply deadlines when input can block indefinitely.

## Trust and invariants

Socket paths are limited to 100 encoded bytes and reject NUL or unsupported
components. Socket and lock checks require trusted ownership, one hard link,
and no group/other mode permissions; lock path and descriptor identities match.
The immediate parent must be a private directory owned by the service UID.
Parent validation examines the immediate parent; callers establish ancestor custody.

`credentials::is_systemd_credential` recognizes a root-owned, singly linked
regular file with mode 0440 on a read-only tmpfs/ramfs mount and the exact ACL
for the selected non-root service UID. It relies on descriptor metadata,
filesystem flags, and xattrs. Pathnames and environment variables supply no proof.

`credentials::is_sealed_credential` requires a read-only handle and all four
permanent Linux seals: seal, shrink, grow, and write. Both recognition functions
return false on other platforms. `harden_process_custody` sets and verifies
non-dumpable state, then sets Linux no-new-privileges; callers choose when to
apply those process changes.

## Dependencies

`rustix` supplies peer credentials, descriptor flags, file locks, and filesystem
inspection. `libc` supports the narrow unsafe descriptor-transfer and process
hardening calls. `serde` defines peer identity encoding with unknown-field
rejection; `thiserror` supplies custody, configuration, framing, and I/O errors.
Tests use `tempfile` and `chio-test-support` for owned fixtures and assertions.

## Verification

Frame tests cover round trips, empty frames, and oversized prefixes. Descriptor
tests check close-on-exec duplication and retirement of the transferred number.
Listener tests reject unsafe parent permissions. Linux credential tests verify
read-only handles, required seals, and rejection of ordinary unlinked files.
Run `cargo test -p chio-secure-ipc` on Linux for those platform paths.
The README frame example runs entirely in memory with default dependencies.

[README](README.md) | [Native wire format](../../../spec/PROTOCOL.md#42-native-wire-format)
