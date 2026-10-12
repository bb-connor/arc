# chio-file-custody architecture

## Responsibility and boundary

This crate owns a Darwin extended-ACL inspection helper.
On Apple targets the public surface exports
`darwin_descriptor_grants_extended_acl_authority(&File) -> io::Result<bool>`.
It borrows a live descriptor and reports whether ACL tags add authority.
The caller retains ownership of the file and all custody decisions.

Ownership, permission bits, file type, and expected descriptor identity require
separate caller checks. The helper performs no path opening or permission edits.
Other target vendors expose no public inspection function.

## Structure

`lib.rs` selects `darwin_acl` for Apple builds and unit tests.
The public re-export is restricted to Apple builds.
`darwin_acl.rs` contains the FFI inspector and two private policy helpers.

`acl_entry_returned` interprets Darwin enumeration return codes.
`apple_acl_tag_grants_additional_authority` classifies extended ACL tags.
Their tests can run on a non-Apple host without calling Darwin FFI.

## Data and control flow

The inspector calls `acl_get_fd_np` with the extended ACL type.
A null result with `NotFound` means no extended ACL object and returns false.
Other acquisition errors propagate to the caller.

Enumeration starts with `ACL_FIRST_ENTRY` and advances with `ACL_NEXT_ENTRY`.
A zero status yields an entry, even when errno contains a stale value.
A minus-one status with `EINVAL` terminates enumeration.
Unexpected status values become `io::ErrorKind::Other` errors.

For each entry the helper retrieves its tag.
A deny tag adds no authority under this policy.
An allow or unknown tag sets the result to true and stops enumeration.
Inspection errors are retained while the ACL object is released.

## Trust and invariants

The inspection uses the supplied descriptor throughout.
It does not reopen a path that could resolve to a different file.
The policy conservatively rejects unknown tags as additional authority,
without reproducing Darwin ACL precedence semantics.

Unsafe operations are confined to calls over a live borrowed descriptor,
an allocated ACL object, and writable entry/tag output storage.
The acquired ACL allocation is freed once after enumeration.
Inspection errors take precedence over cleanup errors; otherwise an ACL free
failure is returned to the caller.

An `Ok(false)` result applies to extended ACL authority only.
The caller must reject inspection errors to enforce a fail-closed custody rule.
The crate neither serializes nor signs a custody assertion.

## Dependencies

`libc` supplies platform errno values and supports the Darwin return-code policy.
The inspector declares its Darwin ACL functions locally using C ABI signatures.
Standard `File` and `io::Error` preserve descriptor ownership and error details.
No service or storage integration is required.

## Verification

Unit tests cover successful enumeration with stale errno, `EINVAL` termination,
real errors, unexpected statuses, and deny/allow/unknown tag classification.

```bash
cargo test -p chio-file-custody
```

Running these tests on a non-Apple host exercises policy helpers only.
Actual descriptor ACL inspection requires an Apple target and Darwin runtime.
The source tests do not provide end-to-end file custody qualification.
