# chio-file-custody

`chio-file-custody` inspects extended ACL authority on a borrowed file descriptor
on Apple targets. Custody callers use the result alongside ownership, mode,
file-type, and descriptor-identity checks before trusting a local file.

## Usage

Pass an already opened file into the platform-specific inspector:

```rust
#[cfg(target_vendor = "apple")]
fn has_additional_authority(file: &std::fs::File) -> std::io::Result<bool> {
    chio_file_custody::darwin_descriptor_grants_extended_acl_authority(file)
}
```

`Ok(true)` means an allow or unknown ACL tag was observed. `Ok(false)` means
no extended ACL authority was found under this conservative tag policy.
Propagate inspection errors into the caller's custody rejection path.

The public inspector is available only on Apple targets. This sample defines a
borrowing helper and performs no file operations when run as a doctest.
On other targets, this crate exposes no equivalent inspector.

## Guarantees

- The inspector borrows `File` and leaves descriptor ownership with its caller.
- `apple_acl_tag_grants_additional_authority` treats only deny tags as harmless.
- `acl_entry_returned` checks errno only for failed enumeration calls.
- The inspector releases its ACL allocation and propagates inspection errors.

## Status

Implemented Darwin descriptor ACL helper with platform-independent tests of
return-code handling and tag classification. Those tests do not exercise Darwin
FFI on non-Apple hosts. The helper alone does not establish file custody.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Core types](../chio-core/README.md)

[License](../../../LICENSE)
