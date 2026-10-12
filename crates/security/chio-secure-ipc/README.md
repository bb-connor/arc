# chio-secure-ipc

`chio-secure-ipc` provides local IPC custody primitives for privileged Chio
services. It authenticates Unix socket peers, owns socket lifecycle cleanup,
adopts inherited secret descriptors, and reads or writes bounded frames.

## Usage

Round-trip a length-prefixed frame in memory. This example opens no socket,
adopts no descriptor, and changes no process attributes.

```rust
use chio_secure_ipc::{read_bounded_frame, write_bounded_frame};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut encoded = Vec::new();
    write_bounded_frame(&mut encoded, b"request-a", 64)?;
    let decoded = read_bounded_frame(&mut Cursor::new(encoded), 64)?;
    assert_eq!(decoded, b"request-a");
    assert!(read_bounded_frame(&mut Cursor::new(65_u32.to_be_bytes()), 64).is_err());
    Ok(())
}
```

## Guarantees

- `read_bounded_frame` rejects zero or oversized lengths before allocating the
  body. `write_bounded_frame` rejects empty or oversized bodies and flushes
  the big-endian length prefix and body.
- `SecureUnixListener::bind` checks socket configuration and private parent
  ownership, takes an exclusive lifecycle lock, and records socket identity.
- `accept_authenticated` and `try_accept_authenticated` compare kernel peer
  PID, UID, and GID with the configured identity and recheck the socket inode.
- Listener drop removes only a socket matching its retained identity.
- `InheritedSecretFile::adopt` duplicates a transferred descriptor with
  close-on-exec and retires the original. Its unsafe contract requires exclusive
  ownership; private-file validation is a separate operation.

## Status

Implemented framing and custody helpers. Authenticated listener binding and
`harden_process_custody` require Linux; unsupported platforms return custody
errors. Unix platforms expose inherited descriptor adoption. Credential checks
recognize Linux systemd credentials and sealed read-only files. Application
message validation, request deadlines, and authorization are caller concerns.
No Cargo features are declared.

## Related

- [Architecture](ARCHITECTURE.md)
- [Native wire format](../../../spec/PROTOCOL.md#42-native-wire-format)
- [Keyring](../chio-keyring/README.md)

[License](../../../LICENSE)
