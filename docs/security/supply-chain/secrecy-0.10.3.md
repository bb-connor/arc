# secrecy 0.10.3 source audit

Reviewed on 2026-09-28 for the compiler and secret-ownership package.
Registry archive SHA-256:
`e891af845473308773346dc847b2c23ee78fe442e0472ac50e22a18a93d3ae5a`.
All eight regular archive members matched the cached source; no absolute paths,
parent traversal, links, build script, generated native code or binary payloads.
The checksum matches Cargo.lock.

Reviewed the complete `src/lib.rs`, original and normalized manifests, and the
workspace call sites. The only dependencies are the existing `zeroize` and
optional `serde` crates. The implementation is `no_std`, forbids unsafe code,
and performs no filesystem, network, environment or process operations.

`SecretBox` owns a `Box`, calls `Zeroize` on drop, and exposes references only
through named traits. Debug reports the type and a constant redaction marker.
Serialization requires the inner type to implement the explicit
`SerializableSecret` marker; the workspace adds no such implementation.
`SecretString` supports deserialization and deliberate cloning, so owning
private-key documents separately omit Clone and Serialize. Explicit borrowed
custody projections remain the only key-export path in the authority package.

The allocation guarantee is limited to owned storage. It does not scrub copies
created before wrapping, serializer input buffers, operating-system copies or
other process memory. String/slice conversion may shrink allocations; broker
byte buffers therefore use `SecretBox<Vec<u8>>` to retain their allocation.
The workspace does not use the clone-based `init_with` constructor. Guard strings
and authority input cleanup retain their existing caller-owned cleanup boundaries.

Decision: safe to deploy in the reviewed dependency role. Consumer redaction,
custody round-trip and compiler trait probes are recorded in the package's
execution report. This source audit is separate from hosted/release qualification.
