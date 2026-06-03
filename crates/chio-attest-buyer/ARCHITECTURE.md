# chio-attest-buyer Architecture

`chio-attest-buyer` owns the public Chio buyer attestation boundary. It exposes Chio-native packet, review-package, lineage, continuation, and verification-report types so callers do not depend directly on the historical runtime verifier shapes.

The crate is a thin boundary adapter. It maps public Chio structs into the verifier backend, normalizes historical error and check codes back into the `chio_attest_buyer` namespace, and delegates full proof replay to `chio-attest-buyer-core` when hydrated proof artifacts are available.

The trust boundary is typed JSON construction. Public `*_from_json` functions must not return Chio-owned structs until schema ids, required identifiers, SHA-256 bindings, artifact paths, duplicate artifact keys, and byte counts have been checked. Verification still replays through the backend, but constructor validation prevents malformed packets or unsafe review packages from being handed to callers as trusted local shapes.

Current hardening: packet and review-package JSON constructors now apply the same fail-closed shape checks that runtime verification uses before returning typed public values.
