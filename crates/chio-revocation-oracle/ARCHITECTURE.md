# chio-revocation-oracle Architecture

`chio-revocation-oracle` owns Chio's signed revocation epoch-root contracts, sparse-Merkle proof generation, freshness windows, passport-bridge revocation application, and root signing/verification traits. It is the primitive used by federation and custody lanes to answer whether a capability or credential subject has been revoked as of an epoch.

The crate is split into public API types, an in-memory sparse-Merkle oracle, epoch-root signing and broadcast helpers, freshness verification, and passport bridge logic. Feature-gated delegation tests wire signed roots through federation gossip into kernel cache behavior.

The security constraint is revocation-key exactness. Subjects, nonces, roots, signatures, and freshness windows must be unambiguous before proofs are emitted or remote caches merge epoch roots.

Planned improvement: reject empty or padded revocation subject identifiers at the oracle boundary so sparse-Merkle leaves cannot be minted for noncanonical subjects.
