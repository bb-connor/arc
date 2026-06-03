# chio-attest-buyer-core Architecture

`chio-attest-buyer-core` is the offline proof-package verifier for Chio buyers and auditors. It verifies proof packages without network access by replaying workflow signatures, vendor cosignatures, trust-bundle pins, revocation checkpoints, lease scope bindings, governance receipts, federation DSSE envelopes, and BBS selective-disclosure proofs.

The trust bundle is verifier policy input, not advisory metadata. Its parser must fail closed on unknown top-level and nested fields so ignored side channels cannot travel with trusted roots, authorities, workflow intersections, or disclosure policy.

Accepted verification reports carry canonical hashes for the package, trust bundle, and verifier context. Rejected reports preserve the checks completed before failure and map each error to a stable phase and failure code for auditors.
