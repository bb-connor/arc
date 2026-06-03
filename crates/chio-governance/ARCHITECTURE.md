# chio-governance Architecture

`chio-governance` owns Chio capability leases, destructive-action governance receipts, generic governance charters, and governance case evaluation. It sits below verifier crates and must fail closed before signed authorization artifacts are accepted by higher-level proof or runtime paths.

Capability leases bind issuer, subject, scope digest, action class, and validity window. Verification checks schema, signature, scope digest, expiry, and issuance time so a future-dated lease cannot authorize a present action.

Generic governance cases evaluate listing identity, charter scope, activation binding, appeal or supersession targets, and effective admission impact. Failures return structured findings instead of panicking so callers can report why a listing is disputed, frozen, sanctioned, or clear.
