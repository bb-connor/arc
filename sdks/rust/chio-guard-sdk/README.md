# chio-guard-sdk (compatibility path)

Rust compatibility package for the `chio:guard@0.2.0` guest SDK. This crate is
a thin shim that re-exports the canonical workspace crate at
`crates/chio-guard-sdk` without changing any request or verdict call sites.

New guard authors should depend on the canonical `crates/chio-guard-sdk`
directly. This path exists to keep existing imports working.
