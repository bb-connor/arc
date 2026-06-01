# Rust Public Surface Metadata

## Boundary

The Rust public surface contract is owned by the root workspace metadata and
the structural gate in `scripts/check-rust-public-surface.py`.

`workspace.metadata.chio.rust_public_entrypoints` names repo-public Rust
crates that are supported entrypoints even while the workspace remains
pre-release and most crates set `publish = false`. Individual crates may also
declare `package.metadata.chio.public_entrypoint = true`; that local marker is
only an assertion that the crate must appear in the root list. The adjacent
`rust_registry_public_crates` list names crates that are allowed to publish to
the Rust registry.

This boundary does not own API design inside those crates, release packaging,
SDK parity, or protocol compatibility. It owns the workspace-level declaration
that a Rust crate is intentionally public and therefore must carry enough
metadata and implementation surface for users, release audit, and CI to reason
about it.

## Pain Points

The current gate verifies sorted unique lists, known crate names, README
presence, package descriptions, implementation targets, and registry-public
`publish` settings. That catches accidental publication drift, but the root
list can still lag behind crate-local metadata and protocol docs.

`chio-api-protect` is the backing library for the documented `chio api protect`
runtime entrypoint. The crate has a README and implementation target, but it is
not listed in `rust_public_entrypoints`. Without a package-local assertion,
that mismatch is review-only and can silently persist.

## Security And API Constraints

- Public entrypoint metadata must remain explicit and sorted so review diffs
  show intentional public-surface changes.
- Package-local `public_entrypoint` markers must be booleans and must not
  create an alternate source of truth; they only force root-list parity.
- Registry-public crates must continue to opt out of `publish = false`; every
  other workspace member must remain private to crates.io by default.
- The gate must stay pure and local. It should inspect Cargo manifests and
  source paths only, not compile the workspace or invoke network access.
- The gate must not infer broad public API compatibility. It only proves that
  declared public Rust crates have the minimum metadata and implementation
  target needed for downstream review.

## Affected Dependents

CI runs `python3 ./scripts/check-rust-public-surface.py` in the workspace
structural gates. The shell regression suite at
`scripts/tests/check-rust-public-surface.test.sh` is the focused compatibility
test for synthetic workspaces. Real entrypoint manifests in `Cargo.toml` should
already satisfy the stricter contract; any transitive edits should be limited
to manifest metadata if the gate exposes an existing omission.

## Planned Improvement

Strengthen the public Rust surface gate so
`package.metadata.chio.public_entrypoint = true` fails unless the package also
appears in `workspace.metadata.chio.rust_public_entrypoints`, then register
`chio-api-protect` as a root public entrypoint with explicit README metadata.
