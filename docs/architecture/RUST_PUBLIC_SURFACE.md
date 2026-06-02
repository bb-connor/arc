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

## Registry Dependency Closure Slice

### Current Boundary

`rust_registry_public_crates` declares which workspace crates may be treated as
crates.io candidates. The structural gate owns this declaration, but the Cargo
registry resolver owns the actual install boundary: a published crate's normal
and build dependencies resolve from the registry, not from workspace `path`
dependencies.

### Pain Point

The gate currently checks that a registry-public crate is itself publishable,
documented, and implemented. It does not check whether that crate's non-dev
workspace dependencies are also registry-public. A crate can therefore appear
safe in metadata while `cargo package` or a downstream `cargo install` fails
because a normal dependency is still private to the workspace.

### Security And API Constraints

- Do not broaden the registry surface by implication. Making one crate
  registry-public must not silently publish its private dependency graph.
- Keep dev-dependencies out of this check. They exercise in-repo verification
  and are not required for normal downstream resolution.
- Optional normal dependencies still count. A published feature that points at
  an unpublished workspace crate is an advertised but unresolvable public
  surface.
- Keep the gate pure and local by parsing manifests. Do not invoke Cargo
  packaging, registry lookup, or network access from the structural check.

### Affected Dependents

CI runs `python3 scripts/check-rust-public-surface.py` from the workspace
structural gate. The shell regression suite owns synthetic workspaces that
prove this policy without depending on the real registry. Real workspace
metadata may need to stop advertising a crate as registry-public until its
normal dependency graph is itself registry-resolvable.

### Planned Material Improvement

Teach the structural gate to fail any registry-public crate whose normal or
build workspace `path` dependency is not also listed in
`rust_registry_public_crates`. Then make the real workspace metadata honest:
`chio-conformance` remains a repo-public conformance harness, but it must not
be listed as registry-public while it still depends on private Chio kernel and
selective-disclosure crates.
