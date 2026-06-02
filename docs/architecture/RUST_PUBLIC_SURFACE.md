# Rust Public Surface Metadata

## Boundary

The Rust public surface contract is owned by the root workspace metadata and
the structural gate in `scripts/check-rust-public-surface.py`.

`workspace.metadata.chio.rust_public_entrypoints` names repo-public Rust
crates that are supported entrypoints even while the workspace remains
pre-release and most crates set `publish = false`. Those crates must also
declare `package.metadata.chio.public_entrypoint = true`, giving each public
crate a package-local acknowledgment of the root contract. The adjacent
`rust_registry_public_crates` list names crates that are allowed to publish to
the Rust registry.

This boundary does not own API design inside those crates, release packaging,
SDK parity, or protocol compatibility. It owns the workspace-level declaration
that a Rust crate is intentionally public and therefore must carry enough
metadata and implementation surface for users, release audit, and CI to reason
about it.

## Pain Points

The gate verifies sorted unique lists, known crate names, README presence,
package descriptions, implementation targets, registry-public `publish`
settings, and root/local public-entrypoint agreement. That catches accidental
publication drift, but the root list can still lag behind protocol docs.

Earlier public-surface drift showed the failure mode: `chio-api-protect` is the
backing library for the documented `chio api protect` runtime entrypoint, but it
was not listed in `rust_public_entrypoints` until the initial registration
slice. Without a package-local assertion, that mismatch was review-only and
could silently persist.

## Security And API Constraints

- Public entrypoint metadata must remain explicit and sorted so review diffs
  show intentional public-surface changes.
- Package-local `public_entrypoint` markers must be booleans and must match
  root-list intent. They do not replace the root list as the reviewable source
  of public surface ordering.
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

## Initial Entrypoint Registration Slice

Strengthen the public Rust surface gate so
`package.metadata.chio.public_entrypoint = true` fails unless the package also
appears in `workspace.metadata.chio.rust_public_entrypoints`; register
`chio-api-protect` as a root public entrypoint with explicit README metadata.

## Root And Local Entrypoint Handshake Slice

### Current Boundary

The root workspace list remains the source of truth for public Rust entrypoint
ordering, but each listed package must acknowledge that public role with
`package.metadata.chio.public_entrypoint = true`.

### Pain Point Addressed

Before this slice, the gate checked only one direction: a crate-local public
marker had to appear in the root list. It did not reject a root-listed crate
that lacked the local marker. That allowed a central Cargo.toml-only diff to
promote a crate to the public surface without any package-local manifest
evidence in the crate being promoted.

### Security And API Constraints

- Keep `workspace.metadata.chio.rust_public_entrypoints` as the sorted root
  source of truth. The local marker is an acknowledgment, not a second ordered
  list.
- Do not infer registry-public status from public entrypoint status. Repo-public
  crates can remain `publish = false`.
- The gate must keep failing closed on malformed `package.metadata.chio` data
  and must stay pure, local, and network-free.

### Affected Dependents

Every crate named in `rust_public_entrypoints` must carry the package-local
marker. The required transitive edits are manifest metadata only and do not
change compiled targets, features, semver surface, canonical bytes, or runtime
behavior.

### Material Improvement

The checker now rejects root-listed public entrypoints missing
`package.metadata.chio.public_entrypoint = true`, includes a synthetic
regression for that failure mode, and adds the local marker to each real
root-listed entrypoint crate that lacks it.

## Registry Dependency Closure Slice

### Current Boundary

`rust_registry_public_crates` declares which workspace crates may be treated as
crates.io candidates. The structural gate owns this declaration, but the Cargo
registry resolver owns the actual install boundary: a published crate's normal
and build dependencies resolve from the registry, not from workspace `path`
dependencies.

### Pain Point Addressed

Before this slice, the gate checked that a registry-public crate was itself
publishable, documented, and implemented. It did not check whether that crate's
non-dev workspace dependencies were also registry-public. A crate could
therefore appear safe in metadata while `cargo package` or a downstream
`cargo install` failed because a normal dependency was still private to the
workspace.

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

### Material Improvement

The structural gate now fails any registry-public crate whose normal or build
workspace `path` dependency is not also listed in
`rust_registry_public_crates`. The real workspace metadata is honest:
`chio-conformance` remains a repo-public conformance harness, but it must not
be listed as registry-public while it still depends on private Chio kernel and
selective-disclosure crates.
