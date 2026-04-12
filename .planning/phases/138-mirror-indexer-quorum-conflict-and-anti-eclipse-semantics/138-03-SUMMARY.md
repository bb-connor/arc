# Summary 138-03

Made quorum and freshness evidence fail closed and regression-covered.

## Delivered

- validated publisher uniqueness, report references, listing digests, and
  conflict evidence in `crates/arc-core/src/federation.rs`
- added regression coverage for missing origin publisher requirements
- kept the federation profile explicit about insufficient quorum and stale
  replica behavior

## Result

Phase 139 inherits a stable visibility model where insufficient quorum or
conflicting state blocks admission instead of being guessed around.
