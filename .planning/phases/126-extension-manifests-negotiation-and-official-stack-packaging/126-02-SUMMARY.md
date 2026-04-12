# Summary 126-02

Packaged the first-party ARC implementation set as one official stack.

## Delivered

- added official-stack package and profile types in `crates/arc-core/src/extension.rs`
- published `docs/standards/ARC_OFFICIAL_STACK.json`
- defined `local_default`, `shared_control_plane`, and `a2a_gateway` official
  profiles over first-party components

## Result

ARC can now distinguish the first-party reference stack from custom
implementations without inventing a second trust model.
