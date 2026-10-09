# Reproduce internal design inputs

> Historical research snapshot retained for provenance. [ADR-0038](../../../../adr/ADR-0038-native-host-program.md), the [program map](../../../../architecture/PROGRAM-MAP.md) and [macOS annex](../ANNEX.md) supersede this document's former implementation choices. Old NK identifiers and platform methods below are historical proposal labels, not current APIs or blanket desktop prerequisites. The shared program retains the needed admission, crossing and ABI safety properties through their owning contracts; it does not require all three redesign keystones before the first product.

The source registry distinguishes public upstream repositories from internal design branches in the **same authenticated working repository as this specification set**. The `origin` remote in an authorized checkout must point to that repository. These locators are internal research provenance, not public installation or checkout instructions. A clone of the public distribution does not contain these unmerged inputs.

A shallow checkout of this PR need not contain the design objects. Fetch their named branches explicitly, then inspect the immutable recorded object rather than assuming the branch tip is still the reviewed version:

```bash
git fetch --no-tags origin refs/heads/docs/ftl-lessons-specs-20261004
git cat-file -e '8dffff3da53dfb56da8e60019af5e3ae896f7f5b^{commit}'
git ls-tree -r --name-only 8dffff3da53dfb56da8e60019af5e3ae896f7f5b docs/superpowers/specs/
git fetch --no-tags origin refs/heads/docs/omarchy-integration-specs-20261007
git cat-file -e 'd092128a18efdf666f4430bf41efd7aff6c16148^{commit}'
git ls-tree -r --name-only d092128a18efdf666f4430bf41efd7aff6c16148 docs/superpowers/specs/2026-10-07-omarchy-integration/
```

Read a listed path using `git show REVISION:PATH`; do not switch or overwrite the active worktree. [source-pins.json](source-pins.json) enumerates exact north-star filenames and SHA-256 content hashes so a reviewer can verify each document independently. The branch fetch above was checked against the recorded north-star revision on 2026-10-07. Branches may move or be deleted; the exact recorded commit and hashes remain mandatory. If the object cannot be retrieved through the authorized remote, stop dependent implementation as unavailable and ask the source owner to restore that retained input. Never substitute current main, a later branch tip, or a similarly named public revision silently.

`MAC-RESEARCH` names the earlier local discussion only; its decisions and refreshed source facts are retained in this package's [decision record](decision-record.md), not an unavailable external prerequisite. `CLW-LOCAL` records an optional byte comparison; implementation relies on the retrievable public upstream pin, not the local checkout.
