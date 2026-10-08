# Reviewed JavaScript source dispositions

The October 7, 2026 review repairs two advisories for exact private SDK
workspace implementations: braces 3.0.3 (GHSA-vfj7-8cjw-p6xm) and node-forge
1.4.0 (GHSA-86w9-cpqp-85rv). Their upstream npm releases remain affected.
No version is invented and no OSV ignore is added. Confidence is high for
the source reconstruction and exercised advisory-specific behavior.

The original npm archives, recorded upstream commits, complete source
deltas, licenses and runtime payload hashes are documented in
`sdks/typescript/vendor/braces/CHIO-PATCH.md` and
`sdks/typescript/vendor/node-forge/CHIO-PATCH.md`. Both manifests are private
and retain their original names, versions and public entry points. The
workspace links cover every actual transitive consumer in the SDK lock.
Publishable SDK names, exports and wire schemas are unchanged.

Braces bounds parsed block nesting at 100 and also bounds recursive
compile/expand/stringify processing of caller-supplied ASTs. The original
escaping behavior is preserved. Forge validates the complete DigestInfo
algorithm child count and optional NULL contents before accepting a
PKCS#1 v1.5 signature. Both minified browser bundles were rebuilt; an
independent offline rebuild matches every shipped minified output exactly.

The source proof gate checks fixed reviewed manifest fingerprints, every
runtime payload hash, absence of unreviewed payloads/symlinks, and actual
bare/transitive npm resolution. Its 22 regressions pass with no skips.
An independently archive-bound run passes seven positive controls and
fails all 15 owning negatives against the original releases. The restored
upstream braces suite passes 764 tests; Forge passes 828 with four
pre-existing pending tests. The complete publishable SDK suite passes
493 tests across nine package suites under Node 22.22.3.

OSV 2.3.6 still reports the original version strings for the private
workspaces. CVE Monitor preserves that raw JSON and raw exit status. It
then evaluates an explicit reviewed-source disposition, whose gate requires
all 22 regressions and source checks to pass. It accepts only these two
exact GHSA IDs, package names/versions, SDK-root lock path, private workspace
links, patch/payload fingerprints and reviewed advisory revision timestamps.
The machine-readable artifact states that the upstream releases remain
affected. A new ID, changed advisory revision, another lock path, another
version, duplicate occurrence, scanner error or incomplete report remains
blocking. The separate boundary tests exercise these refusal behaviors.

Current review and raw evidence are retained in
`target/recovery-pr/dependency-security/` and the independent
`target/recovery-pr/current-review-followup/` peer reports. This reviewed
source closure does not certify unrelated future advisories or infer hosted,
Linux, Windows or production execution from local Node tests.
