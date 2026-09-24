# nono 0.53.0 confinement dependency review

September 20, 2026. Confidence is high for source identity, the reproduced
permission merge and the bounded repair. This is direct source review and
local testing, not independent certification of all upstream product APIs.

## Exact source and Chio entrypoints

The registry archive SHA-256 is
`ae7eb523cc2036e9ad6527411c3da5dc2172dc454cc3447a03b910420a39bfee`.
Its VCS record names upstream commit
`c4b25b827330640cb95f85809d88d977191b42e7`, directory `crates/nono`.
All 41 original regular files were inventoried before modification.

Reviewed both manifests, the build script, generated-manifest integration and
conversion, the complete capability implementation, public exports, Linux ABI
detection and all calls made by Chio's separately owned descriptor wrapper.
A repository source search found upstream nono calls only in that wrapper.
It uses `CapabilitySet::new().block_network()`, `network_mode()`, `AccessMode`,
`NetworkMode` and `detect_abi()`. Default features are disabled, so the system
keyring feature is not selected.

The selected constructor only initializes owned vectors and enum values. The
upstream default permits network access; Chio sets `Blocked` before returning
the wrapper. No upstream pathname grant, deduplication, manifest conversion,
secret loader, supervisor, trust verifier or rollback operation is invoked by
this entrypoint. There is no custom drop implementation on the capability
container. The selected ABI probe creates and closes hard-requirement Landlock
rulesets from ABI 6 down to 1 and caches success. It does not apply restrictions
or infer enforcement from the probe. Chio separately requires ABI 4 or newer
and applies its own descriptor-based filesystem and TCP rulesets.

The build script reads its packaged schema and writes generated Rust under
Cargo's `OUT_DIR`; it performs no network access or subprocess execution.
The generated manifest is not a complete JSON Schema validator. Port conversion
uses checked `u16::try_from`; the separate Typify review records other limits.
The reviewed source scan found no load-time constructor or custom linker
section. The only source inclusion is the build-generated manifest module.

## Permission provenance mismatch

The public deduplication contract gives User/Profile grants precedence over
System/Group grants regardless of access mode. A new test demonstrates that
an explicit user read grant plus a system write grant becomes user read/write.
The original implementation retains the user entry but merges complementary
permissions across provenance tiers. This violates the documented restriction.

There is conflicting upstream test intent: an existing unit test explicitly
expects user Write plus group Read to become ReadWrite. The unmodified
upstream suite therefore passes while the new restriction test fails. The
repair intentionally adopts the documented, stricter provenance rule. The
fork changes that one upstream assertion to require exact user Write and
retains both the original passing run and the first repaired run that failed
the old assertion. This is a documented semantic correction, not an unchanged
upstream-suite pass.

No current Chio runtime path to this deduplicator was found. Chio's descriptor
wrapper keeps an empty upstream filesystem grant list and applies grants
directly through Landlock. The finding concerns the dependency's grant model;
it does not demonstrate failure of Chio's current confinement boundary.

## Selected repair and validation

`third_party/nono-upstream-chio` retains the registry package and changes one
production expression: complementary permissions merge only when both entries
have the same provenance tier. It preserves all public types and methods.
The source patch inventory, exact source digest and required path selection
are enforced alongside the existing wrapper provenance. Mutating the source
or selecting the registry package again makes the structural gate reject.

The added regression target covers every access-mode pair for User/Profile
against System/Group, both input orders, file and directory grants, same-tier
union, three-entry deferred merges and the empty blocked constructor used by
Chio. The root, fuzz and generated-Docker workspace lockfiles select the fork;
all unrelated locked packages and dependency edges remain unchanged.

On macOS arm64 with Rust 1.94.1 and default features disabled:

- Original source: 625 unit tests, 56 integration tests and seven documentation
  checks pass; strict all-target Clippy passes.
- Original new probe: the permission-precedence assertion fails; same-tier
  merging and blocked empty construction pass.
- Repaired source: 625 unit tests, 56 original integration tests, five added
  regression tests and seven documentation checks pass; strict all-target
  Clippy passes.

Thirty-eight of the 41 original files remain byte-identical. The changed files
are the manifest, standalone qualification lockfile and `src/capability.rs`
(one production expression and the conflicting test described above). Added
files contain the regression tests, Apache license and patch inventory.
Linux qualification of the selected fork and a fresh complete candidate cage
run remain required. The earlier cage result cannot be relabeled as covering
this new source.

The original registry release receives no `safe-to-deploy` audit. Cargo-vet
classifies the selected unpublished source as locally maintained code, as for
the other repaired dependency forks. That classification does not establish
a complete review of nono's unused secret, supervisor, trust or rollback APIs.
New use of those APIs requires further review.

Evidence is retained in the primary checkout under
`output/process-security-20260915/nono-audit-77c869129/`: exact archive and
inventory, original and repaired logs, terminal JSON records, original probe,
source comparison and the complete selected source diff.

## Execution image consequence

This source selection changes Cargo.lock SHA-256 to
`28ebb77f5c65fb7c434f25061415a5abdcc11697870783a475b1a203db77c24a`.
The Dockerfile and structural checker pin this exact value. The previously
validated local image for source `013af8f1f` remains retained evidence for its
own inputs; it does not qualify this new source. Rebuild and runtime/cache
validation are required before any image publication or capture authorization.
