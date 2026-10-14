# Historical evidence and maintainable implementation

Status: packaging boundary and proposed changes recorded. No historical files
have been moved, rewritten or deleted.

The implementation evidence directory contributes 481,308 added lines across
5,948 paths. The historical product evidence subtree alone contributes 271,117
added lines across 5,085 paths, apart from its large verification manifests.

Historical evidence is not active runtime authority. Historical executable
copies may be necessary to reproduce their exact records without becoming
maintained production implementations. Packaging changes must preserve those
bytes and their hashes, distinguish historical from current commands, and make
the maintained source independently reviewable.

## Maintained and historical tool boundary

The historical P6 `evidence/verify-package.py` calls `package_record.build_record`.
Its `inventory.py:9` imports the **current**
`fixtures/recovery-product/manifest_builder.py`. It therefore is not a portable
independent verifier of an arbitrary future checkout. Keep the script with its
original snapshot and provenance; remove it from current operating instructions.
Do not patch its sealed assertions to make renamed/current source pass.

The maintained `scripts/verify-recovery-qualification.py` explicitly replaces
that role and imports only standard-library modules. Its historical-package
mode should be the current archive-integrity interface. Current runtime
qualification still needs current source, commands and actual executed results.

The active source selectors in `manifest_builder.py:39-52` and the maintained
auditor `:65-78` already treat historical evidence trees as metadata-only
artifact paths. `selected_source:119` excludes the implementation planning
directory from ordinary runtime source selection. That provides a real boundary
for separating distribution, but moving paths changes inventories and requires
a new package record. It must not mutate historical manifests.

Concrete packaging proposal:

1. Keep one maintained architecture/spec, one review register and one current
   qualification entry point in the normal contributor path.
2. Package phase evidence as immutable content-addressed archives with a small
   index containing subject commit/source binding, archive hash, original path
   map, verdict, redaction provenance and the exact original verifier snapshot.
   Preserve failed attempts and previously sealed manifests inside the archive.
3. Remove expanded historical evidence copies from the default source checkout
   only after the archive exists in a durable agreed location and a clean
   checkout can retrieve and verify it. Do not rewrite Git history or destroy
   originals. No such move/upload/deletion was performed by this review.
4. Keep maintained fixtures that drive the real native public interfaces.
   Archived Python auditors and captured source copies do not belong on an
   ordinary runtime import path. Search active consumers before each move.

The current auditor is itself 5,331 lines at the pin. This is maintainability
work, not justification to weaken evidence. Split its owned verifier into
focused modules for source inventory, command records, compiled provenance,
measurement/trial recomputation and package integrity. Preserve a pinned
independent verifier bundle; do not import producer implementations to validate
their own output. Runner and producer policy data can be shared deliberately,
but producer/verifier independence must remain reviewable.

The qualification README still names source inventory v3 while the pinned
auditor and producer name v4. Update the maintained README with the actual
contract when revising packaging; leave historical v3 records unchanged.

## Generated source is not a second hand-maintained runtime

The new Rust generated binding diff contributes 71,606 added lines and 6,153
removed lines. `chio-core-types/src/_generated/mod.rs` keeps the generated
module quarantined; this arrangement existed before this PR. The generated
file is nevertheless compiled explicitly by
`tests/protocol_primitives_generated.rs:16` and
`tests/security_generated_vectors.rs:11`. Deleting it without changing those
consumers is not dead-code removal. `_generated_check.rs` separately enforces
the quarantine policy; its success does not prove generated semantic coverage.

Concrete consolidation proposal: decide whether the quarantined monolithic
Rust output belongs in committed source or should be deterministically
generated as a test/build artifact. If generated on demand, change its two
test consumers, generator invocation, CI cache inputs and any published-package
requirements together. Preserve schema-to-code drift detection and vector
acceptance. This is a packaging proposal, not an immediately safe deletion.
Generated Go/other SDK types that are actual package interfaces have different
consumers and cannot be removed by analogy.

`chio-spec-codegen/src/schema_catalog.rs` is a finite, in-memory schema resolver.
Its aliases resolve known schema IDs and relative catalog references; it does
not fetch arbitrary URLs. Schema identifiers that look like URLs are identifiers,
not evidence of a runtime dependency on that website. Domain cleanup must
preserve deliberate identifier compatibility or explicitly version it, and must
not rewrite old signed evidence to make historical bytes look current.

## Vendored patches are a separate dependency decision

The path-patched `third_party/rusqlite-chio` and `cpp-demangle-chio` trees add
78,636 lines in the committed diff. Their full upstream bodies have not been
reviewed in this pass. Their patch records identify concrete Rust safety fixes:
SQLite function-name conversion before transferring boxed ownership and valid
handling of a null argument pointer with zero length; an explicitly transparent
private wrapper for the demangler's representation cast.

Those are dependency patches, not extra recovery libraries. Do not replace
them with an unpatched release to reduce the line count. Prefer an upstream
release containing the fixes once its exact version, patch equivalence, lockfile
and affected tests are checked. Upstream availability was not researched in this
review. A separate patch-only vendoring policy can reduce review noise without
pretending dependency code ceased to exist.

## What must stay in the maintained checkout

- The normative architecture and current support policy, with one current
  remediation register rather than a new competing findings ledger.
- Current production code and public-interface fixtures that exercise it.
- Current schema/generator inputs, package interfaces and drift checks.
- The maintained qualification runner and an independently reviewable verifier.
- A small immutable-history index with clear reproduction/retrieval instructions.

Historical verdicts remain historical. A successful archive integrity check
does not qualify new source, and the current runtime must not import executable
copies from an evidence archive. Before executing any relocation, search all
active references to its paths and verify clean-checkout reconstruction. This
review did not exhaustively audit every archived script or distribution target.

