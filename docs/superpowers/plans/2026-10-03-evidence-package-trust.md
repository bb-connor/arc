# Evidence package trust implementation plan

Use superpowers:executing-plans inline with one fresh integrated review.
Spec: [authenticated packages](../specs/2026-10-03-evidence-package-trust-design.md).
Base: 0a455ac2c0fb9641b96d36bb2289bcd8047c325b.

## Global constraints

Reuse the isolated security worktree. Preserve output/ and unrelated worktrees.
No new dependencies, allowances or em dashes. Private seed custody uses the
existing bounded loader. Serialize Cargo, retain command hashes and terminal
outcomes. Source commits and push are authorized; merge/release are separate.

## Task 1: Strict signatures and honest anchor derivation

Files: core-types receipt body/lineage, kernel checkpoint/evidence_export, tests.
Interfaces: existing verify_signature/verify_checkpoint_signature become strict;
build_evidence_transparency_claims requires explicit verifier anchor input.

- [x] RED: weak tool/child/checkpoint signatures and implicit anchor promotion.
- [x] Implement strict verification and prevent self-declared anchor promotion.
- [x] GREEN: focused receipt, checkpoint and transparency owner tests.

## Task 2: Signed package envelope and unified verification

Files: control-plane evidence_export/{envelope,verification,package_io}.rs and
existing export types/writer; dedicated package trust tests.
Interfaces: SignedExportEnvelope, EvidenceVerificationPolicy; manifest and decoded
payload hashes; load_verified_evidence_package(input, policy), structured import
validation(package, policy); writer consumes the existing kernel keypair.

- [x] RED: missing envelope, substituted signer, rewritten manifest/omitted record,
  divergent decoded payload, receipt/checkpoint key mismatch and wrong anchor.
- [x] Implement schema/domain binding, complete required-file inventory, bounded
  readers, trusted signer set, proof key binding and full anchor descriptor match.
- [x] GREEN: positive multi-record package and all adversarial controls; authentic
  advisory/uncheckpointed records keep their narrower evidence claims.

## Task 3: CLI, remote import and product consumer integration

Files: CLI receipt types/dispatch, control-plane receipt handlers, Wall exporter,
Mercury builders/proof-export CLI and their tests.
Interfaces: export --kernel-seed-file; verify/import --trusted-kernel-pubkey
(repeatable), optional --trusted-anchor-file; remote admin import carries separate
verification policy. Generated producers retain their existing in-memory signer.

- [x] RED: required native CLI flags and end-to-end signer/manifest/anchor attacks.
- [x] Wire all consumers without reading a trusted key from the input package.
- [x] GREEN: native export/verify/import and remote administrative route; compile
  all product consumers and run their affected owner tests.

## Task 4: Qualification, review and publication

- [x] Affected owner runtime suites, strict workspace/all-target Clippy, formatting,
  changed reader/clock/file-hygiene gates. Preserve failed/interrupted evidence.
- [x] One independent integrated review, severity regrade, one regression-first
  Important/Critical fix pass and affected-owner rerun.
- [x] Update operator/roadmap records, archive rulings/evidence, commit/push and
  verify origin SHA. Propose the next certificate or retention/denial batch.
