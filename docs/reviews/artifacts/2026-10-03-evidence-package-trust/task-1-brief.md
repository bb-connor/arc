## Task 1: Strict signatures and honest anchor derivation

Files: core-types receipt body/lineage, kernel checkpoint/evidence_export, tests.
Interfaces: existing verify_signature/verify_checkpoint_signature become strict;
build_evidence_transparency_claims requires explicit verifier anchor input.

- [ ] RED: weak tool/child/checkpoint signatures and implicit anchor promotion.
- [ ] Implement strict verification and prevent self-declared anchor promotion.
- [ ] GREEN: focused receipt, checkpoint and transparency owner tests.
