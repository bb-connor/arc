# Deferred Release Packaging Seed

Status: deferred.

This branch is not a tag vehicle. It carries no versioned notes, fixture
pins, hash table, readiness claim, release ledger status, or local-go gate.
It is a restart note for a future packaging pass after the upstream
implementation and evidence branches have landed on `main`.

The previous draft tried to package a named version from branch-local
artifacts. That shape is deliberately removed here because it could be read
as an active release vehicle even when the fixture set, verifier surface,
feature flags, and runnable commands were not complete on this branch.

Future packaging work must start from a fresh branch after the required
implementation PRs have merged. At minimum, that future branch must:

- regenerate receipt, envelope, and checkpoint artifacts from one deterministic
  run after the demo runner exists on `main`;
- prove the recorded hashes match the committed files;
- prove the receipt signature validates against the committed receipt body;
- prove envelope and checkpoint subjects bind the same receipt that is pinned;
- document only commands and feature flags that exist in the committed tree;
- avoid full section 7 verifier language unless the implementation and tests
  actually cover that surface;
- keep any readiness or release metadata out of the tree until the evidence is
  regenerated from the final merge base.
