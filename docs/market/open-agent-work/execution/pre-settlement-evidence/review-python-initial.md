# Independent Python execution-evidence review

Reviewed read-only in `/home/connor/backbay/arc-funded-integration` at HEAD `ad3dedbf37dfe732771d4458721156fc543fd524` with the current uncommitted files. Base supplied by the task: `df2e7ef0ed`. No repository edits, Cargo commands, commits, historical evidence mutations, or external messages were performed.

Reviewed file hashes:

- `examples/federated-work/execution_evidence.py`: `c4c97167e82613294dc9d51103881698214e8fc87e9129b4bcacfeb5130b9095`
- `examples/federated-work/test_execution_evidence.py`: `38f13e09d15b77247bc282a2e1a79959f997cdfe9490690bec5c0eee5a3561b2`

## Findings

### P1: Reject every observed signer revocation, including revocation after the claimed action

Location: `examples/federated-work/execution_evidence.py:107-109`.

`standing()` accepts an authenticated non-null `revoked_from` when it is later than the receipt/checkpoint/profile timestamp. Those timestamps are controlled by the signer; an already revoked signer can backdate newly created evidence and obtain `authorityVerified: true`. The local checkpoint/publication does not establish an independently anchored publication before revocation. Rust deliberately rejects **any** observed revocation in `crates/trust/chio-finding-verifier/src/verify.rs:441-446` and `crates/trust/chio-finding-verifier/src/checkpoints.rs:362-366` for this reason.

Reproduced separately for production, checkpoint, and governance statuses: set `observed_at=NOW`, `revoked_from=NOW-1`, re-sign with the fixture status authority, and retain the original earlier action timestamp. All three return `authorityVerified: true`. Governance mutation additionally requires re-signing the context-bound agreement, as expected. Production and checkpoint attacks do not change the pre-agreed context. The current test at `test_execution_evidence.py:310-319` only checks a revocation before the receipt.

Required fix: require `revoked_from is None` for all three supported roles and test validly signed after-action revocations for each.

### P2: Mirror the full Rust authority-role separation matrix

Location: `examples/federated-work/execution_evidence.py:172-176` (also role construction at lines 148-160).

The local collision list omits purchase, failed-delivery, delivery, and replay keys. Consequently Python authenticates profiles which Rust `validate_supported_finding_verifier_profile()` rejects before evidence verification. Rust requires governance/verifier-report/purchase/failed-delivery keys to be pairwise distinct, all receipt/checkpoint keys to differ from those keys, and receipt/checkpoint keys not to alias over overlapping lifecycles (`crates/trust/chio-finding-verifier/src/verify.rs:295-329`). All Python role policies must cover `now`, so their lifecycles necessarily overlap.

Reproduced with real re-signed profiles/contexts/agreements for each separate mutation: `purchase_authority=governance`, `failed_delivery_authority=verifier`, `delivery=governance`, `replay=checkpoint`, and `purchase_authority=kernel`. Each returns `authorityVerified: true`. This defeats Rust/Python agreement about which authority profiles are admissible, even though financial flags remain false.

Required fix: implement the full supported-profile role matrix while retaining the explicitly permitted provider/native-kernel alias; add mutation tests for every role family.

### P2: Bind the submission allocation ID to the original agreement

Location: `examples/federated-work/execution_evidence.py:290-293`.

The submission binding check omits `allocationId`. This field does not appear in the kernel execution metadata either. A provider can replace just `submission.body.binding.allocationId`, recompute/re-sign the Finding and submission using only the provider key, and keep the exact original agreement, context, receipt, checkpoint, and signed status evidence. Python still returns `authorityVerified: true` and `executionMatchesSubmission: true`. Reproduced with `allocationId='0x' + '12'*32` followed by `Fixture.resign_submission()`.

The original allocation is deterministically derivable from the public agreement. `examples/federated-work/src/funded_work/agreement.rs:63-76` builds Terms with the complete agreement-body digest; `allocation.rs:128-140` computes Keccak-256 of the Solidity ABI encoding of `(chain_id, escrow_address, terms)`. The Rust submission verifier requires `body.binding == original.binding` (`evidence.rs:142-149`), and native reporting verifies the derived allocation. Accepting arbitrary provider-chosen allocation IDs weakens the intended original-source binding in the independent verifier.

Required fix: independently recompute the allocation from the signed agreement's domain and work terms and require exact equality. Include a provider-only signed substitution test without re-signing the buyer agreement or kernel receipt. Financial flags must remain false after this additional identity check.

### P3: Reject whitespace-only Finding-profile text as Rust does

Location: `examples/federated-work/execution_evidence.py:32-34`, used for profile strings at lines 128-129 and authority policies at lines 86-87.

`text()` accepts whitespace-only strings. Rust Finding's `require_bounded_id()` delegates to `require_non_empty()` which rejects `value.trim().is_empty()` (`crates/economy/chio-finding/src/validate.rs:95-116`). A governance-signed profile with `operator=' '` and correctly recomputed profile/context/agreement hashes returns `authorityVerified: true` in Python, but Rust `FindingChallengeVerifierProfile::validate()` rejects it. The same mismatch affects authority IDs and policy references checked through `text()`.

Required fix: use Finding-compatible nonblank validation for Finding-profile fields. Keep execution metadata identifier validation aligned with its separate core contract, which currently rejects empty/NUL/overlong values but does not impose Finding's trim rule.

## Validation and limits

Ran `/tmp/chio-python31-locked-venv/bin/python -m unittest -v test_execution_evidence` from `examples/federated-work`: 18 tests passed in 4.041 seconds. The default `python3` lacked `cryptography`; the pinned environment supplied by root was used for all successful tests and mutation probes.

Reviewed canonical/duplicate-key parsing, bounded reads/nesting/integers, Ed25519 point/scalar checks, receipt signing/id construction, exact single-checkpoint Merkle wrappers and local transparency prefix, signed original context/authority pins, private-preimage limitation, output preimage/Finding commitment, and explicit false financial facets. Existing authenticated wrong-output test passes and reports `executionMatchesSubmission: false`. No additional concrete signature/id or proof-wrapper issue was found in this pass.

The Rust funded context/evidence integration was still under implementation during review. This report does not require the not-yet-generated Rust witness or claim end-to-end qualification. Re-run independent verification against actual Rust-produced canonical evidence after integration.
