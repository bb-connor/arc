# Independent Python execution-evidence re-review

Bounded read-only re-review of the four findings in `python-review.md`, in `/home/connor/backbay/arc-funded-integration`. No repository edits or Cargo commands.

Reviewed hashes:

- `examples/federated-work/execution_evidence.py`: `fe08ed65ab7b64baec35f7b9ef7ecb52f0b58535209ca18f0afe4d390b1a1e9a`
- `examples/federated-work/test_execution_evidence.py`: `de4d5a99a8b9d170ae8e65110cc526488f7465e0a4c20854c2c58d6fafde7b88`

No remaining issue found in the four reviewed fixes:

- P1 revocation: line 110 now rejects every non-null `revoked_from`, including after the claimed action. Production, checkpoint, and governance signed attack probes all reject with the expected revocation reason.
- P2 role collisions: lines 168-175 implement the Rust profile authority-role separation matrix. All five originally reported signed collision probes reject for the intended role conflict. Provider/native-kernel alias remains accepted by the suite.
- P2 allocation identity: lines 272-273 require a separate caller-controlled strict nonzero `allocationId` pin, and lines 292-294 compare it with the submission. Root explicitly selected this pin contract rather than independent Keccak derivation. The provider-only allocation substitution rejects. The docstring explicitly states that the allocation is pinned rather than derived or chain-verified; the result uses `allocationPinVerified`. This closes the finding for the declared externally pinned profile. Supplying the pin from an untrusted witness would violate the caller contract; production integration must retain the original trusted value.
- P3 blank Finding text: `nonblank=True` is applied to the Finding authority/profile/BBS fields, preserving the separate execution-core identifier contract. The signed blank-operator attack now rejects.

Also inspected the new prohibition on receipt `evidence` and its signed regression test. Python now requires the field to be absent, matching the intended tightened execution profile. This re-review does not qualify the concurrently changing Rust implementation.

Validation:

- Ran `/tmp/chio-python31-locked-venv/bin/python -m unittest -v test_execution_evidence test_funded_wire`: 30 tests passed in 4.952 seconds (24 execution, 6 wire).
- Independently reran the original ten signed mutations: three after-action revocations, five role collisions, one provider-only allocation substitution, and one blank operator. All rejected for their intended condition.
- Independently checked the positive control: authority, allocation pin, and output match true; financial, metered-exposure, and settled-spend backing false.
- Independently changed and re-signed the submitted output/Finding: `executionMatchesSubmission` remained false.

Actual Rust-produced canonical witness verification remains a later integration check. This is closure of the bounded Python review findings, not an end-to-end delivery claim.
