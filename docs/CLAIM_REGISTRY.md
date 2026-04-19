# Claim Registry

This registry records which formal and proof-adjacent claims ARC may make
today, which evidence boundary supports them, and which stronger phrases are
currently disallowed.

The source-of-truth inputs are:

- `formal/proof-manifest.toml`
- `formal/theorem-inventory.json`
- `spec/PROTOCOL.md`
- `docs/release/RELEASE_AUDIT.md`

## Evidence Classes

| Class | Meaning |
| --- | --- |
| `lean_root_imported` | theorem appears in the root-imported Lean tree and the shipped proof lane checks `lake build` plus `sorry` hygiene |
| `symbolic_crypto` | Lean theorem assumes the current symbolic signature or Merkle model, not the concrete Rust crypto implementation |
| `audited_axiom` | an explicit Lean `axiom` is allowed only because it is listed in `formal/theorem-inventory.json` and `formal/proof-manifest.toml` |
| `differential_test` | executable spec or diff test is the release gate |
| `runtime_qualification` | property is backed by Rust tests, conformance, or release-qualification lanes rather than Lean |

## Approved Assumptions

| Assumption ID | Status | Allowed wording | Evidence |
| --- | --- | --- | --- |
| `ASSUME-SIG-CHECK` | approved_with_scope | The bounded Lean revocation or evaluation model assumes a trusted capability-signature check oracle. | `audited_axiom` |

That assumption is machine-readably enumerated as
`Arc.Core.verifyCapabilitySignature` in `formal/theorem-inventory.json` and
must remain allowlisted in `formal/proof-manifest.toml`.

## Approved Claims

| Claim ID | Status | Allowed wording | Evidence |
| --- | --- | --- | --- |
| `FORM-BOUNDARY` | approved | ARC has a bounded verified core defined in `formal/proof-manifest.toml`. | `lean_root_imported`, `differential_test`, `runtime_qualification` |
| `P1` | approved_with_scope | ARC has bounded Lean mechanization and executable tests for capability attenuation over the current verified-core model. | `lean_root_imported`, `differential_test` |
| `P4` | approved_with_scope | ARC has symbolic Lean proofs for receipt and checkpoint properties plus runtime receipt-signing checks in Rust. | `symbolic_crypto`, `runtime_qualification` |
| `P5` | approved_with_scope | ARC has bounded structural delegation-chain theorems for the presented-chain model. | `lean_root_imported` |

## Downgraded Or Disallowed Claims

| Claim ID | Status | Disallowed wording | Required downgrade |
| --- | --- | --- | --- |
| `FORM-OVERALL` | disallowed | "ARC is a formally verified protocol" | say ARC has a bounded verified core and additional runtime qualification outside that core |
| `LEAN-4-VERIFIED` | disallowed | "Lean 4 verified" without boundary text | name the proof manifest and theorem inventory explicitly |
| `P2` | downgraded | "P2 is proven in Lean 4" | say presented revocation coverage is a runtime fail-closed property, not a current Lean theorem over the Rust runtime |
| `P3` | downgraded | "P3 is proven total in Lean 4" | say fail-closed evaluation is verified by runtime tests and executable lanes |
| `P4-END-TO-END` | disallowed | "Ed25519 receipts and Merkle log semantics are formally verified end to end" | say receipt proofs are symbolic/model-level and runtime signing is separately tested |
| `P5-ACYCLICITY` | downgraded | "delegation graph acyclicity is proven" | say presented delegation-chain structure is proven in the bounded model |

## Current Source Notes

- `README.md` is currently within the bounded release posture and should stay
  linked to this registry rather than reintroducing broad proof branding.
- `docs/release/RELEASE_AUDIT.md` should reference the proof manifest and this
  registry when discussing formal evidence.
- `formal/theorem-inventory.json` is now assumption-audited as well as
  theorem-audited; any new Lean `axiom` must be added there and allowlisted in
  the proof manifest before the formal lane should pass.
- `docs/VISION.md` still contains stronger historical phrasing around P1-P5
  and Lean 4. It should be aligned to this registry in a later claim-sync pass.
- `docs/COMPETITIVE_LANDSCAPE.md` already uses the bounded P1-P5 language and
  should remain on that executable-evidence framing.
