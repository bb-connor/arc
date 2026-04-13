# ARC Protocol Alignment Matrix

This matrix maps the shipped ARC protocol surfaces to adjacent standards and
ecosystem work. It is an alignment matrix, not a claim that the referenced
standards already define the whole ARC stack.

| ARC concept | Adjacent standard | Current ARC mapping | Boundary / gap |
| --- | --- | --- | --- |
| delegated capability issuance and continuation | GNAP | ARC's capability issuance and continuation model is closest to GNAP-style delegated authorization semantics | ARC uses its own signed capability and receipt artifacts today rather than claiming GNAP wire compatibility |
| signed receipts and evidence export | SCITT | ARC receipts, checkpoints, and export bundles align with the same "signed transparent evidence" problem space | ARC is not yet a SCITT profile and does not claim SCITT interoperability by default |
| runtime attestation and verifier-backed security posture | RATS | ARC's runtime assurance and attestation appraisal work aligns with RATS roles and evidence/appraisal concepts | ARC currently preserves its own receipt and policy binding semantics rather than exposing a full RATS protocol profile |
| sender-constrained protected-resource admission | RFC 9449 (DPoP) | ARC's hosted sender-constrained path aligns with DPoP's proof-of-possession goal | ARC also carries an ARC-native DPoP format and does not claim the native framed lane is RFC 9449 wire-compatible |
| canonical JSON signing and hashing | RFC 8785 | ARC signs capabilities, receipts, and proofs over canonical JSON | This is a direct alignment point and one of ARC's normative dependencies |
| portable trust and credential projection | W3C VC Data Model | ARC passport and portable trust artifacts overlap with VC-style issuer/holder/verifier concerns | ARC remains `did:arc`-first and does not claim generic VC neutrality |
| credential issuance transport | OID4VCI | ARC ships a bounded OID4VCI-compatible issuance lane for passport-style artifacts | The shipped profile is intentionally narrow and not a full multi-format OID4VCI implementation |
| verifier presentation transport | OID4VP | ARC ships a bounded OID4VP-style verifier lane for passport presentation | ARC does not claim broad wallet-network interoperability beyond the documented bounded profile |

## Reading The Matrix

- "aligns with" means ARC solves a related problem using a shape that can be
  compared to the named standard.
- "boundary / gap" records where ARC intentionally remains narrower, different,
  or still incomplete.
- The executable evidence source for the core protocol claims is the native
  conformance lane under `tests/conformance/native/`.
