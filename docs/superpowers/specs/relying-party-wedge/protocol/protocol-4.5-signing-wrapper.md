<!--
Target: spec/PROTOCOL.md
Insertion point: new subsection after "### 4.4 Identity", before "## 5. Capability Contract".
Move the text below this comment into place unchanged; drop this comment.
-->

### 4.5 Signing Wrapper

Status: specified, not implemented. Implementations emit and accept the formats in the sections this one names until this line is removed.

Sections in force until then: 4.1 (signatures over the canonical body), "WYSIWYS Signing Invariant" and "Receipt Identity And DAG" in section 6.

Every Chio signature over a canonical-JSON body signs an 88-byte signing
wrapper instead of the body. This covers capabilities, delegation links, Chio
DPoP proofs, receipts, settlement closures, root policies, identity-provider
key snapshots, checkpoints, export commitments and every other artifact in the
Signed-Artifact Registry (section 5).

```text
wrapper = "chio.signing-wrapper.v1" || 0x00          (24 bytes)
       || SHA-256(utf8(schema_id))                     (32 bytes)
       || SHA-256(canonical_body)                      (32 bytes)
```

Rules:

- `schema_id` is the artifact's registered schema id. A verifier takes
  `schema_id` from its verification context, meaning the artifact type it
  expects at that call site. It never reads `schema_id` from a member of the
  artifact being verified. A signature over one artifact type therefore never
  verifies as another.
- `canonical_body` is the RFC 8785 canonical JSON that section 4.1 defines as
  the signing input. For receipts it is the canonical
  `ChioReceiptSigningBody { id, body, bbs_signature? }`, so BBS signature
  material stays covered by the authoritative signature through this hash.
- Domain separation: no Chio key signs any message other than wrapper bytes,
  except the local authorization server key, which signs JWS signing inputs.
  A JWS signing input is base64url text plus `.` and never contains `0x00`.
  Byte 23 of every wrapper is `0x00`, so the two message spaces are disjoint.
  The local authorization server key is still required to differ from every
  wrapper-signing key (section 5.6).
- Algorithm binding: every pinned key admits exactly one signature algorithm,
  derived from its self-describing encoding (section 4.4). A signature whose
  prefix does not match the pinned key's algorithm rejects before any
  cryptographic check. A verifier holding a pinned hybrid key rejects a bare
  classical signature.
- Ed25519 signs the 88 wrapper bytes.
- ML-DSA-65 signs the 88 wrapper bytes with an empty FIPS 204 context string.
- P-256 signs with ECDSA over SHA-256 of the wrapper. P-384 signs with ECDSA
  over SHA-384 of the wrapper. A remote signer may therefore be sent the
  digest instead of the message.
- Hybrid signatures sign the same 88 bytes with both halves.
- Both inner hashes are SHA-256, which caps the collision resistance of every
  signature at 128 bits, including P-384 and ML-DSA-65. Changing either hash
  or the layout requires a new prefix string and a change to this section.
- Signature encodings are unchanged: bare 128-hex Ed25519, `p256:<DER hex>`,
  `p384:<DER hex>` and the hybrid form of section 4.4.
- JWS objects (local authorization server access tokens and other JWTs) are
  not Chio canonical-JSON signatures and do not use the wrapper.
- Implementations expose one signing helper and one verification helper for
  the wrapper. No path signs a canonical body directly.

Every signing preimage is 88 bytes, so no remote signer's message-size limit
constrains any artifact.

Wrapper schema ids:

| Signed artifact | Wrapper `schema_id` |
|---|---|
| Capability token | `chio.capability.v1` |
| Delegation link | `chio.delegation-link.v1` |
| Chio DPoP proof | `chio.dpop_proof.v1` |
| Receipt | `chio.receipt.v1` |
| Root policy | `chio.root-policy.v1` |
| Identity-provider key snapshot | `chio.idp-key-snapshot.v1` |
| Settlement closure | `chio.settlement-closure.v1` |
| Caller revocation request | `chio.revocation-request.v1` |
| Evidence export commitment | `chio.evidence_export_commitment.v1` |
| Every other registered signed artifact | its id in `spec/schemas/registry.json` |

A signed artifact type with no registered schema id cannot be signed or
verified. Every id in this table is listed in `spec/schemas/registry.json` and
`KNOWN_SIGNED_ARTIFACT_SCHEMAS` before an implementation emits it.
