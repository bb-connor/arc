# Chio Bilateral Co-Signed Invocation: An in-toto Predicate Proposal

**Status:** v1 (Chio-owned pre-release spec carrying an in-toto WG proposal) | **Date:** 2026-05-04
**Intended audience:** in-toto Attestation WG; OpenSSF AI/ML Security
WG; CoSAI Workstream 4. **Editors:** chio maintainers.

This document specifies the shipped Chio-owned predicate type
`chio.bilateral-cosign-invocation.v1` for **bilateral co-signed runtime
invocations** between two distinct organisational kernels, and carries
the matching in-toto WG proposal that mirrors it. The intent is either
to land chio's bilateral-co-signed invocation semantics in the
in-toto vocabulary or to confirm in writing the structural gap that
motivates the chio-namespaced predicate.

The keywords MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to
be interpreted as described in RFC 2119. Canonical JSON serialisation
follows RFC 8785 (JCS). DSSE follows the Secure Systems Lab spec
(`secure-systems-lab/dsse`, envelope and PAE).

---

## 1. Status

- **Version:** v1 (Chio-owned pre-release spec carrying an in-toto WG
  proposal); **Date:** 2026-05-04.
- **Intended audience:** in-toto Attestation WG (primary), OpenSSF AI/ML
  Security WG (secondary), CoSAI Workstream 4 (secondary).
- **Disposition:** Chio ships the Chio-owned predicate type
  `chio.bilateral-cosign-invocation.v1` (section 3) today and proposes
  the matching in-toto canonical URI for adoption by the in-toto WG.
  Implementations switch to the in-toto vocabulary once (or if) it is
  accepted.
- **Engagement contacts named:** Aditya Sirish A Yelgundhalli (in-toto),
  Tom Hennen (SLSA). See section 12.
- **Changelog:** 2026-09: aligned to the shipped verifier.

---

## 2. Motivation

Current in-toto predicates are **artifact-centric**. The SLSA Provenance
predicate (`https://slsa.dev/provenance/v1`) is build-provenance-shaped:
who built which artifact under what configuration. The Runtime Trace
predicate (`https://in-toto.io/attestation/runtime-trace/v0.1`) extends
in-toto into runtime by capturing process, network, and file events
under a single monitor, but its scope is the **builder's own runtime
observability** of a build. Sigstore Rekor anchors single-party DSSE
entries against Fulcio-issued identities and gives a public
transparency log; multi-signature DSSE envelopes are mechanically
permitted (`secure-systems-lab/dsse` protocol allows `(t,n)` thresholds)
but no predicate vocabulary in-toto ships today says "this DSSE envelope
verifies if and only if these two specific organisational identities
both signed the same Statement, each having independently evaluated
their local policy on the underlying invocation."

That is the gap chio addresses. It is not a transparency-log gap and
it is not a build-provenance gap. It is the gap between two parties
**signing the same canonical body** (a statistical accident) and two
parties **independently committing to the same canonical action under
their separate policies** (a verifiable, mechanically-checkable joint
intent). The existing chio primitive is
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs).
The composition unit is the workflow receipt
([../crates/platform/chio-workflow/src/lib.rs](../crates/platform/chio-workflow/src/lib.rs)),
and capability scoping rides on agent passports
([../crates/trust/chio-credentials/src/lib.rs](../crates/trust/chio-credentials/src/lib.rs)).
The cross-vendor agent action attestation use case needs all three properties
at once: bilateral intent, per-action capability scoping, and workflow-receipt
composition.

---

## 3. Predicate Type URI

Two URIs are reserved:

- **Proposed in-toto canonical:**
  `https://in-toto.io/attestation/bilateral-cosign-invocation/v1`
- **Chio-namespaced, the only accepted type:**
  `chio.bilateral-cosign-invocation.v1`

Until the in-toto WG accepts the canonical URI, producers MUST emit the
Chio-namespaced type and verifiers MUST accept only it. A verifier MUST
NOT accept the proposed canonical URI, MUST NOT treat the two as
equivalent, and MUST NOT rewrite one into the other (the predicate type
is part of the signed Statement, so rewriting would break signature
verification). The shipped verifier compares `predicateType` against
the single constant `PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION` in
[../crates/trust/chio-federation/src/bilateral_dsse/types.rs](../crates/trust/chio-federation/src/bilateral_dsse/types.rs)
and rejects every other value with `predicate.type_unrecognised`. If the
WG accepts the canonical URI, this section will name the version at
which producers and verifiers switch together.

Implementation status: `crates/trust/chio-federation` emits and verifies
only the strict predicate type `chio.bilateral-cosign-invocation.v1` for
Chio proof packages. The older `chio.bilateral-signature-slice.v1`
profile remains available as a compatibility artifact for local receipt
binding, but strict Chio verification rejects it as conformance
evidence.

Chio offline package verification is verifier-owned. The proof package
MUST NOT define its own peer pins, accepted ladder refs, action-class
policy, workflow-intersection acceptance hash, revocation checkpoint, BBS
issuer trust, authority lifecycle, or disclosure policy. Those values are
supplied by `chio.federation.verifier-trust-bundle.v1` plus the required
`chio.federation.verification-context.v1`. A verifier MUST reject packages
whose embedded hints disagree with the trust bundle or whose BBS proof
nonce is not bound to the verifier context.

---

## 4. Subject Definition

The in-toto Statement v1 envelope binds a predicate to one or more
ResourceDescriptor subjects. For bilateral co-signed invocations, the
subject is the **content-addressable invocation event itself**, not an
on-disk artifact.

Recommendation: the subject's `digest` MUST be the SHA-256 of the
canonical-JSON (RFC 8785) serialisation of the underlying
`chio_core_types::ChioReceipt` body. The `name` SHOULD be the receipt's
internal identifier (UUID or hash-derived string). Concretely:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "chio-receipt:<receipt_id>",
      "digest": {
        "sha256": "<hex SHA-256 of canonical-JSON ChioReceipt body>"
      }
    }
  ],
  "predicateType": "chio.bilateral-cosign-invocation.v1",
  "predicate": { ... }
}
```

Rationale: anchoring to the receipt body's content hash makes the
predicate refer to a precise invocation event independent of where the
receipt is stored. A verifier resolving the receipt out of a kernel's
audit log can re-hash the body and confirm subject membership without
needing to dereference any external pointer. This mirrors the chio
internal pattern in
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs)
where both kernels sign over the canonical bytes of `CoSigningBody`.

---

## 5. Predicate Body Schema

The predicate is a JSON object with the following JSON Schema (Draft
2020-12). Implementations MUST validate the predicate against this
schema before signature verification.

This schema is the strict CHIO target, not the currently emitted
`chio.bilateral-signature-slice.v1` compatibility profile. A signature
slice MUST NOT be described as conforming to this section unless its
predicate validates against the schema below.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://in-toto.io/attestation/bilateral-cosign-invocation/v1",
  "title": "Chio Bilateral Co-Signed Invocation",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "invocation_id",
    "tool_server_a",
    "tool_server_b",
    "tool_name",
    "tool_args_hash",
    "capability_lease_ref",
    "policy_evaluation_summary",
    "consistency_model",
    "cross_org_visibility",
    "co_sign",
    "timestamp_unix_ms"
  ],
  "properties": {
    "invocation_id": {
      "type": "string",
      "description": "UUIDv4 or canonical-JSON SHA-256 of the underlying invocation event. MUST be globally unique within the federation graph.",
      "pattern": "^[A-Za-z0-9._:-]{1,128}$"
    },
    "tool_server_a": { "$ref": "#/$defs/kernelIdentity" },
    "tool_server_b": { "$ref": "#/$defs/kernelIdentity" },
    "tool_name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256,
      "description": "Logical tool identifier as known to both kernels. Inclusion here ensures the joint commit is bound to a specific named tool surface."
    },
    "tool_args_hash": {
      "type": "object",
      "additionalProperties": false,
      "required": ["alg", "value"],
      "properties": {
        "alg": { "type": "string", "enum": ["sha256"] },
        "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
      },
      "description": "SHA-256 over the canonical-JSON of the tool arguments. The arguments themselves are off-chain; only the hash binds to the predicate."
    },
    "capability_lease_ref": {
      "type": "object",
      "additionalProperties": false,
      "required": ["lease_id", "issuer", "expires_at_unix_ms"],
      "properties": {
        "lease_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
        "issuer": { "type": "string", "description": "did:chio of the kernel that minted the lease." },
        "expires_at_unix_ms": { "type": "integer", "minimum": 0 },
        "scope_digest": {
          "type": "object",
          "additionalProperties": false,
          "required": ["alg", "value"],
          "properties": {
            "alg": { "type": "string", "enum": ["sha256"] },
            "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
          }
        }
      },
      "description": "Reference to the chio capability under which the action ran. Verifier MUST resolve and confirm non-expiry at the pinned epoch."
    },
    "policy_evaluation_summary": {
      "type": "object",
      "additionalProperties": false,
      "required": ["server_a_verdict", "server_b_verdict"],
      "properties": {
        "server_a_verdict": { "$ref": "#/$defs/policyVerdict" },
        "server_b_verdict": { "$ref": "#/$defs/policyVerdict" },
        "joint_disposition": {
          "type": "string",
          "enum": ["allow", "deny"],
          "description": "Derived joint outcome. MUST equal `allow` only when both kernel verdicts are `allow`."
        }
      }
    },
    "governance_receipt_ref": {
      "type": "object",
      "additionalProperties": false,
      "required": ["receipt_id", "kernel_id", "digest"],
      "properties": {
        "receipt_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
        "kernel_id": { "type": "string" },
        "digest": {
          "type": "object",
          "additionalProperties": false,
          "required": ["alg", "value"],
          "properties": {
            "alg": { "type": "string", "enum": ["sha256"] },
            "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
          }
        }
      },
      "description": "REQUIRED iff the action class is declared `receipt-backed` in the chio governance ladder manifest (see CHIO_LADDER.md section 3.3). Otherwise OPTIONAL."
    },
    "consistency_model": {
      "type": "string",
      "enum": ["crdt-commutative", "totally-ordered", "quorum-required"],
      "description": "Mirrors CHIO_LADDER.md section 4. The chosen model MUST match the action class declaration in both kernels' ladder manifests."
    },
    "consistency_anchor": {
      "type": "string",
      "enum": ["chio-anchor", "hash-chain", "frost-quorum"],
      "description": "REQUIRED for `totally-ordered` and `quorum-required` consistency models."
    },
    "cross_org_visibility": {
      "type": "string",
      "enum": ["private", "treaty_only", "federated", "public"],
      "description": "Mirrors the ladder. Drives downstream gossip and BBS+ disclosure decisions."
    },
    "co_sign": {
      "type": "string",
      "enum": ["bilateral_required", "bilateral_if_cross_org", "n_of_m"],
      "description": "Restricted to co-sign modes that produce a multi-signature DSSE envelope. `none` MUST NOT appear in this predicate."
    },
    "timestamp_unix_ms": {
      "type": "integer",
      "minimum": 0,
      "description": "Tool-server B's wall-clock timestamp at the moment the joint body was canonicalised."
    }
  },
  "allOf": [
    {
      "if": { "properties": { "consistency_model": { "const": "totally-ordered" } } },
      "then": { "required": ["consistency_anchor"] }
    },
    {
      "if": { "properties": { "consistency_model": { "const": "quorum-required" } } },
      "then": { "required": ["consistency_anchor"] }
    }
  ],
  "$defs": {
    "kernelIdentity": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kernel_id", "passport_key_fingerprint", "alg"],
      "properties": {
        "kernel_id": {
          "type": "string",
          "description": "did:chio identifier of the participating kernel."
        },
        "passport_key_fingerprint": {
          "type": "string",
          "pattern": "^[0-9a-f]{64}$",
          "description": "SHA-256 of the kernel's passport public key, hex-encoded."
        },
        "alg": {
          "type": "string",
          "enum": ["ed25519", "hybrid:ed25519:mldsa65"]
        }
      }
    },
    "policyVerdict": {
      "type": "object",
      "additionalProperties": false,
      "required": ["verdict", "policy_id", "policy_version"],
      "properties": {
        "verdict": { "type": "string", "enum": ["allow", "deny"] },
        "policy_id": { "type": "string" },
        "policy_version": { "type": "string" },
        "rationale_code": { "type": "string", "maxLength": 64 }
      }
    }
  }
}
```

A predicate that fails this schema MUST be rejected before any
signature verification is attempted.

The shipped verifier (`validate_chio_predicate` in
[../crates/trust/chio-federation/src/bilateral_dsse/verify.rs](../crates/trust/chio-federation/src/bilateral_dsse/verify.rs))
enforces this schema with three strict additions: `schema` and
`receipt_canonical_json` MUST be absent (both belong to the compatibility
profile); an OPTIONAL `treaty_binding_ref` object is accepted, with the
fields and cross-checks of section 7 step 23; and `co_sign: n_of_m` is
accepted only when the verifier was handed a verified FROST
authorization (section 6).

---

## 6. DSSE Envelope Shape

This predicate uses the standard DSSE envelope
(`secure-systems-lab/dsse`) with **exactly two signatures** in every
co-sign mode. The verifier rejects any other count with `dsse.malformed`
(section 7 step 8; an empty array is rejected at step 1). In the
`n_of_m` mode the envelope still carries the two kernel signatures; the
quorum is a FROST authorization
(`VerifiedFrostAuthorization` in
[../crates/trust/chio-federation/src/frost/verify.rs](../crates/trust/chio-federation/src/frost/verify.rs))
verified outside the envelope and bound to the predicate by the verifier
(section 7 step 25). DSSE's `(t,n)` threshold semantics are not used.

The serialised envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<Base64(canonical-JSON Statement)>",
  "signatures": [
    {
      "keyid": "<sha256 of tool_server_a passport public key, hex>",
      "sig": "<Base64(Ed25519 signature over PAE)>"
    },
    {
      "keyid": "<sha256 of tool_server_b passport public key, hex>",
      "sig": "<Base64(Ed25519 signature over PAE)>"
    }
  ]
}
```

Signing uses the standard DSSE Pre-Authentication Encoding:

```
PAE("application/vnd.in-toto+json", canonical-JSON Statement bytes)
  = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
```

Both kernels sign the same PAE bytes. Each `keyid` MUST equal the
SHA-256 of the corresponding kernel's Ed25519 passport public key bytes,
hex-encoded (`Keyid::from_public_key`), and MUST equal the
`passport_key_fingerprint` declared for that kernel in the predicate's
`tool_server_a` or `tool_server_b` field. Signatures are matched by
`keyid`; the array order is not significant. Duplicate `keyid` values
are rejected with `dsse.malformed`, and the two pinned keys MUST be
distinct (section 7 step 13). The predicate body names which two keys
MUST appear in the envelope, and the envelope is invalid if either is
absent. The verification contract is therefore a **named set of two
signers**, stricter than DSSE's default "any t-of-n succeed".

---

## 7. Verification Algorithm

Two verifier entry points ship in `crates/trust/chio-federation`:

- `verify_chio_bilateral_dsse_envelope(envelope, key_a, key_b)` in
  [../crates/trust/chio-federation/src/bilateral_dsse/verify.rs](../crates/trust/chio-federation/src/bilateral_dsse/verify.rs)
  is the envelope layer. It takes the two public keys as arguments,
  holds no state, returns `BilateralCoSigningError`, and performs steps
  8 to 14 below.
- `verify_chio_bilateral_invocation(envelope, config)` in
  [../crates/trust/chio-federation/src/bilateral_verifier/cosign.rs](../crates/trust/chio-federation/src/bilateral_verifier/cosign.rs)
  is the conforming verifier. `config` supplies the verifier-owned
  state: the peer pin set, the pinned epoch (`now_unix_ms`,
  `epoch_height`), the revocation oracle, the receipt store, the
  capability lease registry, the action-class table with its
  unknown-class policy, and the governance receipt store. It performs
  steps 1 to 7, calls the envelope layer with the pinned keys, and
  continues with steps 15 to 26. It returns `VerifierError`;
  envelope-layer errors are mapped into it by `map_bilateral_error`
  (section 7.1). `verify_chio_bilateral_invocation_with_frost` is the
  same function with a verified FROST authorization supplied for
  `n_of_m`.

A conforming verifier MUST execute the steps in this order and MUST
abort at the first failure with the code shown. This is the shipped
order: verifier-owned peer pins are consulted before any byte-level
check, and the two Ed25519 signatures are verified after every
structural check on the envelope. The verifier accepts a unanimous
`deny` for audit and dispute review; admission paths additionally
require `allow` (`require_policy_evaluation_allow_admission`).

```text
verify_chio_bilateral_invocation(envelope, config, frost_authorization?):

  -- structural prefix
   1. envelope.payloadType == "application/vnd.in-toto+json"
      and signatures is non-empty                    -> dsse.malformed
   2. Base64-decode envelope.payload; parse the Statement
                                                     -> dsse.malformed (base64)
                                                        statement.malformed (JSON)
   3. predicateType == "chio.bilateral-cosign-invocation.v1"
                                                     -> predicate.type_unrecognised
   4. _type == "https://in-toto.io/Statement/v1"     -> statement.schema_invalid
   5. exactly one subject                            -> statement.schema_invalid

  -- peer pins
   6. pinned_a = peer_pin_set.lookup(pred.tool_server_a.kernel_id);
      keyid(pinned_a.key) == pred.tool_server_a.passport_key_fingerprint
                                                     -> peer.unpinned_or_keyid_mismatch
   7. the same for tool_server_b                     -> peer.unpinned_or_keyid_mismatch

  -- envelope layer:
  -- verify_chio_bilateral_dsse_envelope(envelope, pinned_a.key, pinned_b.key)
   8. payloadType as in step 1; exactly two signatures
                                                     -> dsse.malformed
   9. decode; canonical_json(statement) == payload bytes
                                                     -> statement.malformed
  10. _type and predicateType as in steps 4 and 3    -> statement.schema_invalid
                                                        predicate.type_unrecognised
  11. predicate schema (section 5 and its strict rules); co_sign in
      {bilateral_required, bilateral_if_cross_org}, or n_of_m only when
      a FROST authorization was supplied            -> predicate.schema_invalid
      tool_server_a.alg / tool_server_b.alg != "ed25519"
                                                     -> signature.server_a_invalid / _b_
      a verdict outside {allow, deny}, an empty policy_id or
      policy_version, disagreeing verdicts, or an inconsistent
      joint_disposition                              -> policy.verdict_disagreement
  12. exactly one subject (already checked in step 5), and
      subject[0].name == "chio-receipt:" + pred.invocation_id
                                                     -> subject.digest_mismatch
                                                        (statement.malformed at the
                                                        envelope layer)
  13. key distinctness: pinned_a.key != pinned_b.key and
      keyid(pinned_a.key) != keyid(pinned_b.key)      -> dsse.malformed
                                                        (signer.independence_required
                                                        at the envelope layer)
      no duplicate keyid across signatures           -> dsse.malformed
      pred.tool_server_a.passport_key_fingerprint == keyid(pinned_a.key)
                                                     -> signature.server_a_invalid
      pred.tool_server_b.passport_key_fingerprint == keyid(pinned_b.key)
                                                     -> signature.server_b_invalid
  14. pae = PAE(payloadType, payload bytes);
      a signature with keyid(pinned_a.key) exists    -> signature.server_a_invalid
      then a signature with keyid(pinned_b.key) exists
                                                     -> signature.server_b_invalid
      sig_a decodes to 64 bytes                      -> signature.server_a_invalid
      then sig_b decodes to 64 bytes                 -> signature.server_b_invalid
      sig_a verifies under pinned_a.key over pae     -> signature.server_a_invalid
      then sig_b verifies under pinned_b.key over pae
                                                     -> signature.server_b_invalid

  -- verifier-owned state
  15. for tool_server_a, then tool_server_b: the pinned peer carries a
      ladder manifest reference                      -> ladder.manifest_missing
      and that reference is fresh at pinned_epoch.now_unix_ms
                                                     -> ladder.manifest_stale
  16. revocation_oracle.is_active_at_epoch(fingerprint, pinned_epoch.epoch_height)
      for tool_server_a, then tool_server_b          -> peer.revoked_at_epoch
  17. receipt = receipt_store.resolve(pred.invocation_id); the receipt
      exists, its signature verifies, and receipt.tool_name == pred.tool_name
                                                     -> subject.digest_mismatch
      receipt.kernel_key == pinned_b.key             -> peer.unpinned_or_keyid_mismatch
      pred.receipt_canonical_json absent; pred.tool_args_hash present
      with alg sha256 and a 64-char lowercase hex value
                                                     -> predicate.schema_invalid
  18. receipt.action's parameter hash re-verifies and
      pred.tool_args_hash.value == receipt.action.parameter_hash
                                                     -> subject.digest_mismatch
  19. subject[0].name == "chio-receipt:" + receipt.id and
      subject[0].digest.sha256 == sha256_hex(canonical_json(receipt.body()))
                                                     -> subject.digest_mismatch
  20. pred.policy_evaluation_summary present; server_a_verdict and
      server_b_verdict each in {allow, deny} with non-empty policy_id
      and policy_version; the two verdicts equal; joint_disposition,
      if present, equals them                        -> policy.verdict_disagreement
  21. pred.capability_lease_ref present; lease = lease_registry.resolve(lease_id);
      lease.issuer and lease.expires_at_unix_ms equal the predicate's;
      expires_at_unix_ms > pinned_epoch.now_unix_ms; scope_digest present
      and equal on both sides, or absent on both     -> capability.lease_expired_or_unknown
  22. class = action_classes[pred.tool_name]         -> governance.unknown_action_class
      if class is receipt-backed: pred.governance_receipt_ref present,
      its digest well-formed, the receipt resolves in the governance
      receipt store with the same kernel_id and
      sha256_hex(canonical_json) == digest           -> governance.receipt_required_missing
  23. if pred.treaty_binding_ref present (its shape was already checked
      at step 11, where empty refs are rejected): treaty_id,
      action_class_id, and consistency_model non-empty; every *_sha256
      field 64-char lowercase hex; signer_kernel_ids exactly two
      non-empty distinct ids; lease_refs non-empty;
      request_sha256 == tool_args_hash.value;
      signer_kernel_ids == [tool_server_a.kernel_id, tool_server_b.kernel_id];
      lease_refs == [capability_lease_ref.lease_id];
      governance_refs == [governance_receipt_ref.receipt_id], or empty
      when that ref is absent;
      outcome_sha256 == receipt.content_hash;
      remote_receipt_sha256 == sha256_hex(canonical_json(receipt));
      governance_refs == [resolved governance receipt id] when one
      resolved; lease_refs == [lease.lease_id]       -> predicate.schema_invalid
  24. if pred.consistency_model != "crdt-commutative": treaty_binding_ref
      present with an equal consistency_model; the model is one of
      crdt-commutative, totally-ordered, single-kernel, quorum-required;
      totally-ordered and quorum-required carry a non-empty
      consistency_anchor                             -> predicate.schema_invalid
      reserved: reconciling the anchor against a verifier view and
      checking quorum population are not performed
  25. co_sign binding: bilateral_required and bilateral_if_cross_org
      require that no FROST authorization was supplied; n_of_m requires
      one, a treaty_binding_ref, consistency_model "quorum-required"
      with consistency_anchor "frost-quorum", and an authorization whose
      action class == treaty_binding_ref.action_class_id, scope ==
      treaty_binding_ref.treaty_id, resource == pred.invocation_id, and
      which is current at pinned_epoch.now_unix_ms / 1000; any other
      co_sign value                                  -> predicate.schema_invalid
  26. return VerifiedBilateralCoSignInvocation { statement,
      resolved_receipt, resolved_lease, resolved_governance_receipt,
      joint_verdict, frost_authorization }
```

### 7.1 Error Codes

The stable code is `VerifierError::code()` in
[../crates/trust/chio-federation/src/bilateral_verifier/error.rs](../crates/trust/chio-federation/src/bilateral_verifier/error.rs).
`Display` renders `code: detail`; the detail is diagnostic and not part
of the protocol surface. The following sixteen codes MUST be surfaced
verbatim. Each may be recorded as a `GenericGovernanceCaseKind::Dispute`
finding
([../crates/trust/chio-governance/src/generic.rs](../crates/trust/chio-governance/src/generic.rs)).

| Code | Meaning |
| --- | --- |
| `dsse.malformed` | Wrong `payloadType`; empty or not exactly two signatures; undecodable base64 payload; duplicate signature `keyid`; or, through the operational verifier, two pinned keys that are not distinct. |
| `statement.malformed` | Payload is not parseable JSON or is not canonical JSON (RFC 8785). |
| `statement.schema_invalid` | `_type` is not the in-toto Statement v1 type, or the subject count is not one. |
| `predicate.type_unrecognised` | `predicateType` is not `chio.bilateral-cosign-invocation.v1`. |
| `predicate.schema_invalid` | The predicate fails section 5 or a strict rule of steps 11, 17, 23, 24, or 25. |
| `subject.digest_mismatch` | The receipt is not resolvable or its signature is invalid; `tool_name` or the request hash disagrees with it; or the subject name or digest does not match the resolved receipt body. |
| `peer.unpinned_or_keyid_mismatch` | A kernel id is not pinned, its declared fingerprint disagrees with the pin, or the resolved receipt's kernel key is not the pinned `tool_server_b` key. |
| `peer.revoked_at_epoch` | A pinned passport is not active at the pinned epoch height. |
| `signature.server_a_invalid` | `tool_server_a`'s signature is absent, undecodable, or does not verify; or its `alg` is not `ed25519`; or its declared fingerprint is not the pinned key's keyid. |
| `signature.server_b_invalid` | The same for `tool_server_b`. |
| `policy.verdict_disagreement` | Missing summary, a verdict outside {allow, deny}, an empty `policy_id` or `policy_version`, disagreeing verdicts, or an inconsistent `joint_disposition`. |
| `capability.lease_expired_or_unknown` | Missing `capability_lease_ref`; lease not in the registry; issuer, expiry, or scope digest disagreeing with the registry; or expiry at or before `now_unix_ms`. |
| `governance.receipt_required_missing` | A receipt-backed class lacks `governance_receipt_ref`, or the ref does not resolve, names another kernel, or carries a wrong digest. |
| `ladder.manifest_missing` | A pinned peer has no ladder manifest reference. |
| `ladder.manifest_stale` | A pinned peer's ladder manifest reference is not fresh at `now_unix_ms`. |
| `governance.unknown_action_class` | `tool_name` is not in the verifier's action-class table; the only unknown-class policy is reject. |

**Reserved, not emitted.** `consistency.anchor_unverified` and
`consistency.quorum_underpopulated` are reserved for the anchor
reconciliation and quorum-population checks of step 24. No shipped
verifier emits them: an ordered or quorum predicate without an anchor
fails step 24 with `predicate.schema_invalid`, and quorum membership is
established by the FROST authorization of step 25.

**Envelope-layer codes.** `BilateralCoSigningError::code()` in
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs)
is the code surface of the envelope layer and of the co-signing
protocol. It shares `dsse.malformed`, `statement.malformed`,
`statement.schema_invalid`, `predicate.type_unrecognised`,
`predicate.schema_invalid`, `subject.digest_mismatch`,
`signature.server_a_invalid`, and `signature.server_b_invalid` with the
table above and adds:

| Code | Meaning |
| --- | --- |
| `signer.independence_required` | The two signer keys or keyids are identical (step 13). Through the operational verifier this surfaces as `dsse.malformed`. |
| `canonical_json.invalid` | Canonical-JSON encoding failed for a reason no more specific code covers. |
| `peer.unknown` | The co-signing peer is not a trusted federation peer. |
| `peer.expired` | The co-signing peer's rotation window has lapsed; it must re-handshake. |
| `transport.failed` | The co-signing transport failed. |
| `peer.rejected` | The co-signing peer rejected the request. |
| `schema.unsupported` | The co-signing request schema is unsupported. |
| `peer.identity_mismatch` | The bilateral receipt's peer identity does not match the pinned peers. |

`map_bilateral_error` (`bilateral_verifier/error.rs`) converts
envelope-layer errors into `VerifierError` by message prefix: the
subject-name mismatch becomes `subject.digest_mismatch`, verdict
failures become `policy.verdict_disagreement`, and any error without a
recognised prefix, including the signer-independence message and the
protocol codes above, becomes `dsse.malformed`.

### 7.2 Code-Only Rejection Surface

The code of section 7.1 is the whole of the rejection that is part of
this protocol. It is a value of the closed set that `RejectionCode`
([../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs))
enumerates, reachable as `VerifierError::redacted` and
`BilateralCoSigningError::redacted`; the dotted string it renders is what
the two `code()` accessors return, and it names the check that failed and
nothing else.

Everything else a rejection carries is local diagnostic. The `Display`
of either error renders `code: detail`, and the detail names the values
that were compared: presented and expected digests, key fingerprints,
kernel ids, keyids, epoch heights, and policy verdicts. That detail is
written for the operator reading the verifier's own log, on the host that
holds the material already. It is not versioned, not stable across
releases, and not part of the wire contract; an implementation MAY change
any of it without notice, and a peer MUST NOT parse it.

A verifier therefore MUST NOT copy the rendered message, or any value the
message names, into an artifact that leaves the host: a signed receipt, a
co-signed envelope, a governance finding, or an exported verification
report. Such an artifact carries the code and, where its schema requires a
human-readable field, a fixed phrase that does not vary with the material
under verification. This includes the reply frame of the co-signing
protocol itself: a peer that refuses to co-sign returns the code, or a
fixed phrase, and never the rendered message. A rejection that echoed
presented values back to the presenter would make the verifier an oracle
over the material it holds: the sender learns which of its guesses matched
a pinned fingerprint, a receipt digest, or a lease scope, one rejection at
a time. The code alone answers only which check failed, which the sender
already knows it provoked.

The offline buyer verifier is the reference for this rule. Its exported
report
([../crates/trust/chio-attest-buyer-core/src/report.rs](../crates/trust/chio-attest-buyer-core/src/report.rs))
is hashed into the buyer attestation packet, so it is an artifact that
leaves the host: `VerifierFailure::from_error` reduces every failure to
its code, the stage that owns it, and the fixed phrase
`WITHHELD_FAILURE_DETAIL`, and the rendered diagnostic stays with the
local error.

---

## 8. Composition With Workflow Receipts

A chio workflow receipt
([../crates/platform/chio-workflow/src/receipt.rs](../crates/platform/chio-workflow/src/receipt.rs))
captures an N-step skill execution as a single signed artifact. When
the steps cross trust boundaries, each step is itself a
bilateral-cosign-invocation predicate. The composition rule:

1. Each step MAY produce one bilateral-cosign-invocation Statement
   (DSSE-enveloped). The Statement's subject is the step's
   `tool_receipt_id`.
2. The workflow receipt's body lists per-step records, each carrying
   the SHA-256 of the corresponding step's bilateral-cosign-invocation
   Statement payload (not just the underlying tool receipt).
3. The workflow receipt is itself a Statement under a separate
   predicate type (provisionally
   `https://in-toto.io/attestation/chio-workflow-receipt/v1`, to be
   specified in a sibling proposal). Its `subject` is the
   canonical-JSON SHA-256 of the
   [`WorkflowReceiptBody`](../crates/platform/chio-workflow/src/receipt.rs).
4. A verifier of the workflow receipt SHOULD verify each referenced
   bilateral-cosign-invocation predicate independently. Failure of any
   one step's predicate verification MUST be surfaced; the workflow
   receipt itself MAY still verify its own signature, but the
   composite assertion "every cross-org step jointly committed" is
   only true when every step-level predicate verifies.

This separation lets verifiers walk the DAG bottom-up: confirm each
joint commit at the leaves, then confirm the workflow receipt's roll-up
signature at the root. The bilateral-cosign-invocation predicate is
the leaf primitive; the workflow-receipt predicate is the composition
primitive.

---

## 9. Composition With Rekor

The DSSE envelope MAY be additionally submitted to a Sigstore Rekor v2
instance for transparency-log evidence. Recommended Rekor entry kind:
`dsse` (Rekor v2's native DSSE entry). The envelope is anchored
verbatim; no chio-specific transformation is required.

This composition is a **free property**. The verification contract in
section 7 does not depend on Rekor inclusion. A Rekor-anchored envelope
gains:

- Public, append-only proof that the envelope existed at the inclusion
  time, defending against retroactive forgery if both kernels' audit
  stores are later compromised.
- A discoverable index for third-party auditors who do not have direct
  access to either kernel's receipt store.

A Rekor inclusion proof MAY be carried alongside the envelope in a
Sigstore Bundle. Verifiers SHOULD treat Rekor inclusion as **additional
evidence**, not as a substitute for the bilateral verification
contract: a Rekor-anchored envelope that fails section 7 is invalid;
a non-Rekor-anchored envelope that satisfies section 7 is valid. Chio
already integrates with Sigstore at
[../crates/trust/chio-attest-verify/src/lib.rs](../crates/trust/chio-attest-verify/src/lib.rs);
the inverse (writing chio receipts into Rekor) is a small extension.

---

## 10. Comparison Table

| Property | bilateral-cosign-invocation/v1 (this proposal) | runtime-trace/v0.1 | slsa-provenance/v1 | single-party DSSE on Rekor |
| --- | --- | --- | --- | --- |
| Subject | content-hash of a runtime invocation event | one or more built artifacts | one or more built artifacts | arbitrary payload |
| Number of signers | exactly two in every mode (`n_of_m` adds a FROST authorization outside the envelope) | one (the monitor's identity) | one (the builder's identity) | one (the signer's identity) |
| Cross-org semantics | yes; two named signers from two distinct kernels | no; monitor is single party | no; builder is single party | no; one signer per envelope |
| Per-action capability binding | yes (`capability_lease_ref`) | no | no (build-config rather than per-action) | no |
| Policy-verdict agreement contract | yes (`policy_evaluation_summary` MUST agree) | no | no | no |
| Workflow composition primitive | yes (sibling workflow-receipt predicate) | no | no (build, not workflow) | no |
| Consistency-model declaration | yes (CRDT / totally-ordered / quorum) | no | no | no |
| Transparency-log anchoring | optional (Rekor v2) | optional | optional | required (by the Rekor model) |
| What it proves | both kernels independently evaluated and jointly committed to the same canonical action under named capabilities | a monitor observed these events during a build | this artifact was produced by this builder under this configuration | this signer signed this payload |
| What it does NOT prove | that any third party observed the action; that the action's effects are durable beyond the kernels' audit stores | cross-org consent; per-action capability scoping | runtime invocation; multi-party intent | multi-party intent; capability scoping; workflow context |

The structural slice that bilateral-cosign-invocation occupies is the
**joint-commit-at-action-time** slice. Sigstore + in-toto + SLSA in
their current form do not occupy it. A multi-signer DSSE envelope on
Rekor is mechanically possible today but lacks the predicate vocabulary
to express what the multi-signing means: a verifier sees two
signatures and has no in-toto-supplied way to know whether they are
two independent assertions or a single joint commit.

---

## 11. Open Questions for the WG

1. **Predicate adoption vs sibling envelope.** Does in-toto want to
   absorb a multi-signer predicate type into its core vocabulary, or
   prefer a sibling envelope that **wraps** Statement and carries the
   multi-signer semantics out-of-band? The former keeps tooling simple;
   the latter keeps the Statement layer minimal.
2. **DSSE threshold vs named-set semantics.** DSSE permits `(t,n)`
   thresholds. This proposal narrows that to a **named set of two
   signers** (signatures matched by the passport fingerprints declared
   in the predicate body; array order is not significant). Should
   in-toto define a recommended "named multi-signer" pattern other
   predicates can reuse?
3. **Subject as event-hash vs file-hash.** This proposal points
   `subject.digest` at the canonical-JSON SHA-256 of a runtime
   `ChioReceipt`. Is a content-hash of an in-memory event a legitimate
   subject, or should runtime predicates declare a side-channel event
   identifier field instead?
4. **Capability-lease referencing.** Is there appetite for an in-toto
   standard "capability reference" sub-type that other runtime
   predicates (and a future runtime-trace v1) could share?
5. **Composition with workflow / DAG predicates.** Does the WG have a
   preferred shape for "Statement that references other Statements as
   composite parts" (Bundle, Manifest, or a new Composition predicate)
   that this proposal should align with?

---

## 12. Engagement Plan

The chio maintainers intend the following next steps:

1. **In-toto attestation issues.** File this proposal as an issue
   against `in-toto/attestation` referencing the canonical URI
   `https://in-toto.io/attestation/bilateral-cosign-invocation/v1` and
   inviting review by Aditya Sirish A Yelgundhalli and the broader WG.
2. **OpenSSF AI/ML Security WG.** Present at the next WG call as a
   "predicate-shape proposal that arose from cross-vendor agent
   action attestation" and solicit cross-pollination with the
   AI/ML-specific predicates the WG is sketching.
3. **CoSAI Workstream 4.** Share with the Secure AI Software Supply
   Chain workstream as adjacent prior art relevant to their runtime
   invocation receipt discussions.
4. **ITE drafting.** If the in-toto WG indicates appetite, draft an
   in-toto Enhancement (ITE) using this document as the seed text,
   carrying it through the standard ITE review process.
5. **Reference implementation.** Keep the chio-namespaced strict predicate
   implementation covered by production tests, then switch emission to the
   canonical URI if the in-toto WG accepts it. The existing
   `chio.bilateral-signature-slice.v1` helper remains compatibility-only and
   must not be treated as strict Chio predicate evidence.

If the WG declines or the discussion stalls, this document remains the written
record of the structural gap that motivates the chio-namespaced predicate.
