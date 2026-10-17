<!--
Target: spec/WIRE_PROTOCOL.md
Insertion point: new subsection after "### 3.5 Model Metadata Admission" (after its native transport versioning list), before "## 4. Trust-Control Capability Lifecycle".
Move the text below this comment into place unchanged; drop this comment.
-->

### 3.6 Capability Presentation And Receipt Copy

Status: specified, not implemented. Implementations emit and accept the formats in the sections this one names until this line is removed.

Sections in force until then: 3.5 and PROTOCOL "Inbound sender authority profile".

`chioCapability` and `chioReceipt` join the closed list of Chio `_meta`
members.

Capability presentation (request):

- Hosted `tools/call` requests **MAY** carry a
  `chio.capability-presentation.v1` (PROTOCOL section 5.6.5) under
  `_meta.chioCapability`.
- The hosted edge applies the same discipline as `_meta.chioDpopProof`: a
  duplicate `chioCapability` key rejects the request, and the edge validates
  the original bytes of the presentation before projecting any unsigned
  envelope.
- Every capability inside the presentation is verified independently against
  the anchored-root rules of PROTOCOL section 5.6. A presentation whose chain
  fails any of them denies the call.
- Decoding is strict (PROTOCOL section 4.5): an unknown member at any level
  of the presentation, including an `algorithm` member on a capability,
  rejects the request.
- When the presentation's leaf is bound to a sender key, the request also
  carries `_meta.chioDpopProof` signed by the leaf subject.

Receipt copy (response):

- Every `tools/call` response from `serve-http` **MUST** carry
  `_meta.chioReceipt`, an object with two members:
  - `receipt`: the signed `chio.receipt.v1` for the call;
  - `opening`: a `chio.receipt-disclosure.v1` holding the salts for that
    receipt's parameters, content, and anchor subject and tenant commitments,
    with `payload: null` in every opening.
- The caller holds its own arguments, result and identity, so the copy carries
  no payloads.
- Callers **MUST** verify `receipt` before relying on it, using the kernel key
  pinned in their own verifier trust file, and **MUST** decode `receipt` and
  `opening` strictly (PROTOCOL section 4.5).
