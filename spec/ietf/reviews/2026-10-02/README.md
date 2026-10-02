# Release-target review of the Chio Internet-Draft

Review date: 2026-10-02. Author of the draft: Connor Whelan, Backbay Industries.

## Review contract

This review prepares the document for the completed security-roadmap release, as explicitly requested by the owner. The normative draft describes that intended release in present tense. It does not repeat temporary implementation gaps as permanent protocol limitations.

This internal record distinguishes source-supported wire behavior, requirements synthesized from the completed roadmap, and deliberate standards or security corrections that the release implementation must satisfy. It does not mark runtime milestones complete, authorize a Datatracker submission, or change the published site. Confidence is high for the pinned source comparison and documented wire deltas; runtime and independent interoperability acceptance are separate evidence.

The original draft was based on a much older main snapshot. Its most serious problems were incomplete authority binding, recovery semantics described as optional, and transport descriptions that had fallen behind the security integration. Stronger architectural language alone would not have corrected those defects.

## Source selection

The starting draft is `201582139476cfb5dfe7b2e12fe0b32377565f9a`. Its September 30 claim review used implementation `f5566d9a765c21cb36652a99c79de64968a656bf`.

The combined security integration is `f25cd61f49fbf9a15a70396da82d9808ba4e1da2` on `integration/process-security-m4`, 717 commits ahead of the inspected remote main. The newer `packet/3-retention-accounting` tip, `122414b48ef1bc7999a9e32c7ae303d561fcd429`, contains that integration and 69 further commits. It is the primary implementation snapshot for this review. `packet/2-runtime-boundaries` is contained in it.

The dry-run, measurement, receipt-boundary, and checkpoint-snapshot branches were compared using patch equivalence as well as ancestry. Their remaining divergent commits are represented in the selected snapshot. The gates, fuzz/model, and adversarial-case branches contain additional work. They were inspected as complementary assurance and intended-invariant sources, not silently treated as merged runtime behavior. The older launch-integration and security-execution branches were not substituted for the newer combined source.

[Source manifest](source-manifest.json) records exact refs, ancestry, divergence, and file digests. No source checkout instructions depend on these private revisions. The draft names only the public Chio repository.

## Findings and dispositions

Severity describes the consequence of leaving the old wording unchanged. All document corrections below are incorporated. A release-target requirement can still require implementation acceptance before publication.

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| R01 | High | The opening described dispatch and signatures but not durable execution ownership. | Define the kernel lifecycle: authenticated admission, reservation, dispatch commitment, output release, finalization, and recovery. |
| R02 | High | Artifact parsing and kernel execution were conflated as conformance. | Separate artifact verifiers from execution kernels and require complete enforcement of every selected feature. |
| R03 | High | Duplicate JSON members and numeric conversion could be accepted before signed meaning was established. | Validate original bytes, reject duplicates at every depth, preserve integer ranges, prohibit integer coercion, and distinguish arbitrary unsigned application JSON. |
| R04 | High | Signer floors were optional helper behavior, allowing weak fallbacks and partial approval checks. | Require trusted suite policy on every relevant signer role, backend identity verification, and no weaker fallback. Preserve artifact-specific absent-hint defaults. |
| R05 | High | The old draft rejected every caveat and omitted authenticated runtime context. | Specify `bind_security_context`, its exact canonical predicate and fields, and comparison with independently authenticated host context. |
| R06 | High | Approval of a declared intent could be mistaken for approval of exact parameters. | Specify `bound_tool_invocation`; bind the capability ID and canonical parameter digest; reject substitution before approval verification. |
| R07 | High | Only v1 execution nonces were described, despite the operation-owned v2 signing profile. | Specify the v2 wrapper, trusted operation binding, cross-version rejection, and durable consumption. Preserve the legacy v1 predicate's separate meaning. |
| R08 | High | Caller reservation and unsigned reconciliation could be mistaken for external execution authority. | Require authenticated start, independently pinned executor, durable operation claim, signed report, original binding, and guarded output. Keep full caller wire formats in a companion profile. |
| R09 | High | Restart could reset replay and sibling-allocation state under the old wording. | Make durable shared authority mandatory when used for enforcement; reject missing, corrupt, or rolled-back stores. |
| R10 | High | Timeout, cancellation, and retry language could release exposure or repeat an uncertain effect. | Distinguish precommit cancellation from committed uncertainty; prohibit automatic refund or redispatch without authoritative recovery evidence. |
| R11 | High | The native result union omitted `pending_approval` and hid the proposal behind an undocumented retrieval path. | Specify the closed result, complete proposal, deny receipt, absence of chunks/nonce, and resumption of the original admission. |
| R12 | High | The draft said hosted MCP results contain no receipts. | Specify `_meta.chio` and `_meta.chioEvidence`, original output binding, untrusted wrapper diagnostics, and replacement of tool-supplied metadata. |
| R13 | High | A native evaluation error could be described as a receipt from the expected kernel after signing under a fresh key. | Prohibit unauthenticated fallback keys; terminate the exchange and preserve recoverable state when signing fails. |
| R14 | High | Checkpoint package validation omitted signed tree-size and sequence-position checks. | Require both equalities, checked arithmetic, consistent snapshots, and explicit uncheckpointed tails. |
| R15 | High | Confinement was described as an optional deployment suggestion. | Define the selected runtime profile's manifest, publisher, operator ceiling, launch, descriptor, executable, and actual-destination enforcement requirements. |
| R16 | High | Credential custody, flow control, and active response were nearly absent. | Add broker ownership, composed quota authority, authenticated labels, one-shot declassification, governed response, simulation/live separation, and owned rollback. |
| R17 | High | Tenant query descriptions did not bind stored projections back to signed tenant identity. | Require authenticated query scope and signed-body agreement; identifiers and unattributed records do not grant tenant read access. |
| R18 | High | Key rotation and signing roles were under-specified as operational trust assumptions. | Define role separation, fenced activation, historical verification, compromise handling, and trusted witness policy without inventing a new key-log wire format. |
| R19 | High | Clock errors and arithmetic saturation could extend authority. | Require checked arithmetic, fallible trusted time, regression rejection, and deadlines that retries or restart cannot renew. |
| R20 | Medium | JWT issuer/audience/expiry checks and proxy provenance were conditional in the old profile. | Require configured JWT validation under RFC 8725, authenticated introspection, and trusted ingress for certificate/attestation bindings. |
| R21 | Medium | HTTP Origin and Content-Type were described using unsafe host/prefix tests. | Specify full-origin allowlisting and parsed media-type matching. |
| R22 | Medium | MCP terminal status, accepted notification handling, and version negotiation differed from the cited transport. | Use terminal 404, bodyless accepted 202, actual message processing, and MCP's supported-version response negotiation. |
| R23 | Medium | JSON-RPC response IDs and HTTP rejection semantics were muddled. | Distinguish JSON-RPC responses from HTTP-layer errors and notifications. MCP permits some id-less HTTP diagnostic objects; this binding chooses ordinary response objects for request failures and plain HTTP notification rejection. |
| R24 | Medium | Retention could be read as permission to discard replay or recovery authority. | Separate evidence presentation retention from security-state lifetime; preserve immutable identities, archive continuity, and rollback protection. |
| R25 | Medium | Revocation acknowledgment could be mistaken for universal observation or reversal of committed work. | Define durable local acknowledgment, freshness/fencing duties, and the boundary at already-committed effects. |
| R26 | Medium | The IANA section listed fourteen unrelated transaction diagnostics as if fully specified. | Keep the range reserved, remove unsupported per-code descriptions, and register the in-scope v2 nonce and signed lineage/proof artifacts. |
| R27 | Medium | Implementation status contained stale source archaeology and private-style repository paths. | Describe the intended production kernel, supported profile, public source, and distinct wire/runtime assurance categories. |
| R28 | Editorial | Related work emphasized tool mediation and repeated defensive qualifications. | Explain the stateful kernel execution boundary and its relationship to token and communication protocols. Retain actual interoperability limits. |

## Roadmap coverage

| Milestone | What the draft carries forward | What remains implementation evidence |
|---|---|---|
| M0: consolidation | One coherent source baseline and explicit feature profiles. | Branch integration and dependency qualification. |
| M1: complete confined native call | Capability/context binding, confinement, guards, resource admission, receipt and output release. | Platform-specific launcher and operating-system probes. |
| M2: restart and failure | Original operation ownership, dispatch fence, conservative exposure, immutable finalization, fail-closed readiness. | Crash injection and restart matrix. |
| M3: authenticated caller | Reservation/start distinction, pinned executor, durable claim, authenticated report, output custody. | Full caller-delivery schema and executor integration tests. |
| M4: no adapter bypass | Trusted peer feature selection, preserved context and authorization artifacts, rejection of unsupported enforcement. | Every adapter/SDK composition and fallback path. |
| M5: process/swarm binding | Authenticated context, lineage sensitivity, exact operation and receipt evidence. | End-to-end process and swarm acceptance. |
| M6: enterprise hardening | Brokered secrets, manifest ceiling, confinement, role-specific key lifecycle and witness policy. | Keyring/broker/cage service deployment and fault qualification. |
| M7: active defense | Trusted causal evidence, governed plans, dry-run/live separation, fenced response recovery and owned rollback. | Detection quality, operational promotion, and live response gates. |
| M8: retention/recovery | Stable sequence and checkpoint identity, consistent evidence, preserved replay and unresolved obligations. | Retention scale, corruption, archive and reopen campaigns. |
| M9: packaged runtime | Implementation status identifies the composed runtime and profile. | Reproducible release artifacts, installer/platform evidence. |
| M10: qualification | Clearly separated artifact, wire, and runtime conformance. | Exact-candidate full qualification and independent review. |
| M11: observed promotion | No invented pilot statistics, certification, or independent interoperability. | The operator's actual rollout and acceptance record. |

## Changes that require release reconciliation

These are intentional requirements of the prepared release draft, not claims that the inspected branch already passes them universally:

1. Mandatory durable lifecycle, replay, allocation, and output-release obligations apply across every conforming execution path. Legacy in-memory helpers can remain as non-enforcing or explicitly limited utilities.
2. Every signed ingress and recovery reader must satisfy the stricter original-byte rules, including signed integer spelling. Existing type-specific tolerant decoders do not establish that property on their own.
3. JWT validation, Origin/media-type handling, MCP version negotiation, terminal 404, notification 202, and request error IDs must be reconciled with the release transport behavior. These are corrections against the external standards, not automatic consequences of merging the roadmap.
4. Singly approved exact-argument operations must use the bound intent. The existing intent-only format is retained with its narrower meaning.
5. Sibling-share enforcement needs durable authoritative state. The old process-local registry is not an acceptable production implementation of the new requirement.
6. Capability family marker fields must be accepted by the complete release schemas. The selected token schema still omits aggregate marker members in some closed nested definitions; the draft now defines the required signed semantics rather than exposing that implementation gap as a protocol rule.
7. No error path may manufacture a receipt under an unconfigured key. All signers, including proposal and recovery paths, must enforce the selected role and suite.
8. Issuance must reject invalid lifetimes and checked-add overflow; query validation uses 400 for an invalid outcome. Revocation success must reflect the durability and visibility claimed in the draft.
9. New source wire forms (`pending_approval`, context caveats, bound intents, nonce v2, `chio_internal`, inline MCP evidence) require the integrated release source and schemas. The isolated document branch intentionally does not cherry-pick the runtime into the old source base.

Before submission, run acceptance on the actual completed release and reconcile each item with its test evidence. This is a document-to-release contract, not an invitation to weaken the draft to match an unfinished build.

## Preserved protocol boundaries

- The full-width integer extension is explicitly distinguished from unrestricted RFC 8785/I-JSON processing.
- Existing capability, receipt, child-receipt, Merkle, approval, and continuation signing inputs are preserved. Nonce v2 has its own explicit wrapper; changing a schema label does not translate a signature.
- `single_node_atomic` is the selected operator profile. Multiple processes do not imply distributed linearizability.
- Authenticated attenuation remains the specified one-hop profile. This review does not invent general offline delegation or a new policy language.
- Signatures authenticate statements under keys. They do not independently prove execution, delivery, provider effects, truth of caller metadata, or absence of equivocation.
- Confined Linux execution is not represented as universal portable operating-system support.
- Full broker, key-log, active-response, caller-delivery, and flow-artifact wire formats remain companion profiles. This draft specifies the enforcement obligations at their boundary and the in-scope context binding.

## Standards checked

Primary specifications checked during this review:

- [RFC 3552](https://www.rfc-editor.org/rfc/rfc3552.html): explicit threat model and residual trust boundaries.
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html): BCP 14 requirement notation.
- [RFC 8126](https://www.rfc-editor.org/rfc/rfc8126.html): registry policy and expert review.
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html): configured JWT algorithm, issuer, audience and application validation.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html): distinguish Chio's proof from the OAuth DPoP JWT format.
- [MCP 2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) and [lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle): HTTP response, session, origin and negotiation rules.
- [JSON-RPC 2.0](https://www.jsonrpc.org/specification): request IDs and notification semantics.
- [RFC 7942](https://www.rfc-editor.org/rfc/rfc7942.html): implementation-status scope.
- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) and [WIMSE architecture -08](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/): current related-work identity and scope.

## Acceptance evidence

See [verification](verification.md), [wire verification](wire-verification.json), and the [normative inventory](normative-inventory.json). The previous claim ledger is preserved as [historical evidence](previous-claims.md), not represented as a new review of this source.
