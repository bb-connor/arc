# Security model and invariants

## Authority and adversaries

The agent, model outputs, tool-return text, discovered tool descriptions, worker-supplied identifiers, connector packages and serialized offers are untrusted inputs. An authenticated provider may still return attacker-authored content. An authenticated package publisher is not automatically an authority over a tenant's data.

The trusted computing base consists of the kernel's verifiers and native admission path, the serving-store fence/transaction implementation, the operator's selected policy and trust roots, the broker/confinement boundary for an enforced profile, and the code that resolves authentic provider facts. Approved transformation implementations join that base only for their declared powers. Approval UI and identity binding are trusted for faithfully presenting and authorizing the exact action.

Assume hostile timing, duplicate messages, out-of-order delivery, process death at any await/commit boundary, storage commit ambiguity, stale workers, revoked authority, clock discontinuity, malformed signed input, conflicting database versions, poisoned classifications and partial external effects. A compromised operator signing root or an external provider that lies about its own authenticated effects requires containment and key rotation; the architecture cannot cryptographically repair that root's dishonesty.

## Three authority classes

1. **Proposal:** an intent, candidate plan, offer or simulation. It may be inspectable and signed for provenance. It confers no execution right.
2. **Historical evidence:** an authenticated grant, receipt, retained outcome, launch measurement or no-effect proof. Its use requires context, audience, freshness and binding verification.
3. **Live ownership:** a non-serializable handle issued by native capture for one exact operation under the current serving fence. It is never reconstructed from an offer, receipt, workflow row or wire field.

Cryptographic authenticity does not imply current authority. An expired grant, a historical epoch, a valid receipt for another tenant, or a report signed by an unexpected key cannot authorize new capture or release. Authenticated historical evidence may still establish what happened under its original authority; current fenced recovery authority owns settlement. Revocation must not turn an uncertain operation into a new execution opportunity or make historical facts depend on renewing the initiating capability.

## Confidentiality and integrity

Retain Chio's existing `InformationLabel` algebra. The effective confidentiality source joins payload, observed input floor, principal, lineage and session restrictions. An unrepresentable join becomes restrictive unknown; neither overflow nor decode failure erases knowledge. `Top` is not an operational clearance. An approved crossing changes authority for a specific release and does not clear the principal's retained knowledge.

Source evidence and integrity are separate. The proposed `InfluenceState` retains the union of observed origin classes and an explicit `Unknown` state across the same relevant principal/lineage/session contexts. Origin classes name operator-bound provenance categories, not a model's confidence score. Tool contracts declare acceptable influence sets and required verified attestations. A scoped endorsement may authorize an exact derived artifact or invocation despite those influences; it does not rewrite global influence history. This is an additive contract and requires new native participant evidence before deployment.

All model-visible input counts as observation: prompt construction, restored memory, tool responses, errors, retrieved snippets, child status, streamed fragments and provider context caches. A profile with an unmediated channel must disclose that coverage gap and cannot claim enforced information-flow recovery on that channel.

## Effect truth

Recovery reads the owning kernel's operation, dispatch and outcome evidence. `Verdict::Deny`, `is_terminal()`, HTTP failure, timeout, and a completed evaluation receipt do not establish that a resource effect never happened. Current source explicitly permits a terminal denial evaluation while its resource outcome remains unknown.

The recovery observation vocabulary is:

| Observation | Permitted next behavior |
|---|---|
| Never admitted, current intent only | Plan and request authority |
| Verified closed before effect | Preserve evidence and allocate a linked continuation |
| Awaiting approval in an existing native lifecycle | Resume that lifecycle with its exact native contract |
| In flight or awaiting caller report | Observe/wait; retain ownership |
| Effect unknown | Reconcile under the original operation identity |
| Effect known and output withheld | Recover allowed status/evidence; never infer no effect |
| Effect complete | Recover the original result subject to current read authority |
| Settled partial effects or failed after effect | Preserve the spent step; report exact disposition and authorize any compensating/remainder step separately |
| Corrupt, unsupported or unverifiable | Quarantine the workflow and refuse execution |

`VerifiedPreDispatchNoEffect` is an existing useful foundation. A recovery close certificate must additionally bind the selected operation version, complete participant evidence and irreversible closure against future dispatch. A partial provider lookup or “record not found” is insufficient unless the resource contract proves authoritative, final non-acceptance and the old attempt is fenced out.

## Invariants

| ID | Normative obligation | Proposed acceptance test | Phase |
|---|---|---|---|
| SEC-01 | Every external effect MUST enter the existing kernel/native dispatch ownership path. | `security::no_alternate_dispatch_path` | P0 |
| SEC-02 | Serialized or reconstructed evidence MUST NOT manufacture live ownership. | `types::evidence_cannot_construct_dispatch_owner` | P0 |
| SEC-03 | A workflow MUST have at most one unresolved effectful continuation. | `recovery::concurrent_continuation_selection` | P1 |
| SEC-04 | An unknown, delivered-but-denied or awaiting-report operation MUST NOT authorize a replacement effect. | `recovery::deny_receipt_with_unknown_effect` | P1 |
| SEC-05 | Disclosure/endorsement MUST NOT reduce retained confidentiality or influence history. | `flow::exceptions_preserve_knowledge` | P1 |
| SEC-06 | All authorization checks MUST bind tenant, authority domain, process and exact action; mismatches refuse. | `authority::cross_context_substitution` | P1 |
| SEC-07 | Stale serving/coordinator epochs MUST be rejected at every authoritative mutation and capture. | `recovery::stale_owner_after_takeover` | P1 |
| SEC-08 | Missing/corrupt evidence, unknown variants, dependency failure and bounded-resource exhaustion MUST fail closed. | `wire::unknown_and_exhausted_inputs` | P0 |
| SEC-09 | Every data-bearing release MUST be audience-governed for every enabled profile channel, including explanations, errors and retained outputs. | `channels::complete_release_inventory` | P1 |
| SEC-10 | Cancellation, expiry and Drop MUST NOT imply rollback of an accepted or uncertain external effect. | `recovery::cancel_after_dispatch_cutpoints` | P1 |
| SEC-11 | Policy and semantic packages MUST NOT widen the caller's capability authority. | `contracts::approval_without_capability` | P3 |
| SEC-12 | Safety claims MUST identify coverage, assumptions and source/evidence versions. | `conformance::profile_claims_match_coverage` | P6 |

## Bounded work and availability

Protocol ceilings are proposed engineering limits, not performance measurements: request/offer envelopes 64 KiB excluding separately governed artifact bytes; 16 offers per decision; 8 top-level remedy steps and at most 32 total operation nodes after prerequisite expansion, with depth at most 8; 64 evidence references per object; 16 authority attestations per approval bundle; 1 MiB per inline artifact chunk, matching the existing process blob ceiling. Collection limits apply while decoding, before allocation; byte limits apply before parsing. Typed protocol integers stay within the repository's I-JSON-safe positive range where required.

Also cap wire nesting at 32 and aggregate decoded collection entries at 4,096 per envelope in the initial profile. Evidence traversal has one shared work budget across repeated references, signature checks and dependency expansion; a per-node limit does not bound an exponentially expanded graph. Resolve cycles and duplicate canonical identities explicitly. A bounded input buffer alone is not a bound on parser recursion, decoded allocation or cryptographic work. Deployment ceilings may be stricter.

Tenant policy may lower ceilings. Raising a protocol ceiling requires versioned resource analysis and conformance. CPU/fuel, queue depth, in-flight consults, retries and retained bytes also need finite deployment bounds. Planner exhaustion reports `SearchBoundReached` without claiming the task is impossible. Only kernel-identified read-only, stateless observations may use a declared bounded retry policy. Effect reconciliation uses the original identity; only verified no-effect closure can enable a distinct linked continuation for that step.

Availability is subordinate to uncertain-effect safety. Reconciliation must be schedulable, observable and bounded per attempt; persistent uncertainty remains a retained operator-visible state. It must never be repaired by deleting the row, refunding authority automatically, changing an operation key or weakening policy.
