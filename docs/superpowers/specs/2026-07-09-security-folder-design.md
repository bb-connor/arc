# Design: `crates/security/` active-defense arc

- Status: DRAFT (awaiting review)
- Date: 2026-07-09
- Scope: three new crates under a new `crates/security/` folder, plus protocol-type additions in `chio-core-types` and `chio-manifest`.
- Related normative docs: `spec/PROTOCOL.md`, `spec/SECURITY.md`, `spec/GUARDS.md`, `docs/security/threat-coverage.md`.

## 1. Summary

Chio today is almost entirely a preventive system. Guards deny at the call boundary, capabilities scope what an agent may reach, and receipts attest every decision. It has advisory and anomaly signals but no response limb, and it has no deception layer. This design adds an active-defense arc that closes that loop: detect leak paths, bait intruders into revealing themselves, and respond with attested, reversible containment.

Three crates:

- `chio-flow` (detect): information-flow control. Lattice labels propagate along the data path; egress is denied unless the destination clearance dominates the join of everything tainting the agent context. Declassification is an explicit, capability-gated, receipt-logged event.
- `chio-decoy` (deceive): canary capabilities and honey-tools that no legitimate agent path touches, plus per-session honeytoken watermarks. Any interaction is malicious by construction.
- `chio-quarantine` (respond): a declarative response engine that composes existing revocation, velocity, and issuance primitives into tiered, reversible, signed containment actions.

The arc forms one loop: `chio-flow` and `chio-decoy` detect, `chio-quarantine` responds, and every step is a signed receipt.

## 2. Goals and non-goals

Goals:

- Add information-flow control with a full Decentralized Label Model (DLM) label algebra, seeded from existing sources so no hand-authoring is required to adopt it.
- Add a deception primitive (the canary capability) that produces zero-false-positive detections.
- Add attested, tiered, reversible incident response that reuses existing containment primitives rather than inventing new ones.
- Keep the trusted computing base (TCB) unchanged in posture: prevention stays fail-closed and independent; response is best-effort and fully attested.
- Provide the mechanisms that make five currently-uncovered threat rows closable, without claiming closure.

Non-goals:

- This design does not itself close any threat-model row. A row moves to `Covered` only with the conformance test plus caught-mutant evidence that `docs/security/threat-coverage.md` gates on.
- No ML-based anomaly scoring (advisory and embedding-anomaly guards already exist in `crates/guards/`).
- No new attestation verifier or signature scheme (those live in `crates/trust/`).
- No OS-level sandbox compilation (that is a separate candidate, `chio-cage`, deferred out of this arc).

## 3. Background: what already exists

Relevant existing surfaces this design builds on rather than duplicates:

- Data classification and redaction: `crates/guards/chio-data-guards` classifies secrets, PII, and PHI (including ICD-10 and MRN).
- Cumulative flow accounting: `DataFlowGuard` in `crates/guards/chio-guards` tracks bytes read and written per session.
- Provenance: `crates/observability/chio-lineage` maintains a signed receipt and capability-lineage DAG.
- Capability tokens: `crates/core/chio-core-types` carries id (UUIDv7), issuer, subject, scope, TTL, delegation chain, typed caveats, scope attenuations, and budget shares.
- Revocation: `crates/trust/chio-revocation-oracle` (epoch-based, sparse Merkle inclusion and non-inclusion proofs).
- Issuance rate limiting: `crates/trust/chio-custody-hw` (per-subject limiter, per-credential replay nonce store, revocation cascade).
- Velocity: `AgentVelocityGuard` token buckets in `crates/guards/chio-guards`.
- Swarm authority: `crates/kernel/chio-swarm-authority` tracks the task DAG, budget fan-out and fan-in, and continuation tokens.
- Reputation: `crates/trust/chio-reputation` already applies incident penalties.
- SIEM: `crates/observability/chio-siem` forwards receipt events and pages via OpsGenie and PagerDuty backends.
- Adversarial testing: `crates/core/chio-adversarial-suite` (eight attack classes) and `crates/core/chio-arena` (coevolutionary replay arena).

## 4. Folder and boundary design

New folder `crates/security/` with three members:

```
crates/security/
  chio-flow         information-flow control
  chio-decoy        deception / canaries
  chio-quarantine   incident response
```

Rationale for a new folder: the existing folders are organized by primitive kind. `guards/` holds per-call evaluators; `trust/` holds attestation primitives. These three crates are stateful, session-spanning, and reactive, which is a distinct concern.

Two placement rules:

1. Types go in core, engines go in security. The `Label` wire type, the `declassify` capability caveat, and the manifest `sensitivity` and `clearance` fields are protocol-normative and land in `chio-core-types` and `chio-manifest`. This mirrors how `ChioScope` lives in `chio-core-types` while enforcement lives in `crates/guards/`. The information-flow engine lives in `chio-flow`.

2. Prevention stays fail-closed and independent; response is best-effort and attested. `FlowGuard` runs inside the existing guard pipeline (in-TCB, like every guard). `chio-quarantine` sits above the kernel and drives containment through trait ports; it is deliberately not in the TCB. If quarantine is unavailable, prevention still holds and only automated response is lost. A compromised quarantine can fail to contain but cannot forge an allow.

Dependency direction (acyclic):

```
chio-core-types (Label, declassify caveat, receipt subtypes)
        |                         |                    |
        v                         v                    v
   chio-flow                 chio-decoy          chio-quarantine
                                                  (ports -> adapters ->
                                                   revocation-oracle,
                                                   custody-hw,
                                                   swarm-authority,
                                                   siem, guards)
```

## 5. chio-flow (detect)

Modules:

- `label`: DLM lattice operations over the `Label` type defined in `chio-core-types`. A label is a set of policies, each an (owner, readers) pair, plus orthogonal compartments (for example `pii`, `phi`, `secret`, `tenant:<id>`). Operations: `join` (least upper bound), `flows_to` (partial order). `L1 flows_to L2` holds when L2 is at least as restrictive as L1 for every owner and compartment. Restrictions may always be added; they may only be removed by declassification.
- `env`: the per-session taint environment, persisted in the existing kernel session journal. Tracks the current label set in the agent context as the join of everything read this session.
- `seed`: label acquisition. `from_classifier` maps `chio-data-guards` verdicts to compartments (Secret to `secret`, PII to `pii`, ICD-10 and MRN to `phi`). `from_manifest` reads the declared `sensitivity` of a tool output. These two sources seed labels so DLM adoption requires no hand-authoring; full owner and reader precision is available when wanted.
- `guard`: `FlowGuard`, implementing the existing guard trait so it plugs into the current pipeline. On an egress-classed call it computes `context_label` joined with `payload_label`, looks up the destination `clearance` from the manifest, and denies unless the join flows to the clearance. Fail-closed: an unknown label or missing clearance resolves to the top of the lattice (most restrictive), which denies.
- `declassify`: verifies that a `declassify` caveat on the presented capability authorizes downgrading the specific compartments requested, then emits a signed declassification receipt.
- `receipt`: `FlowViolation` and `Declassification` receipt bodies, serialized as canonical JSON (RFC 8785) and signed through the existing `chio-core` receipt machinery.

Core invariant: an egress-classed call is allowed only if `context_label join payload_label` flows to the destination clearance, or an authorized and attested declassification downgrades it. Because every downgrade is a signed event, slow exfiltration (many small below-threshold releases) becomes visible instead of invisible.

## 6. chio-decoy (deceive)

Modules:

- `canary`: mints canary capabilities. A canary is a fully valid, authority-signed `CapabilityToken` whose scope points into a reserved `decoy:*` namespace. It is indistinguishable from a real grant on the wire. A registry of canary ids (their UUIDv7) lets the kernel recognize presentation.
- `catalog`: injects honey-tools into the `list_tools` surface with realistic names, descriptions, and sensitivity labels that route to a sink.
- `watermark`: per-session honeytokens, derived deterministically from `session_id` and a secret so they are verifiable without storage. `emit` injects a watermark into a decoy response; `detect` scans egress payloads. A watermark hit is exposed to `chio-flow` as a label source (restricted plus tripwire).
- `tripwire`: the detection hook the kernel calls when a canary id is presented or a watermark is detected. Emits a distinguished high-severity `Tripwire` receipt and signals `chio-quarantine`.

Because legitimate workflows bind real tools by manifest, they never select a `decoy:*` grant, so any presentation or use of a canary is malicious by construction and carries zero false positives. A CI gate (`check-decoy-unreachable`) enforces that no real manifest binds a `decoy:*` grant, so the deception can never trap a legitimate agent.

## 7. chio-quarantine (respond)

Modules:

- `event`: the `SecurityEvent` stream, tapped from the receipt log. Deterministic and replayable. Sources include canary hits, flow violations, advisory-pipeline promotions, reputation incident penalties, deny storms, and velocity breaches.
- `playbook`: declarative rules of the form `when <trigger> within <window> then <actions>`, reusing the HushSpec parser style from `chio-policy`.
- `action`: the `ContainmentAction` enum and the tiered executor. Tier by reversibility:

  | Tier | Actions | Execution |
  |------|---------|-----------|
  | Auto-reversible | `Throttle`, `RevokeSession`, `QuarantineLineage`, `Escalate` | auto-execute, signed receipt, default TTL |
  | Heavy | `FreezeSubject`, `RevokeTenant`, `RequireCosign` | m-of-n human co-sign to apply and to extend past TTL |

  Every action is a signed `ContainmentReceipt` carrying a TTL, with an explicit signed `LiftOrder` to reverse it. Automated response can never permanently disable a tenant without a human renewing the state past its TTL.
- `ports`: traits over existing primitives, with thin adapters behind cargo features so the crate stays lean and unit-testable with fakes: `RevocationPort` (to `chio-revocation-oracle` epoch bump), `IssuancePort` (to `chio-custody-hw` limiter), `VelocityPort` (to `AgentVelocityGuard`), `AlertPort` (to `chio-siem`), `BlastRadiusPort` (to `chio-swarm-authority`).
- `blast`: given a triggering session or subject, computes the affected continuation-token subtree from `chio-swarm-authority` and scopes actions to exactly that subtree rather than the whole tenant.

Posture: the response engine is best-effort and fully attested, and is not part of the TCB.

## 8. Protocol deltas

Additions to normative surfaces (each needs `spec/PROTOCOL.md` and `spec/SECURITY.md` edits plus conformance vectors):

- `Label` wire type with canonical JSON (RFC 8785) encoding, added to `chio-core-types`.
- `declassify` caveat variant on capabilities, added to `chio-core-types`.
- `sensitivity` and `clearance` fields on manifest tool and resource declarations, added to `chio-manifest`.
- Five new receipt subtypes: `FlowViolation`, `Declassification`, `Tripwire`, `Containment`, `LiftOrder`.
- Canary recognition semantics: the kernel MUST deny and emit a `Tripwire` receipt on presentation of a capability in the `decoy:*` namespace.

## 9. Threat-model mapping

Framed as mechanisms that make rows closable, not as closures. A row moves to `Covered` only with a conformance test at `crates/tooling/chio-conformance/tests/threats/<id>.rs` and caught-mutant evidence at `audits/evidence/threats/<id>.json`, per `docs/security/threat-coverage.md`.

| Threat row | Current state | Mechanism this arc adds |
|------------|---------------|--------------------------|
| `cumulative_data_exfiltration` | Pending, zero corpus | `chio-flow` egress control plus attested declassification |
| `pii_phi_exposure` | Pending, zero corpus | `chio-flow` label seeding strengthens existing `ResponseSanitizationGuard` |
| `capability_token_theft` | Pending | `chio-decoy` canary capabilities give a detection path |
| `agent_velocity_abuse` | Pending, zero corpus | `chio-quarantine` dynamic throttle response |
| `behavioral_sequence_attack` | Pending, zero corpus | `chio-quarantine` response to `BehavioralSequenceGuard` triggers |

## 10. Testing and evidence

- Adversarial corpus: new classes in `chio-adversarial-suite` (`label_downgrade` for declassification without a caveat, `canary_evasion`, `containment_rollback`), wired into `chio-arena` coevolution.
- Conformance: tests per new receipt subtype and per invariant (flow egress dominance, canary deny-and-tripwire, containment reversibility).
- Fuzz: targets for the lattice operations (`join`, `flows_to`) and the playbook parser.
- Formal: a Kani or TLA property that the lattice is a partial order (reflexive, antisymmetric, transitive) with `join` as least upper bound, fitting the existing `formal/` scaffolding.

## 11. Release framing

Split per the project's roadmap-framing convention:

- Release gates (CI must enforce): `check-flow-invariants` (egress dominance holds on the conformance corpus), `check-decoy-unreachable` (no real manifest binds `decoy:*`), `check-containment-reversible` (every containment action has a lift path and a TTL).
- Implementation: the three crates plus the `chio-core-types` and `chio-manifest` type additions.
- External evidence: caught-mutant evidence for the mapped rows, conformance vectors, and the formal lattice property.

Claims stay bounded: this arc ships mechanisms and gates. Threat-row closure is asserted only when the coverage gate accepts the evidence.

## 12. Risks and open questions

- Egress classification accuracy. `FlowGuard` depends on the manifest correctly marking which tool calls are egress-classed. A mislabeled tool is a hole. Mitigation: default unmarked destinations to top clearance (deny), forcing explicit declaration.
- Declassification ergonomics. If too many workflows need declassify caveats, operators may over-grant them. Mitigation: declassification is per-compartment and receipt-logged, so over-granting is visible in audit.
- Playbook misfire. A bad trigger could throttle or revoke legitimately. Mitigation: tiering keeps auto actions reversible and TTL-bounded; heavy actions need co-sign.
- Label state growth. The per-session taint environment must be bounded. Mitigation: reuse the session journal lifecycle and cap label-set cardinality with a fail-closed overflow to top.

## 13. Crate manifest summary

| Crate | Folder | Depends on (new) | In TCB |
|-------|--------|------------------|--------|
| `chio-flow` | `crates/security` | `chio-core-types`, `chio-manifest`, guard trait | Yes (FlowGuard in pipeline) |
| `chio-decoy` | `crates/security` | `chio-core-types`, `chio-manifest` | Authority-adjacent (minting) |
| `chio-quarantine` | `crates/security` | `chio-core-types`, port traits | No (best-effort, attested) |
