# Ship Blocker Ladder

Date: 2026-04-15
Owner: Release-truth and shipping-decision boundary

## Purpose

This memo turns the current review package into one concrete release decision
surface.

The earlier remediation memos explain the individual holes. This memo answers a
different question:

1. What must be fixed before ARC can be shipped honestly as **bounded ARC**?
2. What must be fixed before ARC can ship **stronger security claims**?
3. What must be fixed before ARC can ship the **comptroller thesis**?

It is intentionally strict. A blocker can be cleared in only three ways:

- implement the missing machinery
- gate or disable the affected surface
- narrow the public claim until it matches the shipped evidence boundary

Anything else is just wording drift.

## Current Position

The recent `v3.12` through `v3.17` work materially improved ARC:

- bounded protocol-aware cross-protocol execution is real
- the kernel-backed HTTP authority path is real
- the economic/control-plane surface is large and serious
- the example suite is now strong enough to teach the product honestly
- the repo now has an explicit local boundary of **comptroller-capable**
  software rather than a proved market position

The project is therefore close to shipping **one honest version of ARC**.

The current tree is **not** yet pristine enough to ship the strongest story.
The live gaps fall into three classes:

- core runtime invariants that are still weaker than the public claim
- hosted/distributed/economic semantics that are still bounded rather than
  strongest-form
- release-truth drift across README, review, qualification, and planning state

Examples of current drift in the tree:

- `README.md` still carries `Lean 4 verified` branding and says ARC achieves
  its guarantee through a "formally verified protocol specification"
  (`README.md:27`, `README.md:45`)
- `docs/COMPETITIVE_LANDSCAPE.md` still says `P1-P5 are proven in Lean 4`
  (`docs/COMPETITIVE_LANDSCAPE.md:459`)
- `PROJECT.md` says the latest completed milestone is `v3.17`, while
  `REQUIREMENTS.md` still says `v3.16`
  (`.planning/PROJECT.md:22`, `.planning/REQUIREMENTS.md:4`)
- `STATE.md` says `v3.17` is complete locally but still contains stale
  "plan and execute `v3.17`" style next-step text
  (`.planning/STATE.md:27`, `.planning/STATE.md:183-191`)

Those are not the only problems, but they are representative of the current
state: the substrate is increasingly real, but the release boundary still needs
to be tightened.

## Priority Model

### P0

Must be resolved before shipping the named claim boundary. A P0 can be cleared
either by implementation or by explicit downgrade of the affected feature or
claim.

### P1

Must be resolved before shipping the stronger version of the story. P1 items
may coexist with a bounded release only if the release docs explicitly mark the
surface as compatibility-only, experimental, local-only, or otherwise bounded.

### P2

Should be resolved before calling the release pristine. P2 items are often
release-hygiene, commercial-hardening, or cross-surface coherence issues rather
than immediate catastrophic runtime failures, but they still matter if the
goal is a reviewer-clean and externally legible ship.

## Interpretation Rule

This memo is not permission to keep strong wording while punting the underlying
work.

If a blocker remains open, one of the following must happen:

- the claim disappears
- the surface is demoted or fenced
- the missing machinery is implemented and qualified

## Release Tracks

### Track A: Ship Bounded ARC

Target claim:

> ARC is a bounded, cryptographically signed governance and evidence control
> plane with real protocol mediation, real budgeted authorization, real
> receipts, and bounded operator/economic control surfaces.

This track does **not** include:

- full recursive delegated-authority claims
- verifier-backed runtime-attestation claims
- full non-repudiation / transparency-log claims
- consensus-grade HA claims
- proved comptroller-of-the-agent-economy claims

### Track B: Ship Stronger Security Claims

Target claim:

> ARC's strongest security-sensitive control surfaces are enforced by runtime
> invariants rather than mostly by documentation boundaries.

This track includes:

- verified or tightly bounded proof language
- runtime-enforced delegation semantics
- verified provenance classes
- stronger sender-constrained identity continuity
- verifier-backed runtime assurance
- stronger hosted/distributed safety claims

### Track C: Ship the Comptroller Thesis

Target claim:

> ARC is not only comptroller-capable software, but the right control-plane
> substrate to support comptroller-grade agent-economy operations.

This track still does **not** prove a market position by repo evidence alone.
That final step requires external operator adoption and partner dependence.

## Track A: Must-Fix Before Shipping Bounded ARC

### P0-A1: Claim discipline and release truth

**Why it blocks**

If ARC ships boundedly but still markets itself with stronger formal-proof,
non-repudiation, universal-authentication, or comptroller language, the ship is
not honest. This is the fastest way to destroy reviewer trust.

**Current evidence**

- `README.md` still carries `Lean 4 verified` and "formally verified protocol
  specification" language (`README.md:27`, `README.md:45`)
- `docs/COMPETITIVE_LANDSCAPE.md` still says `P1-P5 are proven in Lean 4`
  (`docs/COMPETITIVE_LANDSCAPE.md:459`)
- the review package itself says the interpretation rule is "either narrow the
  public claim or implement the missing machinery" (`docs/review/README.md:56-59`)
- milestone and planning truth still drift (`.planning/PROJECT.md:22`,
  `.planning/REQUIREMENTS.md:4`, `.planning/STATE.md:183-191`)

**Primary remediation docs**

- `docs/review/01-formal-verification-remediation.md`
- `docs/review/12-standards-positioning-remediation.md`

**Acceptable ship exits**

- remove or qualify the strongest formal-proof language
- align README, qualification docs, competitive docs, and planning state to one
  bounded release story
- explicitly publish what ARC is **not** claiming in the ship boundary

**Not acceptable**

- keeping overclaiming copy because a narrower caveat exists somewhere else
- treating planning-state drift as harmless because the code is further along

### P0-A2: Delegated authority must either be runtime-enforced or demoted

**Why it blocks**

Bounded ARC can ship without the strongest recursive-delegation claim, but it
cannot honestly talk as if runtime admission already enforces full delegation
chain validity, attenuation, and lineage completeness when the hot path does
not.

**Current evidence**

- helper validators exist in
  `crates/arc-core-types/src/capability.rs:1218-1268`
- the live kernel path still reduces revocation to the leaf plus the presented
  chain IDs in `crates/arc-kernel/src/kernel/mod.rs:2049`
- the dedicated review memo still describes the runtime as not invoking
  `validate_delegation_chain` or `validate_attenuation` at admission time
  (`docs/review/02-delegation-enforcement-remediation.md:26-54`)

**Primary remediation doc**

- `docs/review/02-delegation-enforcement-remediation.md`

**Acceptable ship exits**

- implement a real fail-closed lineage verifier in the kernel
- or narrow the ship boundary to root-issued / authority-reissued capability
  semantics and remove strong recursive delegation language

**Not acceptable**

- keeping "revocation cascades through the entire delegation chain" style
  language while trusting caller-presented lineage metadata

### P0-A3: Hosted/authenticated surfaces need named security profiles

**Why it blocks**

Bounded ARC can ship with hosted HTTP and session reuse, but only if the
release names the security profile honestly. Today the repo still risks reading
like sender-constrained identity continuity is universal when it is not.

**Current evidence**

- DPoP is optional per grant, not universal
  (`docs/review/06-authentication-dpop-remediation.md:1-49`)
- session reuse compares only transport plus a narrow identity tuple
  (`crates/arc-cli/src/remote_mcp/oauth.rs:829`)
- the session-isolation memo is explicit that strong non-interference does not
  yet follow from `shared_hosted_owner`
  (`docs/review/09-session-isolation-remediation.md:1-84`)

**Primary remediation docs**

- `docs/review/06-authentication-dpop-remediation.md`
- `docs/review/09-session-isolation-remediation.md`

**Acceptable ship exits**

- ship only a named conservative profile as the default and recommended mode:
  dedicated session runtime, explicit sender-constrained requirements, exact
  reuse semantics
- or mark shared-owner / privilege-shrink-sensitive flows as compatibility-only

**Not acceptable**

- describing stolen capabilities as generally worthless
- describing shared hosted ownership as strong multi-tenant isolation

### P0-A4: Governed provenance must be typed or downgraded

**Why it blocks**

ARC can sign local observations today. It cannot yet sign caller-supplied
cross-request provenance as if it were authenticated upstream truth.

**Current evidence**

- `call_chain` metadata is preserved into signed receipts, but the provenance
  memo still says it is not an authenticated upstream chain
  (`docs/review/04-provenance-call-chain-remediation.md:1-56`)
- the current strong claim boundary therefore outruns what receipts actually
  prove

**Primary remediation doc**

- `docs/review/04-provenance-call-chain-remediation.md`

**Acceptable ship exits**

- add `asserted` / `observed` / `verified` provenance classes and expose them
  explicitly
- or downgrade all governed call-chain language to "preserved caller context"

**Not acceptable**

- reviewer-pack or authorization-context language that treats preserved
  `call_chain` metadata as already authenticated cross-kernel truth

### P0-A5: Bounded ARC must ship on bounded operational profiles

**Why it blocks**

The repo can ship bounded ARC on local or single-writer truth. It cannot ship
bounded ARC honestly if the release default language sounds like HA trust
control, distributed budgets, or transparency-grade receipt publication are
already solved.

**Current evidence**

- the HA memo says the cluster is deterministic leader selection plus repair,
  not consensus (`docs/review/07-ha-control-plane-remediation.md:1-67`)
- the budget memo says the money path is a per-node counter with an HA overrun
  bound rather than a distributed spending invariant
  (`docs/review/08-distributed-budget-remediation.md:1-74`)
- the non-repudiation memo says the receipt plane is still operator-local audit
  evidence rather than a true transparency service
  (`docs/review/05-non-repudiation-remediation.md:1-67`)

**Primary remediation docs**

- `docs/review/05-non-repudiation-remediation.md`
- `docs/review/07-ha-control-plane-remediation.md`
- `docs/review/08-distributed-budget-remediation.md`

**Acceptable ship exits**

- declare the recommended bounded ship profile as:
  - local or leader-local control-plane truth
  - bounded failover/repair rather than consensus
  - local budget atomicity rather than distributed linearizability
  - signed audit evidence rather than public append-only transparency
- keep the broader cluster surfaces explicitly non-GA or operationally bounded

**Not acceptable**

- generic "HA clustered control plane" or "atomic budget enforcement" language
  without one named bounded profile

### P1-A1: Runtime attestation should not be sold as verifier-backed end to end

**Why it matters**

Bounded ARC can ship with verifier adapters and normalized runtime-attestation
support, but not with the strongest verifier-backed-runtime language as long as
issuance and admission still accept caller-supplied normalized evidence.

**Current evidence**

- capability issuance still accepts `RuntimeAttestationEvidence` directly
  (`crates/arc-cli/src/issuance.rs:122`)
- effective runtime assurance is still computed over that normalized object
  (`crates/arc-cli/src/issuance.rs:397`)
- the runtime-attestation memo calls this out directly
  (`docs/review/03-runtime-attestation-remediation.md:7-39`)

**Primary remediation doc**

- `docs/review/03-runtime-attestation-remediation.md`

**Acceptable bounded ship**

- keep runtime attestation framed as verifier adapters, appraisal/report
  surfaces, and bounded local trust policy

**Required before stronger claim**

- move kernel admission to locally verified records only

### P1-A2: Non-repudiation language must stay narrower than transparency language

**Why it matters**

Bounded ARC can ship signed receipts and checkpointed audit evidence, but not
public append-only ledger or non-repudiation rhetoric in the strongest sense.

**Primary remediation doc**

- `docs/review/05-non-repudiation-remediation.md`

### P1-A3: Shared-owner hosted mode must remain clearly compatibility-bounded

**Why it matters**

The hosted surface can ship now, but shared-owner reuse should remain profile-C
style compatibility/performance behavior unless the verified multi-session
runtime contract is implemented.

**Primary remediation doc**

- `docs/review/09-session-isolation-remediation.md`

### P2-A1: Release hygiene and planning-state parity

**Why it matters**

This does not usually create an immediate exploit, but it does create release
confusion, audit drag, and external reviewer distrust.

**Current evidence**

- `PROJECT.md`, `REQUIREMENTS.md`, and `STATE.md` still disagree about the
  latest completed milestone and next action

**Acceptable exit**

- reconcile live planning files to the actual post-`v3.17` state

## Track B: Must-Fix Before Shipping Stronger Security Claims

This section assumes ARC wants to say more than bounded ARC, for example:

- stronger formal-verification posture
- stronger recursive delegation semantics
- stronger provenance claims
- verifier-backed runtime assurance
- stronger hosted multi-tenant and HA safety claims

### P0-B1: Define and enforce one verified-core claim boundary

**Blocker**

ARC cannot ship stronger security language until the formal-verification story
is reduced to one audited proof boundary, one theorem inventory, and one set of
allowed public phrases.

**Primary remediation docs**

- `docs/review/01-formal-verification-remediation.md`
- `docs/review/12-standards-positioning-remediation.md`

**Required state**

- a bounded verified core
- a proof manifest
- approved claim text
- removal of the current "Lean 4 verified" drift outside that boundary

### P0-B2: Make delegation enforcement a runtime admission invariant

**Blocker**

Stronger security claims are impossible while delegation enforcement is still
mostly helper-level and documentation-level rather than a fail-closed kernel
acceptance condition.

**Primary remediation doc**

- `docs/review/02-delegation-enforcement-remediation.md`

### P0-B3: Make sender-constrained identity continuity real

**Blocker**

ARC cannot honestly say stolen capabilities are useless or that caller identity
continuity is robust across hosted surfaces until sender-constrained semantics,
subject binding, and replay resistance are named and enforced consistently.

**Primary remediation doc**

- `docs/review/06-authentication-dpop-remediation.md`

### P0-B4: Make runtime assurance depend on verified records, not raw evidence

**Blocker**

The stronger runtime-security story is blocked until the kernel consumes only
locally verified attestation records or locally re-admitted imported appraisal
results.

**Primary remediation doc**

- `docs/review/03-runtime-attestation-remediation.md`

### P0-B5: Separate asserted provenance from verified provenance

**Blocker**

Stronger reviewer-pack, federation, and call-chain truth claims require a typed
provenance model. Without that, ARC is still signing a mixture of local facts
and caller assertions as if they had the same evidentiary weight.

**Primary remediation doc**

- `docs/review/04-provenance-call-chain-remediation.md`

### P1-B1: Move from signed audit evidence to real transparency semantics

**Blocker**

If ARC wants non-repudiation / append-only / CT-style language, it needs:

- anchored key identity
- append-only continuity
- anti-equivocation
- stronger publication semantics

**Primary remediation doc**

- `docs/review/05-non-repudiation-remediation.md`

### P1-B2: Name and enforce hosted isolation profiles

**Blocker**

If ARC wants stronger multi-client hosted-security claims, it needs:

- exact auth-continuity checks
- named dedicated / verified-multi-session / legacy-shared profiles
- stronger shared-upstream non-interference guarantees

**Primary remediation doc**

- `docs/review/09-session-isolation-remediation.md`

### P1-B3: Replace HA rhetoric with quorum-committed truth or keep it bounded

**Blocker**

If ARC wants stronger distributed-security or trust-root claims, the control
plane needs:

- quorum-committed writes
- stale-leader fencing
- non-replicated root secrets or HSM-backed authority custody

**Primary remediation doc**

- `docs/review/07-ha-control-plane-remediation.md`

### P1-B4: Replace replicated counters with immutable authorization events

**Blocker**

If ARC wants stronger distributed budget / spend invariants, it needs:

- authorization-event truth
- explicit hold/capture/release states
- linearizable or escrow-style distributed budget semantics

**Primary remediation doc**

- `docs/review/08-distributed-budget-remediation.md`

### P2-B1: Close the documentation, qualification, and example gap for every strong claim

**Blocker**

A stronger security release also needs:

- claim-to-test traceability
- examples that do not overteach deprecated or bounded modes
- qualification docs that speak with one voice about what is proven,
  differentially tested, runtime-verified, or bounded

## Track C: Must-Fix Before Shipping the Comptroller Thesis

This section assumes ARC wants to say more than "bounded ARC" or "comptroller-
capable software." It assumes ARC wants to build toward a real comptroller
thesis.

### P0-C1: Economic authorization must bind the real economic parties

**Blocker**

ARC cannot ship the stronger economic-control story while payment
authorization still binds:

- `payer = request.agent_id`
- `payee = request.server_id`

rather than real payer accounts, merchant identity, payee settlement
destinations, and the governed intent/quote/rail actually being authorized.

**Current evidence**

- kernel payment authorization still binds `payer` and `payee` this way
  (`crates/arc-kernel/src/kernel/mod.rs:2260`)
- the payment request shape is still too thin for stronger merchant/liability
  truth (`crates/arc-kernel/src/payment.rs:86`)

**Primary remediation doc**

- `docs/review/10-economic-authorization-remediation.md`

**Required state**

- canonical economic-party identities
- cryptographic merchant/payee binding
- rail/asset/quote/settlement binding
- truthful separation between budget truth, payment authorization truth,
  settlement truth, and liability truth

### P0-C2: The market-position thesis remains blocked by external proof

**Blocker**

Even after repo-local implementation work, ARC cannot honestly claim a proved
comptroller-of-the-agent-economy market position without external dependency.

**Current evidence**

- `docs/release/QUALIFICATION.md` explicitly limits the current local claim to
  comptroller-capable software and excludes a proved market position
  (`docs/release/QUALIFICATION.md:54-55`, `docs/release/QUALIFICATION.md:89-103`)
- `docs/release/ARC_COMPTROLLER_FEDERATED_PROOF.md` and related `v3.17`
  artifacts package local proof, not market dependence

**Required state**

- multiple independent operators running ARC in production
- partner-visible receipt / settlement contract reliance
- federated multi-operator evidence that is not just repo-local packaging
- evidence that turning ARC off would break real coordination, settlement,
  billing, or partner acceptance

**Important rule**

This is not a code-only blocker. It is a product, ecosystem, and operations
blocker.

### P1-C1: Reputation and federation must become stronger than bounded artifact portability

**Blocker**

The current portability layer is still bounded local truth plus conservative
import. That is the right current design, but it is not yet a strong networked
trust substrate.

**Primary remediation doc**

- `docs/review/11-reputation-federation-remediation.md`

**Required state**

- stronger issuer independence
- bounded but real subject continuity
- stronger Sybil-resistance machinery
- stronger federation activation and clearing semantics

### P1-C2: HA budgets and settlement semantics must support economic truth, not just control hints

**Blocker**

The comptroller story cannot rest on local counters and best-effort repair.
Distributed economic truth needs stronger hold/capture/release and settlement
state semantics.

**Primary remediation docs**

- `docs/review/08-distributed-budget-remediation.md`
- `docs/review/10-economic-authorization-remediation.md`

### P2-C1: Commercial and reviewer packaging must stay narrower than legal or market reality

**Blocker**

Before shipping any stronger economic narrative, ARC must continue to prevent
drift from:

- governed evidence -> payment finality
- settlement evidence -> liability determination
- software capability -> proved market position

This is mostly claim-discipline and reviewer-packaging work, but it matters
because commercial overreach is one of the fastest ways to invalidate a strong
technical story.

## Consolidated Blocker Matrix

| ID | Priority | Blocks | Topic | Primary doc |
| --- | --- | --- | --- | --- |
| A1 | P0 | bounded ARC | claim discipline and release truth | `01`, `12` |
| A2 | P0 | bounded ARC | delegation enforcement or downgrade | `02` |
| A3 | P0 | bounded ARC | hosted/auth profile truth | `06`, `09` |
| A4 | P0 | bounded ARC | provenance typing or downgrade | `04` |
| A5 | P0 | bounded ARC | bounded operational profile containment | `05`, `07`, `08` |
| A1b | P1 | bounded ARC polish | verifier-backed attestation wording | `03` |
| A2b | P1 | bounded ARC polish | non-repudiation wording | `05` |
| A3b | P1 | bounded ARC polish | shared-owner isolation claims | `09` |
| A4b | P2 | bounded ARC polish | planning/release hygiene parity | current tree |
| B1 | P0 | stronger security claims | verified-core proof boundary | `01`, `12` |
| B2 | P0 | stronger security claims | runtime delegation invariant | `02` |
| B3 | P0 | stronger security claims | sender-constrained identity continuity | `06` |
| B4 | P0 | stronger security claims | verified-record attestation path | `03` |
| B5 | P0 | stronger security claims | asserted vs verified provenance | `04` |
| B6 | P1 | stronger security claims | transparency-log semantics | `05` |
| B7 | P1 | stronger security claims | hosted isolation profiles | `09` |
| B8 | P1 | stronger security claims | HA control plane and key custody | `07` |
| B9 | P1 | stronger security claims | distributed budget invariants | `08` |
| C1 | P0 | comptroller thesis | economic-party and rail binding | `10` |
| C2 | P0 | comptroller thesis | external market proof | `v3.17` claim boundary |
| C3 | P1 | comptroller thesis | stronger federation / portability / Sybil resistance | `11` |
| C4 | P1 | comptroller thesis | distributed economic truth | `08`, `10` |
| C5 | P2 | comptroller thesis polish | commercial/reviewer claim discipline | `10`, `11`, `12` |

## Practical Ship Guidance

### If the goal is to ship bounded ARC soon

Do these first:

1. fix claim drift and planning/release truth
2. either implement or explicitly downgrade recursive delegation claims
3. name hosted/auth security profiles honestly
4. type or downgrade governed provenance
5. publish one bounded operational profile for trust control, budgets, and
   receipts

### If the goal is to ship stronger security claims

Do not skip straight to marketing. First:

1. define the verified core
2. enforce delegation and provenance at runtime
3. require sender-constrained identity continuity on the strong path
4. move runtime assurance to verified records
5. only then revisit non-repudiation / HA / distributed-budget rhetoric

### If the goal is to ship the comptroller thesis

Assume two parallel workstreams:

1. repo-local machinery:
   - economic binding
   - settlement semantics
   - federation hardening
2. external proof:
   - real operators
   - real partner-visible contracts
   - real cross-org dependence

Without both, the honest claim remains:

> ARC is comptroller-capable software, not a proved comptroller market
> position.

## Bottom Line

ARC is close to shipping one honest and impressive product boundary.

That boundary is not "everything the repo has ever hinted at." It is the
bounded control-plane story backed by the current code.

To make the project pristine:

- clear every Track A P0 before bounded ship
- clear every Track B P0 and P1 before stronger security ship
- clear every Track C P0 and P1, and then add external market proof, before
  claiming the comptroller thesis

The important discipline is simple:

- bounded ARC is near
- stronger security claims are still blocked by real runtime and proof work
- the comptroller thesis is blocked by both repo work and external proof
