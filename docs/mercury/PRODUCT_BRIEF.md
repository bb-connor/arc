# MERCURY: Review-Grade Evidence for Governed AI Trading Workflows

**Product Brief**  
**Date:** 2026-04-02

---

## 1. What MERCURY Is

MERCURY is the first finance-specific product layer built on ARC. It packages
ARC's rights-and-receipts substrate into a review-grade evidence platform for
governed AI trading workflows.

MERCURY produces signed, tamper-evident evidence records that bind a workflow
decision to:

- identity and authorization context
- policy and model configuration
- retained source artifacts
- recorded approvals and control outcomes
- later verification through signed checkpoints and proofs

The first product release is designed for:

- supervised AI-assisted trading workflows
- AI change-control and release attestation
- rollback and exception-review evidence
- supervisory control evidence for approvals and overrides
- incident reconstruction and inquiry packaging
- shadow-mode, replay, paper-trading, and controlled supervised-live pilots

MERCURY is not a replacement for OMS/EMS platforms, surveillance systems,
reporting systems, or model governance programs. It is the evidence layer that
connects those systems into a portable, verifiable record of what happened.

---

## 2. The Problem

### AI influence is growing faster than decision evidence

Trading firms are already using AI in research, execution recommendation,
workflow triage, approval preparation, parameter selection, and policy-bound
automation. In many cases, AI is materially influencing outcomes even when a
human or OMS remains in the formal decision chain.

That creates a new evidentiary gap.

When a workflow is questioned, firms struggle to reconstruct:

- which model or workflow version was active
- what policy and limits were in force
- which artifacts or market context informed the decision
- what approvals or checks ran
- how to prove the record was not altered later

### Existing systems are fragmented

Current control evidence is usually spread across:

- application logs
- model traces
- OMS or broker records
- surveillance alerts
- policy documents
- ticketing systems and human approvals

Each source is useful, but there is rarely one portable, decision-level record
that binds them together.

### Buyers need stronger review infrastructure now

The near-term demand is not for a magical compliance box. The real demand is
for stronger evidence that helps:

- compliance investigate
- trading infrastructure teams reconstruct incidents
- risk teams review exceptions
- workflow owners approve or reject rollout changes with confidence

The sharpest initial workflow is narrower than broad governed-workflow
coverage. It is the point where a model, prompt, policy, routing rule, or
parameter change requires:

- release approval
- rollback authorization
- exception review
- supervisory sign-off
- later incident reconstruction if something goes wrong

---

## 3. Why Now

Three conditions make the category timely.

### AI adoption is real inside trading workflows

Firms no longer need to believe in fully autonomous trading to care about this
problem. AI is already influencing decisions in ways that existing record and
supervision systems were not designed to explain.

### Supervisory expectations are rising

Regulatory materials remain technology-neutral, but they consistently emphasize:

- governance
- documentation
- monitoring
- human oversight
- reliable records

Firms need better evidence of how AI was used even when no rule explicitly
requires cryptographic attestation.

### Existing categories do not own the evidence layer

TCA, surveillance, and LLM observability solve adjacent problems. None of them
is purpose-built to create signed, review-grade decision provenance for
governed AI trading workflows.

---

## 4. Product Definition

### Core product

MERCURY records a canonical evidence object for each relevant workflow action.
The highest-value first records are the ones surrounding:

- model, prompt, policy, or parameter release
- approval
- override
- exception
- rollback
- incident reconstruction

That record can include:

- decision type: propose, approve, deny, rollback, release, simulate, observe
- account, desk, workflow, and strategy identifiers
- model identifier, workflow version, and policy hash
- model provider and hosting provenance
- approval metadata and control outputs
- references to retained evidence bundles
- source-system identifiers for reconciliation

### Evidence bundles

Receipts can reference retained artifacts such as:

- prompts or workflow inputs
- order intent objects
- OMS acknowledgements or drop-copy events
- approval records
- market-context artifacts
- policy snapshots or exception tickets

The receipt does not need to carry every raw artifact inline. It needs to bind
those artifacts to a signed record in a way a later verifier can check.

### Verification and inquiry packaging

MERCURY signs receipts, commits them into checkpoints, and exposes the proof
material needed for later verification. A reviewer can confirm:

- the record body was signed by the expected key
- the record was committed into the published checkpoint chain
- retained artifacts match the references embedded in the record

The first commercial packaging should not stop at raw proof. MERCURY also
builds inquiry-ready exports on top of that proof:

- `Proof Package v1` for verifier-equivalent technical review
- `Inquiry Package v1` for reviewed internal, client, auditor, or regulator
  disclosures

---

## 5. Proof Boundary

MERCURY is strongest when its proof boundary is explicit.

### What MERCURY can prove

- a specific key signed a specific record
- the record contained a specific set of metadata and references
- the record was later committed into a published checkpoint
- retained artifacts match their referenced hashes or identifiers
- configured checks or approvals produced the recorded results
- an exported inquiry package corresponds to a specific proof package and
  approved disclosure state

### What MERCURY does not prove by itself

- that a market-data snapshot was complete or exchange-authoritative
- that a broker, venue, or OMS response was economically correct
- that best execution was achieved
- that a policy was adequate
- that the firm's overall governance program was sufficient
- that no activity occurred outside the trusted system boundary

That distinction is central to product credibility.

---

## 6. Deployment Model

MERCURY supports three deployment patterns.

| Mode | Description | Product status |
|------|-------------|----------------|
| Shadow / replay | Generate evidence from replayed, synthetic, or paper-trading workflow events | Core release path |
| Supervised live workflow | Capture evidence for a production workflow while keeping existing execution systems in place | Supported after pilot validation |
| Mediated in-line control | Put ARC directly in the live authorization path for selected actions | Expansion path |

The first product release centers on change-review, release, rollback, and
inquiry evidence in the first mode, with a path to supervised-live production
for the same workflow when a buyer funds that step.

---

## 7. Target Buyers

### First buyers

The best early customers are firms that already have AI influencing a trading
workflow and already run formal change, review, or exception processes.

That usually means:

- bank electronic trading platform teams
- broker-dealer workflow engineering groups
- algo or control-program owners with formal rollout gates
- selective systematic firms with meaningful human-in-the-loop review

### Buying committee

The typical buyer group includes:

- a technical champion in platform, workflow, or control engineering
- a compliance or risk stakeholder who cares about proof boundaries
- an operational owner who approves releases, rollbacks, or exception handling
- a business owner who can sponsor a paid pilot

### Later segments

After initial deployment, MERCURY can expand into:

- supervised-live productionization of the same workflow
- governance workflows for broader control programs
- downstream review, archive, surveillance, and case-management connectors
- assurance workflows for clients, allocators, auditors, and regulators
- embedded OEM distribution, trust-network services, and companion products
  such as ARC-Wall

---

## 8. Competitive Position

MERCURY sits between several established categories.

| Category | What it does well | Where MERCURY differs |
|----------|-------------------|-----------------------|
| Archive / communications compliance | Retention and supervision | MERCURY adds workflow-native proof, causal linkage, and verifier-equivalent exports |
| Surveillance | Pattern detection and alerting | MERCURY creates evidence closer to the workflow decision and release process |
| LLM observability | Prompt, trace, and debug tooling | MERCURY emphasizes signed, portable, inquiry-grade records |
| OMS / EMS | Execution workflow ownership | MERCURY adds neutral evidence publication across systems |
| In-house logging | Low-cost trace capture | MERCURY adds integrity, publication, and verification discipline |

The positioning is not "replace these systems." The positioning is "provide the
evidence substrate they currently lack."

---

## 9. Why ARC Matters

MERCURY is viable because ARC already provides:

- receipt structures
- capability and delegation primitives
- signing and checkpoint mechanics
- verification foundations
- the broader rights-and-receipts thesis that MERCURY commercializes first in
  finance

That allows MERCURY to focus on the trading-specific evidence model, source
artifact retention, reconciliation, trust distribution, and buyer-facing
verification surfaces instead of rebuilding foundational cryptography.

---

## 10. Product Progression

The product program is staged intentionally.

1. **Change-control and inquiry wedge**
   - signed release, rollback, approval, and exception records
   - retained evidence bundles
   - `Proof Package v1` and `Inquiry Package v1`
2. **Supervised-live productionization**
   - the same workflow moves from replay or shadow into controlled production
3. **Governance, downstream, and assurance expansion**
   - broader governed workflows
   - archive, review, and surveillance connectors
   - reviewer-facing assurance packages
4. **Embedded distribution and companion products**
   - OEM or embedded evidence distribution
   - trust-network services
   - ARC-Wall

This progression keeps the first release commercially useful and technically
credible while preserving expansion options.

---

## Summary

MERCURY is not a generic AI governance product and it is not a trading system.
It is the first finance-specific commercialization of ARC's rights-and-receipts
substrate: signed, reconstructable, portable, and verifiable evidence for
governed AI trading workflows. The sharpest first use case is change control,
release attestation, and inquiry packaging, which then opens the path to
supervised-live deployment, governance, downstream distribution, and broader
ARC product expansion.
