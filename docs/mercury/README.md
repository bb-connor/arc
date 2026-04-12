# MERCURY Documentation Suite

MERCURY is the first finance-specific product layer built on ARC. ARC remains
the broader rights, receipts, and trust substrate for consequential agent
actions; MERCURY packages that substrate for regulated trading workflows where
buyers need review-grade evidence, controlled change records, and portable
inquiry exports.

The current product program centers on a sharp first wedge:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

That sentence is the canonical Phase 0-1 scope lock. Product, GTM, pilot, and
engineering docs should reuse it instead of widening into generic AI-governance
or connector-sprawl claims.

This suite is therefore both a product plan for MERCURY and a concrete example
of how ARC becomes a sellable vertical system without redefining ARC itself.

This suite is the canonical planning set for product, engineering, commercial,
security, and partner workstreams.

Before adding a new MERCURY lane or reading the later post-launch documents as
equal product surfaces, read [PRODUCT_SURFACE_AUDIT](PRODUCT_SURFACE_AUDIT.md).
It explains which parts of the repo are durable Mercury substrate and which
parts are repeated lane-specific packaging scaffolding.

---

## Start Here

Pick the reading path that matches your role.

- **Executive / investor:** [PRODUCT_BRIEF](PRODUCT_BRIEF.md) >
  [MARKET_SIZING](MARKET_SIZING.md) > [INVESTOR_NARRATIVE](INVESTOR_NARRATIVE.md) >
  [GO_TO_MARKET](GO_TO_MARKET.md)
- **Engineer / architect:** [TECHNICAL_ARCHITECTURE](TECHNICAL_ARCHITECTURE.md) >
  [PRODUCT_SURFACE_AUDIT](PRODUCT_SURFACE_AUDIT.md) >
  [IMPLEMENTATION_ROADMAP](IMPLEMENTATION_ROADMAP.md) >
  [SUPERVISED_LIVE_BRIDGE](SUPERVISED_LIVE_BRIDGE.md) >
  [GOVERNANCE_WORKBENCH](GOVERNANCE_WORKBENCH.md) >
  [ASSURANCE_SUITE](ASSURANCE_SUITE.md) >
  [EMBEDDED_OEM](EMBEDDED_OEM.md) >
  [TRUST_NETWORK](TRUST_NETWORK.md) >
  [RELEASE_READINESS](RELEASE_READINESS.md) >
  [CONTROLLED_ADOPTION](CONTROLLED_ADOPTION.md) >
  [REFERENCE_DISTRIBUTION](REFERENCE_DISTRIBUTION.md) >
  [BROADER_DISTRIBUTION](BROADER_DISTRIBUTION.md) >
  [DELIVERY_CONTINUITY](DELIVERY_CONTINUITY.md) >
  [RENEWAL_QUALIFICATION](RENEWAL_QUALIFICATION.md) >
  [SECOND_ACCOUNT_EXPANSION](SECOND_ACCOUNT_EXPANSION.md) >
  [PORTFOLIO_PROGRAM](PORTFOLIO_PROGRAM.md) >
  [SECOND_PORTFOLIO_PROGRAM](SECOND_PORTFOLIO_PROGRAM.md) >
  [../arc-wall/README](../arc-wall/README.md) >
  [PRODUCT_SURFACE_BOUNDARIES](PRODUCT_SURFACE_BOUNDARIES.md) >
  [SHARED_SERVICE_VERSION_PINNING](SHARED_SERVICE_VERSION_PINNING.md) >
  [CROSS_PRODUCT_GOVERNANCE](CROSS_PRODUCT_GOVERNANCE.md) >
  [CROSS_PRODUCT_RELEASE_MATRIX](CROSS_PRODUCT_RELEASE_MATRIX.md) >
  [TRUST_MATERIAL_RECOVERY_DRILL](TRUST_MATERIAL_RECOVERY_DRILL.md) >
  [OPERATOR_ALERT_ROUTING](OPERATOR_ALERT_ROUTING.md) >
  [epics/MASTER_PROJECT](epics/MASTER_PROJECT.md) >
  [TECHNICAL_FAQ](TECHNICAL_FAQ.md)
- **Compliance / legal:** [REGULATORY_POSITIONING](REGULATORY_POSITIONING.md) >
  [PRODUCT_BRIEF](PRODUCT_BRIEF.md) > [POC_DESIGN](POC_DESIGN.md) >
  [SUPERVISED_LIVE_OPERATING_MODEL](SUPERVISED_LIVE_OPERATING_MODEL.md) >
  [THREAT_MODEL](THREAT_MODEL.md)
- **Sales / partnerships:** [GO_TO_MARKET](GO_TO_MARKET.md) >
  [POC_DESIGN](POC_DESIGN.md) >
  [SUPERVISED_LIVE_QUALIFICATION_PACKAGE](SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md) >
  [SUPERVISED_LIVE_DECISION_RECORD](SUPERVISED_LIVE_DECISION_RECORD.md) >
  [GOVERNANCE_WORKBENCH_DECISION_RECORD](GOVERNANCE_WORKBENCH_DECISION_RECORD.md) >
  [ASSURANCE_SUITE_DECISION_RECORD](ASSURANCE_SUITE_DECISION_RECORD.md) >
  [EMBEDDED_OEM_DECISION_RECORD](EMBEDDED_OEM_DECISION_RECORD.md) >
  [TRUST_NETWORK_DECISION_RECORD](TRUST_NETWORK_DECISION_RECORD.md) >
  [RELEASE_READINESS_DECISION_RECORD](RELEASE_READINESS_DECISION_RECORD.md) >
  [CONTROLLED_ADOPTION_DECISION_RECORD](CONTROLLED_ADOPTION_DECISION_RECORD.md) >
  [REFERENCE_DISTRIBUTION_DECISION_RECORD](REFERENCE_DISTRIBUTION_DECISION_RECORD.md) >
  [BROADER_DISTRIBUTION_DECISION_RECORD](BROADER_DISTRIBUTION_DECISION_RECORD.md) >
  [DELIVERY_CONTINUITY_DECISION_RECORD](DELIVERY_CONTINUITY_DECISION_RECORD.md) >
  [RENEWAL_QUALIFICATION_DECISION_RECORD](RENEWAL_QUALIFICATION_DECISION_RECORD.md) >
  [SECOND_ACCOUNT_EXPANSION_DECISION_RECORD](SECOND_ACCOUNT_EXPANSION_DECISION_RECORD.md) >
  [PORTFOLIO_PROGRAM_DECISION_RECORD](PORTFOLIO_PROGRAM_DECISION_RECORD.md) >
  [SECOND_PORTFOLIO_PROGRAM_DECISION_RECORD](SECOND_PORTFOLIO_PROGRAM_DECISION_RECORD.md) >
  [PLATFORM_HARDENING_DECISION_RECORD](PLATFORM_HARDENING_DECISION_RECORD.md) >
  [PARTNERSHIP_STRATEGY](PARTNERSHIP_STRATEGY.md) >
  [COMPETITIVE_LANDSCAPE](COMPETITIVE_LANDSCAPE.md)
- **Security / verifier:** [THREAT_MODEL](THREAT_MODEL.md) >
  [VERIFIER_SDK_RESEARCH](VERIFIER_SDK_RESEARCH.md) >
  [TECHNICAL_ARCHITECTURE](TECHNICAL_ARCHITECTURE.md) >
  [SUPERVISED_LIVE_OPERATIONS_RUNBOOK](SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md) >
  [ARC_WALL_BRIEF](ARC_WALL_BRIEF.md) >
  [../arc-wall/README](../arc-wall/README.md) >
  [RELEASE_READINESS_VALIDATION_PACKAGE](RELEASE_READINESS_VALIDATION_PACKAGE.md) >
  [CONTROLLED_ADOPTION_VALIDATION_PACKAGE](CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md) >
  [REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE](REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md) >
  [DELIVERY_CONTINUITY_VALIDATION_PACKAGE](DELIVERY_CONTINUITY_VALIDATION_PACKAGE.md) >
  [RENEWAL_QUALIFICATION_VALIDATION_PACKAGE](RENEWAL_QUALIFICATION_VALIDATION_PACKAGE.md) >
  [SECOND_ACCOUNT_EXPANSION_VALIDATION_PACKAGE](SECOND_ACCOUNT_EXPANSION_VALIDATION_PACKAGE.md) >
  [PORTFOLIO_PROGRAM_VALIDATION_PACKAGE](PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md) >
  [SECOND_PORTFOLIO_PROGRAM_VALIDATION_PACKAGE](SECOND_PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md) >
  [PRODUCT_SURFACE_BOUNDARIES](PRODUCT_SURFACE_BOUNDARIES.md)

---

## Suite Map

| Area | Document | Purpose |
|------|----------|---------|
| Product | [PRODUCT_BRIEF.md](PRODUCT_BRIEF.md) | Canonical product definition, first wedge, buyer problem, proof boundary, and positioning |
| Architecture | [TECHNICAL_ARCHITECTURE.md](TECHNICAL_ARCHITECTURE.md) | System design, trust boundary, deployment modes, and extension patterns |
| Regulation | [REGULATORY_POSITIONING.md](REGULATORY_POSITIONING.md) | What MERCURY supports, what it does not replace, and how to describe it safely |
| GTM | [GO_TO_MARKET.md](GO_TO_MARKET.md) | Target customers, pricing, sales motion, and objections |
| Roadmap | [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) | Product phases, milestones, expansion tracks, and release criteria |
| Project board | [epics/MASTER_PROJECT.md](epics/MASTER_PROJECT.md) | Epic registry, dependency graph, and execution markers |
| External package | [EXTERNAL_PACKAGE.md](EXTERNAL_PACKAGE.md) | Short-form narrative, design-partner brief outline, deck outline, and demo storyboard |
| Build checklist | [PHASE_0_1_BUILD_CHECKLIST.md](PHASE_0_1_BUILD_CHECKLIST.md) | Concrete Phase 0-1 execution checklist and build order |
| ARC mapping | [ARC_MODULE_MAPPING.md](ARC_MODULE_MAPPING.md) | Mapping of MERCURY Phase 0-1 work onto existing ARC modules |
| Pilot | [POC_DESIGN.md](POC_DESIGN.md) | 45-day design-partner pilot definition and conversion path |
| Pilot runbook | [PILOT_RUNBOOK.md](PILOT_RUNBOOK.md) | Executable corpus-generation flow for the primary and rollback pilot paths |
| Demo storyboard | [DEMO_STORYBOARD.md](DEMO_STORYBOARD.md) | Proof-aligned walkthrough for the gold MERCURY workflow |
| Evaluator flow | [EVALUATOR_VERIFICATION_FLOW.md](EVALUATOR_VERIFICATION_FLOW.md) | Step-by-step verification path for proof, inquiry, and rollback artifacts |
| Post-pilot bridge | [SUPERVISED_LIVE_BRIDGE.md](SUPERVISED_LIVE_BRIDGE.md) | Guardrails for the first supervised-live decision after pilot completion |
| Operating model | [SUPERVISED_LIVE_OPERATING_MODEL.md](SUPERVISED_LIVE_OPERATING_MODEL.md) | Named roles, degraded-mode posture, and ownership assumptions for the same-workflow bridge |
| Operations runbook | [SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md](SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md) | Canonical key, monitoring, fail-closed, and recovery posture for supervised-live review |
| Qualification package | [SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md](SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md) | Reviewer-facing package contents, generation command, and supported claims for the bridge close |
| Decision record | [SUPERVISED_LIVE_DECISION_RECORD.md](SUPERVISED_LIVE_DECISION_RECORD.md) | Canonical proceed/defer/stop artifact for closing the supervised-live bridge |
| Downstream distribution | [DOWNSTREAM_REVIEW_DISTRIBUTION.md](DOWNSTREAM_REVIEW_DISTRIBUTION.md) | Selected downstream case-management review lane, owner, and non-goals |
| Downstream operations | [DOWNSTREAM_REVIEW_OPERATIONS.md](DOWNSTREAM_REVIEW_OPERATIONS.md) | Delivery, acknowledgement, fail-closed recovery, and support boundary for downstream review export |
| Downstream validation | [DOWNSTREAM_REVIEW_VALIDATION_PACKAGE.md](DOWNSTREAM_REVIEW_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the downstream review lane |
| Downstream decision | [DOWNSTREAM_REVIEW_DECISION_RECORD.md](DOWNSTREAM_REVIEW_DECISION_RECORD.md) | Explicit next-step boundary for the bounded downstream review expansion |
| Governance workbench | [GOVERNANCE_WORKBENCH.md](GOVERNANCE_WORKBENCH.md) | Selected governance-workbench workflow path, owners, non-goals, and canonical commands |
| Governance operations | [GOVERNANCE_WORKBENCH_OPERATIONS.md](GOVERNANCE_WORKBENCH_OPERATIONS.md) | Approval, release, rollback, exception, and fail-closed operating posture for the bounded governance lane |
| Governance validation | [GOVERNANCE_WORKBENCH_VALIDATION_PACKAGE.md](GOVERNANCE_WORKBENCH_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the governance-workbench lane |
| Governance decision | [GOVERNANCE_WORKBENCH_DECISION_RECORD.md](GOVERNANCE_WORKBENCH_DECISION_RECORD.md) | Explicit next-step boundary for the bounded governance-workbench expansion |
| Assurance suite | [ASSURANCE_SUITE.md](ASSURANCE_SUITE.md) | Selected assurance-suite reviewer populations, owners, non-goals, and canonical commands |
| Assurance operations | [ASSURANCE_SUITE_OPERATIONS.md](ASSURANCE_SUITE_OPERATIONS.md) | Disclosure, investigation, fail-closed recovery, and support boundary for the bounded assurance lane |
| Assurance validation | [ASSURANCE_SUITE_VALIDATION_PACKAGE.md](ASSURANCE_SUITE_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the assurance-suite lane |
| Assurance decision | [ASSURANCE_SUITE_DECISION_RECORD.md](ASSURANCE_SUITE_DECISION_RECORD.md) | Explicit next-step boundary for the bounded assurance-suite expansion |
| Embedded OEM | [EMBEDDED_OEM.md](EMBEDDED_OEM.md) | Selected embedded OEM partner surface, bounded SDK contract, owners, and non-goals |
| Embedded OEM operations | [EMBEDDED_OEM_OPERATIONS.md](EMBEDDED_OEM_OPERATIONS.md) | Partner-bundle staging, acknowledgement, fail-closed recovery, and support boundary for the embedded OEM lane |
| Embedded OEM validation | [EMBEDDED_OEM_VALIDATION_PACKAGE.md](EMBEDDED_OEM_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the embedded OEM lane |
| Embedded OEM decision | [EMBEDDED_OEM_DECISION_RECORD.md](EMBEDDED_OEM_DECISION_RECORD.md) | Explicit next-step boundary for the bounded embedded OEM expansion |
| Trust network | [TRUST_NETWORK.md](TRUST_NETWORK.md) | Selected trust-network sponsor boundary, witness chain, interoperability surface, owners, and non-goals |
| Trust network operations | [TRUST_NETWORK_OPERATIONS.md](TRUST_NETWORK_OPERATIONS.md) | Witness continuity, fail-closed recovery, and support boundary for the bounded trust-network lane |
| Trust network validation | [TRUST_NETWORK_VALIDATION_PACKAGE.md](TRUST_NETWORK_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the trust-network lane |
| Trust network decision | [TRUST_NETWORK_DECISION_RECORD.md](TRUST_NETWORK_DECISION_RECORD.md) | Explicit next-step boundary for the bounded trust-network expansion |
| Release readiness | [RELEASE_READINESS.md](RELEASE_READINESS.md) | Frozen Mercury launch lane, audience set, delivery surface, owners, and non-goals |
| Release readiness operations | [RELEASE_READINESS_OPERATIONS.md](RELEASE_READINESS_OPERATIONS.md) | Operator release checks, escalation rules, fail-closed recovery, and support handoff for the bounded launch lane |
| Release readiness validation | [RELEASE_READINESS_VALIDATION_PACKAGE.md](RELEASE_READINESS_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the release-readiness lane |
| Release readiness decision | [RELEASE_READINESS_DECISION_RECORD.md](RELEASE_READINESS_DECISION_RECORD.md) | Explicit launch decision and next-step boundary for the bounded Mercury launch lane |
| Controlled adoption | [CONTROLLED_ADOPTION.md](CONTROLLED_ADOPTION.md) | Frozen post-launch adoption cohort, renewal evidence surface, owners, and non-goals |
| Controlled adoption operations | [CONTROLLED_ADOPTION_OPERATIONS.md](CONTROLLED_ADOPTION_OPERATIONS.md) | Customer-success checks, reference-readiness boundary, fail-closed recovery, and support escalation for the bounded adoption lane |
| Controlled adoption validation | [CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md](CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the controlled-adoption lane |
| Controlled adoption decision | [CONTROLLED_ADOPTION_DECISION_RECORD.md](CONTROLLED_ADOPTION_DECISION_RECORD.md) | Explicit scale or defer boundary for the bounded Mercury adoption lane |
| Reference distribution | [REFERENCE_DISTRIBUTION.md](REFERENCE_DISTRIBUTION.md) | Frozen landed-account expansion motion, approved reference bundle, owners, and non-goals |
| Reference distribution operations | [REFERENCE_DISTRIBUTION_OPERATIONS.md](REFERENCE_DISTRIBUTION_OPERATIONS.md) | Claim discipline, buyer approval, fail-closed recovery, and sales handoff for the bounded reference-distribution lane |
| Reference distribution validation | [REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md](REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the reference-distribution lane |
| Reference distribution decision | [REFERENCE_DISTRIBUTION_DECISION_RECORD.md](REFERENCE_DISTRIBUTION_DECISION_RECORD.md) | Explicit proceed or defer boundary for the bounded Mercury reference-distribution lane |
| Broader distribution | [BROADER_DISTRIBUTION.md](BROADER_DISTRIBUTION.md) | Frozen selective account-qualification motion, governed distribution bundle, owners, and non-goals |
| Broader distribution operations | [BROADER_DISTRIBUTION_OPERATIONS.md](BROADER_DISTRIBUTION_OPERATIONS.md) | Claim governance, selective-account approval, fail-closed recovery, and distribution handoff for the bounded broader-distribution lane |
| Broader distribution validation | [BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md](BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the broader-distribution lane |
| Broader distribution decision | [BROADER_DISTRIBUTION_DECISION_RECORD.md](BROADER_DISTRIBUTION_DECISION_RECORD.md) | Explicit proceed or defer boundary for the bounded Mercury broader-distribution lane |
| Selective account activation | [SELECTIVE_ACCOUNT_ACTIVATION.md](SELECTIVE_ACCOUNT_ACTIVATION.md) | Frozen selective-account-activation motion, controlled delivery bundle, owners, and non-goals |
| Selective account activation operations | [SELECTIVE_ACCOUNT_ACTIVATION_OPERATIONS.md](SELECTIVE_ACCOUNT_ACTIVATION_OPERATIONS.md) | Claim containment, approval refresh, fail-closed recovery, and customer handoff for the bounded selective-account-activation lane |
| Selective account activation validation | [SELECTIVE_ACCOUNT_ACTIVATION_VALIDATION_PACKAGE.md](SELECTIVE_ACCOUNT_ACTIVATION_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the selective-account-activation lane |
| Selective account activation decision | [SELECTIVE_ACCOUNT_ACTIVATION_DECISION_RECORD.md](SELECTIVE_ACCOUNT_ACTIVATION_DECISION_RECORD.md) | Explicit proceed or defer boundary for the bounded Mercury selective-account-activation lane |
| Delivery continuity | [DELIVERY_CONTINUITY.md](DELIVERY_CONTINUITY.md) | Frozen controlled-delivery continuity motion, outcome-evidence bundle, owners, and non-goals |
| Delivery continuity operations | [DELIVERY_CONTINUITY_OPERATIONS.md](DELIVERY_CONTINUITY_OPERATIONS.md) | Renewal gate, escalation, fail-closed recovery, and customer-evidence handoff for the bounded delivery-continuity lane |
| Delivery continuity validation | [DELIVERY_CONTINUITY_VALIDATION_PACKAGE.md](DELIVERY_CONTINUITY_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the delivery-continuity lane |
| Delivery continuity decision | [DELIVERY_CONTINUITY_DECISION_RECORD.md](DELIVERY_CONTINUITY_DECISION_RECORD.md) | Explicit proceed or defer boundary for the bounded Mercury delivery-continuity lane |
| Renewal qualification | [RENEWAL_QUALIFICATION.md](RENEWAL_QUALIFICATION.md) | Frozen renewal-qualification motion, outcome-review bundle, owners, and non-goals |
| Renewal qualification operations | [RENEWAL_QUALIFICATION_OPERATIONS.md](RENEWAL_QUALIFICATION_OPERATIONS.md) | Renewal approval, reference reuse, fail-closed recovery, and expansion-boundary handoff for the bounded renewal-qualification lane |
| Renewal qualification validation | [RENEWAL_QUALIFICATION_VALIDATION_PACKAGE.md](RENEWAL_QUALIFICATION_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the renewal-qualification lane |
| Renewal qualification decision | [RENEWAL_QUALIFICATION_DECISION_RECORD.md](RENEWAL_QUALIFICATION_DECISION_RECORD.md) | Explicit proceed or defer boundary for the bounded Mercury renewal-qualification lane |
| Second-account expansion | [SECOND_ACCOUNT_EXPANSION.md](SECOND_ACCOUNT_EXPANSION.md) | Frozen second-account-expansion motion, portfolio-review bundle, owners, and non-goals |
| Second-account expansion operations | [SECOND_ACCOUNT_EXPANSION_OPERATIONS.md](SECOND_ACCOUNT_EXPANSION_OPERATIONS.md) | Portfolio review, expansion approval, fail-closed recovery, and second-account handoff for the bounded second-account-expansion lane |
| Second-account expansion validation | [SECOND_ACCOUNT_EXPANSION_VALIDATION_PACKAGE.md](SECOND_ACCOUNT_EXPANSION_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the second-account-expansion lane |
| Second-account expansion decision | [SECOND_ACCOUNT_EXPANSION_DECISION_RECORD.md](SECOND_ACCOUNT_EXPANSION_DECISION_RECORD.md) | Explicit proceed or defer boundary for the bounded Mercury second-account-expansion lane |
| Portfolio program | [PORTFOLIO_PROGRAM.md](PORTFOLIO_PROGRAM.md) | Frozen portfolio-program motion, program-review bundle, owners, and non-goals |
| Portfolio program operations | [PORTFOLIO_PROGRAM_OPERATIONS.md](PORTFOLIO_PROGRAM_OPERATIONS.md) | Program review, portfolio approval, fail-closed recovery, and program handoff for the bounded portfolio-program lane |
| Portfolio program validation | [PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md](PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the portfolio-program lane |
| Portfolio program decision | [PORTFOLIO_PROGRAM_DECISION_RECORD.md](PORTFOLIO_PROGRAM_DECISION_RECORD.md) | Explicit proceed or defer boundary for the bounded Mercury portfolio-program lane |
| Second portfolio program | [SECOND_PORTFOLIO_PROGRAM.md](SECOND_PORTFOLIO_PROGRAM.md) | Frozen second-portfolio-program motion, portfolio-reuse bundle, owners, and non-goals |
| Second portfolio program operations | [SECOND_PORTFOLIO_PROGRAM_OPERATIONS.md](SECOND_PORTFOLIO_PROGRAM_OPERATIONS.md) | Portfolio-reuse review, revenue-boundary guardrails, fail-closed recovery, and second-program handoff for the bounded second-portfolio-program lane |
| Second portfolio program validation | [SECOND_PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md](SECOND_PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the second-portfolio-program lane |
| Second portfolio program decision | [SECOND_PORTFOLIO_PROGRAM_DECISION_RECORD.md](SECOND_PORTFOLIO_PROGRAM_DECISION_RECORD.md) | Explicit proceed or defer boundary for the bounded Mercury second-portfolio-program lane |
| Product surface boundaries | [PRODUCT_SURFACE_BOUNDARIES.md](PRODUCT_SURFACE_BOUNDARIES.md) | Shared ARC substrate seams plus separate MERCURY and ARC-Wall product-owned surfaces |
| Shared service version pinning | [SHARED_SERVICE_VERSION_PINNING.md](SHARED_SERVICE_VERSION_PINNING.md) | Shared ARC dependency map and fail-closed version-pinning rules for the current product set |
| Cross-product governance | [CROSS_PRODUCT_GOVERNANCE.md](CROSS_PRODUCT_GOVERNANCE.md) | Release, incident, and trust-material ownership across the current product set |
| Cross-product release matrix | [CROSS_PRODUCT_RELEASE_MATRIX.md](CROSS_PRODUCT_RELEASE_MATRIX.md) | Shared-substrate versus product-local release classes, approvers, and pause rules |
| Trust-material recovery drill | [TRUST_MATERIAL_RECOVERY_DRILL.md](TRUST_MATERIAL_RECOVERY_DRILL.md) | Shared recovery sequence for ARC-owned receipt, checkpoint, and release-approval material |
| Operator alert routing | [OPERATOR_ALERT_ROUTING.md](OPERATOR_ALERT_ROUTING.md) | Incident classification and ownership routing across ARC, MERCURY, and ARC-Wall |
| Platform hardening backlog | [PLATFORM_HARDENING_BACKLOG.md](PLATFORM_HARDENING_BACKLOG.md) | Prioritized hardening backlog for sustained multi-product operation |
| Platform hardening validation | [PLATFORM_HARDENING_VALIDATION_PACKAGE.md](PLATFORM_HARDENING_VALIDATION_PACKAGE.md) | Validation-package command, layout, and supported claim for the hardening lane |
| Platform hardening decision | [PLATFORM_HARDENING_DECISION_RECORD.md](PLATFORM_HARDENING_DECISION_RECORD.md) | Explicit next-step boundary for the bounded post-ARC-Wall hardening lane |
| Investor | [INVESTOR_NARRATIVE.md](INVESTOR_NARRATIVE.md) | Fundraising story, wedge, expansion path, and risks |
| Market | [MARKET_SIZING.md](MARKET_SIZING.md) | SAM, SOM, pricing bands, and scenario model |
| FAQ | [TECHNICAL_FAQ.md](TECHNICAL_FAQ.md) | Evaluator-facing technical answers and deployment assumptions |
| Competition | [COMPETITIVE_LANDSCAPE.md](COMPETITIVE_LANDSCAPE.md) | Adjacent categories, white space, and moat analysis |
| Partnerships | [PARTNERSHIP_STRATEGY.md](PARTNERSHIP_STRATEGY.md) | Partner priorities, integration sequencing, and channel logic |
| Use cases | [USE_CASES.md](USE_CASES.md) | Representative workflow scenarios and buyer-facing examples |
| Security | [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, adversaries, trust boundaries, and mitigations |
| Verification | [VERIFIER_SDK_RESEARCH.md](VERIFIER_SDK_RESEARCH.md) | Verifier surfaces, trust anchors, and distribution plan |
| FIX expansion | [FIX_INTEGRATION_RESEARCH.md](FIX_INTEGRATION_RESEARCH.md) | Live execution integration strategy and FIX-specific constraints |
| Companion product | [ARC_WALL_BRIEF.md](ARC_WALL_BRIEF.md) | Information-domain control product built on the same ARC substrate |
| ARC-Wall docs | [../arc-wall/README.md](../arc-wall/README.md) | Canonical ARC-Wall control-path, operations, validation, and decision docs |
| Adjacency research | [DEFI_CROSSOVER_RESEARCH.md](DEFI_CROSSOVER_RESEARCH.md) | TradFi / DeFi crossover opportunities after core product maturity |

---

## Execution Artifacts

The roadmap is organized into six phases:

- Phases 0-3 define the product program through pilot readiness.
- A post-pilot bridge defines the first supervised-live productionization path.
- Phase 4 defines governance, downstream-consumer, and assurance expansion work.
- Phase 5 defines embedded OEM, trust-network, and ARC-Wall expansion work.
- Post-launch adoption defines bounded renewal, reference, and follow-on expansion lanes.

The later post-launch lane docs are an execution history of bounded package
surfaces, not a recommendation to keep multiplying first-class Mercury
capabilities without refactoring. Use
[PRODUCT_SURFACE_AUDIT](PRODUCT_SURFACE_AUDIT.md) as the corrective read before
treating those lanes as the default future build path.

Supporting execution docs:

- [epics/PHASE_0_1_TICKETS.md](epics/PHASE_0_1_TICKETS.md)
- [epics/PHASE_2_3_TICKETS.md](epics/PHASE_2_3_TICKETS.md)
- [epics/PHASE_4_5_TICKETS.md](epics/PHASE_4_5_TICKETS.md)
- [epics/CROSS_CUTTING_TICKETS.md](epics/CROSS_CUTTING_TICKETS.md)
- [epics/POC_SPRINT_PLAN.md](epics/POC_SPRINT_PLAN.md)
- [EXTERNAL_PACKAGE.md](EXTERNAL_PACKAGE.md)
- [PHASE_0_1_BUILD_CHECKLIST.md](PHASE_0_1_BUILD_CHECKLIST.md)
- [ARC_MODULE_MAPPING.md](ARC_MODULE_MAPPING.md)
- [PILOT_RUNBOOK.md](PILOT_RUNBOOK.md)
- [DEMO_STORYBOARD.md](DEMO_STORYBOARD.md)
- [EVALUATOR_VERIFICATION_FLOW.md](EVALUATOR_VERIFICATION_FLOW.md)
- [SUPERVISED_LIVE_BRIDGE.md](SUPERVISED_LIVE_BRIDGE.md)
- [SUPERVISED_LIVE_OPERATING_MODEL.md](SUPERVISED_LIVE_OPERATING_MODEL.md)
- [SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md](SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md)
- [SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md](SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md)
- [SUPERVISED_LIVE_DECISION_RECORD.md](SUPERVISED_LIVE_DECISION_RECORD.md)
- [DOWNSTREAM_REVIEW_DISTRIBUTION.md](DOWNSTREAM_REVIEW_DISTRIBUTION.md)
- [DOWNSTREAM_REVIEW_OPERATIONS.md](DOWNSTREAM_REVIEW_OPERATIONS.md)
- [DOWNSTREAM_REVIEW_VALIDATION_PACKAGE.md](DOWNSTREAM_REVIEW_VALIDATION_PACKAGE.md)
- [DOWNSTREAM_REVIEW_DECISION_RECORD.md](DOWNSTREAM_REVIEW_DECISION_RECORD.md)
- [GOVERNANCE_WORKBENCH.md](GOVERNANCE_WORKBENCH.md)
- [GOVERNANCE_WORKBENCH_OPERATIONS.md](GOVERNANCE_WORKBENCH_OPERATIONS.md)
- [GOVERNANCE_WORKBENCH_VALIDATION_PACKAGE.md](GOVERNANCE_WORKBENCH_VALIDATION_PACKAGE.md)
- [GOVERNANCE_WORKBENCH_DECISION_RECORD.md](GOVERNANCE_WORKBENCH_DECISION_RECORD.md)
- [ASSURANCE_SUITE.md](ASSURANCE_SUITE.md)
- [ASSURANCE_SUITE_OPERATIONS.md](ASSURANCE_SUITE_OPERATIONS.md)
- [ASSURANCE_SUITE_VALIDATION_PACKAGE.md](ASSURANCE_SUITE_VALIDATION_PACKAGE.md)
- [ASSURANCE_SUITE_DECISION_RECORD.md](ASSURANCE_SUITE_DECISION_RECORD.md)
- [EMBEDDED_OEM.md](EMBEDDED_OEM.md)
- [EMBEDDED_OEM_OPERATIONS.md](EMBEDDED_OEM_OPERATIONS.md)
- [EMBEDDED_OEM_VALIDATION_PACKAGE.md](EMBEDDED_OEM_VALIDATION_PACKAGE.md)
- [EMBEDDED_OEM_DECISION_RECORD.md](EMBEDDED_OEM_DECISION_RECORD.md)
- [TRUST_NETWORK.md](TRUST_NETWORK.md)
- [TRUST_NETWORK_OPERATIONS.md](TRUST_NETWORK_OPERATIONS.md)
- [TRUST_NETWORK_VALIDATION_PACKAGE.md](TRUST_NETWORK_VALIDATION_PACKAGE.md)
- [TRUST_NETWORK_DECISION_RECORD.md](TRUST_NETWORK_DECISION_RECORD.md)
- [RELEASE_READINESS.md](RELEASE_READINESS.md)
- [RELEASE_READINESS_OPERATIONS.md](RELEASE_READINESS_OPERATIONS.md)
- [RELEASE_READINESS_VALIDATION_PACKAGE.md](RELEASE_READINESS_VALIDATION_PACKAGE.md)
- [RELEASE_READINESS_DECISION_RECORD.md](RELEASE_READINESS_DECISION_RECORD.md)
- [CONTROLLED_ADOPTION.md](CONTROLLED_ADOPTION.md)
- [CONTROLLED_ADOPTION_OPERATIONS.md](CONTROLLED_ADOPTION_OPERATIONS.md)
- [CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md](CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md)
- [CONTROLLED_ADOPTION_DECISION_RECORD.md](CONTROLLED_ADOPTION_DECISION_RECORD.md)
- [REFERENCE_DISTRIBUTION.md](REFERENCE_DISTRIBUTION.md)
- [REFERENCE_DISTRIBUTION_OPERATIONS.md](REFERENCE_DISTRIBUTION_OPERATIONS.md)
- [REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md](REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md)
- [REFERENCE_DISTRIBUTION_DECISION_RECORD.md](REFERENCE_DISTRIBUTION_DECISION_RECORD.md)
- [BROADER_DISTRIBUTION.md](BROADER_DISTRIBUTION.md)
- [BROADER_DISTRIBUTION_OPERATIONS.md](BROADER_DISTRIBUTION_OPERATIONS.md)
- [BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md](BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md)
- [BROADER_DISTRIBUTION_DECISION_RECORD.md](BROADER_DISTRIBUTION_DECISION_RECORD.md)
- [PRODUCT_SURFACE_BOUNDARIES.md](PRODUCT_SURFACE_BOUNDARIES.md)
- [SHARED_SERVICE_VERSION_PINNING.md](SHARED_SERVICE_VERSION_PINNING.md)
- [CROSS_PRODUCT_GOVERNANCE.md](CROSS_PRODUCT_GOVERNANCE.md)
- [CROSS_PRODUCT_RELEASE_MATRIX.md](CROSS_PRODUCT_RELEASE_MATRIX.md)
- [TRUST_MATERIAL_RECOVERY_DRILL.md](TRUST_MATERIAL_RECOVERY_DRILL.md)
- [OPERATOR_ALERT_ROUTING.md](OPERATOR_ALERT_ROUTING.md)
- [PLATFORM_HARDENING_BACKLOG.md](PLATFORM_HARDENING_BACKLOG.md)
- [PLATFORM_HARDENING_VALIDATION_PACKAGE.md](PLATFORM_HARDENING_VALIDATION_PACKAGE.md)
- [PLATFORM_HARDENING_DECISION_RECORD.md](PLATFORM_HARDENING_DECISION_RECORD.md)

---

## Key Themes

### Product definition

- [What MERCURY is](PRODUCT_BRIEF.md#1-what-mercury-is)
- [Proof boundary](PRODUCT_BRIEF.md#5-proof-boundary)
- [Deployment model](PRODUCT_BRIEF.md#6-deployment-model)
- [Why ARC matters](PRODUCT_BRIEF.md#9-why-arc-matters)

### Regulatory and buyer messaging

- [Framing principles](REGULATORY_POSITIONING.md#1-positioning-principles)
- [What MERCURY can support](REGULATORY_POSITIONING.md#4-what-mercury-can-support)
- [What MERCURY does not replace](REGULATORY_POSITIONING.md#5-what-mercury-does-not-replace)

### Product program

- [Program summary](IMPLEMENTATION_ROADMAP.md#1-program-summary)
- [Current build phases](IMPLEMENTATION_ROADMAP.md#3-phases-0-3-current-product-program)
- [Post-pilot bridge](IMPLEMENTATION_ROADMAP.md#4-post-pilot-bridge)
- [Expansion phases](IMPLEMENTATION_ROADMAP.md#5-phases-4-5-expansion-tracks)
- [Dependency graph](epics/MASTER_PROJECT.md#4-dependency-graph)

### Commercial path

- [Target customers](GO_TO_MARKET.md#2-target-accounts-and-buyers)
- [Pricing](GO_TO_MARKET.md#3-offer-structure-and-pricing)
- [Pilot motion](POC_DESIGN.md#5-pilot-plan)
- [Financial model](MARKET_SIZING.md#4-som-model)

---

## Relationship to ARC

ARC is the platform thesis. MERCURY is the first vertical commercialization of
that thesis in regulated financial workflows.

ARC provides the generic substrate:

- fail-closed kernel mediation
- delegated authority and policy enforcement
- signed receipts and checkpoints
- trust distribution and verification foundations

MERCURY adds the trading-specific layer:

- workflow and control-program evidence types
- change-review, release, rollback, and inquiry packaging
- retained artifact and record-policy semantics
- reconciliation, chronology, and buyer-facing retrieval surfaces

MERCURY's operator surface ships as the dedicated `arc-mercury` app and
`mercury` binary, built on ARC's generic evidence-export and control-plane
substrate. ARC stays generic; MERCURY stays opinionated.

For ARC protocol details, see the main ARC specification and crate
documentation in the repository root.

---

## Status

This suite now supports design-partner validation with an executable pilot
corpus, proof-aligned demo materials, evaluator-facing verification
instructions, a bounded supervised-live bridge with one operating model and
one proceed/defer/stop artifact, one bounded downstream case-management review
distribution lane with explicit delivery and decision records, one bounded
governance-workbench change-review lane with explicit owners, validation, and
decision records, one bounded assurance-suite reviewer family for internal,
auditor, and counterparty review, one bounded embedded OEM distribution lane
for a single reviewer-workbench partner surface with a manifest-based bundle
contract, and one bounded trust-network lane for a single counterparty-review
exchange sponsor with a checkpoint-backed witness chain and proof-profile
interoperability manifest, plus one bounded ARC-Wall companion-product lane
for a single `research -> execution` barrier-control workflow. The current
post-ARC-Wall step is one shared-service, governance, and platform-hardening
lane across the existing MERCURY plus ARC-Wall product set. Product, roadmap,
ticketing, and research documents remain aligned to the same canonical scope
and terminology.
