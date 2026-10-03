# Planning review

Date: 2026-10-03
Method: coordinator source review and inline plan self-review, followed by source-pin, document-link and requirement-coverage checks. No independent agent review or runtime qualification is claimed.

## Outcome

The third workstream is defined as promoting the existing work construction into the public runtime and owner services, then demonstrating reuse through existing protocols and SDKs. Security and recovery remain separately owned. The package specifies a concrete end condition rather than another open-ended breakthrough experiment.

The paper plan executes first through architecture-manuscript completion. Its final evidence/publication step follows implementation and beta convergence. The early manuscript can describe the completed architecture without claiming unobserved deployment or performance.

## Review corrections incorporated

1. Public runtime already exists. The design extends chio-runtime rather than inventing a new top-level kernel or runtime crate.
2. The example carries both owners' private keys in fixture setup. The service design replaces this with separately scoped owner preparation and exact-body signature exchange.
3. A low-level signed-command API would still force applications to write graph/signature glue. Required prepare operations now cover delegation, receiver offers, selection, graph extension and agreements.
4. Preparation can lose its acknowledgement after authority is issued. Preparation and application have distinct stage keys, and retries return retained artifacts under the original ID.
5. The kernel already depends on chio-settle. Financial semantics stay in settlement; the native PaymentAdapter implementation stays in control-plane to avoid a dependency cycle.
6. The orchestration command index must not become another execution authority or retain unclassified credential/output copies. It stores scoped digests/references and resolves the existing native/recovery owner.
7. Approved recovery can change the action. The original sealed work remains immutable; a supported new bounded child/continuation explicitly represents the changed work.
8. Remote receipt completion was absent in the retained local trajectory. Real peer co-signing and durable exact-statement completion are acceptance work, with pending delivery separate from execution/payment.
9. Native host swarm provisioning currently rejects dynamic spawn templates. The plan promotes the shared graph-authoring seam rather than assuming the CLI already exposes dynamic D1/S1 work.
10. Envoy and provider observation surfaces have narrower authority boundaries. Work support is negotiated by dimension and tested in the existing protocol inventory.
11. The old publication checker requires a foundational/economic breakthrough. The new architecture profile is explicit and separately tested; old open gates remain unchanged.
12. Beta terminology is ahead of the existing alpha release plan. Candidate convergence must record version/scope deliberately and preserve existing required release gates.
13. The active recovery agent is on the owner's Mac. The plan consumes PR #1172 and requires its actual landing commit before integration rather than citing an older local recovery branch.
14. Current source inventories include documentation outside the paper. Paper execution must preserve source-qualified historical evidence; new planning files cannot silently be counted as already tested native inputs.
15. A mandatory new full comparator would recreate the earlier experimental churn. Beta requires two-application reuse and honest responsibility/cost reporting. Quantitative superiority is claimed only if its matched evidence is actually produced; otherwise it remains unestablished without blocking the bounded architecture claim.

## Requirement and execution review

AW01 through AW20 each map to a named task in the architecture specification. W1 through W3 produce separately reviewable code; W4 consumes their evidence and the other two lanes. P.1 through P.4 produce the requested early manuscript, while P.5 reconciles the actual final implementation.

Every plan has a goal, architecture, specification reference, global constraints, review focus, concrete file ownership, interfaces or evidence contracts, and checkable acceptance steps. Commands in implementation plans are instructions to the future implementer, not results observed during planning.

Unresolved external dependencies are explicit: the Mac recovery implementation's actual landing APIs/SHA, the security lane's final accepted candidate, native/hosted release evidence, and a real independent operator for any claim of independent administration. None prevents completing this planning package. None is represented as already satisfied.

## Validation boundary

Validation of this package checks document structure, local links, exact source hashes, requirement/task mapping, forbidden em dashes and the absence of product/manuscript changes. It does not compile or test the proposed APIs. Runtime, native, hosted and release checks belong to execution of the plans.

The final document validator passed: 12 Markdown files, five plans, 34 local links (including seven anchors), 66 pinned source hashes and all 20 acceptance requirements mapped to 22 tasks. The initial staged whitespace check found three extra trailing blank lines; these were removed. Product source, dependency files and the existing manuscript/artifact remain unchanged from the planning base.
