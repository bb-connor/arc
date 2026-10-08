# Native host design review and verification

Scope: documentation, source research and implementation planning only. Initial consolidation: 2026-10-07. Systems-layer amendment: 2026-10-08 UTC. No desktop runtime, backend, installed application or release was built or qualified.

The owner approved applying the broader architecture proposal. ADR-0038 records the accepted planning direction. The independent source review checked the shared owner map against pinned foundation, workbench, work, recovery, north-star and strategy sources. The platform review checked the two annexes and implementation packets against that shared design.

Corrections made during independent review:

- S8 phase 1 covers Kernel scope; S28 is phase 3, Tenant phase 4 and Recovery phase 5.
- The passkey verifier is exported code; production approval-path integration and qualification remain unestablished.
- Historical recovery finding counts and foundation milestones are not current composed acceptance.
- W1 acceptance comes from its original configured evaluator evidence. Human patch approval is separate.
- The shared projection includes recovery SelectOffer and stale/lost-selection obligations.
- ArtifactReleasePort and ConfinedReturnPort are planned W1 references, not existing recovery implementation symbols. Their concrete APIs remain owner reconciliation gates.
- Candidate wire bindings and conformance probes precede product implementation; final wire freeze follows implemented-client acceptance.
- Signed candidate assembly precedes installed I08 qualification; promotion follows qualification of the exact candidate bytes.
- The later review separates receipt/hook observation from W1, recovery mutation and approval dependencies, assigns the existing trust-control reads and host-hook provenance owners, and keeps the proposed projection in the planning package until implemented-surface wire freeze.
- Public plugin copy was checked against Claude Code `65ac8390c57a5292c055fba50caa1aafbd915848`, Cursor `d129cc508cfd3317078da6c2afa890fadf7c44da` and Codex `deefb3a85001ee47a22fcfbb43ab6749c4944004`. Hook diagnostics remain `detect_only`; the Cursor discovery candidate disables protected model execution, and the Claude/Codex restricted candidates do not establish complete I01-I08 or published-delivery acceptance. Scoped README/AGENTS repairs track the broader wording issue without declaring every external surface repaired.

Local verification covers Markdown links/anchors in the retained and new package, whitespace, structured research-source JSON parsing, and the repository release-copy truth check. Source pins were inspected through Git or official primary sources. These checks validate documents and bounded source claims only.

Prior schema/fixture repairs remain in Git history, and their security obligations are retained in [QUALIFICATION](QUALIFICATION.md) and [OPERATOR](OPERATOR.md). The old generated validation records and fixture counts are retired with those unshipped platform protocols. Bot verdicts and hosted CI are checked on the final PR heads separately; this file does not predict either result.

## Systems-layer amendment

The owner explicitly approved the product direction: Chio is a Rust kernel for
agentic operating systems that coordinate work, share resources, and cooperate
across organizational boundaries. The amendment removes the mandatory workbench
and sealed-coding-first sequence. It does not remove native safety obligations.

Research read the live public documentation and downloaded Megastart, then
compared selected source/lock files and verified its kernel pin exists publicly.
The archived example demonstrates an application-host/Herdr split; its mission
API remains application-owned. The research also inspected pinned foundation,
work, recovery, eleven-spec kernel and NVIDIA strategy inputs, plus primary
Apple, Linux/systemd and bounded current OpenShell sources. Source captures and
limitations are linked from the shared/platform research records. No runtime
experiment or benchmark was executed as part of this documentation amendment.

New HOST-CONTRACT, CAPABILITIES and CONSUMERS documents define native ports,
deployment principals, trusted roles and independent application/harness evidence.
Q23-Q30 add product acceptance for headless continuity, passports, recursion,
swarm authority, shared resources and independent organizations. Q01-Q22 native
obligations remain with selected-profile applicability. Both platform plans now
lead with reusable native owners, then optional presentation.

Source reconciliation found concrete predecessor work: proposed W1 facade and
release APIs, incompatible historical process ABI, unqualified recovery, Darwin
IPC/server authentication, service-principal credential custody, Linux rootless
runner/endpoint and suspend-inclusive lifetime support, and selected S7 evidence
kinds. These remain gates, not defects claimed repaired by documentation.

The NVIDIA strategy's proposed category change and native-runtime freeze conflict
with the newly approved direction. ADR-0038 and CAPABILITIES explicitly reconcile
that conflict while retaining source-grounded seam, evidence and reuse lessons.
No competitor exclusivity, performance superiority or commercial demand is
inferred from a source inventory.

Independent reviews cover cross-document dependency gates, authority/profile
separation and product traceability. A stale closing reference to sealed-before-
protected ordering was found in CONSUMERS and removed before candidate review.
The review also corrected unconditional streaming/all-six-host gates and a
premature API freeze in the owner map. Final document checks, current-head hosted
results and remaining review findings are recorded in the PR review closure
rather than predicted here.

Current-head Codex review identified two further shared P2 gaps: non-execution
clock rollback and an unassigned qualification verifier. Q31 now covers all
time-bounded native authority, and RELEASE/shared packet 2a assign a concrete
extension of `chio-release-evidence` plus installed native activation consumers.
Its current self-signed artifact manifest is explicitly insufficient. Separate
qualification-only candidate admission prevents an installed-evidence/promotion
cycle without allowing production activation from incomplete evidence.
