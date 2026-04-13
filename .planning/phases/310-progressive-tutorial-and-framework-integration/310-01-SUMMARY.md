---
phase: 310
plan: 01
created: 2026-04-13
status: complete
---

# Summary 310-01

Phase `310` now has a real onboarding document in
[docs/PROGRESSIVE_TUTORIAL.md](/Users/connor/Medica/backbay/standalone/arc/docs/PROGRESSIVE_TUTORIAL.md).
It connects the phase `309` deployable quickstart to the core ARC concepts,
shows the policy shape that issues governed tool authority, demonstrates the
hosted-edge wrapping command, and walks through governed execution plus receipt
lookup against the trust service.

The same document also closes the roadmap's delegation requirement honestly:
instead of inventing a local child-issuance command that ARC does not currently
expose, it points developers at the concrete federated continuation lane
(`federated-delegation-policy-create` plus `trust federated-issue
--upstream-capability-id ...`) and explains how that continuation becomes
delegation lineage in the trust store.
