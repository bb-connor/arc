# Current code and remaining architectural work

Inspection date: 2026-10-03. This is a source/document review, not a fresh runtime qualification campaign. File hashes and commit identities are in [SOURCES.json](SOURCES.json).

## Judgment

Chio already contains most of the enforcement machinery needed by the thesis. The remaining third workstream is productizing its common programming model: a public runtime contract, owner-authorized preparation and service boundaries, and shared protocol/SDK behavior demonstrated by two applications.

It is not accurate to say that finishing these features alone proves beta readiness. The active security and recovery lanes, semantic source integration, supported-platform qualification, package installation and existing release gates still determine readiness.

## Sources of truth

| Source | Observed state | Meaning |
| --- | --- | --- |
| Paper/work source 611660eb24521a4d02020615f650dadad92eae03 | Clean paper worktree at inspection | Current D1/S1/F1 composition and architecture manuscript |
| Active security source a99437b3ea8ef7ea03c7d2926049b27cb140b3c5 | packet/3-retention-accounting; untracked output directory | Newer security continuation; output directory was not inspected or modified |
| Security PR #1160 at f25cd61f49fbf9a15a70396da82d9808ba4e1da2 | Open PR, older checkpoint | Do not equate its head with the latest local security work |
| Recovery PR #1172 at de84fc306efbb4c8dd6de748d0ad2a8d695fd30e | Architecture revision 3, 111 requirements, P0-P6 | Normative contract for the parallel recovery implementation |
| Mac recovery agent | Owner confirms it is executing that PR's spec over Tailscale | Active implementation; current SHA/phase acceptance not observed here |
| Main checkout | docs/nvidia-stack-research at 666274baef7a503a6bf4791816483cbc6eb1b4ed | Not the current integration candidate |

GitHub PR state was refreshed with gh during this review. The paper and active security histories diverge; neither is the union of all active work.

## Reuse map and actual gaps

| Area | Inspected existing implementation | Delta assigned to this lane |
| --- | --- | --- |
| Work allocation | chio-workflow/src/delegation: holder-signed subdivision, receiver offer, replace-before-seal selection, bounded readers/effects/units, sealed dispatch permit | Expose through a public work interface and owner-scoped preparation; retain exact seal readback |
| Swarm composition | chio-swarm-authority/src/evolution.rs; runtime-core SQLite swarm_authority_bundles.rs: additive verification, head CAS and archived versions | Public facade wrappers and supported graph authoring; reuse existing transaction/verification |
| Public runtime | chio-runtime/src/lib.rs and stores.rs already form a facade over runtime-core | Add work feature/API; the inspected facade lacks the new extend_swarm_authority_bundle wrapper |
| Native execution | chio-kernel/src/delegated_work.rs; admission coordinator; SQLite authority | Install existing checks and bind the same request; no new execution owner |
| Treaty sovereignty | runtime-core treaty/admission hooks; federation peer configuration and DSSE; protected replay-source activation | Owner-scoped deployment and authenticated peer service; incoming evidence never provisions authority |
| Durable processes | ProcessRuntime and private WorkerService, existing Python/TypeScript clients | Work transport extension and public client helpers, coordinated with recovery's host changes |
| Native host swarm | chio-cli process_host/swarm.rs | Current inspected provisioning rejects dynamic spawn_templates and requires fixed direct children; extend through the shared work adapter without deleting other security prerequisites |
| Composed funded work | Standalone examples/federated-work workspace; funded_work/composition.rs, evolving.rs, native.rs and rail.rs | Extract reusable composition; remove W0 fixed amount/tool/profile assumptions from the public interface |
| Peer transport | Prototype peer_https/peer_client and verifier-specific service | Reuse cases, not production status; full work service and local-context co-signing remain required |
| Bilateral delivery | Existing BilateralCoSigningProtocol; composed example uses InProcessCoSigner | Remote co-signer under configured owner authority, exact durable delivery without duplicate dispatch |
| Funding | Existing F1 agreement/reserve/transaction recovery and ChioWorkClaimEscrow; existing PaymentAdapter | Promote terms/observation to chio-settle and native adapter to control-plane; avoid a kernel dependency cycle |
| Protocols | MCP/A2A ToolServerConnection; cross-protocol orchestrator; ACP edges; HTTP authority | Shared work-profile negotiation and real adapter conformance |
| Envoy | ext_authz shim delegates to configured EnvoyKernel | Admission integration until a complete deployment qualifies stronger execution semantics |
| Policy | HushSpec compiler produces guard pipelines and default scopes | Reuse policy/guard machinery; do not equate technical controls with universal regulatory compliance |
| Recovery | PR #1172 exact continuations, owner approvals, effect truth, artifacts, confined returns and operational APIs | Consume the parallel lane; own only the work-contract join |
| Release | Existing candidate/audit/qualification documents and installed process package qualifier | Converge all three lanes and include work requirements in the current release system |

The core gap is visible in code placement and interface reach: the standalone example assembles production mechanisms directly, while the public facade and process clients expose only parts of that composition. Existing machinery should become reusable product surface, not be reimplemented.

## Hard boundaries inherited from the existing work

- D1's permits bind exact receiver/subject/request/capability/input and bounded contract terms. Capacity is not financial backing.
- S1 is additive. It preserves issued commitments; it is not arbitrary graph rewriting, owner migration or budget reclamation.
- Runtime replay source activation is a trusted provisioning operation. Reopening work cannot activate a new source.
- A current capability, admitted execution, permitted data release, earned payment and bilateral receipt delivery have different lifetimes.
- Each resource relies on its configured protected custodian. The paper does not establish Byzantine safety for independently spendable copies of the same authority.
- Final bilateral delivery was unavailable in the retained composed run. Later local completion does not retrospectively establish remote receipt delivery.
- Existing results are local, one-administrator and private-chain. No outside partner has operated the contract.
- chio-kernel already depends on chio-settle; adding a production kernel dependency to chio-settle would create a cycle.
- The security roadmap's newer execution notes supersede stale per-finding lists for local repairs. Milestone-wide/native/hosted/release acceptance must still be refreshed.
- The prior publication gate is intentionally stronger than an architectural contribution. Its four open research hypotheses must remain historical facts when the new publication profile is introduced.

## Planning consequence

Use the existing public runtime and host, add the missing owner-authorized preparation/service joins, qualify shared protocol behavior, and demonstrate reuse. Do not commission another search for a novel financial primitive or another standalone experiment. The selected contribution is a systems architecture with a usable contract.

The whitepaper can be completed as a specification of that architecture before these plans run. Statements about new implementation, comparative advantage, outside operation and shipping wait for their actual evidence.
