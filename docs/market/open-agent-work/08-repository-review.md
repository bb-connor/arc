# Repository reconciliation for the verifiable-work program

Reviewed 2026-09-14 against local base
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81` plus the current uncommitted work.
Approved whitepaper: **Chio: A Peer-to-Peer Economy of Verifiable Work**.

## 1. Judgment and scope

The direction fits Chio, but the initial plan undercounted existing machinery
and several integration obligations. The most consequential correction is to
reuse the authenticated finding-pool ledger, swarm verifier, finding verifier
and challenge pipeline while preserving their exact trust boundaries. The
new work is the cross-company composition and its funded acceptance semantics,
not a replacement implementation of all these foundations.

This review inventories every resolved root-workspace member, inspects the
relevant source interfaces and selected implementations/tests, and reconciles
the SDK, schema, deployment and evidence paths. It is a repository-wide
planning review, not a line-by-line audit of every crate or fresh release
qualification. No current-main/remote-CI/deployment state was established.
Tests cited below were inspected as source, not rerun during this docs change.

The [inventory](08-workspace-inventory.json) records all 163 workspace members,
their manifest hashes, declared dependencies/features, separately rooted
research examples and source-reference hashes. The 163 comprise 142 crates
under the eleven functional groups and 21 other workspace packages. The
108-crate description in the existing project instructions is stale inventory;
the instructions' security and code conventions still apply.

Historical memory is a search guide, not a source of current implementation
status. For example, current PostgreSQL source implements the hosted domain
backend; an older note about incomplete domain activation cannot justify
planning to rebuild it. The `chio-workbench` and `chio-process` paths mentioned
in earlier work are absent in this checkout and are not assumed dependencies.

## 2. Coverage and disposition

| Surface | Workspace count | Review disposition |
| --- | --- | --- |
| Core | 7 | Reuse signed types, bounded values, supervisor/health primitives and error conventions; no new cryptographic foundation planned |
| Kernel | 9 | Directly inspect admission-related swarm/pool and settlement boundaries; preserve durable unknown execution and platform profile limits |
| Guards | 7 | Retain native policy/input/output enforcement; map checker distribution and resource limits onto existing guard and sandbox interfaces |
| Protocol | 28 | Reuse A2A and provider-tool fabric; qualify the chosen live transport, egress and model integration; other adapters remain explicitly outside the first profile |
| Economy | 16 | Reuse findings, bids, fees, metering, credit/capital and settlement types according to their actual authority; defer FX and unsecured credit |
| Trust | 25 | Reuse local activation, swarm/finding verification, custody, disclosure and revocation; keep reputation/attestation claims bounded |
| Platform | 20 | Reuse qualified SQLite stores and existing hosted ports where selected; integrate commerce/passport verification without pretending it executes work |
| Observability | 5 | Reuse exports and lineage; authority records remain the source of monetary truth |
| Products | 11 | Reuse CLI, Proof Room, market server/worker/canary surfaces as applicable; Wall, Mercury and API-protection products are optional consumers |
| SDK | 6 | Preserve guard-authoring and binding contracts; cross-company client changes must also cover the Python/TypeScript SDK trees outside these Rust crates |
| Tooling | 8 | Reuse conformance, schema validation/codegen, trace and release-evidence gates |
| Other workspace packages | 21 | Inventory examples, benchmarks, chaos/load tools, integrations and xtask; include relevant conformance paths, not every example in the trial |

No unrelated product expansion, browser/mobile parity, new currency rail,
global reputation system or autonomous insurance marketplace is required for
the first independently operated work profile. Each receives an explicit
deferral instead of silently becoming a prerequisite.

## 3. Findings and required plan corrections

### R01. Freeze the actual integration inventory

The [root manifest](../../../Cargo.toml) resolves 163 members. The three
important research examples have their own workspace roots. A broad conceptual
crate map cannot identify the exact files a new profile must change.

**Correction:** P00/P05/P36 must use a versioned inventory, artifact ownership
map and feature/profile matrix. Reconcile schema owners, runtime consumers,
SDK consumers and required checks before adding a crate or claiming complete
qualification. P40 makes this an explicit integration deliverable.

### R02. The qualified pool ledger is a major reusable foundation

[Kernel finding-pool admission](../../../crates/kernel/chio-kernel/src/finding_pool.rs)
defines authenticated debit/claim/terminal operations and requires a
`QualifiedFindingPoolLedger`. [Its SQLite implementation](../../../crates/platform/chio-store-sqlite/src/finding_pool_ledger.rs)
uses immediate transactions, exact replay, decimal monetary storage, a signed
receipt outbox and durable allocation/store bindings. The
[allocation companion](../../../crates/kernel/chio-swarm-authority/src/finding_pool.rs)
authenticates the exact pool, purchaser, currency, amount and concrete ledger.

[Existing tests](../../../crates/platform/chio-store-sqlite/tests/finding_pool_ledger.rs)
cover domain exclusion, different-store rejection, SQLite clone rejection,
restart and key-rotation behavior. The
[rollback anchor](../../../crates/platform/chio-store-sqlite/src/rollback_generation.rs)
requires a different filesystem device from the protected database. These are
real defenses that the first plan's toy double-pledge model does not exercise.

**Correction:** P01 must distinguish a deliberately unsafe local-balance model,
the actual qualified ledger under its operating assumptions, and a remote
administrator who controls all its local enforcement and state. P16/P41 should
adapt the qualified local ledger instead of creating a parallel company wallet.
External scarce backing still requires an independently enforced funding
authority; a local marker trait is not proof against its malicious implementer.
Do not count a database-only clone already rejected by this ledger as a new
Chio vulnerability or research contribution.

### R03. Workflow accounting does not reserve the next action's cost

[WorkflowAuthority::validate_step](../../../crates/platform/chio-workflow/src/authority.rs)
checks active state, authorization, ordering and time. The cost-dependent
budget logic is in `record_step`, after a result and cost exist. Meanwhile
[BudgetTree::evaluate](../../../crates/economy/chio-metering/src/budget_hierarchy.rs)
checks a proposed spend against a caller-supplied snapshot; it does not make
that snapshot an atomic shared reservation.

**Correction:** P28/P42 must reserve enforceable worst-case model, tool and
verification costs before dispatch through the existing monetary authority.
Concurrent checks against one old snapshot are not sufficient. Preserve
post-step accounting for truthful actual cost, including overruns and unknown
charges. Reject hard-ceiling profiles for APIs whose maximum charge cannot be
bounded by an enforced provider contract.

### R04. Swarm graphs, continuation witnesses and preflight already exist

[The swarm verifier](../../../crates/kernel/chio-swarm-authority/src/verifier.rs)
already validates task/delegation evidence and provides fan-out/fan-in budget
transformations. [Runtime admission](../../../crates/kernel/chio-runtime-core/src/admission_hook/swarm_authority.rs)
loads and verifies swarm evidence from its own store. The
[workflow preflight](../../../crates/platform/chio-workflow-preflight/src/lib.rs)
is explicitly planning evidence. `SwarmBudgetPool` itself remains unsigned
planning data until bound to a qualified debit through its signed companion.

**Correction:** P17/P21/P43 must map work agreements and procurement permits to
these graphs and witnesses, then specify what the funding profile adds. Do not
reuse the single-pool sum as a sum of gross intercompany transfers. Document
which budgets are attenuated authority, which are local resource ceilings and
which are separately funded commercial obligations. Test joins, cancellation
and replay without confusing these three meanings.

### R05. The settlement observer cannot perform funding admission

[The kernel settlement observer](../../../crates/kernel/chio-kernel/src/kernel/settlement_observer.rs)
and [SettlementHook](../../../crates/economy/chio-settle/src/hook.rs) run after a
receipt has been signed and persisted. Their durable retry and idempotency
machinery is useful for settlement processing, but registering a hook does
not establish that a job was funded before it ran.

[ChioEscrow](../../../contracts/src/ChioEscrow.sol) already enforces deposits,
release amounts, receipt consumption and registry-dependent authorization.
Its deadline-based refund does not itself consult an off-chain pending result.

**Correction:** P03/P10-P14/P44 must map each admission, rail intent, native
payment terminal and observation to one logical obligation. Require backing
before payable execution and reconcile uncertain submissions afterward. A
local capture followed by an unrelated external payout must not accidentally
charge the buyer twice. Key/registry rotation and claim/refund ordering require
explicit preservation of previously eligible claims, not only new-job tests.

### R06. Finding verification and challenge semantics should be extended

[FindingEvidenceVerifier](../../../crates/trust/chio-finding-verifier/src/verify.rs)
has a 13-facet evaluation with distinct `verified`, `asserted`, `unavailable`
and `failed` outcomes. [Challenge evaluation](../../../crates/trust/chio-finding-challenge/src/evaluate.rs)
already verifies standing, retained authority policy, role separation and
class-compatible evidence. Runtime challenge coordination is downstream.

**Correction:** P12/P26/P45 must map W0/W1 acceptance onto named existing facets
and new task predicates, preserving required-facet failure. Define which F1
verifier decisions establish result eligibility, custody and monetary claims.
Do not replace the challenge pipeline with a generic signed `accepted: true`.
Passing artifact-integrity or settled-spend facets does not prove usefulness.
Existing seller-facing verified-fix artifacts also deserve reuse before adding
a second source-repair format.

### R07. Discovery and federation have explicit local-activation boundaries

[Listing discovery](../../../crates/economy/chio-listing/README.md) already
provides signed listings, aggregation, pricing comparison and trust activation.
[FederationImportControl](../../../crates/trust/chio-federation/src/artifacts.rs)
defaults to explicit local activation and manual review; federation evidence
does not automatically become runtime trust. Reputation imports likewise
remain subject to the receiver's selected policy.

**Correction:** P24/P46 must reuse discovery and distinguish admission of a new
counterparty under an already approved policy from import of new issuer roots.
The newcomer experiment can eliminate pair-specific code without pretending
that these policy decisions disappeared. If an existing profile requires
manual trust import, retain that requirement or define and qualify a new
profile explicitly. No request-side exception may disable local activation.

### R08. Existing commercial proof and risk surfaces have claim ceilings

[Commerce order verification](../../../crates/platform/chio-commerce-order/README.md)
replays and binds supplied evidence; it does not execute purchases.
[Risk-comptroller verification](../../../crates/platform/chio-risk-comptroller/src/lib.rs)
checks supplied reports and portfolio reserve consistency; it is not a source
of deposited capital. Credit/underwriting/autonomy artifacts and
[financial credentials](../../../crates/economy/chio-fincred/src/lib.rs) likewise
must retain the authority and completeness assumptions of their source data.

The [trust-market claim catalog](../../../crates/platform/chio-trust-market-context/src/claims.rs)
explicitly blocks claims about an operated permissionless provider marketplace,
global trust score, liquidity pool, risk syndication, underwriter market,
autonomous guarantee sales and slashing court.

**Correction:** P05/P15/P47 must cross-map the new work profile to commerce,
passport and risk claims. Open policy-based enrollment is not automatically
the blocked permissionless-market claim. Preserve old-profile rejections;
qualifying a new narrow claim requires a versioned verifier decision and tests.
Reuse fee/bond vocabulary from `chio-fiscal`, but fund every promised payout.
No insurance formula, credential or reputation score counts as cash backing.

### R09. Production key custody needs a concrete route

[SigningBackend](../../../crates/core/chio-core-types/src/crypto.rs) supports
separation of signing from private-key extraction.
[Remote signing adapters](../../../crates/trust/chio-signing-remote/src/lib.rs)
pin a public key/version and verify returned signatures. Hardware-custody
interfaces support other locally selected issuance flows.

**Correction:** P25/P31/P48 must specify separate agent, kernel, verifier,
funding and governance keys, exact role/algorithm bindings, signing availability
and rotation of outstanding agreements. Use supported signing seams where
possible; audit any path still requiring a raw `Keypair`. Do not give an agent
a general-purpose remote signing endpoint or make a signing service a receipt
oracle. Remote signing improves key custody, not honesty of a remote company.

### R10. Disclosure has existing evidence machinery and a larger recipient set

[Selective-disclosure projections](../../../crates/trust/chio-selective-disclosure/src/lib.rs)
and [disclosure-lineage verification](../../../crates/trust/chio-disclosure-lineage/README.md)
already bind receipt fields, leakage accounting and privacy profiles. Those
mechanisms cover selected evidence predicates, not arbitrary declassification
of source code or deletion from a remote administrator's machine.

**Correction:** P19/P27/P49 must account for every data recipient: specialist,
model provider, F1 verifier/custodian, artifact host and evidence consumer.
Reuse disclosure profiles where their exact field semantics fit. Preserve
required claim evidence when hiding fields. Include identifiers, repeated
disclosures, logs and artifact paths in leakage tests. The `chio-tee` crate is
a traffic-tap shadow runner, not proof of hardware trusted execution merely
because its name contains `tee`.

### R11. Provider adapters and SDKs affect both economics and independence

[Tool-call fabric](../../../crates/protocol/chio-tool-call-fabric/README.md)
and [provider adapter core](../../../crates/protocol/chio-provider-adapter-core/README.md)
already supply canonical tool invocations and verdict-gated streaming. Reuse
them for live procurement instead of exposing a second bypass path.

The production [Python market SDK](../../../sdks/python/chio-sdk-python/src/chio_sdk/cognition_market.py)
and [TypeScript market SDK](../../../sdks/typescript/chio-ts/src/cognition_market.ts)
invoke the `chio` binary to verify proof bundles. This is sensible product
reuse but does not supply independent application-verifier authorship.

**Correction:** P22/P23/P28/P50 must distinguish SDK integration from an
independently authored verifier/provider. Record shared application code and
CLI subprocess dependencies in the trial. The existing standalone Python
research verifier remains relevant separate evidence. Publish SDK error,
status, uncertainty and replay behavior for the chosen new profile.

### R12. Every newly introduced fetch must use the egress boundary

[HttpEgressContract](../../../crates/protocol/chio-egress-contract/src/lib.rs)
already addresses authorities, IP classes, DNS, redirects and byte limits.
[Guard-registry loading](../../../crates/guards/chio-guard-registry/README.md)
has digest-pinned artifact distribution and verification policy.

**Correction:** P19/P24/P27/P51 must cover discovery URLs, quoted endpoints,
funding RPC, verifier downloads, model calls and checker dependencies with an
actual enforced transport contract. Test DNS changes at connect time, redirects
to private addresses, oversized responses and credential forwarding. Keep
receiver-native input/output guards in the paid dispatch path. A digest-pinned
checker still requires isolated execution and explicit network authority.

### R13. Choose a deployment profile; do not rebuild hosted machinery blindly

The [PostgreSQL HTTP backend](../../../crates/platform/chio-finding-market-store-postgres/src/http.rs)
implements `HostedMarketBackend` and uses typed domain events. Its
[spend store](../../../crates/platform/chio-finding-market-store-postgres/src/spend.rs)
has tenant-scoped reservations. The existing hosted edge, role-scoped auth,
workers, migrations and canary are substantial implementations. The
[worker executor](../../../crates/platform/chio-finding-worker/src/executor.rs)
contains a pinned Firecracker/jailer and resource configuration.

**Correction:** P31/P34/P52 must choose either independently operated qualified
single-operator nodes or the hosted tenant profile, then map every new work
operation through the chosen auth/store/worker route. Use the narrow node
profile first unless the trial needs multi-tenant hosting. PostgreSQL tenancy
does not make companies administratively independent. A bubblewrap demo does
not qualify a Firecracker deployment, and KVM evidence does not prove a remote
company is honest. Current source presence is not public activation evidence.

### R14. Retention, capacity and numeric representation are contract inputs

[Market capacity](../CAPACITY.md), pool monetary decimal encodings and hosted
I-JSON integer bounds are not interchangeable. The source allows full `u64`
amounts in certain canonical decimal-string artifacts, while hosted spend
admission caps numeric units at `2^53 - 1`. Nested evidence also meets limits
on input bytes, parser depth, receipts, jobs, nonces and retained terminals.

**Correction:** P05/P06/P20/P53 must freeze numeric encodings per artifact and
reject out-of-range adapters rather than truncate. Test values at `2^53 - 1`,
`2^53`, and `u64::MAX` where supported. Define retention long enough for claims,
disputes and recovery; do not garbage-collect unknown obligations or occupied
nonces to regain capacity. Reconcile current retention implementations with
the reliability program before treating old RFC defects as live findings.

### R15. Telemetry and proof presentation have different authority

[OTel receipt export](../../../crates/observability/chio-otel-receipt-exporter/README.md)
creates observation receipts and has bounded queuing. Such telemetry is not
the authoritative spend ledger. [Proof Room](../../../crates/products/chio-proof-room/README.md)
already recomputes domain-verifier results from source artifacts.
[Enterprise export](../../../crates/platform/chio-enterprise-export/README.md)
and lineage interfaces can support company evidence needs without inventing
another receipt format.

**Correction:** P15/P33/P35/P54 must correlate agreement, operation, allocation,
receipt and rail effect while preserving their distinct identities. Derive
money totals from authoritative records and report missing/dropped telemetry.
Extend Proof Room/domain verification for new claims instead of rendering
supplier-declared success. Keep authority evidence retrievable without the UI.

### R16. Existing qualification does not automatically cover new examples

[Federated work](../../../examples/federated-work/Cargo.toml), composed baseline
and outcome-ledger comparison are standalone workspaces. A root
`cargo test --workspace` does not run them. The inspected workflow sources do
not explicitly name the new federated-work suite. This review does not infer
complete effective CI selection from that absence alone.

[Schema registry checks](../../../scripts/check-chio-schema-registry.sh),
four-language code generation and the existing hosted/network/KVM qualification
scripts must be accounted for. The [network](../../../scripts/qualify-cognition-market-network.sh)
and [KVM](../../../scripts/qualify-cognition-market-kvm.sh) scripts require
concrete setup and clean exact candidates. An absent prerequisite is a missing
qualification result, not a passed scenario.

**Correction:** P09/P36/P37/P55 must add explicit standalone-suite selection,
the required feature/target matrix, cross-language vectors, source manifests
and profile-specific deployment gates. Preserve full native receipt/kernel
tests where their code changes. Do not claim all adapters or platforms are
qualified because the chosen Linux/A2A profile passes.

## 4. What changed in the program

The roadmap now carries P40-P55, one integration package for each finding,
with milestone placement, dependencies and concrete acceptance evidence.
Existing P00-P39 remain stable identifiers. The protocol, workload,
qualification and trial documents incorporate the relevant decisions directly;
this review is supporting evidence, not an appendix that implementers may
ignore.

M0 now begins by testing the actual ledger boundary and mapping existing
artifact owners. M1 chooses numeric, trust and claim semantics before schema
expansion. M2 distinguishes funded admission from the settlement observer.
M3 builds on durable pool and swarm machinery. M4 separates independent
implementation from SDK wrappers. M6 chooses and qualifies a concrete operator
profile rather than inheriting a historical hosted status claim.

## 5. Remaining evidence boundaries

This review identified reusable code and planning gaps. It did not prove the
new F1 exchange, implement the added packages, run the Rust/contract/KVM suites,
audit every cryptographic dependency or establish current remote release
status. No external operator, real funds or production listener was activated.

The next meaningful result remains one funded bilateral work exchange with
the chosen acceptance procedure, a noncooperative-party failure case and a
truthful comparison. The broader repository review makes that slice better
specified and avoids rebuilding components Chio already has.
