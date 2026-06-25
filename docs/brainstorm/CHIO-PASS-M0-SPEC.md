# Chio Pass - M0 Implementation Spec

Status: implementation-ready build doc (M0).
Audience: an engineer starting the build from zero.
House rules in force: no em dashes (hyphens/parentheses only); fail-closed (errors deny);
no `.unwrap()`/`.expect()` in production code (clippy `unwrap_used`/`expect_used` are deny);
canonical JSON (RFC 8785) for every signed payload; conventional commits.

This document folds in every verification correction and the integration review. Where a
component spec disagreed with another or with the code, the resolved decision is stated here
and is authoritative. Section 2 (Canonical shared types) is the single source of truth that
every later section binds to; if a later section appears to diverge, Section 2 wins.

Ground-truth code facts this spec was verified against:
- `chio-credentials/src/lib.rs` `include!`s end at line 91 with `include!("tests.rs");`;
  `include!("portable_reputation.rs");` is line 90. No `chio_pass.rs` exists yet. The crate is a
  single flat `include!` namespace; the included files carry no `use` statements and rely on the
  `use` block at `lib.rs:16-32` (which already imports `chrono::{DateTime, SecondsFormat, TimeZone, Utc}`,
  `chio_did::{DidChio, DidError}`, and `chio_core::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature}`).
- `AttestationWindow { since: Option<u64>, until: u64 }` (`artifact.rs:183`, `deny_unknown_fields`); `since`
  is an `Option` and can be absent.
- `BudgetUsageRecord` keys strictly on `(capability_id: String, grant_index: u32)` (`budget_store.rs:16-25`);
  there is no global/aggregate term today. `committed_cost_units()` = `total_cost_exposed + total_cost_realized_spend`.
- `CapabilityTokenBody { id: String, issuer, subject, scope, issued_at: u64, expires_at: u64, delegation_chain }`
  (`token.rs:90-108`); `id` is caller-supplied and copied verbatim into the signed token.
- `ChioScope { grants: Vec<ToolGrant>, resource_grants: Vec<ResourceGrant>, prompt_grants: Vec<PromptGrant> }`
  (`scope.rs:11-22`). `ToolGrant` carries `max_cost_per_invocation: Option<MonetaryAmount>` and
  `max_total_cost: Option<MonetaryAmount>` (`scope.rs:63-85`); `MonetaryAmount { units: u64, currency: String }`.
  `ResourceGrant { uri_pattern, operations: Vec<Operation> }`; `Operation::{Read, Subscribe, Invoke, Delegate, ...}`.
- `ChioKernel::new(config: KernelConfig) -> Self` is INFALLIBLE (`construction.rs:133`); there is no `try_new`.
  `budget_store_lock: Mutex<()>` set at `construction.rs:151`; `with_budget_store` recovers a poisoned lock
  via `into_inner()` (`construction.rs:105-114`).
- The pre-execution charge is `ChioKernel::check_and_increment_budget(&self, request_id, cap, matching_grants)`
  (`validation.rs:750-842`). The monetary branch computes
  `cost_units = grant.max_cost_per_invocation.map(|m| m.units).unwrap_or(0)` and
  `currency = max_cost_per_invocation.currency || max_total_cost.currency || "USD"`. There is NO `now` parameter.
- `KernelError` has NO `InvalidConfiguration` variant (`error.rs:29-204`); it has `InvalidConstraint(String)`,
  `CapabilityIssuanceFailed(String)`, `BudgetExhausted(CapabilityId)`.
- UUIDv7 capability mint sites exist in FOUR places: `chio-kernel/authority.rs:62`,
  `chio-store-sqlite/authority.rs:627`, `chio-http-core/authority.rs:542/579/690`.
- `minor_units_for_currency` (`chio-link/src/convert.rs:5`) returns `Err(PriceOracleError::InvalidConfiguration)`
  for any unpinned code (USD/EUR/GBP/JPY/USDC/USDT/BTC/ETH/LINK are pinned; `XCC` is not). `chio-kernel` already
  depends on `chio-link` (`Cargo.toml:56`).
- `premium.rs:144` requires a currency code to be exactly 3 ASCII uppercase letters; `XCC` passes the shape
  but stays unpriced.
- `ChioReceipt` (`receipt/body.rs`) carries `timestamp: u64`, `capability_id: String`, `decision: Option<Decision>`,
  `receipt_kind: ReceiptKind`, `trust_level: TrustLevel`, `metadata: Option<serde_json::Value>`, `kernel_key: PublicKey`,
  `verify_signature() -> Result<bool>` (verifies against the receipt's OWN `kernel_key`), and typed accessors
  `typed_metadata("financial")` AND `typed_metadata("budget_authority")` (TWO economic envelope keys).
- `CostMetadata { dimensions: Vec<CostDimension>, .. }` (`chio-metering/cost.rs:69-86`); `CostDimension::Custom { name, value: u64, unit: Option<String> }` (`cost.rs:53`); `compute_total_monetary_cost` sums ONLY `ApiCost` (`cost.rs:124`).
- `CliError` (`chio-control-plane/src/lib.rs:48`) has `Other(String)` and many `#[from]` arms
  (`Credential`, `BudgetStore`, `ReceiptStore`, `Kernel`, ...); there is NO `CliError::internal`.
- chrono is a `chio-kernel` dependency with the `serde` feature (`Cargo.toml:51`); `chio-kernel` is a std crate.

---

## 1. Overview and scope

### 1.1 What M0 ships

The Chio Pass is a soulbound (non-transferable, non-redeemable) verifiable credential added to the
existing `chio-credentials` crate. It is NOT a token, there is no ERC-20, and no value moves on-chain.
A Pass grants its holder, keyed to a single attested `did:chio`:

1. A permanent tier_0 baseline RIGHT: free Read/Subscribe over three aggregate trust feeds plus the
   holder's OWN receipts and OWN lineage (the own streams are an always-free baseline right with the
   financial leg redacted out).
2. A day-zero metered free-compute allotment, handed to the NEWCOMER at tier_0 (the costly half goes to
   the newcomer; tier governs allotment SIZE/refill only, never its existence).

Three new kernel controls make the free tier Sybil-bounded with no money leg:

- CONTROL 1 - Aggregate global pool ceiling. A synthetic monthly budget term
  `freetier:global:{window_ym}` that every per-Pass free-tier charge co-debits, so realized liability is
  hard-capped at `min(N x allotment, POOL)`; exhaustion fails closed to a Deny receipt with
  `cost_charged = 0`.
- CONTROL 2 - Deterministic window-scoped capability id. `token.id = "chiopass:" + sha256_hex(canonical(domain, subjectDid, windowYm))`,
  `grant_index 0` pinned, the same id on every re-presentation, AttestationWindow expiry == monthly reset.
  This closes the re-mint reset exploit (re-minting a fresh UUIDv7 to reset the per-token counter).
- CONTROL 3 - Refresh-on-genuine-use. The next window's allotment refresh is gated on fresh genuine
  receipt activity plus fresh re-attestation, so dormant/extractive identities fall to a 0 ceiling that
  denies fail-closed on their first metered charge.

Distribution is throttled per window by a population cap plus a retroactive unpredictable snapshot so
farmers cannot time mass-registration.

### 1.2 Explicitly OUT of scope (Phase 1+)

- No money leg. No ERC-20 token, no on-chain value transfer, no real-currency allotment. The allotment is
  a private-use unit (`XCC`) that is intentionally never priced.
- The refundable escrow activation deposit (a money leg via `ChioEscrow`) is DEFERRED to Phase 1.
- The bond-anchored fix for issuer independence is DEFERRED to Phase 2. M0 inherits the verified-weak,
  self-declared `issuer_independence_group_id` (`chio-federation/reputation.rs:201`); the pool ceiling and
  population cap BOUND the blast radius of that residual Sybil weakness in M0 (they do not fix it).
- The immutable contracts `ChioRootRegistry`, `ChioEscrow`, `ChioBondVault`, `ChioPriceResolver` are
  UNTOUCHED. `ChioRootRegistry` is used READ-ONLY for anchoring issuance/revocation Merkle roots.
- Pool-context-in-receipt projection (surfacing the pool term/board_approval/pool_remaining into receipts)
  is OUT of M0; the Deny receipt's `cost_charged = 0` / `budget_remaining = 0` is the M0 evidence.
- Per-namespace pheromone concentration scoping, anchoring cadence/batching policy, and a richer
  multi-tool genuine-use floor are deferred (see open questions).

Grounding to shipped commerce primitives (IN scope, hard requirements, not deferrals):
- POOL-TERM NAMESPACE ISOLATION (required). The synthetic `freetier:global:<window_ym>` budget term shares
  the `(capability_id, grant_index)` budget store with real capability/commerce holds, so it MUST be
  namespace-isolated by its `freetier:global:` prefix and NEVER counted as a real capability/commerce budget
  by aggregate budget projections or the `chio.risk.comptroller-report.v1` reserve view. It is a Sybil-ceiling
  accounting term, not capital; fail-closed exclusion from every reserve/aggregate projection is the rule.
- SCHEMA DISCIPLINE. `chio.pass.v1` is a VC credential family, NOT a signed-artifact-registry member, so it
  correctly need NOT register in `spec/schemas/registry.json` / `KNOWN_SIGNED_ARTIFACT_SCHEMAS` (mirroring
  `chio.agent-passport.v1`). The reused anchor schemas (`chio.anchor-inclusion-proof.v1` /
  `chio.anchor-proof-bundle.v1`) are ALREADY registered (R-T05-16 closed at HEAD); the Pass adds no new
  signed-artifact schema or claim.
- PROOF-ROOM EVIDENCE PANEL. Pass issuance/revocation inclusion renders as a `chio-proof-room` sealed evidence
  panel with asserted/observed/verified evidence classes (Section 8.3), not an offline-only assertion.

---

## 2. Canonical shared types (single source of truth)

Every component binds these EXACTLY. These resolve the three rival capability-id derivations, the three
disagreeing tier tables, the XCC-vs-CPU unit clash, and the AttestationWindow duplication.

### 2.1 AttestationWindowId (ONE window type)

Defined once in `chio-core-types::capability::token` so the std kernel and the credential layer share it
without a chrono/did dependency cycle:

```rust
// crates/core/chio-core-types/src/capability/token.rs (additive)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationWindowId {
    /// UTC calendar-month label, formatted "%Y-%m" (e.g. "2026-06"). The single
    /// term shared with CONTROL 1's freetier:global:<window_ym> pool.
    pub window_ym: String,
    /// 00:00:00Z on the first of the month (unix seconds). == token.issued_at.
    pub since: u64,
    /// 00:00:00Z on the first of the NEXT month (unix seconds). == token.expires_at.
    pub until: u64,
}
```

Half-open interval `[since, until)`. Invariants: `token.issued_at == since`, `token.expires_at == until`.
`AttestationWindowId::validate(&self) -> Result<()>` (core `Result`) rejects an empty `window_ym` or
`until <= since` with the new `Error::InvalidAttestationWindow { reason: String }`.

The credential's existing `AttestationWindow { since: Option<u64>, until }` (`artifact.rs:183`) is reused
ONLY for `ChioPassEvidence.snapshot_window`, and MUST carry `since: Some(window.since)` (never `None`).
Spec 1's separate `ChioPassWindow {window_id, since_unix, until_unix}` is dropped and folded into
`AttestationWindowId` (`window_id` -> `window_ym`).

### 2.2 Deterministic capability id (ONE function, ONE formula, ONE home)

```rust
// crates/core/chio-core-types/src/capability/token.rs (additive)
pub const CHIO_PASS_CAPABILITY_ID_DOMAIN: &str = "chio.pass.capability.id.v1";
pub const CHIO_PASS_CAPABILITY_ID_PREFIX: &str = "chiopass:";

#[derive(Debug, Clone, Serialize)]
struct WindowScopedCapabilityIdInput<'a> {
    domain: &'a str,
    subject_did: &'a str,
    window_ym: &'a str,
}

/// id = "chiopass:" + sha256_hex(canonical_json_bytes({domain, subjectDid, windowYm})).
/// RFC 8785 canonicalization sorts keys, so determinism is independent of struct field
/// declaration order. Fails closed on a malformed window or any canonicalization error.
pub fn window_scoped_capability_id(
    subject_did: &str,
    window: &AttestationWindowId,
) -> Result<String> {
    window.validate()?;
    let input = WindowScopedCapabilityIdInput {
        domain: CHIO_PASS_CAPABILITY_ID_DOMAIN,
        subject_did,
        window_ym: window.window_ym.as_str(),
    };
    let bytes = crate::canonical::canonical_json_bytes(&input)?;
    Ok(format!("{CHIO_PASS_CAPABILITY_ID_PREFIX}{}", crate::hashing::sha256_hex(&bytes)))
}
```

`grant_index` is pinned to `0`. `chio-credentials` and the kernel `authority.rs` BOTH call this one
function; nobody re-implements it. This kills the rival derivations (raw-concat-with-0x00, the
`"chio.pass.capability-id.v1"` schema string, the no-prefix forms) which would hash to different bytes and
split the budget row.

SINGLE-ISSUER ASSUMPTION (stated, not hidden): the id binds `(domain, subjectDid, windowYm)` only; there
is no issuer column, and the budget key `(capability_id, grant_index)` has none either. Under M0's single
issuing authority this is correct. If M0 ever runs multiple Pass issuers, two issuers minting for the same
subject+month would collide on one budget row; that is acceptable only because M0 has one authority. The id
intentionally does NOT commit to scope or tier (a tier change reuses the same row by design).

The id always derives from the CANONICAL `did:chio` (`DidChio::from_*(...).as_str()`), never a raw
caller-supplied string, so the row is stable across re-presentations.

### 2.3 Allotment unit = "XCC" everywhere

`XCC` is a 3-uppercase-letter ISO-4217 private-use (X-range) code. It passes `premium.rs:144`'s shape rule
and is intentionally NOT pinned in `chio-link::minor_units_for_currency` (so it stays fail-closed-unpriced
and never acquires a money leg). It is used in TWO places, and both must say `XCC`:

- The grant currency on the metered `ToolGrant`'s `max_cost_per_invocation` AND `max_total_cost`
  (`MonetaryAmount.currency = "XCC"`). This is what CONTROL 1 recognizes as free-tier.
- The metering dimension `CostDimension::Custom { name: "chio.pass.allotment.v1", value, unit: Some("XCC") }`
  written into receipt `metadata["cost"].dimensions`, which keeps the allotment off `total_monetary_cost`
  (summed only from `ApiCost`).

Spec 4's `unit: "CPU"` is wrong; use `XCC`. Shared constants:

```rust
pub const CHIO_PASS_ALLOTMENT_UNIT: &str = "XCC";           // grant currency + Custom unit
pub const CHIO_PASS_ALLOTMENT_COST_NAME: &str = "chio.pass.allotment.v1"; // Custom dimension name
```

### 2.4 Global pool term

`capability_id = format!("freetier:global:{window_ym}")`, `grant_index = 0`,
`max_total_cost_units = monthly_pool_units`. `window_ym` is the SAME string CONTROL 2 bound into the token.
It is derived from `cap.issued_at` (== `since` == first-of-active-month), NOT from `now` (drifts at
boundaries) and NOT from `cap.expires_at` (which is first-of-NEXT-month and would desync the pool from the
per-Pass row by one month). The kernel formats it with chrono `DateTime::from_timestamp` (no `TimeZone`
trait import needed).

### 2.5 Tier -> allotment-units table (ONE governance-pinned source)

The three component tables disagreed (`1000/1000/2500/5000`, `1000/1000/4000/10000`, `1000/2000/5000/10000`).
The table is GOVERNANCE-PINNED CONFIG (not a `const`), loaded fail-closed. M0 default placeholder
(needs board sign-off, see open questions):

| Tier | window_units |
|------|--------------|
| Unverified (tier_0 newcomer) | 1000 |
| Attested  | 1000 |
| Verified  | 2500 |
| Premier   | 5000 |

Invariant ALL code must honor: the floor applies unconditionally (`Unverified > 0`, the newcomer gets the
costly half); tier scales SIZE only, never existence. ONE lookup `allotment_units_for_tier(tier, &table)`
lives in `chio-credentials` (Section 3); the duplicate `tier_allotment_units` and the second
`allotment_units_for_tier` are dropped (B2). Per-invocation XCC cost is a separate small positive config
constant (`per_invocation_units`, default 1) so `max_cost_per_invocation.units > 0` always holds (see 2.7).

### 2.6 Genuine-use predicate (ONE predicate + ONE const)

```rust
pub const MIN_GENUINE_USE_RECEIPTS: u32 = 1;
fn is_genuine_use_receipt(receipt, pass_capability_id, window, &accepted_kernel_keys) -> Result<bool, CredentialError>
```

Defined once in `chio-credentials` (Section 6.4). It reads the EXISTING `CostMetadata` Custom dimension
under `receipt.metadata["cost"].dimensions[]` (name == `CHIO_PASS_ALLOTMENT_COST_NAME`, value > 0), NOT a
net-new `metadata.metering.allotment_debit` block. Spec 1's `evidence.genuine_use_observed` becomes the
EMBEDDED OUTPUT of this scan. Spec 6's `refreshes_allotment` / `ChioPassRefreshEvidence` /
`CHIO_PASS_MIN_GENUINE_RECEIPTS(u64)` duplicates are dropped (note: the u32-vs-u64 clash is resolved to u32).

### 2.7 Canonical Pass `ChioScope` shape (the union no single component stated)

A valid Pass mints EXACTLY this scope (and the verify/admission path rejects anything else fail-closed):

```
ChioScope {
  grants: [ EXACTLY ONE metered ToolGrant @ index 0:
              server_id = "chio.pass.compute", tool_name = "*",
              operations = [Invoke],
              max_cost_per_invocation = Some(MonetaryAmount { units: per_invocation_units (>0), currency: "XCC" }),
              max_total_cost          = Some(MonetaryAmount { units: window_units (>=0),        currency: "XCC" }),
              max_invocations = None ],
  resource_grants: pass_baseline_resource_grants(subject_tenant)  // EXACTLY 5, Read/Subscribe, indices 0..4
  prompt_grants: []   // MUST be empty
}
```

Budget rows open only on `grants[0]` (the metered XCC ToolGrant). The 5 `resource_grants` carry no `max_*`
limits and never open budget rows. `max_total_cost` MUST be `Some(...)` (never `None`, which would be
unlimited / fail-open); a WithheldDormant refresh sets `max_total_cost.units = 0`.
`max_cost_per_invocation.units` MUST be `> 0` (else the pool co-debit requests 0 units and bounds nothing).

### 2.8 New error variants (single home each, no clashes)

- `chio_core_types::error::Error::InvalidAttestationWindow { reason: String }` (CONTROL 2).
- `CredentialError::InvalidChioPassSchema` (UNIT, schema-string mismatch, mirrors `InvalidPassportSchema`).
- `CredentialError::ChioPassExpired` (UNIT, mirrors `CredentialExpired`).
- `CredentialError::InvalidChioPassValidityWindow` (UNIT).
- `CredentialError::InvalidChioPassAllotmentGrant(String)`.
- `CredentialError::InvalidChioPassWindow(String)`.
- `CredentialError::InvalidChioPassCapabilityBinding(String)` (the window-scoped-id binding failure;
  renamed from Spec 3's `InvalidChioPassSchema(String)` to avoid the unit-vs-String arity clash, B3; mirrors
  the String-carrying `PassportSubjectMismatch(String)` template, not the unit `InvalidPassportSchema`).
- `CredentialError::ChioPassGenuineUseScanFailed(String)`, `CredentialError::ChioPassReattestationMissing`,
  `CredentialError::InvalidChioPassRefreshWindow` (CONTROL 3).
- `KernelError::InvalidFreeTierPoolConfig(String)` (CONTROL 1, NEW; `KernelError::InvalidConfiguration` does
  not exist, do not reference it).
- `KernelError::PassScopeInflation(String)`, `KernelError::PassTenantBindingInvalid(String)`,
  `KernelError::PassRedactionFailed(String)`, `KernelError::PassCapabilityIdNotDeterministic(String)`
  (data-stream gating + the B7 admission assertion).

Soulbinding REUSES the existing `CredentialError::PresentationHolderMismatch` (`artifact.rs:111`); no new
soulbinding variant.

---

## 3. Chio Pass credential format + issuance/revocation/anchoring

New flat-namespace module `crates/trust/chio-credentials/src/chio_pass.rs`, wired by adding
`include!("chio_pass.rs");` at `lib.rs:91` (immediately before `include!("tests.rs");`, after
`include!("portable_reputation.rs");` at line 90). Following the `include!` convention, `chio_pass.rs`
carries NO `use` statements; the needed imports are ADDED to the `lib.rs` top-level `use` block:
extend `lib.rs:31` to `use chrono::{DateTime, Datelike, Months, SecondsFormat, TimeZone, Utc};` (add only
`Datelike, Months`) and add
`use chio_core::capability::token::{AttestationWindowId, CapabilityToken, window_scoped_capability_id};`.
`DidChio`/`canonical_json_bytes`/`sha256_hex`/`Keypair`/`PublicKey`/`Signature`/`TrustTier` are already in
scope at the crate root.

### 3.1 Credential bodies (modeled byte-for-byte on `ReputationCredential`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassAllotmentGrant {
    pub unit: String,                 // MUST == CHIO_PASS_ALLOTMENT_UNIT ("XCC")
    pub window_units: u64,            // allotment SIZE for this window (tier-sized; 0 == withheld)
    pub per_invocation_units: u64,    // MUST be > 0 (binds max_cost_per_invocation)
    pub refill_cadence_secs: u64,     // MUST == window.until - window.since
    pub requires_genuine_use_refresh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassEntitlements {
    pub tier: TrustTier,              // governs allotment SIZE/refill only
    pub read_scopes: Vec<String>,     // == chio_kernel::pass_gating::pass_baseline_read_uris(subject_did)
    pub allotment: ChioPassAllotmentGrant,
    pub window: AttestationWindowId,  // canonical shared window (Section 2.1)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassEvidence {
    pub attested_tier: TrustTier,
    pub snapshot_window: AttestationWindow, // existing type; since MUST be Some(window.since)
    pub genuine_use_observed: bool,         // embedded output of CONTROL 3's scan
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassSubject { pub id: String, pub entitlements: ChioPassEntitlements }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]   // flatten target: no deny_unknown_fields (matches UnsignedReputationCredential)
pub struct UnsignedChioPass {
    #[serde(rename = "@context")] pub context: Vec<String>,    // [VC_CONTEXT_V1, CHIO_CREDENTIAL_CONTEXT_V1]
    #[serde(rename = "type")]     pub credential_type: Vec<String>, // [VC_TYPE, CHIO_PASS_TYPE]
    pub schema: String,            // CHIO_PASS_SCHEMA = "chio.pass.v1"
    pub issuer: String,            // issuer did:chio
    pub issuance_date: String,     // RFC3339 == window.since
    pub expiration_date: String,   // RFC3339 == window.until
    pub credential_subject: ChioPassSubject,
    pub evidence: ChioPassEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPass {
    #[serde(flatten)] pub unsigned: UnsignedChioPass,
    pub proof: CredentialProof,    // reused as-is (artifact.rs:306)
}

pub const CHIO_PASS_TYPE: &str = "ChioPass";
pub const CHIO_PASS_SCHEMA: &str = "chio.pass.v1";
```

Wire artifact is canonical-JSON (RFC 8785) identical in envelope shape to `ReputationCredential`:
`@context = [VC_CONTEXT_V1, CHIO_CREDENTIAL_CONTEXT_V1]`, `type = [VC_TYPE, "ChioPass"]`,
`proof.type = "Ed25519Signature2020"`, `proof.proofPurpose = "assertionMethod"`,
`proof.verificationMethod = issuer did#key-1`.

Naming note (B-review): `ChioPass` is the soulbound credential; it is distinct from the existing
`AgentPassport` / `PassportLifecycleRecord` bundle. The module doc comment must state this to avoid
`ChioPass` vs `ChioPassport` reader confusion.

### 3.2 Tier sizing and baseline scopes

```rust
#[must_use]
pub fn allotment_units_for_tier(tier: TrustTier, table: &TierAllotmentTable) -> u64 {
    match tier {
        TrustTier::Unverified => table.unverified,
        TrustTier::Attested   => table.attested,
        TrustTier::Verified   => table.verified,
        TrustTier::Premier    => table.premier,
    }
}
```

`read_scopes` are NOT hand-rolled here. They MUST equal the canonical builder
`chio_kernel::pass_gating::pass_baseline_read_uris(subject_did)` (Section 5), which uses the mandatory `/`
delimiter (`chio://receipts/tenant/<did>/*`, `chio://lineage/tenant/<did>/*`) that closes the
prefix-collision hole. Spec 1's no-delimiter `chio://receipts/tenant/{did}*` form is DROPPED (B8). Both the
issuer (when building `read_scopes`) and `validate_chio_pass_entitlements` (cross-check at verify) call the
same builder against the CANONICAL `credential_subject.id`.

### 3.3 Snapshot, issue, verify, revoke

`snapshot_chio_pass_entitlements(subject_did, attested_tier, window: &AttestationWindowId, is_first_window, genuine_use_observed, &config) -> Result<(ChioPassEntitlements, ChioPassEvidence), CredentialError>`:
canonicalizes `subject_did` via `DidChio::from_str` FIRST, then builds `read_scopes` and the capability id
from the canonical DID. REFRESH-ON-GENUINE-USE: `window_units = if is_first_window || genuine_use_observed { allotment_units_for_tier(tier, table) } else { 0 }`;
baseline `read_scopes` persist regardless. `evidence.genuine_use_observed = is_first_window || genuine_use_observed`.
`snapshot_window = AttestationWindow { since: Some(window.since), until: window.until }`.

`issue_chio_pass(issuer_keypair, subject_did, entitlements, evidence, issued_at, valid_until) -> Result<ChioPass, CredentialError>`:
mirrors `issue_reputation_credential_with_enterprise_identity` (`challenge.rs:136`). `issued_at > valid_until`
=> `InvalidChioPassValidityWindow`. Calls `validate_chio_pass_entitlements` (below). Subject is canonicalized
via `DidChio::from_str(subject_did)`; the `window_subject_guard` dead-code block from Spec 1 is DELETED
entirely (it referenced a non-existent method and would not compile). Read scopes are rebuilt from the
canonical `subject.to_string()` so issuance and the capability id derive from the same canonical DID. Signs
with `Keypair::sign_canonical`.

`validate_chio_pass_entitlements(entitlements, issuance, expiration, subject_did, &config) -> Result<(), CredentialError>` enforces, fail-closed:
- `allotment.unit == "XCC"` else `InvalidChioPassAllotmentGrant`.
- `allotment.per_invocation_units > 0` else `InvalidChioPassAllotmentGrant` (binds the non-zero
  `max_cost_per_invocation`, closing the pool-bypass).
- `window.window_id` non-empty, `since == issuance`, `until == expiration`, `since < until`,
  `refill_cadence_secs == until - since` (checked_sub) else `InvalidChioPassWindow` /
  `InvalidChioPassAllotmentGrant`.
- `entitlements.read_scopes == pass_baseline_read_uris(subject_did)` (canonical subject) else
  `InvalidChioPassAllotmentGrant` (binds own-tenant scopes to the canonical DID; closes the scope-binding gap).
- If `allotment.window_units > 0` then `evidence.genuine_use_observed` must be true AND
  `window_units == allotment_units_for_tier(tier, table)`; else `InvalidChioPassAllotmentGrant`. This makes
  refresh-on-genuine-use issuer-INDEPENDENTLY verifiable (a verifier can recompute it), not merely asserted.

`verify_chio_pass(pass, now) -> Result<(), CredentialError>`: mirrors `verify_reputation_credential`
(`challenge.rs:185`). Schema must equal `CHIO_PASS_SCHEMA` else `InvalidChioPassSchema`. Proof type/purpose
checks. Issuer DID parse + `verification_method` match. `issuance > expiration` => `InvalidChioPassValidityWindow`.
EXPIRY IS HALF-OPEN to match the token's `validate_time` (B11): `now >= expiration` => `ChioPassExpired`
(NOT `now > expiration`; `until` is the start of the next window). Runs `validate_chio_pass_entitlements`,
then verifies the Ed25519 signature over `canonical_json_bytes(&pass.unsigned)`.

`verify_chio_pass_holder_binding(pass, holder_public_key) -> Result<(), CredentialError>`: derives
`DidChio::from_public_key(holder_public_key)` and compares to `credential_subject.id`; mismatch =>
`PresentationHolderMismatch`. A non-Ed25519 holder key is rejected by `DidChio::from_public_key`
(`UnsupportedKeyAlgorithm`).

`chio_pass_artifact_id(pass) -> Result<String, CredentialError>` = `sha256_hex(canonical_json_bytes(pass))`
over the FULL signed Pass (mirrors `passport_artifact_id`). This is the anchor leaf / lifecycle key.

`revoke_chio_pass_record(pass, revoked_at, revoked_reason) -> Result<PassportLifecycleRecord, CredentialError>`:
rejects `revoked_at == 0` up front; builds a `PassportLifecycleRecord` with `status: Revoked`,
`passport_id = chio_pass_artifact_id(pass)`, `issuers = [issuer]`, `published_at = issuance unix (non-zero)`,
`updated_at = revoked_at`, `valid_until = expiration_date`; calls `record.validate()` then the caller calls
`record.to_revocation_event()` (`passport.rs:189`) to emit `PassportRevocationEvent`. No new oracle surface.

### 3.4 Anchoring pipeline (read-only `ChioRootRegistry`)

Issued and revoked Pass artifact ids (`chio_pass_artifact_id`) are the Merkle leaves. Build off-chain with
`build_anchor_batch_body` (`chio-anchor/batch.rs:119`: canonical-JSON each leaf, `MerkleTree::from_leaves`,
capture `tree_root`, one `AnchorBatchInclusion` per leaf), sign with `AnchorBatch::sign`. The Pass anchoring
is the SAME RFC6962 substrate the transaction/settlement passports use, not a duplicate lane; the Pass is a
SUBJECT/identity leaf set and is NEVER a transaction-passport root.

API-PATH CORRECTION (the flow below, matching `prepare_root_publication` at `chio-anchor/src/evm.rs:119`; the
prior bare `publishRoot(tree_root)` form would not compile against it). The `AnchorBatch` `tree_root` is NOT
committed directly: wrap it in a `KernelCheckpoint` carrying a strictly-increasing per-operator
`checkpoint_seq`, and obtain a `SignedWeb3IdentityBinding` whose `purpose == Web3KeyBindingPurpose::Anchor`
(under a Pass-specific anchor purpose label, e.g. `chio.pass.anchor.v1`), whose `chain_scope` names the target
chain, and whose `settlement_address == operator_address`. `prepare_root_publication` then drives
`IChioRootRegistry::publishRoot` / `publishRootBatch` (`publish_root` `evm.rs:212`, `confirm_root_publication`
`evm.rs:262`). Prove single-Pass membership with `verifyInclusionDetailed` via `verify_inclusion_onchain`
(`evm.rs:431`, on-chain call at ~`evm.rs:462`). The reused anchor schemas (`chio.anchor-inclusion-proof.v1` /
`chio.anchor-proof-bundle.v1` / `chio.checkpoint_statement.v1`) are already registered; the Pass introduces no
new anchor schema. `ChioRootRegistry` stays read-only and value-free; no value moves on-chain. This API fix is
NON-BLOCKING for M0: anchoring is explicitly deferred per Section 6.6 (the metered fail-closed gate does not
depend on it), but the path must be wired this way when scheduled. Anchoring CADENCE owner is assigned in
Section 6.6 (or explicitly deferred).

### 3.5 Fail-closed summary (credential layer)

Every error path denies: bad schema, expiry (`now >= until`), inverted validity window, non-XCC unit,
zero `per_invocation_units`, malformed/mismatched window, read-scope mismatch against the canonical subject,
`window_units > 0` without `genuine_use_observed`/wrong size, holder-key not deriving the subject, any
canonical-JSON tamper (`InvalidCredentialSignature`), `revoked_at == 0`. `deny_unknown_fields` rejects extra
keys on every body struct except the two `#[serde(flatten)]` envelopes (`UnsignedChioPass`/`ChioPass`),
exactly as the reputation pair does.

---

## 4. The three kernel controls + end-to-end charge ordering

### 4.1 CONTROL 2 - Deterministic window-scoped capability id

Files: `chio-core-types/src/capability/token.rs` (the `AttestationWindowId` + `window_scoped_capability_id`
of Section 2.1/2.2, plus the `Error::InvalidAttestationWindow` variant in `chio-core-types/src/error.rs`,
both std `#[error(...)]` and the no_std `Display` arm); `chio-kernel/src/authority.rs` (the mint override);
`chio-credentials/src/chio_pass.rs` (`attestation_window_containing`, `verify_window_scoped_capability_id`).

`chio-kernel/src/authority.rs` (extend the `use chio_core::capability::token::{...}` import at
`authority.rs:4` with `AttestationWindowId, window_scoped_capability_id`):

```rust
// On trait CapabilityAuthority (authority.rs:11): fail-closed DEFAULT so no other impl breaks.
fn issue_window_scoped_capability(
    &self, _subject: &PublicKey, _subject_did: &str, _scope: ChioScope, _window: &AttestationWindowId,
) -> Result<CapabilityToken, KernelError> {
    Err(KernelError::CapabilityIssuanceFailed(
        "window-scoped Pass issuance unsupported by this authority".to_string()))
}

// LocalCapabilityAuthority override (this is the choke point that replaces authority.rs:62's UUIDv7 stamp):
fn issue_window_scoped_capability(
    &self, subject: &PublicKey, subject_did: &str, scope: ChioScope, window: &AttestationWindowId,
) -> Result<CapabilityToken, KernelError> {
    window.validate().map_err(|e| KernelError::CapabilityIssuanceFailed(e.to_string()))?;
    if scope.grants.len() != 1 {
        return Err(KernelError::CapabilityIssuanceFailed(
            "Pass scope must carry exactly one metered grant pinned at index 0".to_string()));
    }
    let id = window_scoped_capability_id(subject_did, window)
        .map_err(|e| KernelError::CapabilityIssuanceFailed(e.to_string()))?;
    let body = CapabilityTokenBody {
        id,
        issuer: self.keypair.public_key(),
        subject: subject.clone(),
        scope,
        issued_at: window.since,    // == window_ym start; CONTROL 1 derives window_ym from this
        expires_at: window.until,   // window expiry == monthly reset (validate_time, token.rs:650-662)
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, &self.keypair)
        .map_err(|e| KernelError::CapabilityIssuanceFailed(e.to_string()))
}
```

`chio-credentials/src/chio_pass.rs`:

```rust
/// UTC calendar-month window containing `now`. Uses chrono::DateTime::from_timestamp
/// (no TimeZone-trait import). Fails closed on out-of-range ts or month overflow.
pub fn attestation_window_containing(now: u64) -> Result<AttestationWindowId, CredentialError> {
    let secs = i64::try_from(now).map_err(|_| CredentialError::InvalidUnixTimestamp(now))?;
    let dt = DateTime::from_timestamp(secs, 0).ok_or(CredentialError::InvalidUnixTimestamp(now))?;
    let month_start_naive = dt.date_naive().with_day(1)
        .and_then(|d| d.and_hms_opt(0, 0, 0)).ok_or(CredentialError::InvalidUnixTimestamp(now))?;
    let month_start = Utc.from_utc_datetime(&month_start_naive);
    let next_month = month_start.checked_add_months(Months::new(1))
        .ok_or(CredentialError::InvalidUnixTimestamp(now))?;
    let since = u64::try_from(month_start.timestamp()).map_err(|_| CredentialError::InvalidUnixTimestamp(now))?;
    let until = u64::try_from(next_month.timestamp()).map_err(|_| CredentialError::InvalidUnixTimestamp(now))?;
    Ok(AttestationWindowId { window_ym: month_start.format("%Y-%m").to_string(), since, until })
}

/// Admission-boundary defense-in-depth: recompute the expected id from the token's OWN subject and
/// its issued_at-aligned window, and reject any mismatch. Robust to mint-skew because it recomputes
/// the window from token.issued_at (which is pinned == window.since).
pub fn verify_window_scoped_capability_id(token: &CapabilityToken) -> Result<(), CredentialError> {
    let subject_did = DidChio::from_public_key(token.subject.clone())
        .map_err(|e| CredentialError::InvalidChioPassCapabilityBinding(e.to_string()))?.to_string();
    let window = attestation_window_containing(token.issued_at)?;
    if token.expires_at != window.until {
        return Err(CredentialError::InvalidChioPassCapabilityBinding(
            "Pass expiry is not pinned to its attestation-window boundary".to_string()));
    }
    let expected = window_scoped_capability_id(&subject_did, &window)
        .map_err(|e| CredentialError::InvalidChioPassCapabilityBinding(e.to_string()))?;
    if token.id != expected {
        return Err(CredentialError::InvalidChioPassCapabilityBinding(
            "Pass capability id is not the canonical window-scoped id".to_string()));
    }
    Ok(())
}
```

Why this closes the re-mint reset: the budget store keys on `(capability_id, grant_index)`. Two mints of the
same Pass in the same month reproduce a byte-identical `token.id`, so charges accumulate against ONE
`(chiopass:<hash>, 0)` row. A fresh UUIDv7 re-mint cannot create a fresh zero row. Determinism wording is
exact: only `token.id` is deterministic; `issued_at`/`expires_at` are also signed and are equal across
re-mints in the same window, but the closure relies only on the stable id, which is what keys the budget row.

### 4.2 CONTROL 1 - Aggregate global pool ceiling

Files: `chio-kernel/src/kernel/mod.rs` (`FreeTierPoolConfig`, `FreeTierPoolHold`, the `free_tier_pool`
field on `ChioKernel`, the `with_free_tier_pool` builder, `free_tier_pool_config()` accessor, and the
`FREETIER_GLOBAL_GRANT_INDEX` const); `chio-kernel/src/kernel/construction.rs` (init field to `None` at the
`Self {}` literal); `chio-kernel/src/kernel/validation.rs` (the single-closure splice + `try_debit_freetier_pool`
+ symmetric reversal); `chio-kernel/src/kernel/error.rs` (`InvalidFreeTierPoolConfig`).

CONFIG LIVES ON THE KERNEL, NOT ON `KernelConfig` (this is the key fix to both the infallible-`new` problem
and the ~46 `KernelConfig { .. }` literal sites). `ChioKernel` gains one field initialized to `None`; the
config travels via a fallible post-construction builder:

```rust
// crates/kernel/chio-kernel/src/kernel/mod.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeTierPoolConfig {
    pub monthly_pool_units: u64,
    pub allotment_unit: String,     // "XCC"
    pub board_approval_ref: String, // audit-only; never participates in math
}
impl FreeTierPoolConfig {
    pub fn validate(&self) -> Result<(), KernelError> {
        if self.monthly_pool_units == 0 {
            return Err(KernelError::InvalidFreeTierPoolConfig(
                "monthly_pool_units must be non-zero".to_string())); }
        let unit_ok = self.allotment_unit.len() == 3
            && self.allotment_unit.bytes().all(|b| b.is_ascii_uppercase());
        if !unit_ok {
            return Err(KernelError::InvalidFreeTierPoolConfig(
                "allotment_unit must be 3 uppercase ASCII letters".to_string())); }
        if self.board_approval_ref.is_empty() {
            return Err(KernelError::InvalidFreeTierPoolConfig(
                "board_approval_ref must be present".to_string())); }
        Ok(())
    }
    /// window_ym from cap.issued_at (== window.since == first-of-active-month). Not now, not expires_at.
    pub fn window_ym_from_issued_at(issued_at: u64) -> Result<String, KernelError> {
        let secs = i64::try_from(issued_at).map_err(|_| KernelError::InvalidFreeTierPoolConfig(
            "issued_at out of range".to_string()))?;
        let dt = chrono::DateTime::from_timestamp(secs, 0).ok_or_else(|| {
            KernelError::InvalidFreeTierPoolConfig("issued_at not representable".to_string()) })?;
        Ok(format!("freetier:global:{}", dt.format("%Y-%m")))
    }
}

pub(crate) const FREETIER_GLOBAL_GRANT_INDEX: usize = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreeTierPoolHold { pub term_id: String, pub hold_id: String, pub units: u64 }

impl ChioKernel {
    /// Fallible builder; validates fail-closed. This is where misconfig is rejected (new() stays infallible).
    pub fn with_free_tier_pool(mut self, cfg: FreeTierPoolConfig) -> Result<Self, KernelError> {
        cfg.validate()?;
        self.free_tier_pool = Some(cfg);
        Ok(self)
    }
    pub(crate) fn free_tier_pool_config(&self) -> Option<&FreeTierPoolConfig> { self.free_tier_pool.as_ref() }
}
```

Free-tier RECOGNITION + B5 resolution. Add `BudgetChargeResult.free_tier_pool_hold: Option<FreeTierPoolHold>`
(additive, defaults `None`). In the monetary `Authorized` arm of `check_and_increment_budget`
(`validation.rs:797-815`), restructure so per-Pass debit + pool debit + compensating reversal all run in ONE
`with_budget_store` closure (B4 - Spec 2's atomic design; discard Spec 6's two-lock `authorize_free_tier_pool`):

```rust
// is_private_use_unit fails closed: 3 uppercase AND unpinned by chio-link (XCC qualifies, USD/ETH do not).
let is_private_use = currency.len() == 3
    && currency.bytes().all(|b| b.is_ascii_uppercase())
    && chio_link::minor_units_for_currency(&currency).is_err();

let outcome = self.with_budget_store(|store| {
    let per_pass = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: cap.id.clone(), grant_index: matching.index,
        max_invocations: grant.max_invocations, requested_exposure_units: cost_units,
        max_cost_per_invocation: max_per, max_total_cost_units: max_total,
        hold_id: Some(budget_hold_id.clone()), event_id: Some(authorize_event_id.clone()),
        authority: Some(authority.clone()),
    })?;
    let authorized = match per_pass {
        BudgetAuthorizeHoldDecision::Authorized(a) => a,
        BudgetAuthorizeHoldDecision::Denied(_) => return Ok(PoolGuardedCharge::PerPassDenied),
    };
    if is_private_use {
        // A private-use (free-tier) charge REQUIRES a pool and a non-zero per-invocation cost.
        let Some(pool) = self.free_tier_pool_config() else {
            store.reverse_budget_hold(/* reverse the per-Pass hold just taken */ ..)?;
            return Ok(PoolGuardedCharge::PoolDenied); // no pool => deny (B5 fail-closed)
        };
        if currency != pool.allotment_unit || cost_units == 0 {
            store.reverse_budget_hold(..)?;
            return Ok(PoolGuardedCharge::PoolDenied); // wrong unit or zero per-invocation => deny
        }
        let term_id = FreeTierPoolConfig::window_ym_from_issued_at(cap.issued_at)?;
        let pool_hold_id = format!("freetier-pool-hold:{request_id}:{term_id}");
        let pool_decision = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: term_id.clone(), grant_index: FREETIER_GLOBAL_GRANT_INDEX,
            max_invocations: None, requested_exposure_units: cost_units,
            max_cost_per_invocation: None, max_total_cost_units: Some(pool.monthly_pool_units),
            hold_id: Some(pool_hold_id.clone()), event_id: Some(format!("{pool_hold_id}:authorize")),
            authority: Some(authority.clone()),
        })?;
        match pool_decision {
            BudgetAuthorizeHoldDecision::Authorized(_) =>
                Ok(PoolGuardedCharge::Authorized(authorized,
                    Some(FreeTierPoolHold { term_id, hold_id: pool_hold_id, units: cost_units }))),
            BudgetAuthorizeHoldDecision::Denied(_) => {
                store.reverse_budget_hold(/* reverse the per-Pass hold in the SAME closure */ ..)?;
                Ok(PoolGuardedCharge::PoolDenied)
            }
        }
    } else {
        Ok(PoolGuardedCharge::Authorized(authorized, None)) // USD/pinned currency: unchanged path
    }
})?;
match outcome {
    PoolGuardedCharge::Authorized(authorized, pool_hold) => { /* build BudgetChargeResult with free_tier_pool_hold = pool_hold, return Charge */ }
    PoolGuardedCharge::PerPassDenied | PoolGuardedCharge::PoolDenied => { saw_exhausted_budget = true; }
}
```

`enum PoolGuardedCharge { Authorized(AuthorizedBudgetHold, Option<FreeTierPoolHold>), PerPassDenied, PoolDenied }`
(private to `validation.rs`). Charge ordering is per-Pass FIRST (tighter, no pool churn when a single Pass is
already exhausted), pool SECOND. The whole pair plus the compensating reversal is indivisible because it
holds the process-wide `budget_store_lock` for the entire closure (Spec 6's separate-helper-with-second-lock
variant is discarded; it would re-acquire the lock and allow a concurrent interleave to overrun POOL).

SYMMETRIC pool-hold reversal/reconcile (closes the dead-field / leak hazard). `reverse_budget_charge`
(`validation.rs:844-860`) and the post-execution reconcile path must ALSO reverse/reconcile
`charge.free_tier_pool_hold` against `(term_id, FREETIER_GLOBAL_GRANT_INDEX)` whenever the per-Pass hold is
reversed/reconciled. Without this, a later request cancellation leaves stale pool exposure and the pool
exhausts prematurely (fail-closed direction, but a liveness bug). M0 uses the exposure model (worst-case
per-invocation debit at hold time); reconcile-to-realized is wired symmetrically with the per-Pass hold.

Exhaustion dispatch is the UNCHANGED path: `saw_exhausted_budget` -> `Err(KernelError::BudgetExhausted(cap.id))`
(`validation.rs:836`) -> caught at `evaluation.rs:697-712` -> `build_monetary_deny_response_with_metadata`
-> `FinancialReceiptMetadata { cost_charged: 0, budget_remaining: 0 }` -> `Decision::Deny { guard: "kernel" }`.
Liability is hard-capped at `min(N x allotment, POOL)`.

Monthly reset is implicit: a new month yields a new `window_ym`, hence a fresh `freetier:global:<next>` row
that starts at 0. Prior-month rows are retained (auditable history; row count grows over time - a retention
concern, not a correctness break). HA NOTE: under multi-node HA sharing one SQLite file the pool ceiling is
SOFT - overrun is bounded by `max_cost_per_invocation x node_count` per window
(`budget_store.rs:280-285`); size the pool below the runway accordingly (open question).

### 4.3 CONTROL 3 - Refresh-on-genuine-use

Files: `chio-credentials/src/chio_pass.rs` (the pure predicate + decision); the control-plane orchestrator
(Section 6.4). CONTROL 3 does NOT touch the kernel hot path: the kernel keeps charging a deterministic id
against a fixed `max_total_cost` ceiling. CONTROL 3 only sets WHETHER the next window's `window_units` is
tier-sized or 0.

Genuine use in `window_n` is, per receipt, ALL of: (1) `capability_id == prior_capability_id`;
(2) `decision == Some(Decision::Allow)`; (3) `receipt_kind == ReceiptKind::MediatedDecision` AND
`trust_level == TrustLevel::Mediated`; (4) `since <= timestamp < until` (signed u64 bounds, no wall clock;
`since` MUST be present, see B9); (5) the receipt DEBITED the XCC allotment, detected by reading the
existing `CostMetadata` Custom dimension under `metadata["cost"].dimensions[]` with
`name == CHIO_PASS_ALLOTMENT_COST_NAME` and `value > 0` (NOT an invented `metadata.metering.allotment_debit`);
(6) `verify_signature()? == true` AND `receipt.kernel_key` is in a pinned
`accepted_kernel_keys: &[PublicKey]` allowlist. Point (6) is the security fix: `verify_signature` only proves
internal self-consistency against the receipt's OWN `kernel_key`; the allowlist is what makes it "a trusted
kernel signed it". PROVENANCE (not an ad-hoc caller config): `accepted_kernel_keys` is the EXISTING pinned
authority-key set - the kernel signing keys that emit the metered receipts and/or the trust-market pinned
market-authority registry (RR2-TM-01) - loaded fail-closed from the one board-approved `ChioPassConfig`
surface (Section 6.4 / Open Question 3), never a value passed in per request. Rotation reuses the
market-authority registry's pinned-key rotation: a retired key stays accepted for receipts dated before its
rotation epoch, so in-flight windows do not silently fail genuine-use. Deny/Cancelled/exhaustion-`cost_charged:0`
receipts and pure free-read activity never count.

```rust
fn is_genuine_use_receipt(
    receipt: &ChioReceipt, pass_capability_id: &str, window: &AttestationWindowId,
    accepted_kernel_keys: &[PublicKey],
) -> Result<bool, CredentialError> {
    if receipt.capability_id != pass_capability_id { return Ok(false); }
    if !matches!(receipt.decision, Some(Decision::Allow)) { return Ok(false); }
    if receipt.receipt_kind != ReceiptKind::MediatedDecision
        || receipt.trust_level != TrustLevel::Mediated { return Ok(false); }
    if receipt.timestamp < window.since || receipt.timestamp >= window.until { return Ok(false); }
    if !receipt_debited_pass_allotment(receipt) { return Ok(false); }
    if !accepted_kernel_keys.iter().any(|k| k == &receipt.kernel_key) { return Ok(false); }
    match receipt.verify_signature() {
        Ok(verified) => Ok(verified),
        Err(e) => Err(CredentialError::ChioPassGenuineUseScanFailed(e.to_string())),
    }
}
```

`receipt_debited_pass_allotment` parses `receipt.metadata["cost"]` as `CostMetadata` (or reads the
`dimensions` array via serde_json) and returns true iff any `CostDimension::Custom { name, value, .. }` has
`name == CHIO_PASS_ALLOTMENT_COST_NAME && value > 0`; option access uses `and_then` / `let-else` /
`unwrap_or(false)` (no panics).

```rust
pub enum ChioPassRefreshOutcome { Granted, WithheldDormant, DeniedNoReattestation }

pub fn chio_pass_refresh_decision(
    subject: &DidChio, prior_window: &AttestationWindowId, next_window: &AttestationWindowId,
    prior_capability_id: String, next_capability_id: String,
    genuine_use_count: u32, reattested: bool, tier: TrustTier, table: &TierAllotmentTable,
) -> Result<ChioPassRefreshDecision, CredentialError> {
    // Contiguous monthly rollover (use the non-optional AttestationWindowId bounds).
    if next_window.since != prior_window.until || next_window.until <= prior_window.until {
        return Err(CredentialError::InvalidChioPassRefreshWindow);
    }
    let (next_allotment_units, outcome) = if !reattested {
        (0, ChioPassRefreshOutcome::DeniedNoReattestation)
    } else if genuine_use_count >= MIN_GENUINE_USE_RECEIPTS {
        (allotment_units_for_tier(tier, table), ChioPassRefreshOutcome::Granted)
    } else {
        (0, ChioPassRefreshOutcome::WithheldDormant)
    };
    Ok(ChioPassRefreshDecision { /* serializable audit record (camelCase, canonical JSON), NOT the authority */ })
}
```

Outcomes: `Granted` -> mint next window's Pass with `window_units = tier size`. `WithheldDormant`
(re-attested, no genuine use) -> mint a Pass with `window_units = 0` (baseline reads persist; first metered
charge denies). `DeniedNoReattestation` -> no new Pass is minted; the old token lapses at expiry. M0 SHIPS
the presentation challenge/response path for rollover re-attestation (B12): `reattested` is the verified
result of a fresh `verify_passport_presentation_response_with_policy` (fresh nonce, tight window) at
rollover. Initial admission uses the direct `verify_chio_pass` + holder-binding pair.

### 4.4 End-to-end charge ordering (normative)

For a metered Pass request:
1. `check_and_increment_budget` keys `(chiopass:<hash>, 0)` (CONTROL 2 gave the deterministic id).
2. In ONE locked closure: per-Pass XCC debit FIRST (`max_total_cost` ceiling = `window_units`; a 0 ceiling
   denies here). If admitted, pool debit SECOND (`freetier:global:{window_ym}` ceiling = POOL).
3. Both must pass. If the pool denies, the per-Pass hold is reversed in the SAME closure.
4. Any deny -> `BudgetExhausted` -> Deny receipt `cost_charged = 0`, `budget_remaining = 0`. No exposure
   persists on either term.
5. On success, the metered XCC charge emits `CostDimension::Custom { name: "chio.pass.allotment.v1", value, unit: Some("XCC") }`
   into `metadata["cost"]` (C3), OUTSIDE `metadata["financial"]` so the redaction in Section 5 does not strip
   it and CONTROL 3's scan can see it.

---

## 5. Data-stream access gating

New module `crates/kernel/chio-kernel/src/pass_gating.rs`, declared `pub mod pass_gating;` in
`chio-kernel/src/lib.rs`. Reuses the unchanged matchers `capability_matches_resource_request`
(`request_matching.rs:242`) and `capability_matches_resource_subscription` (`request_matching.rs:253`); the
private `mod request_matching` exposes `pub fn`s callable from the sibling module, so `request_matching.rs`
needs NO edit. The 3 new `KernelError` variants go in `chio-kernel/src/kernel/error.rs`.

Import correctly: `use chio_core_types::capability::token::CapabilityToken;` (the flat
`capability::CapabilityToken` path does NOT exist; the `mod.rs` root has no re-export layer).

### 5.1 The five gifted streams (tier_0 baseline, no TrustTier predicate)

| idx | uri_pattern | kind |
|-----|-------------|------|
| 0 | `chio://trust/reputation/tier/*` | aggregate (coarse tier label only) |
| 1 | `chio://marketplace/listings*` | aggregate (operator-advertised prices) |
| 2 | `chio://trust/pheromone/concentration/*` | aggregate (collapsed origin counts) |
| 3 | `chio://receipts/tenant/<subject_tenant>/*` | OWN (tenant-bound, baseline right) |
| 4 | `chio://lineage/tenant/<subject_tenant>/*` | OWN (tenant-bound, baseline right) |

Each is `ResourceGrant { uri_pattern, operations: [Read, Subscribe] }` at pinned indices 0..4. Own patterns
use the MANDATORY `/` delimiter before the trailing `*` (so tenant `did:chioabcd` cannot match
`did:chioabcde...`). `pass_baseline_read_uris(subject_did)` and `pass_baseline_resource_grants(subject_tenant)`
are the SINGLE builders that both the credential layer (Section 3.2) and the scope builder (Section 6.3) call.

```rust
pub const PASS_DENY_PHEROMONE_DEPOSITS: &str = "chio://trust/pheromone/deposits";
pub const PASS_DENY_MARKET_FINANCIAL: &str = "chio://market/";
/// Economic envelope keys removed from every served free-read VIEW (whitelist-by-removal, fail-closed).
pub const PASS_REDACTED_METADATA_KEYS: [&str; 3] = ["financial", "budget_authority", "cost"];

#[must_use]
pub fn uri_is_pass_denied(uri: &str) -> bool {
    uri.starts_with(PASS_DENY_PHEROMONE_DEPOSITS) || uri.starts_with(PASS_DENY_MARKET_FINANCIAL)
}

fn validated_tenant(t: &str) -> Result<&str, KernelError> {
    let trimmed = t.trim();
    if trimmed.is_empty() || trimmed.contains('*') || trimmed.contains('/') {
        return Err(KernelError::PassTenantBindingInvalid(t.to_string()));
    }
    Ok(trimmed)
}
```

### 5.2 Scope-inflation validation (fail-closed, covers ALL grant kinds)

```rust
pub fn validate_pass_scope_is_baseline(scope: &ChioScope, subject_tenant: &str) -> Result<(), KernelError> {
    // Tool/prompt inflation: the Pass carries EXACTLY one metered XCC ToolGrant and ZERO prompt grants.
    if scope.grants.len() != 1 {
        return Err(KernelError::PassScopeInflation("expected exactly one metered grant".to_string()));
    }
    if !scope.prompt_grants.is_empty() {
        return Err(KernelError::PassScopeInflation("prompt grants are not permitted".to_string()));
    }
    // The single ToolGrant must be the XCC metered allotment (operations == [Invoke], currency XCC).
    // ... assert server_id/operations and that max_cost_per_invocation/max_total_cost are XCC ...

    // Resource grants must EXACTLY equal the canonical baseline (count, order, pattern, operations),
    // and reach no deny-listed surface.
    let baseline = pass_baseline_resource_grants(subject_tenant)?;
    if scope.resource_grants != baseline {
        return Err(KernelError::PassScopeInflation("resource grants are not the canonical baseline".to_string()));
    }
    for g in &scope.resource_grants {
        if uri_is_pass_denied(&g.uri_pattern) {
            return Err(KernelError::PassScopeInflation(g.uri_pattern.clone()));
        }
    }
    Ok(())
}
```

The verification flagged the original subset-only check as fail-open for `grants`/`prompt_grants`; the fix
above rejects tool/prompt inflation explicitly and uses EXACT equality for the 5 resource grants. (Note: the
deterministic `token.id` is independent of scope, so issuance, not this validator, is the canonical-ordering
authority for the id; the validator is the inflation backstop and additionally pins exact equality for
hardening.) `ResourceGrant` derives `Clone` but NOT `PartialEq` today; add `#[derive(PartialEq, Eq)]` to
`ResourceGrant`/`Operation` (additive, both are plain data) OR compare field-by-field if a derive is
undesirable.

### 5.3 Redaction (whitelist-by-removal, fail-closed)

`project_pass_stream_view(receipt_body: &serde_json::Value) -> Result<serde_json::Value, KernelError>`
returns a redacted COPY (never mutates or re-signs the artifact). It removes EVERY key in
`PASS_REDACTED_METADATA_KEYS` from `metadata` (not just `"financial"` - the single-key blacklist was
fail-open because `metadata["budget_authority"]` -> `FinancialBudgetAuthorityReceiptMetadata` survived) and
stamps `redaction: "summary"`. Fail-closed: a body that is not a JSON object, or a `metadata` that is
neither object nor null, returns `Err(PassRedactionFailed)` so the row is denied rather than served with cost
data leaked. (The CONTROL 3 genuine-use scan reads the STORED receipt directly, so stripping `"cost"` from
the served VIEW does not affect the scan.)

DISCLOSURE BINDING (grounding to the shipped privacy layer). The 3-key `project_pass_stream_view` strip is
an INTERNAL selection/redaction step, NOT the gift boundary. The own-receipts/own-lineage gift MUST be served
through the SHIPPED disclosure-lineage export, `chio-disclosure-lineage::verify_disclosure_lineage_bundle`
(or `chio-selective-disclosure`): a pinned-key signed lineage subgraph (signatures verify only against
`TRUSTED_LINEAGE_SIGNER_PUBLIC_KEYS`, `verifier.rs:22,412`), bound to a `transaction_passport_ref`, carrying a
verifier privacy profile, a MANDATORY `DisclosureLeakageLedger` (`validate_leakage_ledger`, `verifier.rs:664`,
required even when empty), hashed identifiers (tenant/seller/capability via sha256), and the accounted derived
facts `issuer_status`/`revocation_freshness`/`presentation_timing` (`REQUIRED_DISCLOSURE_DERIVED_FACTS`,
`verifier.rs:54`). A bare `serde_json::Value` 3-key strip is weaker than the layer mandates; excess disclosure
is a fail-closed privacy failure even when the credential signature verifies. Raw full-evidence exports
(`receipts.ndjson` / full capability snapshots) stay admin-only (`admin_full_evidence_v1`) and are never the
Pass gift boundary.

### 5.4 Serving gates and own-tenant backstop

`pass_authorizes_read(cap, uri)` / `pass_authorizes_subscription(cap, uri)` deny-list FIRST
(`uri_is_pass_denied` -> `Ok(false)`), then defer to the unchanged matcher. No TrustTier branch exists in this
module, so a tier_0 newcomer and a Premier holder get byte-identical decisions across all five streams. Own
receipts also flow through `ReceiptReadContext::authenticated_tenant(subject_tenant)` (`include_null_tenant = false`)
-> `ReceiptQuery::effective_read_scope` (no-widening guard at `receipt_query.rs:177`) -> SQL
`(r.tenant_id = ?12)`, an independent second denial behind the uri binding. Own lineage MUST constrain the
`LineageGraph` `forward`/`reverse` traversal itself to IN-TENANT nodes (not merely a seed/window prefilter,
which can still surface cross-tenant `LineageNode/Edge.tenant_id` checkpoint-metadata one hop out); the
disclosure-export wrapper of Section 5.3 records any cross-tenant checkpoint-metadata leakage in the
mandatory `DisclosureLeakageLedger` and emits a tenant disclosure notice rather than silently widening the
view. The aggregate `query_deposits` (origin-identifying) is deny-listed and unreachable.

OPEN (resolve before build): confirm the issuance `tenant_id` equals the raw `did:chio` used verbatim in
`chio://receipts/tenant/<tenant>/*`, since the SQL guard compares `r.tenant_id = ?12`; any
normalization/hashing mismatch silently denies all own-stream reads.

---

## 6. Anti-farm + distribution (Phase-0 scope)

New module `crates/trust/chio-credentials/src/chio_pass_antifarm.rs`, `include!`d after `chio_pass.rs` and
before `tests.rs`. The pure functions live here (storage-free); the receipt scan and the orchestrator live in
the control plane.

### 6.1 Population cap + per-window throttle

```rust
pub struct ChioPassAdmissionPolicy { pub window_ym: String, pub window_token_capacity: u64, pub active_population_cap: u64 }
pub enum ChioPassAdmissionDecision { Admit, DenyWindowExhausted, DenyPopulationCapReached, DenyPolicyInvalid }

#[must_use]
pub fn evaluate_pass_admission(policy: &ChioPassAdmissionPolicy, window_issued_count: u64, active_population: u64)
    -> ChioPassAdmissionDecision {
    if policy.window_token_capacity == 0 || policy.active_population_cap == 0 { return DenyPolicyInvalid; }
    if window_issued_count >= policy.window_token_capacity { return DenyWindowExhausted; }
    if active_population >= policy.active_population_cap { return DenyPopulationCapReached; }
    Admit
}
```

Mirrors the pheromone admission contract (`token_capacity` at `chio-pheromone/lib.rs:409`; zero rejected at
`validation.rs:393`; `bucket_count >= token_capacity` at `validation.rs:201`). `active_population` is sourced
from the revocation-oracle LIVE set (non-revoked, non-expired Passes), pinned so the cap cannot be
undercounted under concurrency (C5).

ATTESTED-IDENTITY BINDING (reuse, do not duplicate). The `TrustTier` and snapshot/population-cap admission
inputs (`ChioPassCandidate.tier`, the `ChioPassSnapshot` attested set) bind to the SHIPPED provider-admission
substrate in `chio-trust-market-context/src/artifacts.rs`, not a re-derivation from `chio-reputation/tier.rs`
+ `chio-federation` alone: eligibility flows from `validate_reputation_import` (trusted issuer, accepted
`import_verdict`, `subject_binding_ref`, capped `local_weight`) plus discovery-snapshot membership and a signed
`ProviderSelectionReport`/`TrustScorecardSnapshot` (`ProviderDiscoverySnapshot -> ProviderSelectionReport ->
TrustScorecardSnapshot`). The attested `TrustTier` MUST reconcile with the scorecard `computed_score` so the
two tier notions cannot fork. This REUSES the self-declared `issuer_independence_group_id`
(`chio-federation/reputation.rs:201`) as the bounded M0 input; it does not duplicate or re-implement it (the
bond-anchored fix stays Phase 2, Section 6.5). Fail-closed posture, stated: portable reputation CANNOT prove
collateral or solvency, so the Pass tier governs allotment SIZE/refill only and is NEVER marketed or wired as
a bond/coverage/premium discount (that capital path is the risk-comptroller facility model, out of M0).

### 6.2 Retroactive unpredictable snapshot

```rust
pub struct ChioPassCandidate { pub subject_did: String, pub attested_at_unix: u64, pub tier: TrustTier }
pub struct ChioPassSnapshot { pub snapshot_unix: u64, pub window_ym: String, pub candidates: Vec<ChioPassCandidate> }

/// Admit oldest-attestation-first, ties broken by DID lexicographic, until either cap is hit.
/// Deterministic for audit/anchoring; unpredictability is OPERATIONAL (snapshot_unix not pre-announced).
#[must_use]
pub fn select_snapshot_admissions(snapshot, policy, starting_active_population) -> Vec<ChioPassCandidate> { /* ... */ }
```

Saturating arithmetic throughout; breaks on the first non-`Admit`.

### 6.3 Pass -> ChioScope builder (C1, the central bridge)

Owned by the control plane (it needs both the credential and the kernel scope types). Turns a verified
`ChioPass` into the canonical scope of Section 2.7:

```rust
pub fn build_pass_scope(pass: &ChioPass, subject_tenant: &str) -> Result<ChioScope, CliError> {
    let g = &pass.unsigned.credential_subject.entitlements.allotment;
    let metered = ToolGrant {
        server_id: "chio.pass.compute".to_string(), tool_name: "*".to_string(),
        operations: vec![Operation::Invoke], constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount { units: g.per_invocation_units, currency: "XCC".to_string() }),
        max_total_cost:          Some(MonetaryAmount { units: g.window_units,          currency: "XCC".to_string() }),
        dpop_required: None,
    };
    let resource_grants = chio_kernel::pass_gating::pass_baseline_resource_grants(subject_tenant)?;
    Ok(ChioScope { grants: vec![metered], resource_grants, prompt_grants: vec![] })
}
```

### 6.4 Refresh orchestrator + genuine-use scan (control plane)

`crates/platform/chio-control-plane/src/trust_control/chio_pass_handlers.rs`, declared via
`#[path = "trust_control/chio_pass_handlers.rs"] mod chio_pass_handlers;` in `trust_control.rs` (matching the
crate's explicit-path convention). Uses `SqliteReceiptStore::query_receipts` (the seam used at
`receipt_handlers.rs:206-221`). Errors use REAL `CliError` constructors (`CliError::Other(...)` or the
`#[from]` arms `Credential`/`ReceiptStore`/`BudgetStore`); `CliError::internal` does NOT exist.

```rust
pub(crate) fn count_genuine_use(
    store: &SqliteReceiptStore, subject_key_hex: &str, tenant: &str,
    pass_capability_id: &str, window: &AttestationWindowId, accepted_kernel_keys: &[PublicKey],
) -> Result<u32, CliError> {
    let mut count = 0u32;
    let mut cursor = None;
    loop {
        let query = ReceiptQuery {
            capability_id: Some(pass_capability_id.to_string()),
            outcome: Some("allow".to_string()),
            since: Some(window.since), until: Some(window.until),
            cursor, limit: chio_kernel::MAX_QUERY_LIMIT,
            agent_subject: Some(subject_key_hex.to_string()),
            tenant_filter: Some(tenant.to_string()),
            read_context: Some(ReceiptReadContext::authenticated_tenant(tenant)),
            ..Default::default()
        };
        let page = store.query_receipts(&query)?; // CliError via #[from] ReceiptStore
        for stored in &page.receipts {
            if is_genuine_use_receipt(&stored.receipt, pass_capability_id, window, accepted_kernel_keys)? {
                count = count.checked_add(1).ok_or_else(|| CliError::Other("genuine-use overflow".into()))?;
            }
        }
        match page.next_cursor { Some(n) => cursor = Some(n), None => break }
    }
    Ok(count)
}
```

`refresh_chio_pass_window(...)` verifies fresh re-attestation (`verify_passport_presentation_response_with_policy`),
scans genuine use, builds `chio_pass_refresh_decision`, and on `Granted`/`WithheldDormant` issues the next
window's `ChioPass`. Scan IO error or crypto fault -> `Err` -> NO new Pass minted (dormant identity defaults
to no metered draw). This orchestrator carries a forward-dependency on the credential format (Section 3) and
the scope builder (6.3); it lands AFTER them in the task order.

### 6.5 Residual Sybil weakness (bounded, not fixed in M0)

`issuer_independence_group_id` is self-declared and optional (`chio-federation/reputation.rs:201`). M0 does
NOT fix it. The aggregate pool ceiling (CONTROL 1), `window_token_capacity`, and `active_population_cap` BOUND
total free-tier drain at the board-approved runway even under collusion. Bond-anchored issuer independence is
Phase 2; the escrow activation deposit is Phase 1.

### 6.6 Anchoring job owner

M0 assigns the issuance/revocation Merkle batch + `publishRoot` cadence to a control-plane scheduled job
(`chio_pass_handlers` batch task). If schedule wiring slips, anchoring is EXPLICITLY DEFERRED with the
read-only `verifyInclusionDetailed` membership proof retained for auditability; the "metered fail-closed" M0
gate does not depend on anchoring.

---

## 7. End-to-end flow

1. ATTEST. A `did:chio` is attested to a coarse `TrustTier` (step function, no discretionary oracle) sourced
   from the shipped `chio-trust-market-context` substrate (`validate_reputation_import` + a signed
   `TrustScorecardSnapshot`; the `TrustTier` reconciles with the scorecard `computed_score`), NOT a fresh
   `chio-reputation`/`chio-federation` derivation. The issuer freezes the attested set at an unannounced
   instant `S` -> `ChioPassSnapshot`. Portable reputation cannot prove collateral or solvency, so the tier is
   never a bond/coverage discount (Section 6.1).
2. DISTRIBUTE (anti-farm). `select_snapshot_admissions` orders by `(attested_at, did)` and admits via
   `evaluate_pass_admission` until `window_token_capacity` OR `active_population_cap` is hit (fail-closed),
   with candidate membership bound to a `ProviderDiscoverySnapshot`/`ProviderSelectionReport` rather than a
   re-derived gate. `active_population` is the revocation-oracle live set.
3. WINDOW. `attestation_window_containing(now)` -> `AttestationWindowId { window_ym, since, until }`.
4. ENTITLEMENTS. `snapshot_chio_pass_entitlements(tier, window, is_first_window = true, genuine_use = true, &cfg)`
   -> tier + 5 baseline read_scopes + XCC allotment sized by the Section 2.5 table (floor unconditional).
5. ISSUE CREDENTIAL. `issue_chio_pass(...)` -> soulbound `ChioPass` VC (Ed25519, canonical JSON). Optionally
   anchor `chio_pass_artifact_id` read-only.
6. BRIDGE -> MINT. `build_pass_scope(pass, tenant)` -> canonical `ChioScope` (1 XCC ToolGrant @0 + 5
   resource grants). Mint via `issue_window_scoped_capability(subject, subject_did, scope, &window)` ->
   `token.id = chiopass:<hash>`, `grant_index 0`, `issued_at = since`, `expires_at = until`. Rejects
   `grants.len() != 1` and any non-baseline/deny-listed scope.
7. PRESENT / ADMIT. `verify_chio_pass` + `verify_chio_pass_holder_binding` (soulbound) ->
   `validate_pass_scope_is_baseline` -> `verify_window_scoped_capability_id` + the kernel admission assertion
   (any token whose scope carries the XCC metered grant but whose id is not `chiopass:`-prefixed is rejected
   with `PassCapabilityIdNotDeterministic`, closing the other three UUIDv7 mint sites, B7).
8. RUN GIFTED WORKLOAD (metered). Invoke the metered grant -> `check_and_increment_budget` keys
   `(chiopass:<hash>, 0)`; in ONE locked closure: per-Pass XCC debit FIRST -> `freetier:global:{window_ym}`
   pool debit SECOND; emit the `CostDimension::Custom` allotment dimension. On pool exhaustion: reverse the
   per-Pass hold in-closure -> `BudgetExhausted` -> Deny receipt `cost_charged = 0`, `budget_remaining = 0`.
   Liability = `min(N x allotment, POOL)`, fail-closed.
9. READ GIFTED FEED. Read/Subscribe the 5 streams -> `pass_authorizes_read/subscription` deny-lists first,
   then the unchanged matcher; own receipts/lineage are tenant-bound; `project_pass_stream_view` strips the
   economic envelope keys and stamps `redaction: "summary"`. No tier predicate gates reads.
10. ROLLOVER = MONTHLY RESET. At `now >= until` the token is expired (`CapabilityExpired`). The holder
    re-attests via a fresh presentation challenge; `count_genuine_use` scans the prior window's own-tenant
    metered Allow receipts; `chio_pass_refresh_decision` -> `Granted` (tier-sized) | `WithheldDormant`
    (ceiling 0, baseline reads persist) | `DeniedNoReattestation` (no mint). New `window_ym` -> new
    deterministic id -> fresh per-Pass row AND fresh `freetier:global:{next}` pool. Dormant/extractive
    identities draw 0 on their first metered charge; genuinely active re-attesting identities refill at tier
    size.

Net invariants preserved: budget accumulates on one `(chiopass:<hash>, 0)` row per (subject, month);
aggregate free-tier liability hard-capped at POOL (single-closure atomicity); per-Pass row and pool roll over
on the SAME `window_ym`; no value moves on-chain; immutable contracts untouched.

---

## 8. Test plan + launch-readiness gate

### 8.1 Credential unit/property (chio-credentials)

- Round-trip: `issue_chio_pass` then `verify_chio_pass` Ok within window; `canonical_json_bytes(&unsigned)`
  byte-stable across two identical issuances (RFC 8785).
- Soulbinding: holder-binding Ok with the subject key; `PresentationHolderMismatch` with a different Ed25519
  key; `Did(UnsupportedKeyAlgorithm)` with a non-Ed25519 key.
- Expiry half-open: `verify_chio_pass(now = until)` -> `ChioPassExpired`; `now = until - 1` -> Ok (B11).
- Schema/validity/window integrity: each malformed field returns its specific error; `deny_unknown_fields`
  rejects unknown keys.
- Allotment fail-closed: non-XCC unit -> `InvalidChioPassAllotmentGrant`; `per_invocation_units == 0` ->
  `InvalidChioPassAllotmentGrant`; confirm XCC is NOT priced by `minor_units_for_currency`.
- Read-scope binding: a Pass whose `read_scopes != pass_baseline_read_uris(canonical subject)` -> error
  (closes the scope-binding gap); the own-tenant patterns carry the canonical DID with the `/` delimiter.
- Refresh-verifiable: `window_units > 0` with `genuine_use_observed == false`, or with `window_units !=`
  tier size -> `InvalidChioPassAllotmentGrant` at verify (issuer-independent check).
- Tier governs SIZE not existence: `allotment_units_for_tier(Unverified, table) > 0`.
- Genuine-use matrix: Allow+Mediated+MediatedDecision+in-window+Custom-allotment-dim>0+accepted-kernel-key+valid-sig
  -> Ok(true); each of Deny / wrong cap id / `timestamp == until` / Advisory / no allotment dim / kernel_key
  not in allowlist / tampered sig -> Ok(false); crypto fault -> `Err(ChioPassGenuineUseScanFailed)`.
- Capability-id determinism (CONTROL 2): `window_scoped_capability_id` stable across calls; starts with
  `chiopass:`; different `window_ym` or subject -> different id; property test asserts collision-free
  distinctness and intra-window stability.
- `attestation_window_containing`: mid-month ts -> correct `window_ym`/`since`/`until`, including
  December->January and leap-Feb boundaries.
- Revocation -> oracle: `revoke_chio_pass_record(.., revoked_at>0, ..).validate()` Ok and
  `to_revocation_event()` yields `Some` with `passport_id == chio_pass_artifact_id`; `revoked_at == 0` -> Err.

### 8.2 Kernel integration (chio-kernel tests)

- Pool disabled (additive no-op): no `free_tier_pool` -> replay an existing USD budget scenario; assert
  byte-identical Allow/Deny verdicts and `get_usage` rows; no `freetier:global` row created.
- Currency scoping: a USD grant under an enabled pool charges only its per-Pass row; no `freetier:global` row.
- Config fail-closed: `FreeTierPoolConfig { monthly_pool_units: 0 }`, `allotment_unit "XC"/"xcc"/"XCCD"`, and
  empty `board_approval_ref` each `validate()` -> Err; `ChioKernel::with_free_tier_pool` rejects each.
- Pool-bypass closed: an XCC grant with `max_cost_per_invocation` absent/zero -> the charge denies fail-closed
  (cost_units == 0 path), proving the pool cannot be silently defeated.
- B5: an XCC charge with `free_tier_pool == None` denies (per-Pass hold reversed), proving issuing XCC
  requires the pool.
- Monthly roll: charge in month M (row `freetier:global:M`), advance `cap.issued_at` into M+1, charge again,
  assert a fresh `freetier:global:M+1` row at 0 and the M row untouched.
- Concurrency atomicity (deterministic two-thread std-Mutex integration test, NOT loom - loom cannot drive
  the real `std::sync::Mutex` budget path): with POOL room for exactly one charge, two threads each attempt a
  free-tier charge; assert exactly one Allow, one Deny, and the pool row never exceeds POOL.
- Symmetric reversal: authorize a free-tier charge, then cancel the request; assert BOTH the per-Pass hold
  AND the pool hold are reversed (no stale pool exposure).

### 8.3 LAUNCH-READINESS GATE (M0 evidence)

1. AGGREGATE POOL DENIES FAIL-CLOSED. `with_free_tier_pool({ monthly_pool_units: 3*allot, allotment_unit: "XCC", board_approval_ref: "board-2026-06" })`,
   issue > 3 distinct Passes (distinct subjects, same window) each charging an XCC allotment; the first 3
   charges Allow, the 4th returns `Verdict::Deny` with `cost_charged == 0` and `budget_remaining == 0`; the
   denying Pass's own `(cap.id, 0)` row is UNCHANGED (per-Pass hold reversed in-closure) and
   `get_usage(freetier:global:<m>, 0).committed == POOL` exactly. Liability == `min(N x allotment, POOL)`.
2. RE-MINT RESET CLOSED. Mint two tokens for the same subject + same window with
   `id = window_scoped_capability_id(subject_did, window)`; assert ids byte-identical; charge each and assert
   `get_usage(id, 0)` shows accumulated invocation count / exposed across both presentations (ONE row).
   Advance past `until`; assert `validate_time` denies the old token; a new `window_ym` yields a new id and a
   fresh zero row plus a fresh `freetier:global:<next>` term. The B7 kernel admission assertion rejects a
   UUIDv7-id token carrying the XCC metered grant.
3. SOULBINDING HOLDS. A presentation whose holder key does not derive `credential_subject.id` is rejected
   with `PresentationHolderMismatch`; a non-Ed25519 holder key is rejected.
4. OWN-TENANT BASELINE RIGHT IS NEVER TIER-GATED. A tier_0 Unverified Pass and a Premier Pass produce
   byte-identical resource grants for the same tenant; `pass_authorizes_read` yields identical decisions for
   both across all five streams; `pass_gating.rs` contains no `TrustTier` symbol. Cross-tenant: tenant A's
   Pass denies a Read of tenant B's receipts via BOTH the uri binding and the no-widening read-scope guard;
   the prefix-collision case (`did:chioabcd` vs `did:chioabcde`) denies because of the mandatory `/`.
   Redaction: `project_pass_stream_view` strips `financial`/`budget_authority`/`cost` and stamps
   `redaction: "summary"`; a non-object body -> `Err(PassRedactionFailed)`.
5. DORMANT STOPS DRAWING. A `WithheldDormant` next-window token (`max_total_cost.units == 0`) denies its first
   metered charge with `cost_charged == 0`; baseline reads still succeed.
6. ANCHORING ROUND-TRIP (read-only). Build a batch over issued + revoked Pass artifact ids, wrap the
   `AnchorBatch` `tree_root` in a `KernelCheckpoint` (strictly-increasing `checkpoint_seq`) under a
   `SignedWeb3IdentityBinding` (`Web3KeyBindingPurpose::Anchor`, Pass anchor purpose, `chain_scope` set,
   `settlement_address == operator_address`; Section 3.4), publish a root in a mock `ChioRootRegistry`, prove
   single-Pass membership via `verifyInclusionDetailed` with no value transfer.
7. PROOF-ROOM SEALED VERDICT + NAMESPACE ISOLATION. The Pass issuance/revocation inclusion proof
   (`verifyInclusionDetailed` over the anchored root) renders as a `chio-proof-room` (`chio proof verify`)
   evidence panel with asserted/observed/verified classes and a SEALED verdict, backed by a fixture on the
   proof-room spine (mirroring the already-registered `chio.anchor-inclusion-proof.v1` /
   `chio.anchor-proof-bundle.v1`; the Pass adds no new signed-artifact schema). Assert that aggregate budget
   projections and the `chio.risk.comptroller-report.v1` reserve view EXCLUDE every `freetier:global:<m>` row
   (namespace isolation, Section 1.2 / 4.2), so a Sybil-ceiling term is never counted as a real
   capability/commerce budget hold. The new free-tier user-facing copy passes
   `check-chio-proof-room-release-truth.sh` (no "passport" naming overload; the Pass is a
   reputation-credential, not an AgentPassport/transaction-passport).

### 8.4 Workspace gate

`cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`
all green. Clippy confirms no `unwrap`/`expect` in new production code; grep confirms no em dashes (U+2014) in
any new file.

---

## 9. Task breakdown (ordered)

Sequenced so the canonical shared types, kernel controls, and credential format land before gating,
distribution, and orchestration. Each task: {files, new symbols, acceptance test, dependencies}.

T1 - Canonical capability id + AttestationWindowId (CONTROL 2 core).
- Files: `chio-core-types/src/capability/token.rs`, `chio-core-types/src/error.rs`.
- Symbols: `AttestationWindowId` (+`validate`), `WindowScopedCapabilityIdInput`, `window_scoped_capability_id`,
  `CHIO_PASS_CAPABILITY_ID_DOMAIN`, `CHIO_PASS_CAPABILITY_ID_PREFIX`, `Error::InvalidAttestationWindow`.
- Acceptance: determinism + window-sensitivity + fail-closed-window unit tests (8.1 capability-id items).
- Deps: none.

T2 - Kernel mint override (CONTROL 2 wiring).
- Files: `chio-kernel/src/authority.rs`.
- Symbols: `CapabilityAuthority::issue_window_scoped_capability` (trait default Err + `LocalCapabilityAuthority` override).
- Acceptance: minted token has `id == window_scoped_capability_id(...)`, `issued_at == since`,
  `expires_at == until`; `grants.len() != 1` rejected; UUIDv7 path unaffected for non-Pass tokens.
- Deps: T1.

T3 - Aggregate global pool ceiling (CONTROL 1).
- Files: `chio-kernel/src/kernel/mod.rs`, `construction.rs`, `validation.rs`, `kernel/error.rs`.
- Symbols: `FreeTierPoolConfig` (+`validate`, `window_ym_from_issued_at`), `FreeTierPoolHold`,
  `ChioKernel.free_tier_pool` field, `with_free_tier_pool`, `free_tier_pool_config`, `FREETIER_GLOBAL_GRANT_INDEX`,
  `PoolGuardedCharge`, `BudgetChargeResult.free_tier_pool_hold`, `KernelError::InvalidFreeTierPoolConfig`.
- Acceptance: 8.2 (pool disabled no-op, currency scoping, config fail-closed, pool-bypass closed, B5,
  monthly roll, atomicity, symmetric reversal) + launch gate 1.
- Deps: T1 (window_ym derivation aligns with the bound window). Conventional commit: `feat(kernel): aggregate free-tier pool ceiling`.

T4 - Chio Pass credential format + issuance/verify/revoke.
- Files: `chio-credentials/src/chio_pass.rs` (new), `lib.rs` (include + use-block extension), `artifact.rs`
  (CredentialError variants).
- Symbols: `ChioPass`/`UnsignedChioPass`/`ChioPassSubject`/`ChioPassEntitlements`/`ChioPassAllotmentGrant`/`ChioPassEvidence`,
  `CHIO_PASS_TYPE`/`CHIO_PASS_SCHEMA`/`CHIO_PASS_ALLOTMENT_UNIT`/`CHIO_PASS_ALLOTMENT_COST_NAME`,
  `TierAllotmentTable`, `allotment_units_for_tier`, `snapshot_chio_pass_entitlements`, `issue_chio_pass`,
  `verify_chio_pass`, `verify_chio_pass_holder_binding`, `validate_chio_pass_entitlements`,
  `chio_pass_artifact_id`, `revoke_chio_pass_record`, `attestation_window_containing`,
  `verify_window_scoped_capability_id`, the CredentialError variants of Section 2.8.
- Acceptance: 8.1 credential suite + launch gate 3.
- Deps: T1 (re-exports `AttestationWindowId`/`window_scoped_capability_id`).

T5 - Data-stream gating module.
- Files: `chio-kernel/src/pass_gating.rs` (new), `chio-kernel/src/lib.rs` (`pub mod`), `kernel/error.rs`
  (`PassScopeInflation`/`PassTenantBindingInvalid`/`PassRedactionFailed`/`PassCapabilityIdNotDeterministic`),
  `chio-core-types/src/capability/scope.rs` (`#[derive(PartialEq, Eq)]` on `ResourceGrant`/`Operation`).
- Symbols: `ChioPassStream`, `pass_baseline_read_uris`, `pass_baseline_resource_grants`, `pass_stream_uri`,
  `validate_pass_scope_is_baseline`, `uri_is_pass_denied`, `pass_receipt_read_context`,
  `project_pass_stream_view`, `pass_authorizes_read`, `pass_authorizes_subscription`, the const set.
- Acceptance: launch gate 4 + scope-inflation (grants/prompt_grants/resource exact-equality) + redaction
  whitelist + prefix-collision tests.
- Deps: T1, T2 (CapabilityToken import path).

T6 - B7 kernel admission assertion.
- Files: the Pass admission boundary in the control plane (presentation path) + a kernel-side check that a
  token carrying the XCC metered grant has a `chiopass:`-prefixed id.
- Symbols: `KernelError::PassCapabilityIdNotDeterministic` usage; admission glue.
- Acceptance: a UUIDv7-id token bearing the XCC metered grant is rejected; closes the 3 other mint sites.
- Deps: T2, T4, T5.

T7 - Anti-farm pure functions.
- Files: `chio-credentials/src/chio_pass_antifarm.rs` (new), `lib.rs` (include).
- Symbols: `ChioPassAdmissionPolicy`/`Decision`, `evaluate_pass_admission`, `ChioPassCandidate`/`Snapshot`,
  `select_snapshot_admissions`.
- Acceptance: admission throttle + snapshot determinism + cap-stop tests.
- Deps: T4 (TrustTier already shared; no kernel dep).

T8 - Refresh-on-genuine-use predicate + decision (CONTROL 3 pure half).
- Files: `chio-credentials/src/chio_pass.rs` (extend), `artifact.rs` (CONTROL 3 CredentialError variants).
- Symbols: `MIN_GENUINE_USE_RECEIPTS`, `is_genuine_use_receipt`, `receipt_debited_pass_allotment`,
  `ChioPassRefreshOutcome`, `ChioPassRefreshDecision`, `chio_pass_refresh_decision`.
- Acceptance: 8.1 genuine-use matrix + dormant/extractive/withhold decision tests.
- Deps: T4. Needs `ChioReceipt`/`Decision`/`ReceiptKind`/`TrustLevel`/`PublicKey` in the `lib.rs` use-block.

T9 - Control-plane orchestrator: scope builder + scan glue + refresh + issuance command (C1/C2/C4/C5).
- Files: `chio-control-plane/src/trust_control/chio_pass_handlers.rs` (new),
  `chio-control-plane/src/trust_control.rs` (`#[path] mod`), a CLI/command entrypoint, one board-approved
  `ChioPassConfig` surface (POOL, tier table, `window_token_capacity`, `active_population_cap`,
  `MIN_GENUINE_USE_RECEIPTS`, `board_approval_ref`, `accepted_kernel_keys`) loaded fail-closed.
- Symbols: `build_pass_scope`, `count_genuine_use`, `refresh_chio_pass_window`, the issuance command,
  `ChioPassConfig`, active-population source bound to the revocation-oracle live set.
- Acceptance: end-to-end issue -> mint -> charge -> read -> rollover integration test (Section 7) + launch
  gate 2/5; re-mint reset + dormant-stops-drawing cross-component evidence.
- Deps: T2, T3, T4, T5, T7, T8.

T10 - Anchoring job (read-only) (C6).
- Files: `chio_pass_handlers.rs` batch task.
- Symbols: issuance/revocation Merkle batch + `publishRoot` cadence.
- Acceptance: launch gate 6 anchoring round-trip; or explicitly deferred per Section 6.6.
- Deps: T4, T9.

---

## Open questions (flagged, not papered over)

1. GOVERNANCE NUMBERS (blocking sign-off, not blocking build): the tier->units table (Section 2.5 default
   `1000/1000/2500/5000`), the monthly POOL ceiling, `per_invocation_units`, `window_token_capacity`,
   `active_population_cap`, and `MIN_GENUINE_USE_RECEIPTS` are placeholders needing board approval and a single
   `ChioPassConfig` source of truth (config, not const).
2. HA POSTURE: is single-node `budget_store_lock` the committed M0 deployment model? If multi-process shares
   one SQLite file, the pool ceiling is SOFT (overrun bounded by `max_cost_per_invocation x node_count`); size
   POOL below the runway (e.g. 95%) and state the tolerance.
3. `accepted_kernel_keys` PROVENANCE (RESOLVED, posture stated): the trusted-kernel-key allowlist used by the
   genuine-use scan is the EXISTING pinned authority-key set - the kernel signing keys that emit the metered
   receipts and/or the trust-market pinned market-authority registry (RR2-TM-01) - loaded fail-closed from the
   single board-approved `ChioPassConfig` (Section 4.3 / 6.4), NOT an ad-hoc per-request caller config. Without
   this pin, a self-signed receipt under an attacker-chosen `kernel_key` passes `verify_signature` (which only
   proves self-consistency). Rotation reuses the market-authority registry's pinned-key rotation: a retired key
   remains accepted for receipts dated before its rotation epoch so in-flight windows do not silently fail.
   Remaining sign-off: the exact key list and rotation epochs are board/registry inputs, not a code default.
4. TENANT-ID DERIVATION (blocking the own-stream gate): confirm issuance writes `tenant_id` as the raw
   `did:chio` used verbatim in `chio://receipts/tenant/<tenant>/*`; any normalization/hashing mismatch against
   the SQL `r.tenant_id = ?12` silently denies all own-stream reads.
5. GENUINE-USE FLOOR: is a single qualifying metered Allow sufficient, or should refresh require a small floor
   (e.g. >= 3) or a distinct-tool-server count to resist a trivial self-call keeping the allotment alive?
   Higher floor strengthens anti-extraction but penalizes light legitimate users.
6. ROLLOVER GRACE: when a holder re-attests AFTER the next window has begun, do they get a full allotment, a
   pro-rated one, or wait until the window after? M0 is full-or-nothing at mint time.
7. ANCHORING CADENCE: per-issuance vs batched daily, and whether revocation digests share a Merkle tree with
   issuance digests or get a separate root (affects proof sizing, not the credential format).
8. PRESENTATION PATH: M0 ships both the direct `verify_chio_pass` + holder-binding pair (initial admission)
   and the challenge/response presentation path (rollover re-attestation). Confirm verifiers that already speak
   the `AgentPassport` challenge protocol do not also need a wrapped-Pass presentation form in M0.
9. RETENTION: monthly `freetier:global:<YYYY-MM>` rows are never deleted (auditable history); confirm a
   retention/compaction policy for unbounded row growth over time.
