//! Chio Pass control-plane orchestrator (M0 spec Section 6.3/6.4, task T9).
//!
//! This module is the control plane that owns the cross-crate Pass wiring: it
//! needs BOTH the credential layer (`chio-credentials`) and the kernel scope/mint
//! surface (`chio-kernel`), so the bridge lives here rather than in either leaf
//! crate. It composes the deterministic primitives committed in T1-T8 (it never
//! re-implements `window_scoped_capability_id`, `allotment_units_for_tier`,
//! `is_genuine_use_receipt`, `chio_pass_refresh_decision`, `FreeTierPoolConfig`,
//! or `pass_baseline_resource_grants`):
//!
//! - [`ChioPassConfig`] is the ONE board-approved governance surface (Open
//!   Question 3). It pins the trusted-kernel-key allowlist
//!   (`accepted_kernel_keys`) that the genuine-use scan consumes, the
//!   [`FreeTierPoolConfig`] pool ceiling, the tier -> allotment table, and the
//!   distribution-throttle policy. It is loaded fail-closed (its `validate`
//!   rejects every degenerate field), and it is the provenance for
//!   `accepted_kernel_keys`: never an ad-hoc per-request value.
//! - [`build_pass_scope`] is the C1 bridge: it turns a verified [`ChioPass`] into
//!   the canonical Pass [`ChioScope`] of spec Section 2.7 (exactly one metered XCC
//!   `ToolGrant` pinned at index 0 plus the five gifted-stream resource grants).
//! - [`count_genuine_use`] is the CONTROL 3 storage-backed scan: it pages the
//!   receipt store and counts genuine-use receipts via the committed
//!   `is_genuine_use_receipt`, rejecting any receipt signed by a kernel key
//!   outside the pinned `accepted_kernel_keys` allowlist.
//! - [`refresh_chio_pass_window`] sizes the next window by calling the committed
//!   `chio_pass_refresh_decision` and maps its outcome onto issuance (`Granted` ->
//!   tier-sized mint, `WithheldDormant` -> 0-allotment mint, `DeniedNoReattestation`
//!   -> no mint).
//! - [`issue_chio_pass_command`] is the issuance command: it admits the candidate
//!   against the distribution throttle, then mints the soulbound credential and
//!   the window-scoped kernel capability.
//! - [`prepare_pass_anchor_publication`] is the C6 read-only anchoring job (task
//!   T10, spec Sections 3.4 / 6.6): it folds the committed `chio_pass_artifact_id`
//!   leaves of the issued + revoked Passes into an RFC6962 [`AnchorBatch`]
//!   (Merkle `tree_root` plus one inclusion proof per Pass digest), wraps that root
//!   in a [`KernelCheckpoint`] under a strictly-increasing per-operator
//!   `checkpoint_seq`, and binds it to an anchor-purpose
//!   [`SignedWeb3IdentityBinding`] via the committed `prepare_root_publication`. It
//!   is prepare-only: it reuses the already-registered anchor schemas (it adds NO
//!   new signed-artifact schema), it moves NO value on-chain, and the on-chain
//!   `publishRoot` / `verifyInclusionDetailed` side stays out of scope.
//!
//! Naming note: this is the soulbound `ChioPass` reputation credential, distinct
//! from the `AgentPassport`/`PassportLifecycleRecord` transaction-passport bundle.
//!
//! Fail-closed posture: any scan IO error or crypto fault becomes an `Err` so NO
//! new Pass is minted; a dormant identity therefore defaults to a `0` ceiling and
//! denies fail-closed on its first metered charge.

use chio_anchor::{
    build_anchor_batch_body, prepare_root_publication,
    validate_publication_call_data_against_checkpoint, verify_anchor_batch, AnchorBatch,
    AnchorBatchWitness, EvmAnchorTarget, PreparedEvmRootPublication,
};
use chio_core::canonical_json_bytes;
use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::capability::token::{
    window_scoped_capability_id, AttestationWindowId, CapabilityToken,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::hashing::Hash;
use chio_core::merkle::{leaf_hash, MerkleTree};
use chio_core::sha256_hex;
use chio_core::web3::identity::SignedWeb3IdentityBinding;
use chio_credentials::{
    attestation_window_containing, chio_pass_artifact_id, chio_pass_refresh_decision,
    evaluate_pass_admission, is_genuine_use_receipt, issue_chio_pass,
    snapshot_chio_pass_entitlements, ChioPass, ChioPassAdmissionDecision, ChioPassAdmissionPolicy,
    ChioPassRefreshDecision, ChioPassRefreshOutcome, PassportLifecycleRecord, TierAllotmentTable,
    TrustTier, CHIO_PASS_ALLOTMENT_UNIT, MIN_GENUINE_USE_RECEIPTS,
};
use chio_did::DidChio;
use chio_kernel::pass_gating::{pass_baseline_resource_grants, PASS_COMPUTE_SERVER_ID};
use chio_kernel::{
    build_checkpoint_with_previous, validate_checkpoint, CapabilityAuthority, FreeTierPoolConfig,
    KernelCheckpoint, ReceiptQuery, ReceiptReadContext, MAX_QUERY_LIMIT,
};
use chio_store_sqlite::SqliteReceiptStore;

use crate::CliError;

/// The single board-approved Chio Pass governance surface (spec Open Question 3 /
/// Sections 2.5, 4.3, 6.4).
///
/// This is the ONE source of truth for every governance number and trust anchor
/// the orchestrator consumes. It is loaded fail-closed: [`Self::validate`] rejects
/// every degenerate field so a misconfigured surface can never silently widen the
/// free tier. In particular it is the PROVENANCE of `accepted_kernel_keys`: the
/// pinned trusted-kernel-key allowlist the genuine-use scan checks every receipt
/// against, never an ad-hoc per-request caller value.
///
/// Tenant binding: the `tenant_id` every served receipt and own-stream read is
/// scoped by is the raw canonical `did:chio` written VERBATIM (it is never
/// re-derived, hashed, or re-encoded). It MUST match the
/// `chio://receipts/tenant/<tenant>/*` SQL read guard byte-for-byte; any
/// derivation mismatch silently denies ALL of the holder's own-stream reads
/// (fail-closed, but invisibly), so the canonical DID string flows unchanged from
/// issuance (`mint_chio_pass` derives it once from the subject key) through the
/// genuine-use scan and the served read scopes.
#[derive(Debug, Clone)]
pub struct ChioPassConfig {
    /// CONTROL 1 aggregate pool ceiling. Its `allotment_unit` MUST be the Pass XCC
    /// unit so the kernel recognises the co-debit as free-tier.
    pub free_tier_pool: FreeTierPoolConfig,
    /// Tier -> allotment-units table (Section 2.5). The floor is unconditional;
    /// the tier scales SIZE only, never existence.
    pub tier_allotment_table: TierAllotmentTable,
    /// Per-window distribution cap (anti-farm throttle, Section 6.1).
    pub window_token_capacity: u64,
    /// Live-population cap (anti-farm throttle, Section 6.1). Counted against the
    /// revocation-oracle live set (non-revoked, non-expired Passes).
    pub active_population_cap: u64,
    /// Board-pinned genuine-use floor for refresh. M0 ships the committed
    /// [`MIN_GENUINE_USE_RECEIPTS`] (`1`); a higher board floor is enforced by the
    /// orchestrator (Open Questions 1/5).
    pub min_genuine_use_receipts: u32,
    /// Audit-only reference to the board approval that funded this surface.
    pub board_approval_ref: String,
    /// Pinned trusted-kernel-key allowlist (Open Question 3). The genuine-use scan
    /// counts a receipt only when `receipt.kernel_key` is a member here, upgrading
    /// `verify_signature` (self-consistency) to "a TRUSTED kernel signed it".
    pub accepted_kernel_keys: Vec<PublicKey>,
}

impl ChioPassConfig {
    /// M0 placeholder governance numbers (Section 2.5 / Open Question 1).
    ///
    /// These REQUIRE board sign-off; this constructor is a convenience for wiring
    /// the single board-approved surface with the caller-pinned trust anchors (the
    /// pool ceiling, `board_approval_ref`, and the `accepted_kernel_keys`
    /// provenance), NOT a silent wire default.
    #[must_use]
    pub fn m0_placeholder(
        board_approval_ref: String,
        monthly_pool_units: u64,
        accepted_kernel_keys: Vec<PublicKey>,
    ) -> Self {
        Self {
            free_tier_pool: FreeTierPoolConfig {
                monthly_pool_units,
                allotment_unit: CHIO_PASS_ALLOTMENT_UNIT.to_string(),
                board_approval_ref: board_approval_ref.clone(),
            },
            tier_allotment_table: TierAllotmentTable::default(),
            window_token_capacity: 10_000,
            active_population_cap: 100_000,
            min_genuine_use_receipts: MIN_GENUINE_USE_RECEIPTS,
            board_approval_ref,
            accepted_kernel_keys,
        }
    }

    /// The single board-approved M1 launch defaults (task M1-1).
    ///
    /// Returns ONE fail-closed [`ChioPassConfig`] pinned to the M1 launch numbers.
    /// Unlike [`Self::m0_placeholder`] (kept intact for the existing T9/T10 wiring
    /// tests), the board-approved governance numbers are pinned HERE; the only
    /// caller-supplied input is `accepted_kernel_keys`, because the trusted-kernel
    /// allowlist is sourced from the trust-market market-authority registry
    /// RR2-TM-01 and its membership rotates per rotation epoch, so it is loaded from
    /// that registry at install time, never hard-coded into this binary. The
    /// returned surface still loads fail-closed: [`Self::validate`] rejects it when
    /// the supplied `accepted_kernel_keys` is empty.
    ///
    /// Pinned launch defaults:
    /// - tier -> units 1000 / 1000 / 2500 / 5000 (unverified / attested / verified /
    ///   premier): the committed [`TierAllotmentTable`] launch table. The floor is
    ///   unconditional; the tier scales allotment SIZE only, never existence.
    /// - allotment unit XCC ([`CHIO_PASS_ALLOTMENT_UNIT`]); the per-invocation XCC
    ///   cost is the committed positive floor, so the metered grant's
    ///   `max_cost_per_invocation.units > 0` always holds and the CONTROL 1 pool
    ///   co-debit bounds spend (it can never request zero units).
    /// - `window_token_capacity` / `active_population_cap`: anti-farm throttle
    ///   placeholders (Section 6.1).
    /// - `min_genuine_use_receipts`: the committed spec floor.
    #[must_use]
    pub fn m1_launch_default(accepted_kernel_keys: Vec<PublicKey>) -> Self {
        // BOARD-PENDING: replace with the ratified launch governance reference once
        // the board vote lands. This audit-only ref records provenance and never
        // enters any arithmetic; it is non-empty so `validate` accepts the surface.
        let board_approval_ref = "board-approval-pending/chio-pass-M1-launch".to_string();
        // BOARD-PENDING: monthly aggregate free-tier POOL ceiling, in XCC. Documented
        // launch default = active_population_cap (100_000) x the attested tier floor
        // (1_000 XCC). CONTROL 1 makes liability min(N x allotment, pool), so the
        // gift degrades to "the pool shrinks", never "the treasury drains".
        let monthly_pool_units: u64 = 100_000_000;
        Self {
            free_tier_pool: FreeTierPoolConfig {
                monthly_pool_units,
                allotment_unit: CHIO_PASS_ALLOTMENT_UNIT.to_string(),
                board_approval_ref: board_approval_ref.clone(),
            },
            // tier -> units 1000 / 1000 / 2500 / 5000 (unverified/attested/verified/
            // premier): the committed M1 launch allotment table.
            tier_allotment_table: TierAllotmentTable::default(),
            window_token_capacity: 10_000,  // placeholder
            active_population_cap: 100_000, // placeholder
            // The committed spec genuine-use floor. Whether the launch floor is the
            // >= 1 default or a stricter >= 3 is board-decidable (Open Questions 1/5);
            // both are honored by `refresh_chio_pass_window` without touching the
            // const inside `chio_pass_refresh_decision`.
            min_genuine_use_receipts: MIN_GENUINE_USE_RECEIPTS,
            board_approval_ref,
            // Non-empty by contract: the launch trusted-kernel-key allowlist is
            // sourced from the trust-market market-authority registry RR2-TM-01 and
            // rotates per rotation epoch. `validate` rejects an empty set fail-closed
            // (an empty allowlist would silently force every identity dormant).
            accepted_kernel_keys,
        }
    }

    /// Validate the surface fail-closed.
    ///
    /// # Errors
    ///
    /// Returns a [`CliError`] when the pool config is invalid (delegated to
    /// [`FreeTierPoolConfig::validate`]), when the pool unit is not the Pass XCC
    /// unit, when either distribution cap or the genuine-use floor is zero, when
    /// `board_approval_ref` is empty, or when `accepted_kernel_keys` pins no
    /// trusted key (which would silently force every identity dormant).
    pub fn validate(&self) -> Result<(), CliError> {
        self.free_tier_pool.validate()?;
        if self.free_tier_pool.allotment_unit != CHIO_PASS_ALLOTMENT_UNIT {
            return Err(CliError::Other(format!(
                "free-tier pool allotment_unit must be the Pass unit {CHIO_PASS_ALLOTMENT_UNIT}, got {}",
                self.free_tier_pool.allotment_unit
            )));
        }
        if self.window_token_capacity == 0 {
            return Err(CliError::Other(
                "window_token_capacity must be non-zero".to_string(),
            ));
        }
        if self.active_population_cap == 0 {
            return Err(CliError::Other(
                "active_population_cap must be non-zero".to_string(),
            ));
        }
        if self.min_genuine_use_receipts == 0 {
            return Err(CliError::Other(
                "min_genuine_use_receipts must be non-zero".to_string(),
            ));
        }
        if self.board_approval_ref.is_empty() {
            return Err(CliError::Other(
                "board_approval_ref must be present".to_string(),
            ));
        }
        if self.accepted_kernel_keys.is_empty() {
            return Err(CliError::Other(
                "accepted_kernel_keys must pin at least one trusted kernel key".to_string(),
            ));
        }
        Ok(())
    }

    /// Build the per-window distribution-throttle policy from the board-pinned
    /// capacities (Section 6.1). `window_ym` is the per-window label; the capacity
    /// and population cap are governance config.
    #[must_use]
    pub fn admission_policy_for_window(
        &self,
        window_ym: impl Into<String>,
    ) -> ChioPassAdmissionPolicy {
        ChioPassAdmissionPolicy {
            window_ym: window_ym.into(),
            window_token_capacity: self.window_token_capacity,
            active_population_cap: self.active_population_cap,
        }
    }
}

/// The product of one issuance: the soulbound credential, the window-scoped kernel
/// capability minted from its canonical scope, and the attestation window both are
/// pinned to.
#[derive(Debug, Clone)]
pub struct ChioPassIssuance {
    /// The signed soulbound `ChioPass` credential.
    pub pass: ChioPass,
    /// The window-scoped capability token (`token.id == chiopass:<hash>`,
    /// `grant_index 0`, `issued_at == window.since`, `expires_at == window.until`).
    pub capability: CapabilityToken,
    /// The attestation window the Pass and capability are bound to.
    pub window: AttestationWindowId,
}

/// The result of a rollover refresh (CONTROL 3, Section 4.3).
#[derive(Debug, Clone)]
pub enum ChioPassRefreshResult {
    /// Re-attested with genuine use: a fresh tier-sized Pass + capability minted.
    Renewed {
        decision: ChioPassRefreshDecision,
        issuance: ChioPassIssuance,
    },
    /// Re-attested but dormant: a `window_units == 0` Pass + capability minted.
    /// Baseline reads persist; the first metered charge denies fail-closed.
    Dormant {
        decision: ChioPassRefreshDecision,
        issuance: ChioPassIssuance,
    },
    /// No fresh re-attestation: nothing minted; the old token lapses at expiry.
    NotReattested { decision: ChioPassRefreshDecision },
}

/// The Pass -> [`ChioScope`] builder (C1, spec Section 6.3 / 2.7).
///
/// Turns a verified [`ChioPass`] into the canonical Pass scope: EXACTLY one metered
/// XCC `ToolGrant` pinned at index 0 (the only grant that opens a budget row), plus
/// the five gifted-stream resource grants from the committed
/// `pass_baseline_resource_grants` builder, and ZERO prompt grants. The metered
/// grant's `max_total_cost` is `Some(window_units)` (a `0` ceiling denies fail-closed,
/// never `None`/unlimited) and `max_cost_per_invocation` is `Some(per_invocation_units)`
/// in the XCC unit so CONTROL 1 recognises the pool co-debit.
///
/// # Errors
///
/// Returns a [`CliError`] when the baseline resource-grant builder rejects the
/// tenant (delegated to `pass_baseline_resource_grants`).
pub fn build_pass_scope(pass: &ChioPass, subject_tenant: &str) -> Result<ChioScope, CliError> {
    let allotment = &pass.unsigned.credential_subject.entitlements.allotment;
    let metered = ToolGrant {
        server_id: PASS_COMPUTE_SERVER_ID.to_string(),
        tool_name: "*".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: allotment.per_invocation_units,
            currency: CHIO_PASS_ALLOTMENT_UNIT.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: allotment.window_units,
            currency: CHIO_PASS_ALLOTMENT_UNIT.to_string(),
        }),
        dpop_required: None,
    };
    let resource_grants = pass_baseline_resource_grants(subject_tenant)?;
    Ok(ChioScope {
        grants: vec![metered],
        resource_grants,
        prompt_grants: vec![],
    })
}

/// CONTROL 3 storage-backed genuine-use scan (spec Section 6.4).
///
/// Pages the receipt store over `window` (own-tenant, agent-scoped, decision
/// "allow") and counts the receipts that satisfy the committed
/// [`is_genuine_use_receipt`] predicate against `accepted_kernel_keys`. A receipt
/// signed by a kernel key outside the pinned allowlist is NOT counted (the predicate
/// returns `Ok(false)`). A store IO error or a crypto fault propagates as `Err` so
/// the caller mints no new Pass (fail-closed).
///
/// # Errors
///
/// Returns a [`CliError`] when the receipt store query fails, when the predicate
/// faults on a crypto error, or on the (practically unreachable) `u32` count overflow.
pub fn count_genuine_use(
    store: &SqliteReceiptStore,
    subject_key_hex: &str,
    tenant: &str,
    pass_capability_id: &str,
    window: &AttestationWindowId,
    accepted_kernel_keys: &[PublicKey],
) -> Result<u32, CliError> {
    let mut count = 0u32;
    let mut cursor = None;
    loop {
        let query = ReceiptQuery {
            capability_id: Some(pass_capability_id.to_string()),
            outcome: Some("allow".to_string()),
            since: Some(window.since),
            until: Some(window.until),
            cursor,
            limit: MAX_QUERY_LIMIT,
            agent_subject: Some(subject_key_hex.to_string()),
            tenant_filter: Some(tenant.to_string()),
            read_context: Some(ReceiptReadContext::authenticated_tenant(tenant)),
            ..Default::default()
        };
        let page = store.query_receipts(&query)?;
        for stored in &page.receipts {
            if is_genuine_use_receipt(
                &stored.receipt,
                pass_capability_id,
                window,
                accepted_kernel_keys,
            )? {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| CliError::Other("genuine-use count overflow".to_string()))?;
            }
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(count)
}

/// Mint a Pass + window-scoped capability for an explicit window (the shared core
/// of both the issuance command and the rollover refresh).
///
/// The canonical `did:chio` is derived from `subject_public_key` so the credential
/// read scopes, the window-scoped capability id, and the served own-tenant streams
/// all bind to the SAME canonical identity (closing the scope-binding gap). The
/// scope is built by [`build_pass_scope`] and minted via the committed
/// `CapabilityAuthority::issue_window_scoped_capability` choke point, so the token
/// carries the deterministic `chiopass:<hash>` id (never a fresh UUIDv7).
#[allow(clippy::too_many_arguments)]
fn mint_chio_pass<A: CapabilityAuthority + ?Sized>(
    config: &ChioPassConfig,
    authority: &A,
    issuer_keypair: &Keypair,
    subject_public_key: &PublicKey,
    tier: TrustTier,
    window: &AttestationWindowId,
    is_first_window: bool,
    genuine_use_observed: bool,
) -> Result<ChioPassIssuance, CliError> {
    let subject_did = DidChio::from_public_key(subject_public_key.clone())
        .map_err(|error| CliError::Other(error.to_string()))?
        .to_string();
    let (entitlements, evidence) = snapshot_chio_pass_entitlements(
        &subject_did,
        tier,
        window,
        is_first_window,
        genuine_use_observed,
        &config.tier_allotment_table,
    )?;
    let pass = issue_chio_pass(
        issuer_keypair,
        &subject_did,
        entitlements,
        evidence,
        window.since,
        window.until,
        &config.tier_allotment_table,
    )?;
    let scope = build_pass_scope(&pass, &subject_did)?;
    let capability = authority.issue_window_scoped_capability(
        subject_public_key,
        &subject_did,
        scope,
        window,
    )?;
    Ok(ChioPassIssuance {
        pass,
        capability,
        window: window.clone(),
    })
}

/// The Chio Pass issuance command (spec Section 7 steps 4-6).
///
/// Admits the candidate against the board-pinned distribution throttle (Section
/// 6.1: per-window capacity plus the revocation-oracle live-set population cap),
/// then mints the first-window soulbound credential and its deterministic
/// window-scoped capability. `now` selects the UTC monthly window;
/// `window_issued_count`/`active_population` are the pinned distribution counters
/// (the live set is sourced from the revocation oracle, never recomputed here).
///
/// # Errors
///
/// Returns a [`CliError`] when the config is invalid, when the window cannot be
/// derived, when admission is denied (throttle exhausted, population cap reached,
/// or policy invalid), or when credential/capability minting fails.
#[allow(clippy::too_many_arguments)]
pub fn issue_chio_pass_command<A: CapabilityAuthority + ?Sized>(
    config: &ChioPassConfig,
    authority: &A,
    issuer_keypair: &Keypair,
    subject_public_key: &PublicKey,
    tier: TrustTier,
    now: u64,
    window_issued_count: u64,
    active_population: u64,
) -> Result<ChioPassIssuance, CliError> {
    config.validate()?;
    let window = attestation_window_containing(now)?;
    let policy = config.admission_policy_for_window(window.window_ym.clone());
    match evaluate_pass_admission(&policy, window_issued_count, active_population) {
        ChioPassAdmissionDecision::Admit => {}
        ChioPassAdmissionDecision::DenyWindowExhausted => {
            return Err(CliError::Other(
                "Pass issuance denied: window token capacity exhausted".to_string(),
            ));
        }
        ChioPassAdmissionDecision::DenyPopulationCapReached => {
            return Err(CliError::Other(
                "Pass issuance denied: active population cap reached".to_string(),
            ));
        }
        ChioPassAdmissionDecision::DenyPolicyInvalid => {
            return Err(CliError::Other(
                "Pass issuance denied: admission policy invalid".to_string(),
            ));
        }
    }
    // First window: the newcomer gets the unconditional tier floor (Section 2.5).
    mint_chio_pass(
        config,
        authority,
        issuer_keypair,
        subject_public_key,
        tier,
        &window,
        true,
        true,
    )
}

/// Rollover refresh orchestrator (CONTROL 3, spec Sections 4.3 / 6.4).
///
/// Scans the prior window's genuine use, sizes the next window via the committed
/// [`chio_pass_refresh_decision`], and maps its outcome onto issuance:
/// - `Granted` -> mint the next Pass at tier size ([`ChioPassRefreshResult::Renewed`]).
/// - `WithheldDormant` -> mint the next Pass with `window_units == 0`
///   ([`ChioPassRefreshResult::Dormant`]); baseline reads persist, the first metered
///   charge denies fail-closed.
/// - `DeniedNoReattestation` -> mint nothing ([`ChioPassRefreshResult::NotReattested`]).
///
/// `reattested` is the verified result of a fresh rollover presentation challenge
/// (`verify_passport_presentation_response_with_policy`, spec note B12): the caller
/// runs the tight-window/fresh-nonce verification and passes its boolean verdict so
/// this orchestrator never invents re-attestation provenance.
///
/// The board-pinned `min_genuine_use_receipts` floor is enforced here: a raw count
/// below the floor is treated as `0` genuine use, so a higher board floor (Open
/// Question 5) governs without contradicting the committed const inside
/// `chio_pass_refresh_decision`.
///
/// Fail-closed: a scan IO error or crypto fault propagates as `Err`, so NO new Pass
/// is minted and a dormant/extractive identity draws nothing.
///
/// # Errors
///
/// Returns a [`CliError`] when the config is invalid, when the canonical id cannot
/// be derived, when the genuine-use scan fails, when the windows are not a contiguous
/// monthly rollover, or when minting fails.
#[allow(clippy::too_many_arguments)]
pub fn refresh_chio_pass_window<A: CapabilityAuthority + ?Sized>(
    config: &ChioPassConfig,
    store: &SqliteReceiptStore,
    authority: &A,
    issuer_keypair: &Keypair,
    subject_public_key: &PublicKey,
    tier: TrustTier,
    prior_window: &AttestationWindowId,
    next_window: &AttestationWindowId,
    reattested: bool,
) -> Result<ChioPassRefreshResult, CliError> {
    config.validate()?;
    let subject = DidChio::from_public_key(subject_public_key.clone())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let subject_did = subject.to_string();
    let prior_capability_id = window_scoped_capability_id(&subject_did, prior_window)?;
    let next_capability_id = window_scoped_capability_id(&subject_did, next_window)?;
    // CONTROL 3 scan: fail-closed (any store/crypto error -> Err -> no mint).
    let raw_count = count_genuine_use(
        store,
        &subject_public_key.to_hex(),
        &subject_did,
        &prior_capability_id,
        prior_window,
        &config.accepted_kernel_keys,
    )?;
    // Enforce the board-pinned floor: below it, the window draws no genuine use.
    let genuine_use_count = if raw_count >= config.min_genuine_use_receipts {
        raw_count
    } else {
        0
    };
    let decision = chio_pass_refresh_decision(
        &subject,
        prior_window,
        next_window,
        prior_capability_id,
        next_capability_id,
        genuine_use_count,
        reattested,
        tier,
        &config.tier_allotment_table,
    )?;
    match decision.outcome {
        ChioPassRefreshOutcome::Granted => {
            let issuance = mint_chio_pass(
                config,
                authority,
                issuer_keypair,
                subject_public_key,
                tier,
                next_window,
                false,
                true,
            )?;
            Ok(ChioPassRefreshResult::Renewed { decision, issuance })
        }
        ChioPassRefreshOutcome::WithheldDormant => {
            let issuance = mint_chio_pass(
                config,
                authority,
                issuer_keypair,
                subject_public_key,
                tier,
                next_window,
                false,
                false,
            )?;
            Ok(ChioPassRefreshResult::Dormant { decision, issuance })
        }
        ChioPassRefreshOutcome::DeniedNoReattestation => {
            Ok(ChioPassRefreshResult::NotReattested { decision })
        }
    }
}

/// The prepared (un-broadcast) product of the read-only Pass anchoring job (task
/// T10, spec Sections 3.4 / 6.6).
///
/// Every field is an off-chain artifact: nothing here moves value on-chain. The
/// [`AnchorBatch`] carries the Merkle `tree_root` over the anchored Pass digests
/// plus one inclusion proof per digest; the [`KernelCheckpoint`] re-commits that
/// same root under the operator's strictly-increasing `checkpoint_seq`; and the
/// [`PreparedEvmRootPublication`] is the prepared (not sent) `publishRoot` call
/// data bound to the anchor-purpose identity binding. The on-chain `publishRoot` /
/// `verifyInclusionDetailed` calls remain the caller's separate, out-of-scope step.
#[derive(Debug, Clone)]
pub struct PreparedPassAnchorPublication {
    /// The ordered Pass artifact-id digests that became the Merkle leaves: the
    /// issued-Pass digests first (input order), then the revoked-record digests.
    pub anchored_digests: Vec<String>,
    /// The boundary index splitting issued-Pass leaves from revoked-record leaves
    /// in [`Self::anchored_digests`]: `anchored_digests[..issued_count]` are issued
    /// Pass digests and `anchored_digests[issued_count..]` are revoked-record
    /// digests. This is a row-classification hint for the read-only proof panel; it
    /// is NOT part of any signed body (this struct is the un-signed prepared product).
    pub issued_count: usize,
    /// The signed RFC6962 anchor batch: `body.tree_root` is the anchorable root and
    /// `body.inclusions` carries one Merkle inclusion proof per anchored digest.
    pub batch: AnchorBatch,
    /// The kernel checkpoint wrapping `batch.body.tree_root`. Its `merkle_root`
    /// equals `batch.body.tree_root` and its `checkpoint_seq` strictly exceeds the
    /// supplied previous checkpoint's seq (genesis is `0`).
    pub checkpoint: KernelCheckpoint,
    /// The prepared (un-broadcast) EVM root-publication call bound to the
    /// anchor-purpose identity binding. Read-only: no value moves on-chain.
    pub publication: PreparedEvmRootPublication,
}

/// The read-only Chio Pass anchoring job (C6, task T10; spec Sections 3.4 / 6.6).
///
/// Folds the issued + revoked Pass digests into one anchorable Merkle root and the
/// matching inclusion-proof artifacts, then prepares (does NOT send) the on-chain
/// root publication. The pipeline binds only committed primitives:
///
/// 1. Leaves: `chio_pass_artifact_id(pass)` for each issued [`ChioPass`], then the
///    `passport_id` digest of each revoked [`PassportLifecycleRecord`] (which the
///    committed `revoke_chio_pass_record` already set to the Pass artifact id). The
///    Pass is a subject/identity leaf set, never a transaction-passport root.
/// 2. Batch: `build_anchor_batch_body` + `AnchorBatch::sign` capture the `tree_root`
///    and one `AnchorBatchInclusion` per digest over the SAME RFC6962 substrate the
///    transaction/settlement passports use. This reuses the already-registered
///    anchor schemas and introduces NO new signed-artifact schema.
/// 3. Checkpoint: `build_checkpoint_with_previous` wraps that root in a
///    [`KernelCheckpoint`] whose `checkpoint_seq` is `previous_checkpoint.seq + 1`
///    (or `1` for the genesis batch), with a `1`-based `batch_start_seq` that
///    continues the prior checkpoint's range and a `batch_end_seq` that covers
///    exactly `tree_size` leaves, so `validate_checkpoint` (and any continuity
///    consumer) accepts the prepared artifacts.
/// 4. Publication: `prepare_root_publication` produces the prepared
///    `IChioRootRegistry::publishRoot` call. It fails closed unless `binding`'s
///    certificate carries [`Web3KeyBindingPurpose::Anchor`], its `chain_scope`
///    covers `target.chain_id`, and its `settlement_address == operator_address`.
///
/// The job is prepare-only and value-free: `ChioRootRegistry` stays read-only and
/// no on-chain value moves. The actual `publishRoot` broadcast and
/// `verifyInclusionDetailed` membership check are the caller's separate step.
///
/// # Errors
///
/// Fails closed with a [`CliError`] when the digest set is empty, when an artifact
/// id cannot be derived, when the batch/checkpoint cannot be built or signed, when
/// the per-operator `checkpoint_seq` would overflow, when the wrapped root would
/// disagree with the batch root, or when the identity binding does not authorize
/// anchoring on the target chain.
#[allow(clippy::too_many_arguments)]
pub fn prepare_pass_anchor_publication(
    operator_keypair: &Keypair,
    binding: &SignedWeb3IdentityBinding,
    target: &EvmAnchorTarget,
    issued_passes: &[ChioPass],
    revoked_records: &[PassportLifecycleRecord],
    witness: AnchorBatchWitness,
    issued_at: u64,
    previous_checkpoint: Option<&KernelCheckpoint>,
) -> Result<PreparedPassAnchorPublication, CliError> {
    // 1. Collect the issued + revoked Pass digests as the ordered Merkle leaves.
    let issued_count = issued_passes.len();
    let mut anchored_digests =
        Vec::with_capacity(issued_count.saturating_add(revoked_records.len()));
    for pass in issued_passes {
        anchored_digests.push(chio_pass_artifact_id(pass)?);
    }
    for record in revoked_records {
        anchored_digests.push(record.passport_id.clone());
    }
    if anchored_digests.is_empty() {
        // Fail closed: an empty anchor batch commits nothing and would also be
        // rejected by `build_anchor_batch_body`; surface a Pass-specific message.
        return Err(CliError::Other(
            "Pass anchor batch requires at least one issued or revoked Pass digest".to_string(),
        ));
    }
    // Fail closed on a duplicate digest across the issued + revoked sets (PR959
    // codex P2). A Pass artifact id and its revocation record share the same
    // `chio_pass_artifact_id` digest, so a Pass present in both `issued_passes`
    // and `revoked_records` would anchor one digest twice and let the proof
    // panel seal while showing the SAME Pass as both Issued and Revoked -
    // contradictory live/revoked status for a single digest. Reject the batch
    // before it can publish that contradiction.
    let mut seen_digests = std::collections::BTreeSet::new();
    for digest in &anchored_digests {
        if !seen_digests.insert(digest.as_str()) {
            return Err(CliError::Other(format!(
                "Pass anchor batch rejects a duplicate Pass digest across the issued and revoked sets: {digest}"
            )));
        }
    }

    // 2. Build + sign the RFC6962 anchor batch over the digests. `build_anchor_batch_body`
    // canonical-JSON-encodes each digest leaf; reproduce those exact leaf bytes so the
    // checkpoint in step 3 commits the byte-identical Merkle root.
    let leaves = anchored_digests
        .iter()
        .map(canonical_json_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let batch_body = build_anchor_batch_body(
        anchored_digests.clone(),
        witness,
        issued_at,
        operator_keypair.public_key(),
    )
    .map_err(|error| CliError::Other(format!("Pass anchor batch build failed: {error}")))?;
    let batch = AnchorBatch::sign(batch_body, operator_keypair)
        .map_err(|error| CliError::Other(format!("Pass anchor batch sign failed: {error}")))?;

    // 3. Wrap the batch root in a kernel checkpoint with VALID ranges so any standard
    // `validate_checkpoint`/continuity consumer accepts the prepared artifacts.
    // `validate_checkpoint` requires `checkpoint_seq >= 1` (genesis is 1, not 0), a
    // `1`-based `batch_start_seq` that immediately follows the predecessor's
    // `batch_end_seq`, and `batch_end_seq == batch_start_seq + tree_size - 1` so the
    // covered entry count equals the leaf count (never one larger than `tree_size`).
    let leaf_count = u64::try_from(leaves.len())
        .map_err(|_| CliError::Other("anchor leaf count overflow".to_string()))?;
    let (checkpoint_seq, batch_start_seq) = match previous_checkpoint {
        None => (1, 1),
        Some(previous) => {
            let seq = previous.body.checkpoint_seq.checked_add(1).ok_or_else(|| {
                CliError::Other("per-operator checkpoint_seq overflow".to_string())
            })?;
            let start = previous.body.batch_end_seq.checked_add(1).ok_or_else(|| {
                CliError::Other("per-operator batch_start_seq overflow".to_string())
            })?;
            (seq, start)
        }
    };
    // `leaf_count >= 1` (the empty digest set was rejected above), so
    // `batch_end_seq >= batch_start_seq >= 1`.
    let batch_end_seq = batch_start_seq
        .checked_add(leaf_count)
        .and_then(|end| end.checked_sub(1))
        .ok_or_else(|| CliError::Other("anchor batch_end_seq overflow".to_string()))?;
    let checkpoint = build_checkpoint_with_previous(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        &leaves,
        operator_keypair,
        previous_checkpoint,
    )?;
    // Defense-in-depth: the checkpoint must re-commit the batch's tree root exactly.
    if checkpoint.body.merkle_root != batch.body.tree_root {
        return Err(CliError::Other(
            "Pass anchor checkpoint root does not match the anchor batch tree root".to_string(),
        ));
    }
    // Defense-in-depth: fail closed unless the prepared checkpoint actually validates,
    // so a malformed range can never be published or handed to an inclusion verifier.
    validate_checkpoint(&checkpoint)
        .map_err(|error| CliError::Other(format!("Pass anchor checkpoint is invalid: {error}")))?;
    // Bind the prepared publication to the SAME operator identity that signed the
    // checkpoint. `prepare_root_publication` attributes the on-chain call using
    // `binding.certificate.chio_public_key` (its `operatorKeyHash`) but only checks the
    // binding against the EVM target, not against the checkpoint signer. Reject a
    // binding whose key does not match the checkpoint's `kernel_key` so the anchored
    // root's advertised operator identity matches its off-chain signer fail-closed.
    if binding.certificate.chio_public_key != checkpoint.body.kernel_key {
        return Err(CliError::Other(
            "Pass anchor binding key does not match the operator key that signed the checkpoint"
                .to_string(),
        ));
    }

    // 4. Prepare (do NOT broadcast) the on-chain publishRoot call. This fails closed
    // unless the binding authorizes anchoring on the target chain for the operator.
    let publication = prepare_root_publication(target, &checkpoint, binding).map_err(|error| {
        CliError::Other(format!(
            "Pass anchor root publication prepare failed: {error}"
        ))
    })?;

    Ok(PreparedPassAnchorPublication {
        anchored_digests,
        issued_count,
        batch,
        checkpoint,
        publication,
    })
}

/// The display schema label the sealed Pass proof panel domain-separates its seal
/// digest under (task M2-18).
///
/// This is a DISPLAY-ONLY label, NOT a signed-artifact schema: it is never
/// registered with `is_supported_signed_artifact_schema`, never signed, and never
/// written to any on-chain or wire/signed body. It exists only so the panel seal
/// digest cannot be confused with the digest of any other artifact.
pub const CHIO_PASS_PROOF_PANEL_SCHEMA: &str = "chio.pass-proof-panel.v1";

/// Whether an anchored Pass leaf is an issuance proof or a revocation proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PassProofKind {
    /// An issued-Pass artifact-id leaf (an issuance/anchoring inclusion proof).
    Issued,
    /// A revoked-record leaf (a revocation inclusion proof).
    Revoked,
}

/// One read-only row of the sealed Pass proof panel: a single anchored Pass digest,
/// its kind, the RFC6962 leaf the panel RECOMPUTED for it, and whether that leaf's
/// inclusion proof re-walked to the recomputed Merkle root. Every field is derived
/// by recompute; nothing here is trusted from the prepared publication.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PassProofPanelRow {
    /// The anchored Pass digest (issued: `chio_pass_artifact_id`; revoked: the
    /// revocation record's `passport_id`, which is the same committed artifact id).
    pub digest: String,
    /// Issuance proof vs revocation proof.
    pub kind: PassProofKind,
    /// The RFC6962 leaf hash the panel recomputed from `digest`.
    pub leaf_hash: Hash,
    /// Whether this row's inclusion proof re-walked to the recomputed Merkle root.
    /// A `false` here forces the whole panel verdict to `Tampered` (fail-closed).
    pub inclusion_recomputed: bool,
}

/// The RECOMPUTED verdict of a sealed Pass proof panel.
///
/// The verdict is never trusted from the prepared proof set: it is the product of
/// re-deriving the Merkle root from the anchored digests, re-walking every inclusion
/// proof, and cross-binding that root to the anchor batch, the kernel checkpoint, and
/// the prepared publication. A tampered proof set can only ever read `Tampered`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PassProofPanelVerdict {
    /// Every anchored Pass digest recomputed its inclusion to the SAME Merkle root
    /// that the anchor batch, the kernel checkpoint, and the prepared publication all
    /// commit. The proof set is internally consistent.
    Sealed,
    /// At least one recompute disagreed: a forged root, a broken or misordered
    /// inclusion proof, a leaf-hash mismatch, or a checkpoint/publication root that
    /// does not match the independently recomputed root. Fail-closed.
    Tampered {
        /// The first recompute disagreement encountered, in deterministic check
        /// order (so the same tampered input always seals the same reason).
        reason: String,
    },
}

/// A sealed, tamper-evident, READ-ONLY projection of an already-produced Chio Pass
/// proof set (task M2-18, deferred from M1).
///
/// This is a VIEW, not a gate: it grants nothing, mutates nothing, authorizes
/// nothing, and mints nothing. It takes the prepared (un-broadcast) Pass anchoring
/// product of [`prepare_pass_anchor_publication`] (the issued + revoked anchor
/// inclusion proofs, their kernel checkpoint, and the prepared root publication) and
/// assembles a display panel whose verdict is RECOMPUTED, not trusted:
///
/// 1. It re-runs `verify_anchor_batch` over the signed batch (recomputes the Merkle
///    root from the batch's own leaves, re-walks every inclusion proof, and checks
///    the operator signature).
/// 2. It INDEPENDENTLY recomputes the Merkle root from the anchored digests (the
///    panel never trusts the prepared root, it rebuilds it from
///    `canonical_json_bytes(digest)` leaves).
/// 3. It cross-binds that recomputed root to the anchor batch `tree_root`, the
///    kernel checkpoint `merkle_root`, and the prepared publication `merkle_root`,
///    so the issuance/anchoring binding is part of the verdict.
/// 4. It re-walks every per-row inclusion proof against the recomputed root and
///    checks each row's leaf hash and ordered digest.
///
/// Recompute is the SOLE proof lane: any disagreement flips the verdict to
/// [`PassProofPanelVerdict::Tampered`] fail-closed. The panel then binds a `seal`
/// digest over its recomputed body ([`Self::seal_digest`]); because the seal commits
/// the recomputed rows, roots, and verdict, a tampered proof set produces both a
/// `Tampered` verdict AND a different seal (tamper-evident). [`Self::verify_seal`]
/// re-derives that digest from the panel's own body as a self-consistency check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SealedPassProofPanel {
    rows: Vec<PassProofPanelRow>,
    recomputed_root: Hash,
    batch_root: Hash,
    checkpoint_root: Hash,
    publication_root: Hash,
    issued_count: usize,
    revoked_count: usize,
    verdict: PassProofPanelVerdict,
    seal: String,
}

impl SealedPassProofPanel {
    /// Project + recompute + seal a read-only panel over the prepared Pass proof set.
    ///
    /// Always succeeds with a panel: a tampered proof set yields a panel whose
    /// `verdict` is [`PassProofPanelVerdict::Tampered`] (never an error and never a
    /// `Sealed` verdict). The only error path is the seal canonicalization of the
    /// panel's own well-formed body, which is propagated fail-closed.
    ///
    /// `expected_target` is the trusted, registered anchor target whose
    /// `contract_address` is the intended root-registry the publication must
    /// broadcast to. The prepared publication's broadcast envelope (chain, target
    /// contract, operator, publisher) rides OUTSIDE every signed artifact, so it is
    /// bound here to this independently supplied target; a publication tampered to
    /// broadcast to a different contract or chain flips the verdict to
    /// [`PassProofPanelVerdict::Tampered`] fail-closed.
    ///
    /// # Errors
    ///
    /// Returns a [`CliError`] only if the seal body cannot be canonical-JSON encoded.
    pub fn project(
        prepared: &PreparedPassAnchorPublication,
        expected_target: &EvmAnchorTarget,
    ) -> Result<Self, CliError> {
        let recompute = recompute_pass_proof_panel(prepared, expected_target);
        let seal = seal_digest_for(
            &recompute.rows,
            &recompute.recomputed_root,
            &prepared.batch.body.tree_root,
            &prepared.checkpoint.body.merkle_root,
            &prepared.publication.merkle_root,
            prepared.issued_count,
            recompute.revoked_count,
            &recompute.verdict,
        )?;
        Ok(Self {
            rows: recompute.rows,
            recomputed_root: recompute.recomputed_root,
            batch_root: prepared.batch.body.tree_root,
            checkpoint_root: prepared.checkpoint.body.merkle_root,
            publication_root: prepared.publication.merkle_root,
            issued_count: prepared.issued_count,
            revoked_count: recompute.revoked_count,
            verdict: recompute.verdict,
            seal,
        })
    }

    /// The recomputed panel verdict (read-only).
    #[must_use]
    pub fn verdict(&self) -> &PassProofPanelVerdict {
        &self.verdict
    }

    /// The recomputed panel rows (read-only).
    #[must_use]
    pub fn rows(&self) -> &[PassProofPanelRow] {
        &self.rows
    }

    /// The independently recomputed Merkle root over the anchored digests.
    #[must_use]
    pub fn recomputed_root(&self) -> &Hash {
        &self.recomputed_root
    }

    /// The tamper-evident seal digest binding the recomputed panel body.
    #[must_use]
    pub fn seal_digest(&self) -> &str {
        &self.seal
    }

    /// How many panel rows are issuance proofs.
    #[must_use]
    pub fn issued_count(&self) -> usize {
        self.issued_count
    }

    /// How many panel rows are revocation proofs.
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.revoked_count
    }

    /// Fail-closed convenience: `true` ONLY when the recompute fully agreed.
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        matches!(self.verdict, PassProofPanelVerdict::Sealed)
    }

    /// Tamper-evidence self-check: recompute the seal digest over this panel's own
    /// recomputed body and confirm it equals the bound seal. Any field altered after
    /// sealing flips this to `false` (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns a [`CliError`] only if the seal body cannot be canonical-JSON encoded.
    pub fn verify_seal(&self) -> Result<bool, CliError> {
        let recomputed = seal_digest_for(
            &self.rows,
            &self.recomputed_root,
            &self.batch_root,
            &self.checkpoint_root,
            &self.publication_root,
            self.issued_count,
            self.revoked_count,
            &self.verdict,
        )?;
        Ok(recomputed == self.seal)
    }
}

/// The internal product of a panel recompute: the per-row evidence, the
/// independently recomputed root, the revoked-row count, and the verdict.
struct PassProofPanelRecompute {
    rows: Vec<PassProofPanelRow>,
    recomputed_root: Hash,
    revoked_count: usize,
    verdict: PassProofPanelVerdict,
}

/// Record the FIRST tamper reason only, so the verdict (and therefore the seal) is
/// deterministic for a given input regardless of how many checks later disagree.
fn note_tamper(slot: &mut Option<String>, reason: impl Into<String>) {
    if slot.is_none() {
        *slot = Some(reason.into());
    }
}

/// Recompute the panel verdict, rows, and root from the prepared proof set. The
/// recompute is the sole proof lane: it rebuilds the Merkle root, cross-binds it to
/// every anchoring artifact, and re-walks every inclusion proof. It never mutates the
/// input (it borrows it) and never trusts a stored root or verdict.
fn recompute_pass_proof_panel(
    prepared: &PreparedPassAnchorPublication,
    expected_target: &EvmAnchorTarget,
) -> PassProofPanelRecompute {
    let digests = &prepared.anchored_digests;
    let inclusions = &prepared.batch.body.inclusions;
    let digest_count = digests.len();

    let mut first_tamper: Option<String> = None;

    // The issued/revoked boundary is an UNSIGNED positional hint: the recompute
    // lane cannot derive it from the proof set, so the panel must never absorb a
    // count it cannot support. An `issued_count` past the anchored digest count
    // is treated as tampering here rather than being silently clamped, since the
    // old `min(len)` clamp re-labelled every row as issued and hid the revocation
    // rows while still sealing (fail-open). The clamp is retained only as a safe
    // bound for row iteration; the verdict is already `Tampered` in that case.
    if prepared.issued_count > digest_count {
        note_tamper(
            &mut first_tamper,
            format!(
                "issued_count {} exceeds anchored digest count {digest_count}",
                prepared.issued_count
            ),
        );
    }
    let issued_count = prepared.issued_count.min(digest_count);
    let revoked_count = digest_count.saturating_sub(issued_count);

    // (a) The signed anchor batch must self-verify: this recomputes the Merkle root
    // from the batch's own leaves, re-walks every inclusion proof, and checks the
    // operator signature. A forged stored root, proof, or signature is rejected here.
    if let Err(error) = verify_anchor_batch(&prepared.batch) {
        note_tamper(
            &mut first_tamper,
            format!("anchor batch recompute failed: {error}"),
        );
    }

    // (b) Recompute every leaf from the anchored digest's canonical bytes. A
    // canonicalization fault is a tamper signal, never a panic.
    let mut leaf_bytes: Vec<Vec<u8>> = Vec::with_capacity(digests.len());
    for digest in digests {
        match canonical_json_bytes(digest) {
            Ok(bytes) => leaf_bytes.push(bytes),
            Err(error) => {
                note_tamper(
                    &mut first_tamper,
                    format!("digest leaf canonicalization failed: {error}"),
                );
                leaf_bytes.push(Vec::new());
            }
        }
    }

    // (c) Independently recompute the Merkle root from those leaves (the proof lane:
    // the panel never trusts the prepared root, it rebuilds it).
    let recomputed_root = match MerkleTree::from_leaves(&leaf_bytes) {
        Ok(tree) => tree.root(),
        Err(error) => {
            note_tamper(
                &mut first_tamper,
                format!("merkle recompute failed: {error}"),
            );
            Hash::zero()
        }
    };

    // (d) Cross-bind the recomputed root to every anchoring artifact (the
    // issuance/anchoring binding is part of the verdict).
    if recomputed_root != prepared.batch.body.tree_root {
        note_tamper(
            &mut first_tamper,
            "recomputed root does not match the anchor batch tree root",
        );
    }
    if recomputed_root != prepared.checkpoint.body.merkle_root {
        note_tamper(
            &mut first_tamper,
            "recomputed root does not match the kernel checkpoint root",
        );
    }
    // The checkpoint root matching the recomputed root is necessary but NOT
    // sufficient: the checkpoint also carries a kernel signature, an operator
    // `kernel_key`, a `checkpoint_seq`, and a covered range, none of which the
    // root comparison above touches. A checkpoint whose signature, key, seq, or
    // range was altered while the root stayed fixed would still pass the root
    // cross-check and seal. Re-run the kernel's own `validate_checkpoint` so a
    // tampered or unsigned checkpoint fails closed before the panel can seal.
    if let Err(error) = validate_checkpoint(&prepared.checkpoint) {
        note_tamper(
            &mut first_tamper,
            format!("kernel checkpoint failed validation: {error}"),
        );
    }
    if recomputed_root != prepared.publication.merkle_root {
        note_tamper(
            &mut first_tamper,
            "recomputed root does not match the prepared publication root",
        );
    }
    // The publication's display `merkle_root` matching the recomputed root is
    // likewise necessary but NOT sufficient: the broadcastable `call_data` is the
    // payload an operator actually sends, and it independently encodes the root,
    // sequence, range, tree size, operator address, and operator key hash. A
    // proof set can keep `publication.merkle_root` equal to the recomputed root
    // while its `call_data` would publish a DIFFERENT root/seq/range/operator-key-
    // hash. Re-decode the broadcast payload and bind every published field to the
    // (now validated) checkpoint so a divergent broadcast fails closed. The same
    // call also binds the broadcast envelope (chain, target contract, operator,
    // publisher) - which rides outside the ABI payload and every signed artifact -
    // to the trusted `expected_target`, so a publication tampered to broadcast to a
    // different contract or chain fails closed here too.
    if let Err(error) = validate_publication_call_data_against_checkpoint(
        &prepared.publication,
        &prepared.checkpoint,
        expected_target,
    ) {
        note_tamper(
            &mut first_tamper,
            format!("prepared publication call_data disagrees with the checkpoint: {error}"),
        );
    }

    // (e) The inclusion count must match the anchored digest count.
    if inclusions.len() != digests.len() {
        note_tamper(
            &mut first_tamper,
            "inclusion count does not match anchored digest count",
        );
    }

    // (f) Re-walk every per-row inclusion proof against the recomputed root.
    let mut rows = Vec::with_capacity(digests.len());
    for (index, (digest, leaf_bytes_i)) in digests.iter().zip(leaf_bytes.iter()).enumerate() {
        let kind = if index < issued_count {
            PassProofKind::Issued
        } else {
            PassProofKind::Revoked
        };
        let leaf = leaf_hash(leaf_bytes_i);
        let inclusion_recomputed = match inclusions.get(index) {
            Some(inclusion) => {
                let mut ok = true;
                if &inclusion.checkpoint_id != digest {
                    note_tamper(
                        &mut first_tamper,
                        format!("inclusion {index} checkpoint id does not match anchored digest"),
                    );
                    ok = false;
                }
                if inclusion.leaf_hash != leaf {
                    note_tamper(
                        &mut first_tamper,
                        format!("inclusion {index} leaf hash does not match recomputed leaf"),
                    );
                    ok = false;
                }
                if !inclusion.proof.verify_hash(leaf, &recomputed_root) {
                    note_tamper(
                        &mut first_tamper,
                        format!("inclusion {index} proof does not re-walk to the recomputed root"),
                    );
                    ok = false;
                }
                ok
            }
            None => {
                note_tamper(&mut first_tamper, format!("inclusion {index} is missing"));
                false
            }
        };
        rows.push(PassProofPanelRow {
            digest: digest.clone(),
            kind,
            leaf_hash: leaf,
            inclusion_recomputed,
        });
    }

    let verdict = match first_tamper {
        None => PassProofPanelVerdict::Sealed,
        Some(reason) => PassProofPanelVerdict::Tampered { reason },
    };

    PassProofPanelRecompute {
        rows,
        recomputed_root,
        revoked_count,
        verdict,
    }
}

/// The canonical seal body: the panel's recomputed evidence the seal digest commits.
#[derive(serde::Serialize)]
struct PassProofPanelSealBody<'a> {
    panel_schema: &'a str,
    recomputed_root: &'a Hash,
    batch_root: &'a Hash,
    checkpoint_root: &'a Hash,
    publication_root: &'a Hash,
    issued_count: usize,
    revoked_count: usize,
    rows: &'a [PassProofPanelRow],
    verdict: &'a PassProofPanelVerdict,
}

/// Compute the tamper-evident seal digest over the recomputed panel body. The seal
/// is a SHA-256 over the canonical JSON of [`PassProofPanelSealBody`]; any change to
/// the rows, roots, counts, or verdict yields a different digest.
#[allow(clippy::too_many_arguments)]
fn seal_digest_for(
    rows: &[PassProofPanelRow],
    recomputed_root: &Hash,
    batch_root: &Hash,
    checkpoint_root: &Hash,
    publication_root: &Hash,
    issued_count: usize,
    revoked_count: usize,
    verdict: &PassProofPanelVerdict,
) -> Result<String, CliError> {
    let body = PassProofPanelSealBody {
        panel_schema: CHIO_PASS_PROOF_PANEL_SCHEMA,
        recomputed_root,
        batch_root,
        checkpoint_root,
        publication_root,
        issued_count,
        revoked_count,
        rows,
        verdict,
    };
    let bytes = canonical_json_bytes(&body)?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_anchor::{verify_anchor_batch, AnchorBatchWitnessKind};
    use chio_core::hashing::Hash;
    use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
    use chio_core::receipt::decision::{Decision, ToolCallAction};
    use chio_core::receipt::kinds::{
        BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use chio_core::web3::identity::{
        Web3IdentityBindingCertificate, Web3KeyBindingPurpose, CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
    };
    use std::sync::Arc;

    use chio_core::capability::token::CapabilityTokenBody;
    use chio_credentials::{revoke_chio_pass_record, CHIO_PASS_ALLOTMENT_COST_NAME};
    use chio_kernel::pass_gating::{
        assert_pass_capability_id_deterministic, pass_authorizes_read, pass_baseline_read_uris,
        pass_receipt_read_context, pass_stream_uri, ChioPassStream,
    };
    use chio_kernel::{
        validate_checkpoint_predecessor, BudgetStore, ChioKernel, InMemoryBudgetStore,
        KernelConfig, LocalCapabilityAuthority, ReceiptStore, ToolCallRequest, Verdict,
        DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
        DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use chio_mcp_adapter::native::{NativeChioServiceBuilder, NativeTool};

    use super::*;

    // 2026-06-15T12:00:00Z (inside June 2026) and the contiguous July window.
    const MID_JUNE_2026: u64 = 1_781_524_800;
    const JULY_2026: u64 = 1_782_864_000; // 2026-07-01T00:00:00Z

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("chio-pass-t9-{prefix}-{nonce}.sqlite3"))
    }

    fn june_window() -> AttestationWindowId {
        attestation_window_containing(MID_JUNE_2026).expect("june window")
    }

    fn july_window() -> AttestationWindowId {
        attestation_window_containing(JULY_2026).expect("july window")
    }

    fn config_with_keys(keys: Vec<PublicKey>) -> ChioPassConfig {
        // Pool roomy enough to never gate these tests; the keys carry the trust
        // anchor under test.
        ChioPassConfig::m0_placeholder("board-2026-06".to_string(), 1_000_000, keys)
    }

    /// Build a signed metered-Allow receipt. `allotment_value = Some(n)` writes the
    /// `chio.pass.allotment.v1` XCC cost dimension (so it counts as genuine use);
    /// `None` omits it (so the allotment-debit predicate fails).
    fn metered_receipt(
        kernel_keypair: &Keypair,
        capability_id: &str,
        subject_key_hex: &str,
        tenant: &str,
        timestamp: u64,
        allotment_value: Option<u64>,
        id: &str,
    ) -> ChioReceipt {
        let mut metadata = serde_json::json!({
            "attribution": {
                "subject_key": subject_key_hex,
                "issuer_key": kernel_keypair.public_key().to_hex(),
                "delegation_depth": 0u32
            }
        });
        if let Some(value) = allotment_value {
            metadata["cost"] = serde_json::json!({
                "dimensions": [
                    { "name": CHIO_PASS_ALLOTMENT_COST_NAME, "value": value, "unit": "XCC" }
                ]
            });
        }
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: PASS_COMPUTE_SERVER_ID.to_string(),
                tool_name: "*".to_string(),
                action: ToolCallAction::from_parameters(serde_json::json!({})).expect("action"),
                decision: Some(Decision::Allow),
                receipt_kind: ReceiptKind::MediatedDecision,
                boundary_class: BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: ToolOrigin::CallerExecuted,
                redaction_mode: RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: "content-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                trust_level: TrustLevel::Mediated,
                tenant_id: Some(tenant.to_string()),
                kernel_key: kernel_keypair.public_key(),
                bbs_projection_version: None,
            },
            kernel_keypair,
        )
        .expect("sign receipt")
    }

    fn subject_context(subject: &Keypair) -> (String, String, AttestationWindowId, String) {
        let did = DidChio::from_public_key(subject.public_key())
            .expect("ed25519")
            .to_string();
        let key_hex = subject.public_key().to_hex();
        let window = june_window();
        let capability_id = window_scoped_capability_id(&did, &window).expect("cap id");
        (did, key_hex, window, capability_id)
    }

    // ---- M1-12 launch evidence: e2e Pass issue -> mint -> charge -> read ->
    //      rollover + dormant (spec Section 8.3 launch Gates 2 and 5). ----
    //
    // The metered XCC grant is charged through the PUBLIC
    // `evaluate_tool_call_blocking` pipeline. That is the only public charge
    // surface (the lower-level `check_and_increment_budget` is crate-private to
    // chio-kernel), and it is the faithful "REAL kernel charge": the call runs
    // the full admission path (the B7 deterministic-id gate at
    // `assert_pass_capability_id_deterministic`), the per-Pass `(cap.id, 0)`
    // budget row, AND the CONTROL-1 `freetier:global:<YYYY-MM>` pool co-debit.
    // The deterministic `chiopass:<hash>` id minted by `LocalCapabilityAuthority`
    // is what lets the Pass clear B7 (a naive XCC-bearing capability is rejected
    // at admission). Budget rows are read back through the installed `BudgetStore`
    // handle. The current attestation window is June 2026, so a June Pass is
    // time-valid at the wall clock the pipeline reads.

    /// Build a kernel wired exactly as the Pass free-tier path needs it: the
    /// CONTROL-1 pool installed, a caller-held `BudgetStore` handle (so the test
    /// can read `(cap.id, 0)` and `freetier:global:*` rows back), and a
    /// `chio.pass.compute` tool server so an admitted metered charge dispatches
    /// and commits. `ca_public_keys` pins the trusted capability issuers so the
    /// `LocalCapabilityAuthority`-minted Pass clears signature admission.
    fn wired_pass_kernel(
        ca_public_keys: Vec<PublicKey>,
        pool_units: u64,
    ) -> (ChioKernel, Arc<dyn BudgetStore>) {
        let budget_store: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let config = KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys,
            max_delegation_depth: 5,
            policy_hash: "m1-12-e2e-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        };
        let pool = FreeTierPoolConfig {
            monthly_pool_units: pool_units,
            allotment_unit: CHIO_PASS_ALLOTMENT_UNIT.to_string(),
            board_approval_ref: "board-2026-06-m1-12".to_string(),
        };
        let mut kernel = ChioKernel::new(config)
            .with_free_tier_pool(pool)
            .expect("install free-tier pool");
        kernel.set_budget_store_handle(budget_store.clone());
        let service = NativeChioServiceBuilder::new(PASS_COMPUTE_SERVER_ID, "m1-12-pass-compute")
            .tool(
                NativeTool::new("run", "metered pass compute", serde_json::json!({})),
                |arguments| Ok(serde_json::json!({ "echo": arguments })),
            )
            .build()
            .expect("build pass-compute tool server");
        kernel.register_tool_server(Box::new(service));
        (kernel, budget_store)
    }

    fn pass_tool_request(
        request_id: &str,
        capability: &CapabilityToken,
        subject: &PublicKey,
    ) -> ToolCallRequest {
        ToolCallRequest {
            request_id: request_id.to_string(),
            capability: capability.clone(),
            tool_name: "run".to_string(),
            server_id: PASS_COMPUTE_SERVER_ID.to_string(),
            agent_id: subject.to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    /// Committed (held + realized) cost units on the `(capability_id, grant 0)`
    /// budget row. Both the per-Pass row and the aggregate pool row key off grant
    /// index 0. A missing row reads as zero.
    fn committed_units_in(store: &Arc<dyn BudgetStore>, capability_id: &str) -> u64 {
        store
            .get_usage(capability_id, 0)
            .expect("budget usage lookup")
            .map(|record| record.committed_cost_units().expect("committed cost units"))
            .unwrap_or(0)
    }

    /// How many distinct budget rows exist for a capability id. The re-mint test
    /// asserts this is exactly ONE (the deterministic id never opens a second row).
    fn per_pass_row_count(store: &Arc<dyn BudgetStore>, capability_id: &str) -> usize {
        store
            .list_usages(4096, None)
            .expect("list budget usages")
            .into_iter()
            .filter(|record| record.capability_id == capability_id)
            .count()
    }

    /// `cost_charged` rendered onto the signed receipt's financial metadata. A deny
    /// that never charges (or a deny built before the financial leg) reads as zero.
    fn receipt_cost_charged(receipt: &ChioReceipt) -> u64 {
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("financial"))
            .and_then(|financial| financial.get("cost_charged"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn e2e_pass_issue_charge_rollover_dormant_gates_2_and_5() {
        let issuer = Keypair::generate();
        let authority_key = Keypair::generate();
        let authority_pub = authority_key.public_key();
        let authority = LocalCapabilityAuthority::new(authority_key);
        // The genuine-use-scan trust anchor is independent of the kernel CA trust;
        // any non-empty allowlist keeps the orchestrator config fail-closed valid.
        let config = config_with_keys(vec![Keypair::generate().public_key()]);

        // A dedicated trusted signer for the B7 negative token below, so its
        // pipeline denial is attributable to the B7 gate, not an untrusted issuer.
        let b7_signer = Keypair::generate();
        let (kernel, store) =
            wired_pass_kernel(vec![authority_pub, b7_signer.public_key()], 1_000_000);

        // ================================================================
        // GATE 2 (re-mint-reset-closed): a deterministic id maps to ONE row.
        // ================================================================
        let subject = Keypair::generate();
        let (did, _key_hex, window, expected_cap_id) = subject_context(&subject);
        let june_pool_term =
            FreeTierPoolConfig::window_ym_from_issued_at(window.since).expect("june pool term");

        // (2a) Two Passes minted for the SAME subject+window are byte-identical.
        let pass_a = issue_chio_pass_command(
            &config,
            &authority,
            &issuer,
            &subject.public_key(),
            TrustTier::Attested,
            MID_JUNE_2026,
            0,
            0,
        )
        .expect("mint Pass A");
        let pass_b = issue_chio_pass_command(
            &config,
            &authority,
            &issuer,
            &subject.public_key(),
            TrustTier::Attested,
            MID_JUNE_2026,
            1,
            1,
        )
        .expect("mint Pass B");
        assert_eq!(pass_a.capability.id, expected_cap_id);
        assert_eq!(
            pass_a.capability.id.as_bytes(),
            pass_b.capability.id.as_bytes(),
            "a re-mint in the same window yields a byte-identical capability id"
        );

        // (2b) Charge BOTH through the real kernel; they land on ONE per-Pass row.
        let resp_a = kernel
            .evaluate_tool_call_blocking(&pass_tool_request(
                "g2-a",
                &pass_a.capability,
                &subject.public_key(),
            ))
            .expect("charge Pass A");
        assert_eq!(
            resp_a.verdict,
            Verdict::Allow,
            "first metered charge admitted"
        );
        assert_eq!(receipt_cost_charged(&resp_a.receipt), 1);
        assert_eq!(committed_units_in(&store, &expected_cap_id), 1);
        let resp_b = kernel
            .evaluate_tool_call_blocking(&pass_tool_request(
                "g2-b",
                &pass_b.capability,
                &subject.public_key(),
            ))
            .expect("charge Pass B");
        assert_eq!(
            resp_b.verdict,
            Verdict::Allow,
            "second metered charge admitted"
        );
        assert_eq!(
            committed_units_in(&store, &expected_cap_id),
            2,
            "the re-minted Pass accumulates onto the SAME row (the counter is not reset)"
        );
        assert_eq!(
            per_pass_row_count(&store, &expected_cap_id),
            1,
            "exactly ONE per-Pass budget row exists for the deterministic id, not two"
        );
        assert_eq!(
            committed_units_in(&store, &june_pool_term),
            2,
            "both charges co-debit the SAME freetier:global pool row for the window"
        );

        // (2c) Past `until` the old token is denied; the next window is a FRESH row.
        assert!(
            pass_a.capability.validate_time(MID_JUNE_2026).is_ok(),
            "the token is valid inside its window"
        );
        assert!(
            pass_a.capability.validate_time(window.until).is_err(),
            "validate_time denies the old token at the window boundary (until is exclusive)"
        );
        assert!(
            pass_a
                .capability
                .validate_time(window.until.saturating_add(86_400))
                .is_err(),
            "validate_time denies the old token past until"
        );
        let next_window = july_window();
        assert_eq!(
            window.until, next_window.since,
            "contiguous monthly rollover"
        );
        let next_cap_id =
            window_scoped_capability_id(&did, &next_window).expect("next-window cap id");
        assert_ne!(
            next_cap_id, expected_cap_id,
            "the next window has a different deterministic id"
        );
        assert_eq!(
            committed_units_in(&store, &next_cap_id),
            0,
            "the next window opens a FRESH zero per-Pass usage row"
        );
        let next_pool_term = FreeTierPoolConfig::window_ym_from_issued_at(next_window.since)
            .expect("next pool term");
        assert_ne!(
            next_pool_term, june_pool_term,
            "the next window has its own pool term"
        );
        assert_eq!(
            committed_units_in(&store, &next_pool_term),
            0,
            "the next window opens a FRESH freetier:global pool row (the monthly reset is a clean slate)"
        );

        // (2d) B7: a non-deterministic (UUIDv7-style) id carrying the XCC metered
        //      grant is rejected at admission.
        let b7_subject = Keypair::generate();
        let xcc_scope = build_pass_scope(&pass_a.pass, &did).expect("xcc metered scope");
        let nondeterministic = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-018f9b2c-7e3a-7c91-a0b2-uuidv7nonpassid".to_string(),
                issuer: b7_signer.public_key(),
                subject: b7_subject.public_key(),
                scope: xcc_scope,
                issued_at: window.since,
                expires_at: window.until,
                delegation_chain: vec![],
            },
            &b7_signer,
        )
        .expect("sign non-deterministic Pass-shaped token");
        assert!(
            assert_pass_capability_id_deterministic(&nondeterministic).is_err(),
            "B7: a UUIDv7-id token carrying the XCC metered grant must be rejected"
        );
        let b7_resp = kernel
            .evaluate_tool_call_blocking(&pass_tool_request(
                "g2-b7",
                &nondeterministic,
                &b7_subject.public_key(),
            ))
            .expect("B7 admission evaluation");
        assert_eq!(
            b7_resp.verdict,
            Verdict::Deny,
            "B7 denies the non-deterministic Pass-shaped capability at admission"
        );
        assert_eq!(
            receipt_cost_charged(&b7_resp.receipt),
            0,
            "a B7-denied call charges nothing"
        );

        // ================================================================
        // GATE 5 (dormant-stops-drawing): a 0-ceiling metered draw denies
        // fail-closed, but the five gifted streams stay readable.
        // ================================================================
        let dormant_subject = Keypair::generate();
        let dormant_did = DidChio::from_public_key(dormant_subject.public_key())
            .expect("dormant did")
            .to_string();
        // A genuinely empty prior window => no genuine use => WithheldDormant. The
        // dormant window is the CURRENT (June) window so the token is time-valid.
        let prior_window = attestation_window_containing(1_778_000_000).expect("may window");
        assert_eq!(
            prior_window.until, window.since,
            "contiguous May -> June rollover"
        );
        let empty_store = {
            let path = unique_db_path("m1-12-dormant");
            SqliteReceiptStore::open(&path).expect("open empty receipt store")
        };
        let refresh = refresh_chio_pass_window(
            &config,
            &empty_store,
            &authority,
            &issuer,
            &dormant_subject.public_key(),
            TrustTier::Attested,
            &prior_window,
            &window,
            true,
        )
        .expect("dormant refresh");
        let dormant = match refresh {
            ChioPassRefreshResult::Dormant { decision, issuance } => {
                assert_eq!(decision.outcome, ChioPassRefreshOutcome::WithheldDormant);
                assert_eq!(decision.next_allotment_units, 0, "dormant ceiling is 0");
                issuance
            }
            other => panic!("expected WithheldDormant, got {other:?}"),
        };
        let dormant_scope = build_pass_scope(&dormant.pass, &dormant_did).expect("dormant scope");
        assert_eq!(
            dormant_scope.grants[0]
                .max_total_cost
                .as_ref()
                .expect("dormant ceiling")
                .units,
            0,
            "the dormant metered grant carries a 0 ceiling"
        );

        // (5a) The metered draw denies fail-closed: BudgetExhausted -> cost_charged == 0.
        let dormant_resp = kernel
            .evaluate_tool_call_blocking(&pass_tool_request(
                "g5-draw",
                &dormant.capability,
                &dormant_subject.public_key(),
            ))
            .expect("dormant metered charge");
        assert_eq!(
            dormant_resp.verdict,
            Verdict::Deny,
            "the dormant 0-ceiling metered draw is denied"
        );
        let reason = dormant_resp.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("budget") && reason.contains("exhausted"),
            "the deny is a budget-exhaustion deny, got {reason:?}"
        );
        assert_eq!(
            receipt_cost_charged(&dormant_resp.receipt),
            0,
            "the deny renders cost_charged == 0"
        );
        assert_eq!(
            committed_units_in(&store, &dormant.capability.id),
            0,
            "nothing stuck to the dormant Pass row (the per-Pass hold was reversed)"
        );

        // (5b) Every one of the five gifted streams STILL authorizes a read for the
        //      SAME dormant token: dormant stops the metered draw, never the gift.
        let gifted_uris = pass_baseline_read_uris(&dormant_did).expect("baseline read uris");
        assert_eq!(
            gifted_uris.len(),
            5,
            "the Pass gifts exactly five baseline streams"
        );
        for uri in &gifted_uris {
            assert!(
                pass_authorizes_read(&dormant.capability, uri).expect("read authorization"),
                "dormant token must still authorize the gifted read: {uri}"
            );
        }
    }

    #[test]
    fn build_pass_scope_yields_canonical_pass_scope() {
        let issuer = Keypair::generate();
        let authority_key = Keypair::generate();
        let subject = Keypair::generate();
        let config = config_with_keys(vec![authority_key.public_key()]);
        let authority = LocalCapabilityAuthority::new(authority_key);

        let issuance = issue_chio_pass_command(
            &config,
            &authority,
            &issuer,
            &subject.public_key(),
            TrustTier::Attested,
            MID_JUNE_2026,
            0,
            0,
        )
        .expect("issue");

        let (did, _, _, _) = subject_context(&subject);
        let scope = build_pass_scope(&issuance.pass, &did).expect("scope");

        // Exactly one metered XCC ToolGrant pinned at index 0.
        assert_eq!(scope.grants.len(), 1);
        let metered = &scope.grants[0];
        assert_eq!(metered.server_id, PASS_COMPUTE_SERVER_ID);
        assert_eq!(metered.tool_name, "*");
        assert_eq!(metered.operations, vec![Operation::Invoke]);
        let per_inv = metered
            .max_cost_per_invocation
            .as_ref()
            .expect("per-invocation cost");
        assert_eq!(per_inv.currency, CHIO_PASS_ALLOTMENT_UNIT);
        assert!(per_inv.units > 0, "per-invocation units must be > 0");
        let total = metered.max_total_cost.as_ref().expect("total cost");
        assert_eq!(total.currency, CHIO_PASS_ALLOTMENT_UNIT);
        assert_eq!(total.units, config.tier_allotment_table.attested);

        // Exactly five gifted-stream resource grants, no prompt grants.
        assert_eq!(scope.resource_grants.len(), 5);
        assert!(scope.prompt_grants.is_empty());
        assert_eq!(
            scope.resource_grants,
            pass_baseline_resource_grants(&did).expect("baseline")
        );
    }

    #[test]
    fn count_genuine_use_counts_and_rejects_non_allowlisted_kernel_keys() {
        let trusted = Keypair::generate();
        let rogue = Keypair::generate();
        let subject = Keypair::generate();
        let (did, key_hex, window, capability_id) = subject_context(&subject);

        let path = unique_db_path("scan");
        let store = SqliteReceiptStore::open(&path).expect("open store");

        // Two genuine-use receipts signed by the trusted kernel key.
        store
            .append_chio_receipt(&metered_receipt(
                &trusted,
                &capability_id,
                &key_hex,
                &did,
                window.since + 10,
                Some(5),
                "genuine-1",
            ))
            .expect("append genuine-1");
        store
            .append_chio_receipt(&metered_receipt(
                &trusted,
                &capability_id,
                &key_hex,
                &did,
                window.since + 20,
                Some(7),
                "genuine-2",
            ))
            .expect("append genuine-2");
        // Otherwise-genuine receipt signed by a NON-allowlisted (rogue) kernel key.
        store
            .append_chio_receipt(&metered_receipt(
                &rogue,
                &capability_id,
                &key_hex,
                &did,
                window.since + 30,
                Some(9),
                "rogue-1",
            ))
            .expect("append rogue-1");
        // Trusted-key receipt that never debited the allotment (no cost dimension).
        store
            .append_chio_receipt(&metered_receipt(
                &trusted,
                &capability_id,
                &key_hex,
                &did,
                window.since + 40,
                None,
                "no-allotment",
            ))
            .expect("append no-allotment");

        // Only the trusted key is pinned: the rogue and no-allotment receipts drop.
        let trusted_only = [trusted.public_key()];
        let count = count_genuine_use(
            &store,
            &key_hex,
            &did,
            &capability_id,
            &window,
            &trusted_only,
        )
        .expect("scan trusted-only");
        assert_eq!(count, 2, "rogue + no-allotment receipts must not count");

        // Pinning BOTH keys proves the earlier rejection was the allowlist, not the
        // receipt shape: now the rogue receipt also counts.
        let both = [trusted.public_key(), rogue.public_key()];
        let count_both = count_genuine_use(&store, &key_hex, &did, &capability_id, &window, &both)
            .expect("scan both");
        assert_eq!(count_both, 3);
    }

    #[test]
    fn refresh_grants_dormant_and_denies() {
        let issuer = Keypair::generate();
        let trusted = Keypair::generate();
        let subject = Keypair::generate();
        let (did, key_hex, prior_window, prior_cap) = subject_context(&subject);
        let next_window = july_window();
        assert_eq!(prior_window.until, next_window.since, "contiguous rollover");

        let config = config_with_keys(vec![trusted.public_key()]);
        let next_cap = window_scoped_capability_id(&did, &next_window).expect("next cap");

        // ---- Granted: one genuine-use receipt in the prior window + re-attested.
        let granted_store = {
            let path = unique_db_path("refresh-granted");
            let store = SqliteReceiptStore::open(&path).expect("open store");
            store
                .append_chio_receipt(&metered_receipt(
                    &trusted,
                    &prior_cap,
                    &key_hex,
                    &did,
                    prior_window.since + 100,
                    Some(3),
                    "granted-1",
                ))
                .expect("append");
            store
        };
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let granted = refresh_chio_pass_window(
            &config,
            &granted_store,
            &authority,
            &issuer,
            &subject.public_key(),
            TrustTier::Attested,
            &prior_window,
            &next_window,
            true,
        )
        .expect("granted refresh");
        match granted {
            ChioPassRefreshResult::Renewed { decision, issuance } => {
                assert_eq!(decision.outcome, ChioPassRefreshOutcome::Granted);
                assert_eq!(
                    decision.next_allotment_units,
                    config.tier_allotment_table.attested
                );
                assert_eq!(
                    issuance
                        .pass
                        .unsigned
                        .credential_subject
                        .entitlements
                        .allotment
                        .window_units,
                    config.tier_allotment_table.attested
                );
                assert_eq!(issuance.capability.id, next_cap);
                assert_eq!(issuance.capability.issued_at, next_window.since);
                assert_eq!(issuance.capability.expires_at, next_window.until);
            }
            other => panic!("expected Renewed, got {other:?}"),
        }

        // ---- WithheldDormant: re-attested but no genuine use (empty store).
        let dormant_store = {
            let path = unique_db_path("refresh-dormant");
            SqliteReceiptStore::open(&path).expect("open store")
        };
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let dormant = refresh_chio_pass_window(
            &config,
            &dormant_store,
            &authority,
            &issuer,
            &subject.public_key(),
            TrustTier::Attested,
            &prior_window,
            &next_window,
            true,
        )
        .expect("dormant refresh");
        match dormant {
            ChioPassRefreshResult::Dormant { decision, issuance } => {
                assert_eq!(decision.outcome, ChioPassRefreshOutcome::WithheldDormant);
                assert_eq!(decision.next_allotment_units, 0);
                let scope = build_pass_scope(&issuance.pass, &did).expect("scope");
                assert_eq!(
                    scope.grants[0]
                        .max_total_cost
                        .as_ref()
                        .expect("total")
                        .units,
                    0,
                    "dormant ceiling must be 0 (first metered charge denies)"
                );
            }
            other => panic!("expected Dormant, got {other:?}"),
        }

        // ---- DeniedNoReattestation: no fresh re-attestation -> nothing minted.
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let denied = refresh_chio_pass_window(
            &config,
            &dormant_store,
            &authority,
            &issuer,
            &subject.public_key(),
            TrustTier::Attested,
            &prior_window,
            &next_window,
            false,
        )
        .expect("denied refresh");
        match denied {
            ChioPassRefreshResult::NotReattested { decision } => {
                assert_eq!(
                    decision.outcome,
                    ChioPassRefreshOutcome::DeniedNoReattestation
                );
                assert_eq!(decision.next_allotment_units, 0);
            }
            other => panic!("expected NotReattested, got {other:?}"),
        }
    }

    #[test]
    fn config_validates_fail_closed() {
        let key = Keypair::generate().public_key();
        // The board-approved surface is valid.
        config_with_keys(vec![key.clone()])
            .validate()
            .expect("baseline config valid");

        // Empty allowlist -> rejected (would silently force everyone dormant).
        let mut empty_keys = config_with_keys(vec![key.clone()]);
        empty_keys.accepted_kernel_keys.clear();
        assert!(empty_keys.validate().is_err());

        // Zero pool ceiling -> rejected via FreeTierPoolConfig::validate.
        let mut zero_pool = config_with_keys(vec![key.clone()]);
        zero_pool.free_tier_pool.monthly_pool_units = 0;
        assert!(zero_pool.validate().is_err());

        // Non-XCC pool unit -> rejected (must be the Pass allotment unit).
        let mut wrong_unit = config_with_keys(vec![key.clone()]);
        wrong_unit.free_tier_pool.allotment_unit = "USD".to_string();
        assert!(wrong_unit.validate().is_err());

        // Zero distribution caps and floor -> each rejected.
        let mut zero_window = config_with_keys(vec![key.clone()]);
        zero_window.window_token_capacity = 0;
        assert!(zero_window.validate().is_err());

        let mut zero_pop = config_with_keys(vec![key.clone()]);
        zero_pop.active_population_cap = 0;
        assert!(zero_pop.validate().is_err());

        let mut zero_floor = config_with_keys(vec![key.clone()]);
        zero_floor.min_genuine_use_receipts = 0;
        assert!(zero_floor.validate().is_err());

        // Missing board approval reference -> rejected.
        let mut no_board = config_with_keys(vec![key]);
        no_board.board_approval_ref.clear();
        assert!(no_board.validate().is_err());
    }

    #[test]
    fn m1_launch_default_validates_and_rejects_empty_keys() {
        // The single board-approved M1 launch surface validates fail-closed when the
        // registry RR2-TM-01 trusted-kernel key set is non-empty.
        let key = Keypair::generate().public_key();
        let config = ChioPassConfig::m1_launch_default(vec![key]);
        config
            .validate()
            .expect("m1 launch default validates fail-closed");

        // Pinned launch defaults: tier -> units 1000 / 1000 / 2500 / 5000 in XCC.
        assert_eq!(config.tier_allotment_table.unverified, 1000);
        assert_eq!(config.tier_allotment_table.attested, 1000);
        assert_eq!(config.tier_allotment_table.verified, 2500);
        assert_eq!(config.tier_allotment_table.premier, 5000);
        assert_eq!(
            config.free_tier_pool.allotment_unit,
            CHIO_PASS_ALLOTMENT_UNIT
        );
        assert_eq!(config.window_token_capacity, 10_000);
        assert_eq!(config.active_population_cap, 100_000);
        assert_eq!(config.min_genuine_use_receipts, MIN_GENUINE_USE_RECEIPTS);
        assert!(
            !config.board_approval_ref.is_empty(),
            "board_approval_ref placeholder must be present so the surface validates"
        );

        // An empty accepted_kernel_keys set is rejected fail-closed: an empty
        // allowlist would silently force every identity dormant.
        let mut empty_keys = config.clone();
        empty_keys.accepted_kernel_keys.clear();
        assert!(
            empty_keys.validate().is_err(),
            "empty accepted_kernel_keys must reject"
        );
    }

    // ---- T10 read-only anchoring job (spec Sections 3.4 / 6.6, launch gate 6) ----

    const EVM_CHAIN_ID: &str = "eip155:8453";
    const EVM_CONTRACT_ADDRESS: &str = "0x1000000000000000000000000000000000000001";
    const EVM_OPERATOR_ADDRESS: &str = "0x1000000000000000000000000000000000000002";

    fn anchor_target() -> EvmAnchorTarget {
        EvmAnchorTarget {
            chain_id: EVM_CHAIN_ID.to_string(),
            rpc_url: "https://rpc.example".to_string(),
            contract_address: EVM_CONTRACT_ADDRESS.to_string(),
            operator_address: EVM_OPERATOR_ADDRESS.to_string(),
            publisher_address: EVM_OPERATOR_ADDRESS.to_string(),
        }
    }

    /// Anchor-purpose identity binding for `operator`. `settlement_address` is the
    /// target operator address and `chain_scope` covers the target chain, so
    /// `prepare_root_publication` admits it for `purpose`.
    fn operator_binding(
        operator: &Keypair,
        purpose: Vec<Web3KeyBindingPurpose>,
    ) -> SignedWeb3IdentityBinding {
        let certificate = Web3IdentityBindingCertificate {
            schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
            chio_identity: "did:chio:pass-anchor-operator".to_string(),
            chio_public_key: operator.public_key(),
            chain_scope: vec![EVM_CHAIN_ID.to_string()],
            purpose,
            settlement_address: EVM_OPERATOR_ADDRESS.to_string(),
            issued_at: 1_775_100_000,
            expires_at: 1_775_200_000,
            nonce: "pass-anchor-bind-001".to_string(),
        };
        let signature = operator
            .sign_canonical(&certificate)
            .expect("binding signature")
            .0;
        SignedWeb3IdentityBinding {
            certificate,
            signature,
        }
    }

    /// A placeholder public-witness descriptor; the prepare-only job leaves the
    /// witness state pending (no live lane). `build_anchor_batch_body` overwrites
    /// `root` with the computed tree root.
    fn pending_witness() -> AnchorBatchWitness {
        AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "rekor:pass-anchor".to_string(),
            root: Hash::zero(),
            observed_at: None,
        }
    }

    fn issue_first_window_pass(subject: &Keypair, tier: TrustTier) -> ChioPass {
        let issuer = Keypair::generate();
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let config = config_with_keys(vec![Keypair::generate().public_key()]);
        issue_chio_pass_command(
            &config,
            &authority,
            &issuer,
            &subject.public_key(),
            tier,
            MID_JUNE_2026,
            0,
            0,
        )
        .expect("issue first-window pass")
        .pass
    }

    /// PR959 codex P2: the same Pass present as both issued and revoked anchors
    /// the identical artifact digest twice, which would let the proof panel seal
    /// while showing one digest as Issued and the same digest as Revoked. The
    /// prepared publication fails closed on the duplicate instead.
    #[test]
    fn prepare_pass_anchor_publication_rejects_duplicate_digest_across_sets() {
        let operator = Keypair::generate();
        let pass = issue_first_window_pass(&Keypair::generate(), TrustTier::Verified);
        // The same Pass appears as issued AND as a revocation record: both carry
        // the identical `chio_pass_artifact_id` digest.
        let revoked = revoke_chio_pass_record(&pass, MID_JUNE_2026 + 5, "superseded".to_string())
            .expect("revoke pass");
        let binding = operator_binding(&operator, vec![Web3KeyBindingPurpose::Anchor]);
        let error = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &anchor_target(),
            std::slice::from_ref(&pass),
            std::slice::from_ref(&revoked),
            pending_witness(),
            MID_JUNE_2026,
            None,
        )
        .expect_err("duplicate digest across issued/revoked must fail closed");
        match error {
            CliError::Other(message) => assert!(
                message.contains("duplicate Pass digest"),
                "unexpected error: {message}"
            ),
            other => panic!("expected duplicate-digest rejection, got {other:?}"),
        }
    }

    #[test]
    fn prepare_pass_anchor_publication_builds_root_and_inclusions() {
        let operator = Keypair::generate();
        let pass_a = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);
        let pass_b = issue_first_window_pass(&Keypair::generate(), TrustTier::Verified);
        // The revocation record's digest is the committed Pass artifact id.
        let revoked = revoke_chio_pass_record(&pass_b, MID_JUNE_2026 + 5, "superseded".to_string())
            .expect("revoke pass_b");

        let binding = operator_binding(&operator, vec![Web3KeyBindingPurpose::Anchor]);
        let prepared = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &anchor_target(),
            std::slice::from_ref(&pass_a),
            std::slice::from_ref(&revoked),
            pending_witness(),
            MID_JUNE_2026,
            None,
        )
        .expect("prepare anchor publication");

        // Leaves are the issued digest then the revoked digest, in order.
        let issued_digest = chio_pass_artifact_id(&pass_a).expect("issued digest");
        assert_eq!(
            prepared.anchored_digests,
            vec![issued_digest.clone(), revoked.passport_id.clone()]
        );

        // The signed batch self-verifies: the Merkle root, every per-leaf inclusion
        // proof (single-Pass membership), and the signature. This is the read-only
        // membership check; no on-chain call is made.
        verify_anchor_batch(&prepared.batch).expect("anchor batch verifies");
        assert_eq!(prepared.batch.body.inclusions.len(), 2);
        assert_eq!(
            prepared.batch.body.inclusions[0].checkpoint_id,
            issued_digest
        );
        assert_eq!(
            prepared.batch.body.inclusions[1].checkpoint_id,
            revoked.passport_id
        );

        // The checkpoint re-commits the SAME root and the prepared publication
        // carries it; nothing here moves value on-chain.
        assert_eq!(
            prepared.checkpoint.body.merkle_root,
            prepared.batch.body.tree_root
        );
        assert_eq!(
            prepared.publication.merkle_root,
            prepared.batch.body.tree_root
        );
        assert_eq!(prepared.checkpoint.body.tree_size, 2);
        assert_eq!(prepared.publication.tree_size, 2);
        assert_eq!(prepared.publication.operator_address, EVM_OPERATOR_ADDRESS);
        assert_eq!(prepared.publication.chain_id, EVM_CHAIN_ID);
    }

    #[test]
    fn prepare_pass_anchor_publication_empty_set_fails_closed() {
        let operator = Keypair::generate();
        let binding = operator_binding(&operator, vec![Web3KeyBindingPurpose::Anchor]);
        let result = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &anchor_target(),
            &[],
            &[],
            pending_witness(),
            MID_JUNE_2026,
            None,
        );
        assert!(
            result.is_err(),
            "an empty issued + revoked digest set must fail closed"
        );
    }

    #[test]
    fn prepare_pass_anchor_publication_checkpoint_seq_strictly_increases() {
        let operator = Keypair::generate();
        let pass = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);
        let binding = operator_binding(&operator, vec![Web3KeyBindingPurpose::Anchor]);

        let genesis = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &anchor_target(),
            std::slice::from_ref(&pass),
            &[],
            pending_witness(),
            MID_JUNE_2026,
            None,
        )
        .expect("genesis anchor publication");
        // PR957 codex P2: the genesis checkpoint_seq is 1, not 0 (validate_checkpoint
        // rejects seq 0).
        assert_eq!(genesis.checkpoint.body.checkpoint_seq, 1);
        assert!(genesis.checkpoint.body.previous_checkpoint_sha256.is_none());

        let next = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &anchor_target(),
            &[pass],
            &[],
            pending_witness(),
            MID_JUNE_2026 + 1,
            Some(&genesis.checkpoint),
        )
        .expect("next anchor publication");
        assert!(
            next.checkpoint.body.checkpoint_seq > genesis.checkpoint.body.checkpoint_seq,
            "per-operator checkpoint_seq must strictly increase"
        );
        assert_eq!(next.checkpoint.body.checkpoint_seq, 2);
        assert_eq!(next.publication.checkpoint_seq, 2);
        // The next checkpoint chains to the prior checkpoint body (per-operator continuity).
        assert!(next.checkpoint.body.previous_checkpoint_sha256.is_some());
    }

    #[test]
    fn prepare_pass_anchor_publication_produces_validatable_checkpoints() {
        // PR957 codex P2: the prepared genesis + successor checkpoints must pass the
        // standard `validate_checkpoint` and continuity checks (seq >= 1, 1-based
        // batch ranges, covered entry count == tree_size), otherwise the anchoring
        // job cannot produce reusable checkpoints.
        let operator = Keypair::generate();
        let pass_a = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);
        let pass_b = issue_first_window_pass(&Keypair::generate(), TrustTier::Verified);
        let binding = operator_binding(&operator, vec![Web3KeyBindingPurpose::Anchor]);

        let genesis = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &anchor_target(),
            std::slice::from_ref(&pass_a),
            &[],
            pending_witness(),
            MID_JUNE_2026,
            None,
        )
        .expect("genesis anchor publication");
        validate_checkpoint(&genesis.checkpoint).expect("genesis checkpoint validates");
        assert_eq!(genesis.checkpoint.body.batch_start_seq, 1);
        assert_eq!(genesis.checkpoint.body.batch_end_seq, 1);
        assert_eq!(genesis.checkpoint.body.tree_size, 1);

        // A two-leaf successor batch covers [2, 3] (entry count 2 == tree_size 2) and
        // cleanly extends the genesis checkpoint.
        let next = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &anchor_target(),
            &[pass_a, pass_b],
            &[],
            pending_witness(),
            MID_JUNE_2026 + 1,
            Some(&genesis.checkpoint),
        )
        .expect("next anchor publication");
        validate_checkpoint(&next.checkpoint).expect("next checkpoint validates");
        assert_eq!(next.checkpoint.body.batch_start_seq, 2);
        assert_eq!(next.checkpoint.body.batch_end_seq, 3);
        assert_eq!(next.checkpoint.body.tree_size, 2);
        validate_checkpoint_predecessor(&genesis.checkpoint, &next.checkpoint)
            .expect("next cleanly extends genesis");
    }

    #[test]
    fn prepare_pass_anchor_publication_rejects_binding_key_mismatch() {
        // PR957 codex P2: the binding that attributes the on-chain operatorKeyHash must
        // match the operator key that signed the checkpoint. Passing Alice's binding
        // with Bob's keypair would anchor a root whose advertised identity (Alice) does
        // not match its off-chain signer (Bob); reject it fail-closed.
        let bob = Keypair::generate();
        let alice = Keypair::generate();
        let pass = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);
        // Alice's binding is otherwise valid (anchor purpose, target chain, settlement),
        // so only the checkpoint-signer mismatch can reject it.
        let alice_binding = operator_binding(&alice, vec![Web3KeyBindingPurpose::Anchor]);
        let denied = prepare_pass_anchor_publication(
            &bob,
            &alice_binding,
            &anchor_target(),
            &[pass],
            &[],
            pending_witness(),
            MID_JUNE_2026,
            None,
        );
        assert!(
            denied.is_err(),
            "a binding key that does not match the checkpoint signer must be rejected"
        );
    }

    #[test]
    fn prepare_pass_anchor_publication_requires_anchor_binding_purpose() {
        let operator = Keypair::generate();
        let pass = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);

        // An anchor-purpose binding carries Web3KeyBindingPurpose::Anchor and the
        // prepared publication binds it (prepare_root_publication admits it).
        let anchor = operator_binding(&operator, vec![Web3KeyBindingPurpose::Anchor]);
        assert!(anchor
            .certificate
            .purpose
            .contains(&Web3KeyBindingPurpose::Anchor));
        prepare_pass_anchor_publication(
            &operator,
            &anchor,
            &anchor_target(),
            std::slice::from_ref(&pass),
            &[],
            pending_witness(),
            MID_JUNE_2026,
            None,
        )
        .expect("anchor-purpose binding prepares");

        // A Settle-only binding (no Anchor purpose) is rejected fail-closed.
        let settle_only = operator_binding(&operator, vec![Web3KeyBindingPurpose::Settle]);
        let denied = prepare_pass_anchor_publication(
            &operator,
            &settle_only,
            &anchor_target(),
            &[pass],
            &[],
            pending_witness(),
            MID_JUNE_2026,
            None,
        );
        assert!(
            denied.is_err(),
            "a binding without the Anchor purpose must be rejected"
        );
    }

    // -- M1-20: mock ChioRootRegistry publishRoot + verifyInclusionDetailed ----
    //
    // A value-free, in-memory mirror of the on-chain `ChioRootRegistry`
    // (contracts/src/ChioRootRegistry.sol). It reproduces exactly the two calls
    // the read-only Pass-anchor round-trip needs:
    //
    //   * `publishRoot`: store the checkpoint's Merkle root under a per-operator
    //     STRICTLY-INCREASING `checkpointSeq` (the on-chain
    //     `if (checkpointSeq <= latestSeq[operator]) revert` rule), reject a zero
    //     root and a degenerate batch range, and record the root as published.
    //   * `verifyInclusionDetailed`: a read-only RFC6962 inclusion check that
    //     first gates on `publishedRoots[operator][root]` and only then verifies
    //     the audit path, mirroring the Solidity `verifyInclusionDetailed`.
    //
    // No method moves value: there is no balance, mint, or transfer surface here
    // (nor on the contract path these mirror); the round-trip is pure evidence.

    use std::collections::{HashMap, HashSet};

    /// Stored root entry, mirroring `IChioRootRegistry.RootEntry`.
    #[derive(Debug, Clone)]
    struct MockRootEntry {
        merkle_root: Hash,
        checkpoint_seq: u64,
        batch_start_seq: u64,
        batch_end_seq: u64,
        tree_size: u64,
        operator_key_hash: String,
    }

    /// The fail-closed reverts the mirrored `publishRoot` can raise (the
    /// Solidity `InvalidMerkleRoot` / `InvalidBatchRange` /
    /// `InvalidCheckpointSequence` reverts).
    #[derive(Debug, PartialEq, Eq)]
    enum MockRegistryError {
        ZeroMerkleRoot,
        DegenerateBatchRange,
        NonMonotonicCheckpointSeq,
    }

    /// In-memory mirror of the on-chain `ChioRootRegistry`. Value-free: it stores
    /// roots and runs the RFC6962 inclusion check exactly as the contract does,
    /// with no balance/mint/transfer surface anywhere.
    #[derive(Debug, Default)]
    struct MockChioRootRegistry {
        latest_seq: HashMap<String, u64>,
        roots: HashMap<String, HashMap<u64, MockRootEntry>>,
        published_roots: HashSet<(String, Hash)>,
    }

    impl MockChioRootRegistry {
        /// Mirror of `publishRoot`: fail-closed on a zero root or a degenerate
        /// batch range, enforce a strictly-increasing per-operator
        /// `checkpointSeq`, then store the entry and mark the root published.
        fn publish_root(
            &mut self,
            publication: &PreparedEvmRootPublication,
        ) -> Result<(), MockRegistryError> {
            if publication.merkle_root == Hash::zero() {
                return Err(MockRegistryError::ZeroMerkleRoot);
            }
            if publication.batch_start_seq > publication.batch_end_seq || publication.tree_size == 0
            {
                return Err(MockRegistryError::DegenerateBatchRange);
            }
            let operator = publication.operator_address.clone();
            let latest = self.latest_seq.get(&operator).copied().unwrap_or(0);
            if publication.checkpoint_seq <= latest {
                return Err(MockRegistryError::NonMonotonicCheckpointSeq);
            }
            let entry = MockRootEntry {
                merkle_root: publication.merkle_root,
                checkpoint_seq: publication.checkpoint_seq,
                batch_start_seq: publication.batch_start_seq,
                batch_end_seq: publication.batch_end_seq,
                tree_size: publication.tree_size,
                operator_key_hash: publication.operator_key_hash.clone(),
            };
            self.roots
                .entry(operator.clone())
                .or_default()
                .insert(publication.checkpoint_seq, entry);
            self.latest_seq
                .insert(operator.clone(), publication.checkpoint_seq);
            self.published_roots
                .insert((operator, publication.merkle_root));
            Ok(())
        }

        /// Mirror of `getLatestSeq`.
        fn latest_seq(&self, operator: &str) -> u64 {
            self.latest_seq.get(operator).copied().unwrap_or(0)
        }

        /// Mirror of `getRoot`.
        fn get_root(&self, operator: &str, checkpoint_seq: u64) -> Option<&MockRootEntry> {
            self.roots
                .get(operator)
                .and_then(|seqs| seqs.get(&checkpoint_seq))
        }

        /// Mirror of `verifyInclusionDetailed`: read-only. Returns false unless
        /// the root was published for `operator`, then runs the RFC6962 audit
        /// path. No value moves.
        fn verify_inclusion_detailed(
            &self,
            proof: &chio_core::merkle::MerkleProof,
            root: &Hash,
            leaf: Hash,
            operator: &str,
        ) -> bool {
            if !self
                .published_roots
                .contains(&(operator.to_string(), *root))
            {
                return false;
            }
            proof.verify_hash(leaf, root)
        }
    }

    #[test]
    fn mock_chio_root_registry_pass_anchor_publish_and_verify_inclusion_roundtrip() {
        use chio_core::is_supported_signed_artifact_schema;
        use chio_core::merkle::leaf_hash;
        use chio_core::signed_artifact::{
            CHIO_ANCHOR_BATCH_V1_SCHEMA, CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA,
            CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA,
        };

        let operator = Keypair::generate();
        let binding = operator_binding(&operator, vec![Web3KeyBindingPurpose::Anchor]);
        let target = anchor_target();

        // Anchored Pass set: two issued Passes plus one revoked Pass (whose
        // revocation digest is the committed Pass artifact id). A fourth Pass is
        // NEVER anchored; its id must fail the inclusion check.
        let pass_a = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);
        let pass_b = issue_first_window_pass(&Keypair::generate(), TrustTier::Verified);
        let pass_c = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);
        let revoked_c =
            revoke_chio_pass_record(&pass_c, MID_JUNE_2026 + 5, "superseded".to_string())
                .expect("revoke pass_c");
        let pass_excluded = issue_first_window_pass(&Keypair::generate(), TrustTier::Premier);

        let issued = [pass_a.clone(), pass_b.clone()];
        let revoked = [revoked_c.clone()];

        // (1) Build the anchor batch + strictly-increasing kernel checkpoints
        // under the Anchor-purpose binding. The kernel genesis checkpoint is
        // `checkpoint_seq` 1 (validate_checkpoint rejects seq 0), which the
        // on-chain registry accepts as the first published root (its `latestSeq`
        // defaults to 0); the seq-2 root chains onto it and seq-3 onto seq-2.
        let genesis = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &target,
            &issued,
            &revoked,
            pending_witness(),
            MID_JUNE_2026,
            None,
        )
        .expect("genesis prepare");
        assert_eq!(genesis.checkpoint.body.checkpoint_seq, 1);

        let published1 = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &target,
            &issued,
            &revoked,
            pending_witness(),
            MID_JUNE_2026 + 1,
            Some(&genesis.checkpoint),
        )
        .expect("seq-1 prepare");
        let published2 = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &target,
            &issued,
            &revoked,
            pending_witness(),
            MID_JUNE_2026 + 2,
            Some(&published1.checkpoint),
        )
        .expect("seq-2 prepare");
        assert_eq!(published1.publication.checkpoint_seq, 2);
        assert_eq!(published2.publication.checkpoint_seq, 3);
        assert!(published2.publication.checkpoint_seq > published1.publication.checkpoint_seq);
        assert_eq!(
            published1.publication.operator_address,
            target.operator_address
        );

        // (4) No NEW signed-artifact schema: the only signed artifact the
        // pipeline produces is the already-registered anchor batch
        // (`chio.anchor_batch.v1`). Its schema, and the two registered
        // anchor-family schemas the task names, are all known to this verifier
        // build; nothing here introduces a fresh schema id. The mock signs
        // nothing (it stores raw hashes only).
        assert_eq!(published1.batch.body.schema, CHIO_ANCHOR_BATCH_V1_SCHEMA);
        assert!(is_supported_signed_artifact_schema(
            &published1.batch.body.schema
        ));
        assert!(is_supported_signed_artifact_schema(
            CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA
        ));
        assert!(is_supported_signed_artifact_schema(
            CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA
        ));
        // The batch self-verifies read-only (root, every per-leaf proof, and the
        // signature) before any registry call; no on-chain value moves.
        verify_anchor_batch(&published1.batch).expect("anchor batch verifies");

        // (2) Publish into the mock registry. The genesis is now `checkpoint_seq`
        // 1, so it is the first published root; the seq-2 and seq-3 roots publish
        // in strictly-increasing order under the same monotonic rule the contract
        // enforces. NO value moves.
        let mut registry = MockChioRootRegistry::default();
        registry
            .publish_root(&genesis.publication)
            .expect("publish genesis seq-1 root");
        registry
            .publish_root(&published1.publication)
            .expect("publish seq-2 root");
        registry
            .publish_root(&published2.publication)
            .expect("publish seq-3 root");
        assert_eq!(registry.latest_seq(&target.operator_address), 3);
        // Re-publishing an already-anchored (now stale) seq fails closed.
        assert_eq!(
            registry.publish_root(&published1.publication),
            Err(MockRegistryError::NonMonotonicCheckpointSeq),
            "a stale checkpoint_seq must not re-publish"
        );

        // The stored entry mirrors the published checkpoint exactly.
        let stored = registry
            .get_root(&target.operator_address, 2)
            .expect("seq-2 entry stored");
        assert_eq!(stored.merkle_root, published1.publication.merkle_root);
        assert_eq!(stored.checkpoint_seq, 2);
        assert_eq!(
            stored.batch_start_seq,
            published1.publication.batch_start_seq
        );
        assert_eq!(stored.batch_end_seq, published1.publication.batch_end_seq);
        assert_eq!(stored.tree_size, published1.publication.tree_size);
        assert_eq!(
            stored.operator_key_hash,
            published1.publication.operator_key_hash
        );

        // Fail-closed parity with the contract reverts: a zero root and a
        // degenerate batch range are rejected (still value-free).
        let mut zero_root = published2.publication.clone();
        zero_root.checkpoint_seq = 4;
        zero_root.merkle_root = Hash::zero();
        assert_eq!(
            registry.publish_root(&zero_root),
            Err(MockRegistryError::ZeroMerkleRoot)
        );
        let mut bad_range = published2.publication.clone();
        bad_range.checkpoint_seq = 4;
        bad_range.batch_start_seq = 5;
        bad_range.batch_end_seq = 4;
        assert_eq!(
            registry.publish_root(&bad_range),
            Err(MockRegistryError::DegenerateBatchRange)
        );

        // (3) Prove single-Pass membership via verifyInclusionDetailed for each
        // anchored Pass id, against the published seq-2 root. Read-only.
        let root = published1.publication.merkle_root;
        assert_eq!(root, published1.batch.body.tree_root);
        let included_ids = [
            chio_pass_artifact_id(&pass_a).expect("pass_a id"),
            chio_pass_artifact_id(&pass_b).expect("pass_b id"),
            revoked_c.passport_id.clone(),
        ];
        assert_eq!(published1.batch.body.inclusions.len(), included_ids.len());
        for inclusion in &published1.batch.body.inclusions {
            assert!(
                registry.verify_inclusion_detailed(
                    &inclusion.proof,
                    &root,
                    inclusion.leaf_hash,
                    &target.operator_address,
                ),
                "anchored Pass id {} must verify inclusion",
                inclusion.checkpoint_id
            );
            assert!(included_ids.contains(&inclusion.checkpoint_id));
        }

        // A non-included Pass id FAILS: its leaf is not in the tree, so the
        // RFC6962 check rejects it even reusing a real (sibling) audit path.
        let excluded_id = chio_pass_artifact_id(&pass_excluded).expect("excluded id");
        assert!(!included_ids.contains(&excluded_id));
        let excluded_leaf =
            leaf_hash(&canonical_json_bytes(&excluded_id).expect("excluded leaf bytes"));
        assert!(
            !registry.verify_inclusion_detailed(
                &published1.batch.body.inclusions[0].proof,
                &root,
                excluded_leaf,
                &target.operator_address,
            ),
            "a non-anchored Pass id must fail the inclusion check"
        );

        // The published-root gate fails closed: a fully valid leaf + audit path
        // verified against a root that was NEVER published returns false.
        let unpublished = prepare_pass_anchor_publication(
            &operator,
            &binding,
            &target,
            std::slice::from_ref(&pass_excluded),
            &[],
            pending_witness(),
            MID_JUNE_2026 + 3,
            Some(&published2.checkpoint),
        )
        .expect("unpublished prepare");
        let unpublished_inclusion = &unpublished.batch.body.inclusions[0];
        assert!(
            unpublished_inclusion.proof.verify_hash(
                unpublished_inclusion.leaf_hash,
                &unpublished.batch.body.tree_root
            ),
            "the unpublished proof is internally valid"
        );
        assert!(
            !registry.verify_inclusion_detailed(
                &unpublished_inclusion.proof,
                &unpublished.batch.body.tree_root,
                unpublished_inclusion.leaf_hash,
                &target.operator_address,
            ),
            "an unpublished root must fail the inclusion gate"
        );

        // The per-operator gate fails closed: the published root verified under a
        // different operator address returns false.
        assert!(
            !registry.verify_inclusion_detailed(
                &published1.batch.body.inclusions[0].proof,
                &root,
                published1.batch.body.inclusions[0].leaf_hash,
                EVM_CONTRACT_ADDRESS,
            ),
            "a non-publishing operator must fail the inclusion gate"
        );
    }

    // -- M1-14: Gate 4 cross-tenant + byte-identity hardening ------------------

    /// Issue a first-window Pass for `subject` at `tier`, returning the full
    /// issuance (the soulbound Pass plus its minted window-scoped capability).
    fn issue_first_window_issuance(subject: &Keypair, tier: TrustTier) -> ChioPassIssuance {
        let issuer = Keypair::generate();
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let config = config_with_keys(vec![Keypair::generate().public_key()]);
        issue_chio_pass_command(
            &config,
            &authority,
            &issuer,
            &subject.public_key(),
            tier,
            MID_JUNE_2026,
            0,
            0,
        )
        .expect("issue first-window pass")
    }

    #[test]
    fn build_pass_scope_resource_grants_are_byte_identical_unverified_vs_premier() {
        // Own-data is a permanent baseline RIGHT, never TrustTier-gated. The SAME
        // subject minted at tier_0 (Unverified) and at Premier must produce a
        // byte-identical gifted ResourceGrant set; only the metered allotment
        // (window_units) is tier-sized.
        let subject = Keypair::generate();
        let did = DidChio::from_public_key(subject.public_key())
            .expect("did:chio")
            .to_string();

        let pass_tier0 = issue_first_window_pass(&subject, TrustTier::Unverified);
        let pass_premier = issue_first_window_pass(&subject, TrustTier::Premier);

        let scope_tier0 = build_pass_scope(&pass_tier0, &did).expect("tier0 scope");
        let scope_premier = build_pass_scope(&pass_premier, &did).expect("premier scope");

        // Five gifted grants, byte-identical across tiers.
        assert_eq!(scope_tier0.resource_grants.len(), 5);
        assert_eq!(scope_tier0.resource_grants, scope_premier.resource_grants);
        assert_eq!(
            serde_json::to_vec(&scope_tier0.resource_grants).expect("ser tier0"),
            serde_json::to_vec(&scope_premier.resource_grants).expect("ser premier"),
            "gifted ResourceGrant set must be byte-identical across tiers",
        );
        assert!(
            scope_tier0.prompt_grants.is_empty() && scope_premier.prompt_grants.is_empty(),
            "no prompt grants at any tier",
        );

        // The metered allotment IS tier-sized, proving tier still governs the
        // metered leg (1000 XCC for Unverified vs 5000 for Premier), just never the
        // baseline read right.
        let units_tier0 = scope_tier0.grants[0]
            .max_total_cost
            .as_ref()
            .expect("tier0 total")
            .units;
        let units_premier = scope_premier.grants[0]
            .max_total_cost
            .as_ref()
            .expect("premier total")
            .units;
        assert_eq!(units_tier0, 1000);
        assert_eq!(units_premier, 5000);
        assert_ne!(
            units_tier0, units_premier,
            "tier governs the metered allotment, not the gifted streams",
        );
    }

    #[test]
    fn cross_tenant_read_denied_by_uri_binding_and_sql_guard() {
        // Two distinct subjects => two distinct canonical did:chio tenants.
        let subject_a = Keypair::generate();
        let subject_b = Keypair::generate();
        let did_a = DidChio::from_public_key(subject_a.public_key())
            .expect("did a")
            .to_string();
        let did_b = DidChio::from_public_key(subject_b.public_key())
            .expect("did b")
            .to_string();
        assert_ne!(did_a, did_b);

        // Mint tenant A's Pass; its own-receipts grant binds tenant A only.
        let issuance_a = issue_first_window_issuance(&subject_a, TrustTier::Unverified);
        let cap_a = &issuance_a.capability;
        let own_pattern = pass_stream_uri(ChioPassStream::OwnReceipts, &did_a).expect("uri a");
        assert_eq!(own_pattern, format!("chio://receipts/tenant/{did_a}/*"));

        // -- Layer (a): the URI tenant binding denies, no store involved. --
        // A reads its OWN receipts/lineage.
        assert!(
            pass_authorizes_read(cap_a, &format!("chio://receipts/tenant/{did_a}/r1"))
                .expect("read own receipts")
        );
        assert!(
            pass_authorizes_read(cap_a, &format!("chio://lineage/tenant/{did_a}/n1"))
                .expect("read own lineage")
        );
        // A is DENIED tenant B's receipts/lineage purely by the capability/URI
        // binding (independent of any store).
        assert!(
            !pass_authorizes_read(cap_a, &format!("chio://receipts/tenant/{did_b}/r1"))
                .expect("deny B receipts")
        );
        assert!(
            !pass_authorizes_read(cap_a, &format!("chio://lineage/tenant/{did_b}/n1"))
                .expect("deny B lineage")
        );

        // -- Layer (b): the store no-widening SQL guard r.tenant_id = ?12 denies. --
        let path = unique_db_path("cross-tenant");
        let store = SqliteReceiptStore::open(&path).expect("open store");
        assert!(
            store.strict_tenant_isolation_enabled(),
            "strict tenant isolation must be on by default",
        );
        let kernel_kp = Keypair::generate();
        // Tenant B and tenant A each write one receipt into the SAME store.
        store
            .append_chio_receipt(&metered_receipt(
                &kernel_kp,
                "cap-b",
                &subject_b.public_key().to_hex(),
                &did_b,
                MID_JUNE_2026,
                Some(1),
                "rcpt-b",
            ))
            .expect("append B receipt");
        store
            .append_chio_receipt(&metered_receipt(
                &kernel_kp,
                "cap-a",
                &subject_a.public_key().to_hex(),
                &did_a,
                MID_JUNE_2026,
                Some(1),
                "rcpt-a",
            ))
            .expect("append A receipt");

        // A's own-receipts read context is tenant-scoped to did_a with no NULL
        // fallback: this is the second, independent denial behind the URI binding.
        let ctx_a = pass_receipt_read_context(&did_a).expect("ctx a");
        assert!(!ctx_a.include_null_tenant);
        let query_a = ReceiptQuery {
            limit: MAX_QUERY_LIMIT,
            tenant_filter: Some(did_a.clone()),
            read_context: Some(ctx_a),
            ..ReceiptQuery::default()
        };
        let page_a = store.query_receipts(&query_a).expect("query A");
        // Tenant B's row is physically present in the store, yet the SQL guard binds
        // ?12 = did_a so ONLY tenant A's row returns; tenant B's row is filtered out.
        assert_eq!(page_a.total_count, 1, "only tenant A's own row is visible");
        assert!(
            page_a
                .receipts
                .iter()
                .all(|r| r.receipt.tenant_id.as_deref() == Some(did_a.as_str())),
            "tenant A query must return only tenant A rows",
        );
        assert!(
            !page_a
                .receipts
                .iter()
                .any(|r| r.receipt.tenant_id.as_deref() == Some(did_b.as_str())),
            "the r.tenant_id = ?12 guard must hide tenant B's receipt from tenant A",
        );

        // And the read-context layer rejects any attempt to WIDEN tenant A's scope
        // to tenant B before SQL even runs: a Pass for A cannot form a B query.
        let widen_attempt = ReceiptQuery {
            limit: MAX_QUERY_LIMIT,
            tenant_filter: Some(did_b.clone()),
            read_context: Some(pass_receipt_read_context(&did_a).expect("ctx a")),
            ..ReceiptQuery::default()
        };
        let err = store
            .query_receipts(&widen_attempt)
            .expect_err("widening A's scope to B must fail closed");
        assert!(
            err.to_string().contains("cannot widen"),
            "no-widening guard must reject A->B widening, got: {err}",
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    // -- M2-18: sealed Chio Pass proof panel (read-only, recompute-bound) ------

    /// Prepare a Pass proof set of two issued Passes plus one revoked Pass (whose
    /// revocation digest is the committed Pass artifact id), so the panel has both
    /// issuance and revocation inclusion proofs to seal.
    fn prepared_two_issued_one_revoked() -> PreparedPassAnchorPublication {
        let operator = Keypair::generate();
        let pass_a = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);
        let pass_b = issue_first_window_pass(&Keypair::generate(), TrustTier::Verified);
        let pass_c = issue_first_window_pass(&Keypair::generate(), TrustTier::Attested);
        let revoked_c =
            revoke_chio_pass_record(&pass_c, MID_JUNE_2026 + 5, "superseded".to_string())
                .expect("revoke pass_c");
        let binding = operator_binding(&operator, vec![Web3KeyBindingPurpose::Anchor]);
        prepare_pass_anchor_publication(
            &operator,
            &binding,
            &anchor_target(),
            &[pass_a, pass_b],
            std::slice::from_ref(&revoked_c),
            pending_witness(),
            MID_JUNE_2026,
            None,
        )
        .expect("prepare two-issued one-revoked publication")
    }

    #[test]
    fn sealed_pass_proof_panel_recomputes_verdict_and_classifies_rows() {
        use chio_core::is_supported_signed_artifact_schema;

        let prepared = prepared_two_issued_one_revoked();
        let panel =
            SealedPassProofPanel::project(&prepared, &anchor_target()).expect("project panel");

        // The verdict is RECOMPUTED to Sealed for an untampered proof set.
        assert_eq!(panel.verdict(), &PassProofPanelVerdict::Sealed);
        assert!(panel.is_sealed(), "an untampered proof set seals");
        assert!(
            panel.verify_seal().expect("verify seal"),
            "seal self-consistent"
        );
        assert!(
            !panel.seal_digest().is_empty(),
            "the panel binds a seal digest"
        );

        // Rows are classified: two issuance proofs then one revocation proof, in the
        // anchored order, each with a recomputed inclusion proof.
        assert_eq!(panel.rows().len(), 3);
        assert_eq!(panel.issued_count(), 2);
        assert_eq!(panel.revoked_count(), 1);
        assert_eq!(panel.rows()[0].kind, PassProofKind::Issued);
        assert_eq!(panel.rows()[1].kind, PassProofKind::Issued);
        assert_eq!(panel.rows()[2].kind, PassProofKind::Revoked);
        for row in panel.rows() {
            assert!(
                row.inclusion_recomputed,
                "every anchored Pass digest re-walked to the recomputed root: {}",
                row.digest
            );
        }
        assert_eq!(
            panel
                .rows()
                .iter()
                .map(|row| row.digest.clone())
                .collect::<Vec<_>>(),
            prepared.anchored_digests,
            "panel rows mirror the anchored digest order",
        );

        // The independently recomputed root binds the batch, checkpoint, and
        // publication roots (the issuance/anchoring binding is part of the verdict).
        assert_eq!(panel.recomputed_root(), &prepared.batch.body.tree_root);
        assert_eq!(
            panel.recomputed_root(),
            &prepared.checkpoint.body.merkle_root
        );
        assert_eq!(panel.recomputed_root(), &prepared.publication.merkle_root);

        // The panel label is DISPLAY-ONLY: it is never a registered signed-artifact
        // schema (no new signed-artifact schema is introduced).
        assert!(
            !is_supported_signed_artifact_schema(CHIO_PASS_PROOF_PANEL_SCHEMA),
            "the panel schema must not be a signed-artifact schema",
        );
    }

    #[test]
    fn sealed_pass_proof_panel_tampered_proof_flips_verdict_fail_closed() {
        let clean_prepared = prepared_two_issued_one_revoked();
        let clean = SealedPassProofPanel::project(&clean_prepared, &anchor_target())
            .expect("project clean panel");
        assert!(clean.is_sealed());
        let clean_seal = clean.seal_digest().to_string();

        // A helper that asserts a tampered proof set seals to a Tampered verdict, with
        // a non-empty reason and a seal that differs from the clean reference.
        let assert_tampered = |tampered: &PreparedPassAnchorPublication, label: &str| {
            let panel = SealedPassProofPanel::project(tampered, &anchor_target())
                .expect("project tampered panel");
            assert!(
                !panel.is_sealed(),
                "tampered proof set must not seal ({label})"
            );
            match panel.verdict() {
                PassProofPanelVerdict::Tampered { reason } => {
                    assert!(!reason.is_empty(), "tamper reason present ({label})");
                }
                PassProofPanelVerdict::Sealed => {
                    panic!("tampered proof set sealed fail-open ({label})")
                }
            }
            assert_ne!(
                panel.seal_digest(),
                clean_seal,
                "the tampered seal must differ from the clean seal ({label})"
            );
            // The seal still faithfully commits the (tampered) recomputed verdict.
            assert!(panel.verify_seal().expect("verify tampered seal"));
        };

        // (a) Forged anchor batch tree root: the signed-batch recompute rejects it.
        let mut forged_root = prepared_two_issued_one_revoked();
        forged_root.batch.body.tree_root = Hash::zero();
        assert_tampered(&forged_root, "forged tree root");

        // (b) Misordered inclusion proofs: the per-leaf recompute rejects the swap.
        let mut swapped = prepared_two_issued_one_revoked();
        swapped.batch.body.inclusions.swap(0, 1);
        assert_tampered(&swapped, "swapped inclusions");

        // (c) A tampered anchored digest: the INDEPENDENT root recompute (not just the
        // signed batch) catches it, because the leaf no longer matches the tree.
        let mut bad_digest = prepared_two_issued_one_revoked();
        bad_digest.anchored_digests[0] = "chiopass:forged-digest".to_string();
        assert_tampered(&bad_digest, "tampered anchored digest");

        // (d) A checkpoint root that disagrees with the recomputed root: the
        // cross-checkpoint binding catches it even though the batch is intact.
        let mut bad_checkpoint = prepared_two_issued_one_revoked();
        bad_checkpoint.checkpoint.body.merkle_root = Hash::zero();
        assert_tampered(&bad_checkpoint, "checkpoint root mismatch");

        // (e) PR959 codex P2: an issued_count past the anchored digest count is
        // tampering. The old clamp silently absorbed it, re-labelled every row as
        // issued, hid the revocation rows, and still sealed (fail-open); the panel
        // now fails closed on a count it cannot support.
        let mut over_count = prepared_two_issued_one_revoked();
        over_count.issued_count = over_count.anchored_digests.len() + 1;
        assert_tampered(&over_count, "issued_count exceeds digest count");

        // (f) PR959 codex P2 (finding 5): a checkpoint whose SIGNED BODY was altered
        // (here `issued_at`) while its `merkle_root` stays fixed. The root
        // cross-check still matches the recomputed root, so the old panel sealed; the
        // panel now re-runs the kernel's own `validate_checkpoint`, whose signature
        // re-verification fails closed on the tampered body. `issued_at` is touched
        // by neither the root cross-check nor the call_data binding, so ONLY
        // `validate_checkpoint` catches it.
        let mut tampered_checkpoint = prepared_two_issued_one_revoked();
        tampered_checkpoint.checkpoint.body.issued_at ^= 1;
        assert_tampered(
            &tampered_checkpoint,
            "checkpoint body tampered, root unchanged",
        );

        // (g) PR959 codex P2 (finding 6): the publication's display `merkle_root`
        // still equals the recomputed root, but the broadcastable `call_data` is
        // swapped for a DIFFERENT prepared product's payload (a different root,
        // operator key hash, and digest set). The panel decodes the broadcast payload
        // and binds it to the checkpoint, so a call_data that would publish a
        // different root than the panel displays fails closed even though the display
        // root matches.
        let divergent = prepared_two_issued_one_revoked();
        let mut wrong_call_data = prepared_two_issued_one_revoked();
        wrong_call_data.publication.call_data = divergent.publication.call_data.clone();
        assert_tampered(&wrong_call_data, "call_data publishes a different root");

        // (h) PR959 codex P2 (re-review): the broadcast TARGET is tampered. The
        // ABI `call_data`, roots, sequence, and operator key all stay consistent
        // with the checkpoint, but `contract_address` (the `to` of the broadcast)
        // is repointed to a DIFFERENT contract. `publish_root` uses that mutable
        // field as the broadcast target, so without an envelope binding the panel
        // would seal a publication that never reaches the intended root registry.
        // The contract address lives outside the ABI payload and every signed
        // artifact, so only the bind-to-trusted-target check catches it.
        let mut wrong_target = prepared_two_issued_one_revoked();
        wrong_target.publication.contract_address =
            "0x000000000000000000000000000000000000dEaD".to_string();
        assert_tampered(
            &wrong_target,
            "publication broadcasts to a different contract",
        );

        // (i) PR959 codex P2 (re-review): the broadcast chain id is repointed.
        let mut wrong_chain = prepared_two_issued_one_revoked();
        wrong_chain.publication.chain_id = "0xdeadbeef".to_string();
        assert_tampered(&wrong_chain, "publication broadcasts to a different chain");
    }

    #[test]
    fn sealed_pass_proof_panel_is_read_only_and_deterministic() {
        // The panel projection borrows the proof set immutably and consults no
        // authority, keypair, capability, or store: its only input is a shared
        // reference to the already-produced prepared publication. It grants nothing
        // and mints nothing (there is no capability/token on the panel type).
        let prepared = prepared_two_issued_one_revoked();

        // Snapshot the observable proof set before projecting.
        let digests_before = prepared.anchored_digests.clone();
        let batch_root_before = prepared.batch.body.tree_root;
        let checkpoint_root_before = prepared.checkpoint.body.merkle_root;
        let publication_root_before = prepared.publication.merkle_root;
        let inclusions_before = prepared.batch.body.inclusions.len();

        let panel_one =
            SealedPassProofPanel::project(&prepared, &anchor_target()).expect("project once");
        let panel_two =
            SealedPassProofPanel::project(&prepared, &anchor_target()).expect("project twice");

        // Read-only: projecting did not mutate the prepared proof set.
        assert_eq!(prepared.anchored_digests, digests_before);
        assert_eq!(prepared.batch.body.tree_root, batch_root_before);
        assert_eq!(prepared.checkpoint.body.merkle_root, checkpoint_root_before);
        assert_eq!(prepared.publication.merkle_root, publication_root_before);
        assert_eq!(prepared.batch.body.inclusions.len(), inclusions_before);

        // Deterministic + pure: the same proof set always seals to the same panel.
        assert_eq!(panel_one, panel_two);
        assert_eq!(panel_one.seal_digest(), panel_two.seal_digest());
        assert!(panel_one.is_sealed());
    }
}
