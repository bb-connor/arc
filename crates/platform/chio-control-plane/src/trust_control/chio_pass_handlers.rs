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
    build_anchor_batch_body, prepare_root_publication, AnchorBatch, AnchorBatchWitness,
    EvmAnchorTarget, PreparedEvmRootPublication,
};
use chio_core::canonical_json_bytes;
use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::capability::token::{
    window_scoped_capability_id, AttestationWindowId, CapabilityToken,
};
use chio_core::crypto::{Keypair, PublicKey};
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
    build_checkpoint_with_previous, CapabilityAuthority, FreeTierPoolConfig, KernelCheckpoint,
    ReceiptQuery, ReceiptReadContext, MAX_QUERY_LIMIT,
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
///    (or `0` for the genesis batch), so the per-operator sequence strictly
///    increases and chains to the prior checkpoint body.
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
    let mut anchored_digests =
        Vec::with_capacity(issued_passes.len().saturating_add(revoked_records.len()));
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

    // 3. Wrap the batch root in a kernel checkpoint under a strictly-increasing
    // per-operator checkpoint_seq (genesis = 0), chaining to the prior checkpoint.
    let leaf_count = u64::try_from(leaves.len())
        .map_err(|_| CliError::Other("anchor leaf count overflow".to_string()))?;
    let checkpoint_seq =
        match previous_checkpoint {
            None => 0,
            Some(previous) => previous.body.checkpoint_seq.checked_add(1).ok_or_else(|| {
                CliError::Other("per-operator checkpoint_seq overflow".to_string())
            })?,
        };
    let checkpoint = build_checkpoint_with_previous(
        checkpoint_seq,
        0,
        leaf_count,
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

    // 4. Prepare (do NOT broadcast) the on-chain publishRoot call. This fails closed
    // unless the binding authorizes anchoring on the target chain for the operator.
    let publication = prepare_root_publication(target, &checkpoint, binding).map_err(|error| {
        CliError::Other(format!(
            "Pass anchor root publication prepare failed: {error}"
        ))
    })?;

    Ok(PreparedPassAnchorPublication {
        anchored_digests,
        batch,
        checkpoint,
        publication,
    })
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
    use chio_credentials::{revoke_chio_pass_record, CHIO_PASS_ALLOTMENT_COST_NAME};
    use chio_kernel::{LocalCapabilityAuthority, ReceiptStore};

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
            &[pass_a.clone()],
            &[revoked.clone()],
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
            &[pass.clone()],
            &[],
            pending_witness(),
            MID_JUNE_2026,
            None,
        )
        .expect("genesis anchor publication");
        assert_eq!(genesis.checkpoint.body.checkpoint_seq, 0);
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
        assert_eq!(next.checkpoint.body.checkpoint_seq, 1);
        assert_eq!(next.publication.checkpoint_seq, 1);
        // The next checkpoint chains to the prior checkpoint body (per-operator continuity).
        assert!(next.checkpoint.body.previous_checkpoint_sha256.is_some());
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
            &[pass.clone()],
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
}
