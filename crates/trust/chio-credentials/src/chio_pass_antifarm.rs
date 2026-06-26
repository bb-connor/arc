// Chio Pass anti-farm pure functions (M0 task T7, Section 6 "Anti-farm +
// distribution").
//
// These are STORAGE-FREE pure functions: the per-window population cap /
// admission throttle and the retroactive unpredictable snapshot selection. The
// receipt scan (T8) and the refresh/issuance orchestrator (T9) that feed live
// counts into these predicates live in the control plane and are out of scope
// here.
//
// PHASE-0 ANTI-FARM STACK (Section 1.2 / Section 6). M0 makes the free tier
// Sybil-bounded with NO money leg via five layers: soulbinding (the credential
// is keyed to a single attested `did:chio`, [`verify_chio_pass_holder_binding`]),
// the deterministic window-scoped capability id (CONTROL 2,
// [`verify_window_scoped_capability_id`]), refresh-on-genuine-use (CONTROL 3,
// the sizing half lives in [`snapshot_chio_pass_entitlements`]), the aggregate
// pool ceiling (CONTROL 1, in the kernel), and the admission throttle in THIS
// module. Tier governs allotment SIZE/refill only, never existence: the per-feed
// baseline floor is the already-shipped [`pass_baseline_read_uris`] and the
// tier->size table lookup is the already-shipped [`allotment_units_for_tier`]
// (NOT re-implemented here; the floor invariant is `Unverified > 0`, so a tier_0
// newcomer always receives the costly half).
//
// ISSUER-INDEPENDENCE BOUNDARY (M0 vs Phase 2, Section 6.5). M0 inherits the
// verified-weak, self-declared and optional
// `chio_federation::reputation::issuer_independence_group_id`
// (`chio-federation/reputation.rs:201`). It is cheap to forge, so M0 does NOT
// gate the COSTLY allotment on a real issuer-independence count: the
// bond-anchored independence fix is DEFERRED to Phase 2 (the escrow activation
// deposit is Phase 1). What M0 ships instead is the BOUND, not the fix: the
// aggregate pool ceiling (CONTROL 1) together with `window_token_capacity` and
// `active_population_cap` here cap total free-tier drain at the board-approved
// runway even under collusion. The federation
// `minimum_independent_issuers` clearing check
// (`chio-federation/reputation.rs:229`) remains the Phase-2 home for a real,
// non-self-declared independence threshold; this module deliberately does not
// duplicate or re-derive it.
//
// COMMERCE-ALIGNMENT POSTURE (CHIO-TOKEN-COMMERCE-ALIGNMENT). The attested
// [`ChioPassCandidate::tier`] and the snapshot/admission inputs bind to the
// shipped provider-admission substrate
// (`chio-trust-market-context::validate_reputation_import` plus the
// `ProviderDiscoverySnapshot -> ProviderSelectionReport -> TrustScorecardSnapshot`
// chain), not a `chio-reputation` + `chio-federation` re-derivation. Portable
// reputation CANNOT prove collateral or solvency, so the tier carried here
// governs allotment SIZE/refill only and is never a bond/coverage/premium
// signal; these pure functions therefore never read or assert capital.

/// Per-window admission policy for newly issued Passes. Mirrors the pheromone
/// admission contract (`chio_pheromone` `token_capacity`,
/// `chio-pheromone/lib.rs:409`; a zero capacity is rejected at
/// `validation.rs:393`; the saturation test `bucket_count >= token_capacity` is
/// at `validation.rs:201`). The cumulative active-Pass population cap is the
/// second leg that bounds the residual self-declared issuer-independence
/// weakness (Section 6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassAdmissionPolicy {
    /// UTC calendar-month label (`"%Y-%m"`) the policy applies to; the same
    /// string CONTROL 1/CONTROL 2 bind into the pool term and the capability id.
    pub window_ym: String,
    /// Maximum number of Passes that may be ISSUED in this window. Zero is
    /// rejected fail-closed (mirrors the pheromone zero-capacity rejection).
    pub window_token_capacity: u64,
    /// Maximum cumulative LIVE (non-revoked, non-expired) Pass population. Zero
    /// is rejected fail-closed.
    pub active_population_cap: u64,
}

/// Outcome of [`evaluate_pass_admission`]. Fail-closed: any non-`Admit` variant
/// denies issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChioPassAdmissionDecision {
    /// Both caps have headroom; the Pass may be issued.
    Admit,
    /// The per-window issuance cap (`window_token_capacity`) is reached.
    DenyWindowExhausted,
    /// The cumulative active-population cap (`active_population_cap`) is reached.
    DenyPopulationCapReached,
    /// The policy itself is invalid (a zero cap); rejected before any count is
    /// consulted.
    DenyPolicyInvalid,
}

/// Decide whether one more Pass may be admitted in the policy's window, given the
/// count already issued in the window and the current live population.
///
/// Fail-closed ordering, matching the pheromone admission contract: an invalid
/// policy (any zero cap) denies first, then the per-window issuance cap, then the
/// cumulative population cap. The comparison is `>=` (saturation), so a count
/// exactly AT a cap denies. Pure: depends only on its inputs.
#[must_use]
pub fn evaluate_pass_admission(
    policy: &ChioPassAdmissionPolicy,
    window_issued_count: u64,
    active_population: u64,
) -> ChioPassAdmissionDecision {
    if policy.window_token_capacity == 0 || policy.active_population_cap == 0 {
        return ChioPassAdmissionDecision::DenyPolicyInvalid;
    }
    if window_issued_count >= policy.window_token_capacity {
        return ChioPassAdmissionDecision::DenyWindowExhausted;
    }
    if active_population >= policy.active_population_cap {
        return ChioPassAdmissionDecision::DenyPopulationCapReached;
    }
    ChioPassAdmissionDecision::Admit
}

/// A Pass-issuance candidate captured by a retroactive snapshot. The `tier` is
/// the attested [`TrustTier`] reconciled from the provider-admission substrate
/// (Section 6.1); it governs the later allotment SIZE only and is never a
/// capital/solvency signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassCandidate {
    /// Canonical `did:chio` of the candidate subject (soulbinding target).
    pub subject_did: String,
    /// Attestation timestamp (unix seconds). Admission is oldest-first by this.
    pub attested_at_unix: u64,
    /// Attested coarse trust tier (governs allotment SIZE/refill only).
    pub tier: TrustTier,
}

/// A retroactive admission snapshot for one window. The `snapshot_unix` is NOT
/// pre-announced (operational unpredictability), so farmers cannot time
/// mass-registration; the SELECTION over a fixed snapshot is fully deterministic
/// for audit/anchoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassSnapshot {
    /// The (retroactive, unannounced) instant the snapshot was taken.
    pub snapshot_unix: u64,
    /// UTC calendar-month label (`"%Y-%m"`) the snapshot admits into.
    pub window_ym: String,
    /// Candidate set observed at `snapshot_unix`.
    pub candidates: Vec<ChioPassCandidate>,
}

/// Select the candidates to admit from a snapshot, oldest-attestation-first with
/// ties broken by `subject_did` lexicographic order, stopping on the FIRST
/// non-`Admit` decision (either cap, or an invalid policy).
///
/// Deterministic for audit/anchoring over a fixed snapshot; the unpredictability
/// is operational (the snapshot instant is not pre-announced). Saturating
/// arithmetic throughout: each admission advances both the window-issued count
/// and the live population by one (the new Pass joins the live set), so the two
/// caps are honored jointly. An invalid policy yields an empty selection.
#[must_use]
pub fn select_snapshot_admissions(
    snapshot: &ChioPassSnapshot,
    policy: &ChioPassAdmissionPolicy,
    starting_active_population: u64,
) -> Vec<ChioPassCandidate> {
    let mut ordered: Vec<&ChioPassCandidate> = snapshot.candidates.iter().collect();
    ordered.sort_by(|a, b| {
        a.attested_at_unix
            .cmp(&b.attested_at_unix)
            .then_with(|| a.subject_did.cmp(&b.subject_did))
    });

    let mut admitted: Vec<ChioPassCandidate> = Vec::new();
    let mut admitted_count: u64 = 0;
    for candidate in ordered {
        let active_population = starting_active_population.saturating_add(admitted_count);
        if evaluate_pass_admission(policy, admitted_count, active_population)
            != ChioPassAdmissionDecision::Admit
        {
            break;
        }
        admitted.push(candidate.clone());
        admitted_count = admitted_count.saturating_add(1);
    }
    admitted
}

#[cfg(test)]
mod chio_pass_antifarm_tests {
    use super::*;

    fn policy(window_token_capacity: u64, active_population_cap: u64) -> ChioPassAdmissionPolicy {
        ChioPassAdmissionPolicy {
            window_ym: "2026-06".to_string(),
            window_token_capacity,
            active_population_cap,
        }
    }

    fn candidate(subject_did: &str, attested_at_unix: u64, tier: TrustTier) -> ChioPassCandidate {
        ChioPassCandidate {
            subject_did: subject_did.to_string(),
            attested_at_unix,
            tier,
        }
    }

    #[test]
    fn admits_when_both_caps_have_headroom() {
        let policy = policy(100, 100);
        assert_eq!(
            evaluate_pass_admission(&policy, 0, 0),
            ChioPassAdmissionDecision::Admit
        );
        assert_eq!(
            evaluate_pass_admission(&policy, 99, 99),
            ChioPassAdmissionDecision::Admit
        );
    }

    #[test]
    fn denies_window_exhausted_at_and_over_capacity() {
        let policy = policy(10, 1000);
        // Exactly at the window cap denies (the comparison is `>=`).
        assert_eq!(
            evaluate_pass_admission(&policy, 10, 0),
            ChioPassAdmissionDecision::DenyWindowExhausted
        );
        // Over the window cap also denies.
        assert_eq!(
            evaluate_pass_admission(&policy, 11, 0),
            ChioPassAdmissionDecision::DenyWindowExhausted
        );
    }

    #[test]
    fn denies_population_cap_reached_at_and_over_capacity() {
        let policy = policy(1000, 10);
        assert_eq!(
            evaluate_pass_admission(&policy, 0, 10),
            ChioPassAdmissionDecision::DenyPopulationCapReached
        );
        assert_eq!(
            evaluate_pass_admission(&policy, 0, 50),
            ChioPassAdmissionDecision::DenyPopulationCapReached
        );
    }

    #[test]
    fn denies_policy_invalid_on_zero_caps() {
        // A zero window cap is rejected before any count is consulted.
        assert_eq!(
            evaluate_pass_admission(&policy(0, 100), 0, 0),
            ChioPassAdmissionDecision::DenyPolicyInvalid
        );
        // A zero population cap is rejected too.
        assert_eq!(
            evaluate_pass_admission(&policy(100, 0), 0, 0),
            ChioPassAdmissionDecision::DenyPolicyInvalid
        );
        // Policy-invalid wins even when a count would otherwise exhaust a cap.
        assert_eq!(
            evaluate_pass_admission(&policy(0, 0), 999, 999),
            ChioPassAdmissionDecision::DenyPolicyInvalid
        );
    }

    #[test]
    fn select_admits_oldest_first_and_stops_on_window_cap() {
        let snapshot = ChioPassSnapshot {
            snapshot_unix: 1_780_300_000,
            window_ym: "2026-06".to_string(),
            candidates: vec![
                candidate("did:chio:c", 300, TrustTier::Attested),
                candidate("did:chio:a", 100, TrustTier::Verified),
                candidate("did:chio:b", 200, TrustTier::Unverified),
                candidate("did:chio:d", 400, TrustTier::Premier),
            ],
        };
        // Room for exactly two admissions in the window.
        let admitted = select_snapshot_admissions(&snapshot, &policy(2, 1000), 0);
        assert_eq!(admitted.len(), 2);
        // Oldest attestation first: 100 then 200.
        assert_eq!(admitted[0].subject_did, "did:chio:a");
        assert_eq!(admitted[1].subject_did, "did:chio:b");
    }

    #[test]
    fn select_stops_on_population_cap() {
        let snapshot = ChioPassSnapshot {
            snapshot_unix: 1_780_300_000,
            window_ym: "2026-06".to_string(),
            candidates: vec![
                candidate("did:chio:a", 100, TrustTier::Attested),
                candidate("did:chio:b", 200, TrustTier::Attested),
                candidate("did:chio:c", 300, TrustTier::Attested),
            ],
        };
        // Window has plenty of room, but the live population is already at 9 of 10,
        // so only one more Pass may join the live set.
        let admitted = select_snapshot_admissions(&snapshot, &policy(1000, 10), 9);
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].subject_did, "did:chio:a");
    }

    #[test]
    fn select_is_deterministic_with_did_tie_break() {
        // Equal attestation timestamps: ties break on DID lexicographic order.
        let snapshot = ChioPassSnapshot {
            snapshot_unix: 1_780_300_000,
            window_ym: "2026-06".to_string(),
            candidates: vec![
                candidate("did:chio:zeta", 500, TrustTier::Attested),
                candidate("did:chio:alpha", 500, TrustTier::Attested),
                candidate("did:chio:mike", 500, TrustTier::Attested),
            ],
        };
        let policy = policy(1000, 1000);
        let first = select_snapshot_admissions(&snapshot, &policy, 0);
        let second = select_snapshot_admissions(&snapshot, &policy, 0);
        assert_eq!(first, second);
        let order: Vec<&str> = first.iter().map(|c| c.subject_did.as_str()).collect();
        assert_eq!(order, vec!["did:chio:alpha", "did:chio:mike", "did:chio:zeta"]);
    }

    #[test]
    fn select_returns_empty_on_invalid_policy() {
        let snapshot = ChioPassSnapshot {
            snapshot_unix: 1_780_300_000,
            window_ym: "2026-06".to_string(),
            candidates: vec![candidate("did:chio:a", 100, TrustTier::Attested)],
        };
        // A zero cap is an invalid policy and admits nobody (fail-closed).
        assert!(select_snapshot_admissions(&snapshot, &policy(0, 1000), 0).is_empty());
        assert!(select_snapshot_admissions(&snapshot, &policy(1000, 0), 0).is_empty());
    }
}
