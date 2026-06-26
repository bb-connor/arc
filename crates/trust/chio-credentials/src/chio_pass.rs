// Chio Pass: a soulbound (non-transferable, non-redeemable) verifiable
// credential keyed to a single attested `did:chio`.
//
// NAMING (B-review): `ChioPass` is the soulbound free-tier credential and is
// DISTINCT from the existing `AgentPassport` / `PassportLifecycleRecord` bundle
// (the reputation-passport family). A `ChioPass` is a reputation credential, not
// an `AgentPassport` and not a transaction passport; do not conflate `ChioPass`
// with `ChioPassport`. The credential envelope (context/type/proof) mirrors
// `ReputationCredential` byte-for-byte so the same Ed25519 canonical-JSON
// (RFC 8785) signing and verification path applies.
//
// This module owns the credential FORMAT plus issuance, verification, and
// revocation (M0 task T4). The kernel data-stream gating (T5), aggregate pool
// admission (kernel), anti-farm distribution (T7), and the refresh-on-genuine-use
// receipt scan (T8) live in their own tasks/crates and are out of scope here.

/// VC `type` member identifying a Chio Pass credential.
pub const CHIO_PASS_TYPE: &str = "ChioPass";

/// Schema identifier for the Chio Pass credential family (a VC family, not a
/// signed-artifact-registry member, mirroring `chio.agent-passport.v1`).
pub const CHIO_PASS_SCHEMA: &str = "chio.pass.v1";

/// Allotment unit. `XCC` is a 3-uppercase-letter ISO-4217 private-use code that
/// is intentionally NOT priced by `chio-link::minor_units_for_currency`, so the
/// free-tier allotment never acquires a money leg.
pub const CHIO_PASS_ALLOTMENT_UNIT: &str = "XCC";

/// Metering `CostDimension::Custom` name written into served receipts so the
/// allotment debit stays off `total_monetary_cost` (summed only from `ApiCost`)
/// and the CONTROL 3 genuine-use scan can recognize it.
pub const CHIO_PASS_ALLOTMENT_COST_NAME: &str = "chio.pass.allotment.v1";

/// Per-invocation XCC cost (M0 default placeholder). A separate small positive
/// constant so `max_cost_per_invocation.units > 0` always holds and the pool
/// co-debit can never request zero units. Governance config (T9) may override
/// this; the floor is "> 0", not this exact value.
pub const CHIO_PASS_PER_INVOCATION_UNITS: u64 = 1;

/// Tier -> allotment-units table (Section 2.5). GOVERNANCE-PINNED config (not a
/// `const`), loaded fail-closed. The invariant every code path honors: the floor
/// applies unconditionally (a tier_0 newcomer gets a positive allotment); the
/// tier scales SIZE only, never existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TierAllotmentTable {
    pub unverified: u64,
    pub attested: u64,
    pub verified: u64,
    pub premier: u64,
}

impl Default for TierAllotmentTable {
    /// M0 default placeholder (Section 2.5). Needs board sign-off; surfaced as
    /// governance config under `ChioPassConfig` (T9), not a wire constant.
    fn default() -> Self {
        Self {
            unverified: 1000,
            attested: 1000,
            verified: 2500,
            premier: 5000,
        }
    }
}

/// The single tier-size lookup. Pinned `#[must_use]` so the result is never
/// silently dropped at a sizing site.
#[must_use]
pub fn allotment_units_for_tier(tier: TrustTier, table: &TierAllotmentTable) -> u64 {
    match tier {
        TrustTier::Unverified => table.unverified,
        TrustTier::Attested => table.attested,
        TrustTier::Verified => table.verified,
        TrustTier::Premier => table.premier,
    }
}

/// The five tier_0 baseline read URIs (Section 5.1): three aggregate trust feeds
/// plus the holder's OWN receipts and OWN lineage. The own-tenant patterns carry
/// the canonical `did:chio` with the MANDATORY `/` delimiter before the trailing
/// `*` so tenant `did:chioabcd` cannot prefix-match `did:chioabcde...`.
///
/// This is the SINGLE credential-layer builder both issuance and
/// [`validate_chio_pass_entitlements`] call against the canonical subject DID, so
/// `read_scopes` is bound to the canonical identity (closing the scope-binding
/// gap). The kernel data-stream gating (T5) builds the matching `ResourceGrant`
/// set against the same URI strings.
///
/// # Errors
///
/// Fails closed if `subject_did` is not a canonical `did:chio` identifier.
pub fn pass_baseline_read_uris(subject_did: &str) -> Result<Vec<String>, CredentialError> {
    let canonical = DidChio::from_str(subject_did)?.to_string();
    Ok(vec![
        "chio://trust/reputation/tier/*".to_string(),
        "chio://marketplace/listings*".to_string(),
        "chio://trust/pheromone/concentration/*".to_string(),
        format!("chio://receipts/tenant/{canonical}/*"),
        format!("chio://lineage/tenant/{canonical}/*"),
    ])
}

/// The metered XCC allotment a Pass grants for one attestation window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassAllotmentGrant {
    /// MUST equal [`CHIO_PASS_ALLOTMENT_UNIT`] (`"XCC"`).
    pub unit: String,
    /// Allotment SIZE for this window (tier-sized; `0` == withheld dormant).
    pub window_units: u64,
    /// Per-invocation XCC cost. MUST be `> 0` so the pool co-debit bounds spend.
    pub per_invocation_units: u64,
    /// MUST equal `window.until - window.since`.
    pub refill_cadence_secs: u64,
    /// Whether the next window's refresh is gated on genuine-use evidence.
    pub requires_genuine_use_refresh: bool,
}

/// The entitlements a Pass binds to its subject for one window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassEntitlements {
    /// Governs allotment SIZE/refill only, never the baseline read right.
    pub tier: TrustTier,
    /// MUST equal `pass_baseline_read_uris(credential_subject.id)`.
    pub read_scopes: Vec<String>,
    pub allotment: ChioPassAllotmentGrant,
    /// Canonical shared window (Section 2.1).
    pub window: AttestationWindowId,
}

/// Issuer-attested evidence captured at snapshot time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassEvidence {
    pub attested_tier: TrustTier,
    /// Reuses the existing `AttestationWindow`; `since` MUST be `Some(window.since)`.
    pub snapshot_window: AttestationWindow,
    /// Embedded output of the CONTROL 3 genuine-use scan.
    pub genuine_use_observed: bool,
}

/// The credential subject: a soulbound `did:chio` and its entitlements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioPassSubject {
    pub id: String,
    pub entitlements: ChioPassEntitlements,
}

/// The unsigned Chio Pass body (the canonical-JSON signing input). The flatten
/// target carries no `deny_unknown_fields`, matching `UnsignedReputationCredential`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedChioPass {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub schema: String,
    pub issuer: String,
    pub issuance_date: String,
    pub expiration_date: String,
    pub credential_subject: ChioPassSubject,
    pub evidence: ChioPassEvidence,
}

/// The signed Chio Pass credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPass {
    #[serde(flatten)]
    pub unsigned: UnsignedChioPass,
    pub proof: CredentialProof,
}

/// Build the entitlements + evidence snapshot for one window. Canonicalizes
/// `subject_did` FIRST, then derives the baseline read scopes and the allotment
/// size from the canonical DID and the governance table.
///
/// REFRESH-ON-GENUINE-USE (the sizing half, not the receipt scan): the allotment
/// is tier-sized on the first window or when genuine use was observed, otherwise
/// withheld at `0`. The baseline read scopes persist regardless.
///
/// # Errors
///
/// Fails closed on a malformed subject DID or a degenerate window.
pub fn snapshot_chio_pass_entitlements(
    subject_did: &str,
    attested_tier: TrustTier,
    window: &AttestationWindowId,
    is_first_window: bool,
    genuine_use_observed: bool,
    table: &TierAllotmentTable,
) -> Result<(ChioPassEntitlements, ChioPassEvidence), CredentialError> {
    window
        .validate()
        .map_err(|error| CredentialError::InvalidChioPassWindow(error.to_string()))?;
    let canonical = DidChio::from_str(subject_did)?.to_string();
    let read_scopes = pass_baseline_read_uris(&canonical)?;
    let refill_cadence_secs = window.until.checked_sub(window.since).ok_or_else(|| {
        CredentialError::InvalidChioPassWindow("until must be greater than since".to_string())
    })?;
    let observed = is_first_window || genuine_use_observed;
    let window_units = if observed {
        allotment_units_for_tier(attested_tier, table)
    } else {
        0
    };
    let entitlements = ChioPassEntitlements {
        tier: attested_tier,
        read_scopes,
        allotment: ChioPassAllotmentGrant {
            unit: CHIO_PASS_ALLOTMENT_UNIT.to_string(),
            window_units,
            per_invocation_units: CHIO_PASS_PER_INVOCATION_UNITS,
            refill_cadence_secs,
            requires_genuine_use_refresh: true,
        },
        window: window.clone(),
    };
    let evidence = ChioPassEvidence {
        attested_tier,
        snapshot_window: AttestationWindow {
            since: Some(window.since),
            until: window.until,
        },
        genuine_use_observed: observed,
    };
    Ok((entitlements, evidence))
}

/// Validate the entitlements + evidence against the canonical subject and the
/// governance table, fail-closed.
///
/// NOTE (resolved spec inconsistency): Section 3.3 writes the parameter list
/// without `evidence` and the verify entry point without `table`, yet the
/// refresh-verifiable rule (#5) reads `evidence.genuine_use_observed` and
/// recomputes the tier-sized allotment. Both inputs are therefore threaded so the
/// issuer-independent recomputation is actually verifiable.
pub fn validate_chio_pass_entitlements(
    entitlements: &ChioPassEntitlements,
    evidence: &ChioPassEvidence,
    issuance: u64,
    expiration: u64,
    subject_did: &str,
    table: &TierAllotmentTable,
) -> Result<(), CredentialError> {
    let allotment = &entitlements.allotment;
    if allotment.unit != CHIO_PASS_ALLOTMENT_UNIT {
        return Err(CredentialError::InvalidChioPassAllotmentGrant(format!(
            "allotment unit must be {CHIO_PASS_ALLOTMENT_UNIT}, got {}",
            allotment.unit
        )));
    }
    if allotment.per_invocation_units == 0 {
        return Err(CredentialError::InvalidChioPassAllotmentGrant(
            "per_invocation_units must be greater than zero".to_string(),
        ));
    }

    let window = &entitlements.window;
    if window.window_ym.is_empty() {
        return Err(CredentialError::InvalidChioPassWindow(
            "window_ym must not be empty".to_string(),
        ));
    }
    if window.since != issuance {
        return Err(CredentialError::InvalidChioPassWindow(
            "window.since must equal the issuance timestamp".to_string(),
        ));
    }
    if window.until != expiration {
        return Err(CredentialError::InvalidChioPassWindow(
            "window.until must equal the expiration timestamp".to_string(),
        ));
    }
    if window.since >= window.until {
        return Err(CredentialError::InvalidChioPassWindow(
            "window.since must be strictly before window.until".to_string(),
        ));
    }
    let expected_cadence = window.until.checked_sub(window.since).ok_or_else(|| {
        CredentialError::InvalidChioPassWindow("until must be greater than since".to_string())
    })?;
    if allotment.refill_cadence_secs != expected_cadence {
        return Err(CredentialError::InvalidChioPassAllotmentGrant(
            "refill_cadence_secs must equal window.until - window.since".to_string(),
        ));
    }

    let expected_scopes = pass_baseline_read_uris(subject_did)?;
    if entitlements.read_scopes != expected_scopes {
        return Err(CredentialError::InvalidChioPassAllotmentGrant(
            "read_scopes must equal the canonical baseline read URIs for the subject".to_string(),
        ));
    }

    if allotment.window_units > 0 {
        if !evidence.genuine_use_observed {
            return Err(CredentialError::InvalidChioPassAllotmentGrant(
                "a non-zero window_units requires genuine_use_observed".to_string(),
            ));
        }
        let expected_units = allotment_units_for_tier(entitlements.tier, table);
        if allotment.window_units != expected_units {
            return Err(CredentialError::InvalidChioPassAllotmentGrant(
                "window_units must equal the tier-sized allotment".to_string(),
            ));
        }
    }
    Ok(())
}

/// Issue a soulbound Chio Pass. Mirrors
/// `issue_reputation_credential_with_enterprise_identity`: the subject is
/// canonicalized via `DidChio::from_str`, the entitlements are validated
/// fail-closed, and the body is signed with Ed25519 over canonical JSON.
///
/// NOTE: `table` is threaded for the issuer-independent refresh check (see
/// [`validate_chio_pass_entitlements`]).
///
/// # Errors
///
/// Returns [`CredentialError::InvalidChioPassValidityWindow`] when
/// `issued_at > valid_until`, propagates DID / validation failures, and surfaces
/// any signing error.
pub fn issue_chio_pass(
    issuer_keypair: &Keypair,
    subject_did: &str,
    entitlements: ChioPassEntitlements,
    evidence: ChioPassEvidence,
    issued_at: u64,
    valid_until: u64,
    table: &TierAllotmentTable,
) -> Result<ChioPass, CredentialError> {
    if issued_at > valid_until {
        return Err(CredentialError::InvalidChioPassValidityWindow);
    }
    let issuer = DidChio::from_public_key(issuer_keypair.public_key())?;
    let subject = DidChio::from_str(subject_did)?.to_string();
    validate_chio_pass_entitlements(
        &entitlements,
        &evidence,
        issued_at,
        valid_until,
        &subject,
        table,
    )?;

    let unsigned = UnsignedChioPass {
        context: vec![
            VC_CONTEXT_V1.to_string(),
            CHIO_CREDENTIAL_CONTEXT_V1.to_string(),
        ],
        credential_type: vec![VC_TYPE.to_string(), CHIO_PASS_TYPE.to_string()],
        schema: CHIO_PASS_SCHEMA.to_string(),
        issuer: issuer.to_string(),
        issuance_date: rfc3339_from_unix(issued_at)?,
        expiration_date: rfc3339_from_unix(valid_until)?,
        credential_subject: ChioPassSubject {
            id: subject,
            entitlements,
        },
        evidence,
    };

    let (signature, _) = issuer_keypair.sign_canonical(&unsigned)?;
    Ok(ChioPass {
        unsigned,
        proof: CredentialProof {
            proof_type: PROOF_TYPE.to_string(),
            created: rfc3339_from_unix(issued_at)?,
            proof_purpose: PROOF_PURPOSE.to_string(),
            verification_method: issuer.verification_method_id(),
            proof_value: signature.to_hex(),
        },
    })
}

/// Verify a Chio Pass: schema, proof envelope, issuer binding, validity window,
/// half-open expiry, entitlement integrity, and the Ed25519 signature.
///
/// Expiry is HALF-OPEN to match the capability token's `validate_time` (B11):
/// `now >= expiration` is expired because `until` is the start of the next
/// window. Signature verification runs last over `canonical_json_bytes(&unsigned)`.
///
/// # Errors
///
/// Returns the specific [`CredentialError`] for the first failing check.
pub fn verify_chio_pass(
    pass: &ChioPass,
    now: u64,
    table: &TierAllotmentTable,
) -> Result<(), CredentialError> {
    if pass.unsigned.schema != CHIO_PASS_SCHEMA {
        return Err(CredentialError::InvalidChioPassSchema);
    }
    if pass.proof.proof_type != PROOF_TYPE {
        return Err(CredentialError::InvalidProofType);
    }
    if pass.proof.proof_purpose != PROOF_PURPOSE {
        return Err(CredentialError::InvalidProofPurpose);
    }
    let issuer = DidChio::from_str(&pass.unsigned.issuer)?;
    if pass.proof.verification_method != issuer.verification_method_id() {
        return Err(CredentialError::IssuerVerificationMethodMismatch);
    }

    let issuance = unix_from_rfc3339(&pass.unsigned.issuance_date)?;
    let expiration = unix_from_rfc3339(&pass.unsigned.expiration_date)?;
    if issuance > expiration {
        return Err(CredentialError::InvalidChioPassValidityWindow);
    }
    if now >= expiration {
        return Err(CredentialError::ChioPassExpired);
    }

    validate_chio_pass_entitlements(
        &pass.unsigned.credential_subject.entitlements,
        &pass.unsigned.evidence,
        issuance,
        expiration,
        &pass.unsigned.credential_subject.id,
        table,
    )?;

    let signature = Signature::from_hex(&pass.proof.proof_value)?;
    let verified = issuer
        .public_key()
        .verify(&canonical_json_bytes(&pass.unsigned)?, &signature);
    if !verified {
        return Err(CredentialError::InvalidCredentialSignature);
    }
    Ok(())
}

/// Enforce soulbinding: the presenting holder key MUST derive
/// `credential_subject.id`. A non-Ed25519 holder key is rejected by
/// `DidChio::from_public_key`.
///
/// # Errors
///
/// Returns [`CredentialError::PresentationHolderMismatch`] when the derived DID
/// does not match the subject.
pub fn verify_chio_pass_holder_binding(
    pass: &ChioPass,
    holder_public_key: PublicKey,
) -> Result<(), CredentialError> {
    let holder_did = DidChio::from_public_key(holder_public_key)?.to_string();
    if holder_did != pass.unsigned.credential_subject.id {
        return Err(CredentialError::PresentationHolderMismatch);
    }
    Ok(())
}

/// The anchor leaf / lifecycle key: `sha256_hex(canonical_json_bytes(pass))` over
/// the FULL signed Pass (mirrors `passport_artifact_id`).
///
/// # Errors
///
/// Propagates canonical-JSON serialization failures.
pub fn chio_pass_artifact_id(pass: &ChioPass) -> Result<String, CredentialError> {
    Ok(sha256_hex(&canonical_json_bytes(pass)?))
}

/// Build the revocation lifecycle record for a Pass. Rejects `revoked_at == 0`
/// up front, then constructs a `Revoked` [`PassportLifecycleRecord`] keyed by the
/// Pass artifact id and runs `record.validate()`. The caller emits the
/// `PassportRevocationEvent` via `record.to_revocation_event()`.
///
/// # Errors
///
/// Returns [`CredentialError::InvalidPassportLifecycle`] when `revoked_at == 0`
/// or the assembled record fails its own validation, and propagates artifact-id /
/// timestamp errors.
pub fn revoke_chio_pass_record(
    pass: &ChioPass,
    revoked_at: u64,
    revoked_reason: String,
) -> Result<PassportLifecycleRecord, CredentialError> {
    if revoked_at == 0 {
        return Err(CredentialError::InvalidPassportLifecycle(
            "chio pass revocation requires a non-zero revoked_at".to_string(),
        ));
    }
    let passport_id = chio_pass_artifact_id(pass)?;
    let published_at = unix_from_rfc3339(&pass.unsigned.issuance_date)?;
    let record = PassportLifecycleRecord {
        passport_id,
        subject: pass.unsigned.credential_subject.id.clone(),
        issuers: vec![pass.unsigned.issuer.clone()],
        issuer_count: 1,
        published_at,
        updated_at: revoked_at,
        status: PassportLifecycleState::Revoked,
        superseded_by: None,
        revoked_at: Some(revoked_at),
        revoked_reason: Some(revoked_reason),
        distribution: PassportStatusDistribution::default(),
        valid_until: pass.unsigned.expiration_date.clone(),
    };
    record.validate()?;
    Ok(record)
}

/// UTC calendar-month window containing `now`. Uses `DateTime::from_timestamp`
/// (no `TimeZone`-trait read of a wall clock). Fails closed on an out-of-range
/// timestamp or month overflow.
///
/// # Errors
///
/// Returns [`CredentialError::InvalidUnixTimestamp`] on any range failure.
pub fn attestation_window_containing(now: u64) -> Result<AttestationWindowId, CredentialError> {
    let secs = i64::try_from(now).map_err(|_| CredentialError::InvalidUnixTimestamp(now))?;
    let dt = DateTime::from_timestamp(secs, 0).ok_or(CredentialError::InvalidUnixTimestamp(now))?;
    let month_start_naive = dt
        .date_naive()
        .with_day(1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .ok_or(CredentialError::InvalidUnixTimestamp(now))?;
    let month_start = Utc.from_utc_datetime(&month_start_naive);
    let next_month = month_start
        .checked_add_months(Months::new(1))
        .ok_or(CredentialError::InvalidUnixTimestamp(now))?;
    let since =
        u64::try_from(month_start.timestamp()).map_err(|_| CredentialError::InvalidUnixTimestamp(now))?;
    let until =
        u64::try_from(next_month.timestamp()).map_err(|_| CredentialError::InvalidUnixTimestamp(now))?;
    Ok(AttestationWindowId {
        window_ym: month_start.format("%Y-%m").to_string(),
        since,
        until,
    })
}

/// Admission-boundary defense-in-depth: recompute the expected window-scoped id
/// from the token's OWN subject and its `issued_at`-aligned window, and reject any
/// mismatch. Robust to mint skew because it recomputes the window from
/// `token.issued_at` (pinned `== window.since`).
///
/// # Errors
///
/// Returns [`CredentialError::InvalidChioPassCapabilityBinding`] when the subject
/// key is not Ed25519, the expiry is not pinned to the window boundary, or the id
/// is not the canonical window-scoped id.
pub fn verify_window_scoped_capability_id(token: &CapabilityToken) -> Result<(), CredentialError> {
    let subject_did = DidChio::from_public_key(token.subject.clone())
        .map_err(|error| CredentialError::InvalidChioPassCapabilityBinding(error.to_string()))?
        .to_string();
    let window = attestation_window_containing(token.issued_at)?;
    if token.expires_at != window.until {
        return Err(CredentialError::InvalidChioPassCapabilityBinding(
            "Pass expiry is not pinned to its attestation-window boundary".to_string(),
        ));
    }
    let expected = window_scoped_capability_id(&subject_did, &window)
        .map_err(|error| CredentialError::InvalidChioPassCapabilityBinding(error.to_string()))?;
    if token.id != expected {
        return Err(CredentialError::InvalidChioPassCapabilityBinding(
            "Pass capability id is not the canonical window-scoped id".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod chio_pass_tests {
    use super::*;
    use chio_core::capability::scope::ChioScope;
    use chio_core::capability::token::CapabilityTokenBody;
    use chio_core::Keypair;

    // 2026-06-15T12:00:00Z, comfortably inside the June 2026 window.
    const MID_JUNE_2026: u64 = 1_781_524_800;
    // 2026-06-01T00:00:00Z and 2026-07-01T00:00:00Z.
    const JUNE_SINCE: u64 = 1_780_272_000;
    const JULY_SINCE: u64 = 1_782_864_000;

    fn june_window() -> AttestationWindowId {
        attestation_window_containing(MID_JUNE_2026).expect("window")
    }

    fn issued_pass(
        issuer: &Keypair,
        subject: &Keypair,
        window: &AttestationWindowId,
        table: &TierAllotmentTable,
    ) -> ChioPass {
        let subject_did = DidChio::from_public_key(subject.public_key())
            .expect("ed25519")
            .to_string();
        let (entitlements, evidence) = snapshot_chio_pass_entitlements(
            &subject_did,
            TrustTier::Attested,
            window,
            true,
            true,
            table,
        )
        .expect("snapshot");
        issue_chio_pass(
            issuer,
            &subject_did,
            entitlements,
            evidence,
            window.since,
            window.until,
            table,
        )
        .expect("issue")
    }

    #[test]
    fn attestation_window_containing_produces_june_window() {
        let window = june_window();
        assert_eq!(window.window_ym, "2026-06");
        assert_eq!(window.since, JUNE_SINCE);
        assert_eq!(window.until, JULY_SINCE);
        assert!(window.since <= MID_JUNE_2026 && MID_JUNE_2026 < window.until);
    }

    #[test]
    fn attestation_window_handles_december_and_leap_february() {
        // 2024-12-15 -> Dec window rolling into 2025-01.
        let december = attestation_window_containing(1_734_220_800).expect("december");
        assert_eq!(december.window_ym, "2024-12");
        assert_eq!(december.since, 1_733_011_200); // 2024-12-01T00:00:00Z
        assert_eq!(december.until, 1_735_689_600); // 2025-01-01T00:00:00Z
        // 2024-02-15 -> leap February rolling into 2024-03.
        let february = attestation_window_containing(1_708_000_000).expect("february");
        assert_eq!(february.window_ym, "2024-02");
        assert_eq!(february.since, 1_706_745_600); // 2024-02-01T00:00:00Z
        assert_eq!(february.until, 1_709_251_200); // 2024-03-01T00:00:00Z
    }

    #[test]
    fn issue_then_verify_round_trips_and_is_canonical_stable() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let table = TierAllotmentTable::default();
        let window = june_window();
        let pass = issued_pass(&issuer, &subject, &window, &table);

        assert!(verify_chio_pass(&pass, MID_JUNE_2026, &table).is_ok());

        // Identical issuance is byte-stable under RFC 8785 canonicalization.
        let second = issued_pass(&issuer, &subject, &window, &table);
        let first_bytes = canonical_json_bytes(&pass.unsigned).expect("canonical");
        let second_bytes = canonical_json_bytes(&second.unsigned).expect("canonical");
        assert_eq!(first_bytes, second_bytes);

        // Soulbinding: subject key matches, others do not.
        assert!(verify_chio_pass_holder_binding(&pass, subject.public_key()).is_ok());
        let stranger = Keypair::generate();
        assert!(matches!(
            verify_chio_pass_holder_binding(&pass, stranger.public_key()),
            Err(CredentialError::PresentationHolderMismatch)
        ));
    }

    #[test]
    fn verify_rejects_wrong_schema_and_tamper() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let table = TierAllotmentTable::default();
        let window = june_window();
        let pass = issued_pass(&issuer, &subject, &window, &table);

        let mut wrong_schema = pass.clone();
        wrong_schema.unsigned.schema = "chio.pass.v2".to_string();
        assert!(matches!(
            verify_chio_pass(&wrong_schema, MID_JUNE_2026, &table),
            Err(CredentialError::InvalidChioPassSchema)
        ));

        // Tamper the signed body without re-signing -> signature fails.
        let mut tampered = pass.clone();
        tampered
            .unsigned
            .credential_subject
            .entitlements
            .allotment
            .window_units = allotment_units_for_tier(TrustTier::Attested, &table) + 1;
        assert!(verify_chio_pass(&tampered, MID_JUNE_2026, &table).is_err());
    }

    #[test]
    fn verify_expiry_is_half_open() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let table = TierAllotmentTable::default();
        let window = june_window();
        let pass = issued_pass(&issuer, &subject, &window, &table);

        assert!(verify_chio_pass(&pass, window.until - 1, &table).is_ok());
        assert!(matches!(
            verify_chio_pass(&pass, window.until, &table),
            Err(CredentialError::ChioPassExpired)
        ));
    }

    #[test]
    fn validate_rejects_non_xcc_unit_and_zero_per_invocation() {
        let subject = Keypair::generate();
        let subject_did = DidChio::from_public_key(subject.public_key())
            .expect("ed25519")
            .to_string();
        let table = TierAllotmentTable::default();
        let window = june_window();
        let (entitlements, evidence) = snapshot_chio_pass_entitlements(
            &subject_did,
            TrustTier::Attested,
            &window,
            true,
            true,
            &table,
        )
        .expect("snapshot");

        let mut bad_unit = entitlements.clone();
        bad_unit.allotment.unit = "USD".to_string();
        assert!(matches!(
            validate_chio_pass_entitlements(
                &bad_unit,
                &evidence,
                window.since,
                window.until,
                &subject_did,
                &table
            ),
            Err(CredentialError::InvalidChioPassAllotmentGrant(_))
        ));

        let mut zero_per_invocation = entitlements;
        zero_per_invocation.allotment.per_invocation_units = 0;
        assert!(matches!(
            validate_chio_pass_entitlements(
                &zero_per_invocation,
                &evidence,
                window.since,
                window.until,
                &subject_did,
                &table
            ),
            Err(CredentialError::InvalidChioPassAllotmentGrant(_))
        ));
    }

    #[test]
    fn validate_rejects_read_scope_mismatch() {
        let subject = Keypair::generate();
        let subject_did = DidChio::from_public_key(subject.public_key())
            .expect("ed25519")
            .to_string();
        let table = TierAllotmentTable::default();
        let window = june_window();
        let (mut entitlements, evidence) = snapshot_chio_pass_entitlements(
            &subject_did,
            TrustTier::Attested,
            &window,
            true,
            true,
            &table,
        )
        .expect("snapshot");
        entitlements
            .read_scopes
            .push("chio://market/financials/*".to_string());
        assert!(matches!(
            validate_chio_pass_entitlements(
                &entitlements,
                &evidence,
                window.since,
                window.until,
                &subject_did,
                &table
            ),
            Err(CredentialError::InvalidChioPassAllotmentGrant(_))
        ));
    }

    #[test]
    fn validate_refresh_is_issuer_independently_checkable() {
        let subject = Keypair::generate();
        let subject_did = DidChio::from_public_key(subject.public_key())
            .expect("ed25519")
            .to_string();
        let table = TierAllotmentTable::default();
        let window = june_window();
        let (entitlements, _evidence) = snapshot_chio_pass_entitlements(
            &subject_did,
            TrustTier::Attested,
            &window,
            true,
            true,
            &table,
        )
        .expect("snapshot");

        // window_units > 0 but genuine_use_observed == false is rejected.
        let lying_evidence = ChioPassEvidence {
            attested_tier: TrustTier::Attested,
            snapshot_window: AttestationWindow {
                since: Some(window.since),
                until: window.until,
            },
            genuine_use_observed: false,
        };
        assert!(matches!(
            validate_chio_pass_entitlements(
                &entitlements,
                &lying_evidence,
                window.since,
                window.until,
                &subject_did,
                &table
            ),
            Err(CredentialError::InvalidChioPassAllotmentGrant(_))
        ));
    }

    #[test]
    fn tier_governs_size_not_existence() {
        let table = TierAllotmentTable::default();
        assert!(allotment_units_for_tier(TrustTier::Unverified, &table) > 0);
    }

    #[test]
    fn verify_window_scoped_capability_id_accepts_and_rejects() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let subject_did = DidChio::from_public_key(subject.public_key())
            .expect("ed25519")
            .to_string();
        let window = june_window();
        let id = window_scoped_capability_id(&subject_did, &window).expect("id");
        let body = CapabilityTokenBody {
            id,
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: window.since,
            expires_at: window.until,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &issuer).expect("sign");
        assert!(verify_window_scoped_capability_id(&token).is_ok());

        let mut wrong_id = token.clone();
        wrong_id.id = "chiopass:0000".to_string();
        assert!(matches!(
            verify_window_scoped_capability_id(&wrong_id),
            Err(CredentialError::InvalidChioPassCapabilityBinding(_))
        ));

        let mut wrong_expiry = token;
        wrong_expiry.expires_at = window.until + 1;
        assert!(matches!(
            verify_window_scoped_capability_id(&wrong_expiry),
            Err(CredentialError::InvalidChioPassCapabilityBinding(_))
        ));
    }

    #[test]
    fn revoke_builds_validatable_record_and_rejects_zero() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let table = TierAllotmentTable::default();
        let window = june_window();
        let pass = issued_pass(&issuer, &subject, &window, &table);

        let record =
            revoke_chio_pass_record(&pass, window.since + 10, "compromise".to_string()).expect("revoke");
        assert_eq!(record.status, PassportLifecycleState::Revoked);
        assert_eq!(
            record.passport_id,
            chio_pass_artifact_id(&pass).expect("artifact id")
        );
        record.validate().expect("record valid");
        let event = record.to_revocation_event().expect("event");
        let event = event.expect("revocation event present");
        assert_eq!(event.passport_id, record.passport_id);

        assert!(matches!(
            revoke_chio_pass_record(&pass, 0, "compromise".to_string()),
            Err(CredentialError::InvalidPassportLifecycle(_))
        ));
    }
}
