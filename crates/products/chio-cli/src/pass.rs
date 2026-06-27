//! `chio pass` subcommand: the operable CLI entrypoint for the board-approved
//! Chio Pass control-plane orchestrator (task M1-11).
//!
//! The Chio Pass is a soulbound, PORTABLE REPUTATION CREDENTIAL (never a
//! passport): it gifts one attested `did:chio` a metered free-tier allotment plus
//! the baseline gifted-stream reads. This module is the thin CLI shell that loads
//! the single board-approved governance surface
//! ([`ChioPassConfig::m1_launch_default`]) and drives the three already-built
//! control-plane entrypoints end to end:
//!
//! - [`pass_issue`] mints the first-window credential and its deterministic
//!   `chiopass:<hash>` window-scoped capability.
//! - [`pass_refresh`] sizes the next monthly window from the prior window's
//!   genuine-use scan.
//! - [`pass_anchor`] prepares (does NOT broadcast) the read-only on-chain root
//!   publication over the issued and revoked Pass digests.
//!
//! Fail-closed posture (house rule): a missing or invalid config, a missing
//! revocation oracle, or a store IO fault returns an `Err` so NO Pass is minted;
//! nothing panics.

use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_anchor::{AnchorBatchWitness, EvmAnchorTarget};
use chio_core::capability::token::{window_scoped_capability_id, AttestationWindowId};
use chio_core::web3::identity::SignedWeb3IdentityBinding;
use chio_core::{Keypair, PublicKey};
use chio_did::DidChio;
use chio_credentials::{
    attestation_window_containing, chio_pass_artifact_id, verify_chio_pass, ChioPass,
    PassportLifecycleRecord, PassportLifecycleState, TierAllotmentTable, TrustTier,
};
use chio_kernel::{verify_checkpoint_signature, KernelCheckpoint, LocalCapabilityAuthority};
use chio_store_sqlite::{PassIssuanceAdmission, SqliteReceiptStore, SqliteRevocationStore};
use serde::de::DeserializeOwned;

use chio_control_plane::trust_control::chio_pass_handlers::{
    issue_chio_pass_command, prepare_pass_anchor_publication, refresh_chio_pass_window,
    ChioPassConfig, ChioPassIssuance, ChioPassRefreshResult, PreparedPassAnchorPublication,
};

use crate::{
    load_or_create_authority_keypair, require_receipt_db_path, require_revocation_db_path,
    CliError, PassCommands,
};

/// Default on-disk authority seed (mirrors `cmd_cert_generate`): the local Pass
/// authority both signs the soulbound credential and mints the window-scoped
/// capability when no explicit `--authority-seed-file` is supplied.
const DEFAULT_AUTHORITY_SEED_PATH: &str = ".chio-authority-seed";

/// The deterministic Pass capability-id prefix (`window_scoped_capability_id`).
const CHIO_PASS_CAPABILITY_PREFIX: &str = "chiopass:";

/// Bounded diagnostic scan of the revocation oracle's roster. The live
/// distribution counters do not depend on reading every revocation record (see
/// [`oracle_distribution_counters`]); this cap bounds the diagnostic roster size
/// surfaced in the issue report.
const PASS_ORACLE_ROSTER_SCAN_LIMIT: usize = 100_000;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Parse the coarse trust tier governing the allotment SIZE only (never
/// existence). Fail-closed: an unknown tier is rejected, never defaulted.
fn parse_trust_tier(value: &str) -> Result<TrustTier, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "unverified" | "tier0" | "tier_0" => Ok(TrustTier::Unverified),
        "attested" | "tier1" | "tier_1" => Ok(TrustTier::Attested),
        "verified" | "tier2" | "tier_2" => Ok(TrustTier::Verified),
        "premier" | "tier3" | "tier_3" => Ok(TrustTier::Premier),
        other => Err(CliError::Other(format!(
            "unknown trust tier '{other}'; expected unverified, attested, verified, or premier"
        ))),
    }
}

/// Resolve the pinned trusted-kernel-key allowlist the genuine-use scan consumes.
///
/// The launch allowlist is sourced from the trust-market market-authority
/// registry RR2-TM-01 and rotates per epoch, so the operator pins it with the
/// repeatable `--accepted-kernel-key <hex>` flag. Real keys are never hard-coded
/// into the binary.
///
/// FAIL-CLOSED: when no key is supplied the allowlist is rejected. The local Pass
/// authority key is NEVER defaulted into the genuine-use allowlist: doing so
/// would trust any locally-authored receipt as registry-backed kernel provenance
/// and let a self-minted receipt satisfy the refresh scan. The operator MUST pin
/// at least one registry-resolved market-authority key.
fn resolve_accepted_kernel_keys(
    accepted_kernel_keys_hex: &[String],
) -> Result<Vec<PublicKey>, CliError> {
    if accepted_kernel_keys_hex.is_empty() {
        return Err(CliError::Other(
            "Pass genuine-use allowlist is empty: pass at least one \
             --accepted-kernel-key resolved from the RR2-TM-01 market-authority \
             registry. The local authority key is never trusted as a kernel key."
                .to_string(),
        ));
    }
    accepted_kernel_keys_hex
        .iter()
        .map(|hex| PublicKey::from_hex(hex).map_err(CliError::from))
        .collect()
}

/// The per-window anti-farm distribution counters, sourced from the revocation
/// oracle the CLI already has.
struct PassDistributionCounters {
    /// Passes already issued in this window (anti-farm window cap leg).
    window_issued_count: u64,
    /// Cumulative live (non-revoked, non-expired) Pass population (population cap
    /// leg).
    active_population: u64,
    /// Diagnostic: the Pass-scoped entries the oracle currently has on its roster.
    revoked_pass_roster: u64,
}

/// Source the anti-farm distribution counters from the persisted issued-Pass
/// roster the revocation oracle (`--revocation-db`) carries, so
/// [`issue_chio_pass_command`] consumes real persisted state rather than a value
/// recomputed/defaulted at the entrypoint that a caller could understate.
///
/// The oracle persists BOTH the issued-Pass roster (entries) and the revoked set
/// (exits). The two anti-farm cap legs are sourced directly from that persisted
/// state:
///
/// - `window_issued_count`: the number of Passes persisted as issued in this
///   monthly window (the deterministic `chiopass:<hash>` id is the roster key, so
///   re-minting the same subject+window never inflates the count); and
/// - `active_population`: the number of issued Passes that have not expired and
///   are not revoked at `now`.
///
/// A fresh oracle yields `(0, 0)`, admitting the bootstrap issuance under cap; as
/// issuances accumulate the SAME store enforces both caps without changing the
/// entrypoint contract. CONTROL 1's aggregate pool ceiling remains the hard
/// liability bound regardless.
///
/// Fail-closed: a store IO fault propagates as `Err`, so no Pass is minted.
fn oracle_distribution_counters(
    oracle: &SqliteRevocationStore,
    window: &AttestationWindowId,
    now: u64,
) -> Result<PassDistributionCounters, CliError> {
    // Diagnostic revoked-Pass roster (fail-closed: an IO error denies).
    let revoked = oracle.list_revocations(PASS_ORACLE_ROSTER_SCAN_LIMIT, None)?;
    let revoked_pass_count = revoked
        .iter()
        .filter(|record| record.capability_id.starts_with(CHIO_PASS_CAPABILITY_PREFIX))
        .count();
    let revoked_pass_roster = u64::try_from(revoked_pass_count).unwrap_or(u64::MAX);

    // Both cap legs come from the persisted issued-Pass roster, never hard-coded.
    let now_secs = i64::try_from(now).unwrap_or(i64::MAX);
    let window_issued_count = oracle.count_window_issuances(&window.window_ym)?;
    let active_population = oracle.count_active_passes(now_secs)?;

    Ok(PassDistributionCounters {
        window_issued_count,
        active_population,
        revoked_pass_roster,
    })
}

/// Read and deserialize a canonical-JSON artifact, fail-closed on IO or parse.
fn read_json_artifact<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(CliError::from)
}

/// Write a signed Pass artifact to `path` as JSON, fail-closed on serialize or
/// IO. The written file round-trips back through [`read_json_artifact`] so the
/// issued-Pass artifact can be fed straight into `chio pass anchor`.
fn write_json_artifact<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn authority_seed_path(authority_seed_file: Option<&Path>) -> std::path::PathBuf {
    authority_seed_file.map_or_else(
        || std::path::PathBuf::from(DEFAULT_AUTHORITY_SEED_PATH),
        Path::to_path_buf,
    )
}

/// Mint the first-window Chio Pass end to end and return the issuance.
///
/// The minted `capability.id` is the deterministic `chiopass:<hash>` window-scoped
/// id derived purely from `(subject_did, window)`, so the SAME subject minted in
/// the SAME monthly window yields a BYTE-IDENTICAL id regardless of the issuing
/// authority key.
fn pass_issue(
    subject_public_key_hex: &str,
    tier: TrustTier,
    now: u64,
    revocation_db_path: &Path,
    authority_seed_file: Option<&Path>,
    accepted_kernel_keys_hex: &[String],
) -> Result<(ChioPassIssuance, PassDistributionCounters), CliError> {
    let subject_public_key = PublicKey::from_hex(subject_public_key_hex)?;

    // The local Pass authority both signs the credential and mints the capability.
    let seed_path = authority_seed_path(authority_seed_file);
    let authority_keypair = load_or_create_authority_keypair(&seed_path)?;
    let accepted_kernel_keys =
        resolve_accepted_kernel_keys(accepted_kernel_keys_hex)?;

    // The single board-approved M1 launch governance surface (validated
    // fail-closed inside the entrypoint).
    let config = ChioPassConfig::m1_launch_default(accepted_kernel_keys);
    let authority = LocalCapabilityAuthority::new(authority_keypair.clone());

    let oracle = SqliteRevocationStore::open(revocation_db_path)?;
    issue_chio_pass_under_caps(
        &config,
        &authority,
        &authority_keypair,
        &subject_public_key,
        tier,
        now,
        &oracle,
    )
}

/// Mint and persist a first-window Chio Pass under the anti-farm caps, sourcing the
/// distribution counters from the persisted issued-Pass roster (never recomputed).
///
/// IDEMPOTENT RE-ISSUE AT THE CAP: the deterministic `chiopass:<hash>` id is derived
/// from `(subject, window)` and looked up on the roster BEFORE the fast pre-mint
/// admission precheck. When the SAME subject/window is re-issued (e.g. to recover the
/// `--out-pass` / `--out-capability` artifacts) its id is ALREADY on the roster, so
/// re-recording it adds NO new population and the authoritative SQLite cap
/// transaction admits it even at a full cap. The pre-mint precheck counts the roster
/// EXCLUDING the row being (re-)inserted (matching the transaction's own semantics),
/// so for an already-present id we pass counts decremented by this subject's own
/// already-counted row; otherwise a legitimate re-issue exactly at the cap would be
/// wrongly denied by the precheck before the transaction could admit the no-growth
/// update. A genuinely NEW subject's id is absent, so its counts are passed unchanged
/// and the cap is enforced UNWEAKENED.
fn issue_chio_pass_under_caps(
    config: &ChioPassConfig,
    authority: &LocalCapabilityAuthority,
    authority_keypair: &Keypair,
    subject_public_key: &PublicKey,
    tier: TrustTier,
    now: u64,
    oracle: &SqliteRevocationStore,
) -> Result<(ChioPassIssuance, PassDistributionCounters), CliError> {
    // Read the counters BEFORE the mint so a NEW Pass is not counted against its own
    // cap.
    let window = attestation_window_containing(now)?;
    let counters = oracle_distribution_counters(oracle, &window, now)?;

    // Derive the deterministic roster key the mint will produce and detect an
    // idempotent re-issue. The id is subject+window derived (never authority
    // derived), so it matches the id `issue_chio_pass_command` mints below.
    let subject_did = DidChio::from_public_key(subject_public_key.clone())
        .map_err(|error| CliError::Other(error.to_string()))?
        .to_string();
    let deterministic_capability_id = window_scoped_capability_id(&subject_did, &window)
        .map_err(|error| CliError::Other(error.to_string()))?;
    let idempotent_reissue = oracle.pass_issuance_exists(&deterministic_capability_id)?;
    let (precheck_window_issued, precheck_active_population) = if idempotent_reissue {
        (
            counters.window_issued_count.saturating_sub(1),
            counters.active_population.saturating_sub(1),
        )
    } else {
        (counters.window_issued_count, counters.active_population)
    };

    let issuance = issue_chio_pass_command(
        config,
        authority,
        authority_keypair,
        subject_public_key,
        tier,
        now,
        precheck_window_issued,
        precheck_active_population,
    )?;

    // Atomically admit + persist the issuance under the anti-farm caps. The pre-mint
    // counters above are a fast pre-check; the AUTHORITATIVE admission is this single
    // SQLite transaction, which counts + checks + inserts atomically so two
    // concurrent `chio pass issue` runs (each with its own connection) cannot both
    // pass a stale read, both mint, and exceed the caps. It also admits an
    // already-present (idempotent) id with NO growth even at a full cap. Fail-closed:
    // a store IO fault or a cap-full denial returns Err; the credential was only
    // minted in-memory and is never surfaced. `valid_from` is the window start so the
    // live-population count never trusts a future-window row.
    let valid_from = i64::try_from(window.since).unwrap_or(0);
    let expires_at = i64::try_from(window.until).unwrap_or(i64::MAX);
    let now_secs = i64::try_from(now).unwrap_or(i64::MAX);
    match oracle.try_record_pass_issuance_under_caps(
        &issuance.capability.id,
        &window.window_ym,
        valid_from,
        expires_at,
        now_secs,
        config.window_token_capacity,
        config.active_population_cap,
    )? {
        PassIssuanceAdmission::Admitted => {}
        PassIssuanceAdmission::DeniedWindowExhausted => {
            return Err(CliError::Other(
                "Pass issuance denied: per-window distribution cap reached".to_string(),
            ));
        }
        PassIssuanceAdmission::DeniedPopulationCap => {
            return Err(CliError::Other(
                "Pass issuance denied: active population cap reached".to_string(),
            ));
        }
    }
    Ok((issuance, counters))
}

/// Verify a fresh rollover re-attestation presentation proof and derive the
/// re-attestation verdict from the verified result.
///
/// FAIL-CLOSED: the verdict is NEVER trusted from a bare flag. The supplied
/// presentation response MUST verify (nonce-bound and time-windowed), MUST be
/// answered against an EXTERNALLY supplied challenge (never only its own embedded
/// challenge), MUST be accepted by the verifier policy, and MUST be bound to the
/// refresh subject. Any failure denies, so the next-window Pass is never renewed
/// without a genuine, subject-bound re-attestation artifact.
fn verify_reattestation_proof(
    proof_path: &Path,
    challenge_path: Option<&Path>,
    subject_public_key: &PublicKey,
    now: u64,
) -> Result<bool, CliError> {
    // FAIL-CLOSED: a re-attestation proof MUST be pinned to an EXTERNALLY supplied
    // challenge. With no external challenge only the response's own embedded
    // (self-chosen) challenge is verified for freshness, so a holder could
    // self-generate a matching challenge+response and pass the gate. Require the
    // external challenge before any verdict is derived.
    let Some(challenge_path) = challenge_path else {
        return Err(CliError::Other(
            "re-attestation requires an externally supplied --reattestation-challenge: a proof \
             carrying only its own embedded challenge is self-issued and is not trusted"
                .to_string(),
        ));
    };
    let response: chio_credentials::PassportPresentationResponse = read_json_artifact(proof_path)?;
    let expected_challenge: chio_credentials::PassportPresentationChallenge =
        read_json_artifact(challenge_path)?;
    let verification = chio_credentials::verify_passport_presentation_response_with_policy(
        &response,
        Some(&expected_challenge),
        now,
        None,
        None,
    )
    .map_err(|error| {
        CliError::Other(format!(
            "re-attestation presentation proof failed to verify: {error}"
        ))
    })?;
    if !verification.accepted {
        return Err(CliError::Other(
            "re-attestation presentation proof did not pass the verifier policy".to_string(),
        ));
    }
    let expected_subject = DidChio::from_public_key(subject_public_key.clone())
        .map_err(|error| {
            CliError::Other(format!(
                "re-attestation subject DID derivation failed: {error}"
            ))
        })?
        .to_string();
    if verification.subject != expected_subject {
        return Err(CliError::Other(format!(
            "re-attestation proof subject {} does not match the refresh subject {}",
            verification.subject, expected_subject
        )));
    }
    Ok(true)
}

/// The early-span guard (seconds) at the START of an attestation window within
/// which the EXPIRING window a refresh renews is ambiguous from the wall clock
/// alone. A refresh fired inside this span (e.g. a rollover cron running just
/// after the month boundary) could mean "renew the window that just ended" OR
/// "renew the window that just opened", so the operator MUST pin the expiring
/// window explicitly with `--prior-window-at`. One day is comfortably larger than
/// any rollover-job skew yet far smaller than a monthly window, so an interior
/// refresh is never misclassified.
const REFRESH_ROLLOVER_GRACE_SECS: u64 = 86_400;

/// Derive the (expiring prior, minted next) attestation window pair for a refresh.
///
/// A refresh renews an EXPIRING Pass into the contiguous next monthly window. The
/// wall-clock `now` alone cannot identify the expiring window across a month
/// boundary: at the rollover instant AND just after it (e.g. 2026-07-01T00:00:01Z)
/// `now` already lands in the NEW window, so deriving the prior window from `now`
/// would scan the brand-new (empty) window and mint a month too far ahead (scan
/// July, mint August instead of scan June, mint July). The round-2 fix only handled
/// the exact instant `now == since`; a run one second later still mis-derived.
///
/// The expiring window is therefore pinned EXPLICITLY by `prior_window_at` (a unix
/// instant INSIDE the expiring Pass's window) whenever it is supplied; the minted
/// next window is its contiguous rollover. When it is omitted the prior window is
/// derived from `now` ONLY when `now` sits comfortably inside a window's interior
/// (past the `REFRESH_ROLLOVER_GRACE_SECS` early span); a run within that early
/// span fails closed and demands `--prior-window-at`, so the refresh never silently
/// scans the wrong window at the boundary.
fn refresh_windows(
    now: u64,
    prior_window_at: Option<u64>,
) -> Result<(AttestationWindowId, AttestationWindowId), CliError> {
    if let Some(prior_at) = prior_window_at {
        // Explicit: the operator pinned a timestamp inside the EXPIRING window, so
        // the expiring window is unambiguous regardless of the wall clock.
        let prior = attestation_window_containing(prior_at)?;
        let next = attestation_window_containing(prior.until)?;
        // FAIL-CLOSED: the explicit prior window MUST be the CURRENT or an
        // already-expiring window relative to `now`, never a FUTURE month. Pinning
        // a window that has not begun (e.g. a July instant while running in
        // mid-June) would scan the brand-new July window and mint/persist an August
        // Pass, silently reserving a future window with no genuine prior-window use
        // to renew. Require the prior window to have already started
        // (`prior.since <= now`); reject a future prior-window.
        if now < prior.since {
            return Err(CliError::Other(
                "refresh --prior-window-at points at a FUTURE window that has not begun relative \
                 to now: pin the CURRENT or expiring window being renewed, never a future month"
                    .to_string(),
            ));
        }
        // FAIL-CLOSED: the window being MINTED must not have already fully ended
        // before `now`. A prior window two-or-more months stale would mint an
        // already-expired next window (a dead Pass), and is not the
        // "current-or-expiring" window a renewal targets. Together with the bound
        // above this admits exactly the current window (mint the upcoming next) or
        // the just-ended window at a rollover (mint the current), and nothing else.
        if next.until <= now {
            return Err(CliError::Other(
                "refresh --prior-window-at points at a stale window whose renewal target has \
                 already ended: pin the CURRENT or expiring window being renewed"
                    .to_string(),
            ));
        }
        return Ok((prior, next));
    }
    let current = attestation_window_containing(now)?;
    // Fail closed inside the rollover early span: the expiring window is ambiguous
    // there (the just-ended window for a rollover cron, or the current window for an
    // interior refresh), so the operator MUST pin it with --prior-window-at.
    if now.saturating_sub(current.since) < REFRESH_ROLLOVER_GRACE_SECS {
        return Err(CliError::Other(
            "refresh near a window rollover is ambiguous: pass --prior-window-at with a unix \
             instant inside the EXPIRING window so the genuine-use scan targets the window being \
             renewed (not the brand-new window)"
                .to_string(),
        ));
    }
    // Interior: `now` is unambiguously inside the expiring window; mint the next.
    let next = attestation_window_containing(current.until)?;
    Ok((current, next))
}

/// Persist a renewed/dormant next-window issuance into the anti-farm roster
/// through the SAME atomic count/check/insert cap transaction `issue` uses, so a
/// refresh cannot fill the next window past the distribution or population caps
/// before any first-window `issue` denies (the round-2 refresh persisted via plain
/// `record_pass_issuance`, bypassing the caps). The deterministic next-window
/// `chiopass:<hash>` id is the roster key, so re-refreshing the SAME subject/window
/// is an idempotent re-record admitted even at the cap (it adds no population).
/// Fail-closed: a cap-full denial returns Err so the in-memory mint is discarded
/// and never surfaced.
fn record_refreshed_issuance_under_caps(
    oracle: &SqliteRevocationStore,
    capability_id: &str,
    next_window: &AttestationWindowId,
    window_token_capacity: u64,
    active_population_cap: u64,
) -> Result<(), CliError> {
    let valid_from = i64::try_from(next_window.since).unwrap_or(0);
    let expires_at = i64::try_from(next_window.until).unwrap_or(i64::MAX);
    // Count the active population at the WINDOW BEING FILLED, not the refresh wall
    // clock. A late-window refresh inserts a next-window row carrying
    // `valid_from = next_window.since`, which is in the FUTURE relative to the
    // refresh instant (`now < next_window.since`). Counting the population at `now`
    // would exclude every prior refresh into this SAME next window (their rows are
    // also future-dated), so the population cap would never bind and refresh could
    // over-admit past `active_population_cap`. Evaluating at `next_window.since`
    // counts exactly the Passes that become live at that boundary: the
    // next-window rows being filled are included (their `valid_from` equals it) and
    // the current-window rows have expired by then (`expires_at == next_window.since`,
    // half-open), so the cap reflects every Pass that goes live in the filled window.
    let population_eval_at = valid_from;
    match oracle.try_record_pass_issuance_under_caps(
        capability_id,
        &next_window.window_ym,
        valid_from,
        expires_at,
        population_eval_at,
        window_token_capacity,
        active_population_cap,
    )? {
        PassIssuanceAdmission::Admitted => Ok(()),
        PassIssuanceAdmission::DeniedWindowExhausted => Err(CliError::Other(
            "Pass refresh denied: next-window distribution cap reached".to_string(),
        )),
        PassIssuanceAdmission::DeniedPopulationCap => Err(CliError::Other(
            "Pass refresh denied: active population cap reached".to_string(),
        )),
    }
}

/// Roll a Pass forward into its next monthly window from the prior window's
/// genuine-use scan.
#[allow(clippy::too_many_arguments)]
fn pass_refresh(
    subject_public_key_hex: &str,
    tier: TrustTier,
    now: u64,
    prior_window_at: Option<u64>,
    reattested: bool,
    reattestation_proof: Option<&Path>,
    reattestation_challenge: Option<&Path>,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_seed_file: Option<&Path>,
    accepted_kernel_keys_hex: &[String],
) -> Result<ChioPassRefreshResult, CliError> {
    let subject_public_key = PublicKey::from_hex(subject_public_key_hex)?;
    let seed_path = authority_seed_path(authority_seed_file);
    let authority_keypair = load_or_create_authority_keypair(&seed_path)?;
    let accepted_kernel_keys =
        resolve_accepted_kernel_keys(accepted_kernel_keys_hex)?;
    let config = ChioPassConfig::m1_launch_default(accepted_kernel_keys);
    let authority = LocalCapabilityAuthority::new(authority_keypair.clone());

    // Derive the re-attestation verdict from a verified presentation proof, never
    // from the bare `--reattested` flag. A flag set without a verifying proof
    // fails closed so no next-window Pass is renewed without genuine,
    // subject-bound re-attestation provenance.
    let reattested_verdict = if let Some(proof_path) = reattestation_proof {
        verify_reattestation_proof(proof_path, reattestation_challenge, &subject_public_key, now)?
    } else if reattested {
        return Err(CliError::Other(
            "--reattested requires a verified --reattestation-proof presentation artifact; the \
             bare flag is not trusted as re-attestation provenance"
                .to_string(),
        ));
    } else {
        false
    };

    // The genuine-use scan reads the receipt store the CLI already has.
    let store = SqliteReceiptStore::open(receipt_db_path)?;
    // Derive the expiring (prior) and minted (next) windows. At/near a rollover the
    // wall-clock `now` cannot identify the expiring window, so it is pinned with
    // `prior_window_at` (fail-closed when omitted inside the rollover early span).
    let (prior_window, next_window) = refresh_windows(now, prior_window_at)?;

    let result = refresh_chio_pass_window(
        &config,
        &store,
        &authority,
        &authority_keypair,
        &subject_public_key,
        tier,
        &prior_window,
        &next_window,
        reattested_verdict,
    )?;

    // Persist any renewed/dormant next-window issuance into the anti-farm roster
    // through the SAME atomic cap transaction `issue` uses, so a refresh cannot
    // fill the next window past `window_token_capacity`/`active_population_cap`
    // before any first-window `issue` denies. The deterministic next-window
    // `chiopass:<hash>` id is the roster key, so this supersedes the prior window's
    // row (idempotent re-record) rather than inflating the population. Fail-closed:
    // a cap-full denial or store IO fault denies after the in-memory mint, which is
    // never surfaced.
    if let ChioPassRefreshResult::Renewed { issuance, .. }
    | ChioPassRefreshResult::Dormant { issuance, .. } = &result
    {
        let oracle = SqliteRevocationStore::open(revocation_db_path)?;
        record_refreshed_issuance_under_caps(
            &oracle,
            &issuance.capability.id,
            &next_window,
            config.window_token_capacity,
            config.active_population_cap,
        )?;
    }

    Ok(result)
}

/// Persist the refreshed, signed artifacts of a renewed/dormant refresh to the
/// requested output files, mirroring `issue`. A not-reattested refresh mints
/// nothing, so there is nothing to write. Fail-closed: an IO or serialization
/// fault denies.
fn write_refresh_artifacts(
    result: &ChioPassRefreshResult,
    out_pass: Option<&Path>,
    out_capability: Option<&Path>,
) -> Result<(), CliError> {
    let issuance = match result {
        ChioPassRefreshResult::Renewed { issuance, .. }
        | ChioPassRefreshResult::Dormant { issuance, .. } => issuance,
        ChioPassRefreshResult::NotReattested { .. } => return Ok(()),
    };
    if let Some(path) = out_pass {
        write_json_artifact(path, &issuance.pass)?;
    }
    if let Some(path) = out_capability {
        write_json_artifact(path, &issuance.capability)?;
    }
    Ok(())
}

/// Full Chio Pass shape + signature verification with the validity-window EXPIRY
/// check neutralized, for ANCHORING (historical membership evidence).
///
/// Anchoring an issued or revoked Pass commits HISTORICAL membership, so a Pass
/// from a just-ended window is legitimately past its expiry at the anchor
/// publication instant. The time-windowed [`verify_chio_pass`] would reject such a
/// Pass as expired (forcing operators to backdate `--issued-at`), while skipping
/// verification entirely would let a malformed-but-trusted-signed credential be
/// anchored. This mode threads the Pass's OWN issuance instant
/// (`entitlements.window.since`, which the entitlement-shape check binds to equal
/// the issuance timestamp and proves strictly less than the expiration) as `now`,
/// so the half-open expiry check (`now >= expiration`) never fires, while schema,
/// proof type/purpose, issuer binding, ENTITLEMENT SHAPE, and the Ed25519 signature
/// are ALL still enforced. A tampered, foreign-shaped, or otherwise malformed Pass
/// is still rejected. (If the Pass's embedded `window.since` is itself bogus the
/// entitlement-shape check that binds `window.since == issuance` denies it anyway.)
fn verify_anchored_pass_shape(pass: &ChioPass) -> Result<(), CliError> {
    // The launch entitlement-shape table the credential was minted against
    // (`ChioPassConfig::m1_launch_default` pins `TierAllotmentTable::default()`).
    let table = TierAllotmentTable::default();
    let issuance_instant = pass.unsigned.credential_subject.entitlements.window.since;
    verify_chio_pass(pass, issuance_instant, &table)
        .map_err(|error| CliError::Other(format!("Pass shape verification failed: {error}")))
}

/// Verify a revoked Pass's ORIGINAL signed credential is authentic, well-shaped,
/// and was issued by a trusted Pass authority, WITHOUT the time window.
///
/// FAIL-CLOSED: a revoked Pass is exactly the kind that may legitimately be
/// EXPIRED, so the time-windowed [`verify_chio_pass`] cannot be reused as-is (it
/// would reject the expired original). It is instead run through
/// [`verify_anchored_pass_shape`], the SAME full-shape verifier the issued side
/// uses (schema, proof type/purpose, issuer binding, entitlement shape, signature),
/// with only expiry neutralized. The prior revoked-leaf path checked just issuer
/// parsing, the proof method, the issuer allowlist, and the raw signature, so a
/// malformed-but-trusted-signed credential (e.g. a tampered proof envelope, which
/// the issuer signature does not cover) could be anchored as a revoked leaf though
/// it would be rejected as an issued leaf. The issuer is additionally bound to the
/// trusted-issuer set so a foreign/self-issued Pass can never mint a revoked leaf.
fn verify_revoked_pass_authenticity(
    pass: &ChioPass,
    trusted_issuer_dids: &[String],
) -> Result<(), CliError> {
    // Full shape + signature verification (expiry ignored), identical to the issued
    // side. Closes the gap where schema, proof type/purpose, and entitlement shape
    // were skipped for revoked leaves.
    verify_anchored_pass_shape(pass)?;
    // Round-3 trusted-issuer binding: `verify_chio_pass` only proves the Pass is
    // internally consistent against its OWN embedded issuer, not that the issuer is
    // a Pass authority this anchor batch trusts. A foreign/self-issued Pass can
    // never mint a revoked leaf.
    if !trusted_issuer_dids.contains(&pass.unsigned.issuer) {
        return Err(CliError::Other(format!(
            "revoked Pass issuer {} is not a trusted Pass authority for this anchor batch",
            pass.unsigned.issuer
        )));
    }
    Ok(())
}

/// Read and PROVE the revoked-Pass lifecycle records for an anchor batch.
///
/// FAIL-CLOSED: the anchor batch folds each record's `passport_id` directly into a
/// PUBLIC membership root as a revoked leaf, and the lifecycle record carries NO
/// signature of its own, so a structurally valid `Revoked` record with an arbitrary
/// `passport_id` could otherwise be published unproven. Each record is therefore
/// PAIRED BY POSITION with the ORIGINAL signed Pass it revokes: the original Pass
/// must verify against a trusted issuer, and the record's `passport_id` MUST equal
/// the recomputed [`chio_pass_artifact_id`] of that Pass. A hand-written record with
/// a fabricated `passport_id` is rejected because no genuine signed Pass recomputes
/// to it. Records must also be actually-revoked (`status == Revoked`).
fn read_revoked_records(
    revoked_record_paths: &[std::path::PathBuf],
    revoked_pass_paths: &[std::path::PathBuf],
    trusted_issuer_dids: &[String],
) -> Result<Vec<PassportLifecycleRecord>, CliError> {
    if revoked_record_paths.len() != revoked_pass_paths.len() {
        return Err(CliError::Other(format!(
            "each --revoked-record must be paired by position with the original --revoked-pass it \
             revokes: got {} records and {} passes",
            revoked_record_paths.len(),
            revoked_pass_paths.len()
        )));
    }
    revoked_record_paths
        .iter()
        .zip(revoked_pass_paths.iter())
        .map(|(record_path, pass_path)| {
            let record: PassportLifecycleRecord = read_json_artifact(record_path)?;
            record.validate().map_err(|error| {
                CliError::Other(format!(
                    "revoked Pass lifecycle record {} is invalid: {error}",
                    record_path.display()
                ))
            })?;
            if record.status != PassportLifecycleState::Revoked {
                return Err(CliError::Other(format!(
                    "revoked Pass anchor input {} is not a revoked lifecycle record (status: {}); \
                     only Revoked records may be anchored as revoked Pass digests",
                    record_path.display(),
                    record.status.label()
                )));
            }
            // Prove the revoked leaf against the ORIGINAL signed Pass it revokes.
            let pass: ChioPass = read_json_artifact(pass_path)?;
            verify_revoked_pass_authenticity(&pass, trusted_issuer_dids)?;
            let artifact_id = chio_pass_artifact_id(&pass).map_err(|error| {
                CliError::Other(format!(
                    "revoked Pass original {} artifact id could not be derived: {error}",
                    pass_path.display()
                ))
            })?;
            if artifact_id != record.passport_id {
                return Err(CliError::Other(format!(
                    "revoked Pass record {} passport_id does not match the original Pass artifact \
                     id from {}; the revoked leaf is unprovable",
                    record_path.display(),
                    pass_path.display()
                )));
            }
            // Defense in depth: the record's subject must name the same holder as
            // the proven original Pass.
            if record.subject != pass.unsigned.credential_subject.id {
                return Err(CliError::Other(format!(
                    "revoked Pass record {} subject does not match the original Pass subject",
                    record_path.display()
                )));
            }
            Ok(record)
        })
        .collect()
}

/// Build the set of Pass-issuer DIDs an anchor batch trusts. The operator key that
/// signs the batch is ALWAYS a trusted issuer (the self-anchoring case); any
/// explicitly pinned registry issuer DIDs are added too. Each supplied value is
/// validated as a `did:chio`, fail-closed.
fn resolve_trusted_pass_issuers(
    operator_public_key: &PublicKey,
    extra_issuer_dids: &[String],
) -> Result<Vec<String>, CliError> {
    let operator_did = DidChio::from_public_key(operator_public_key.clone())
        .map_err(|error| {
            CliError::Other(format!("operator issuer DID derivation failed: {error}"))
        })?
        .to_string();
    let mut trusted = vec![operator_did];
    for did in extra_issuer_dids {
        let parsed = DidChio::from_str(did)
            .map_err(|error| {
                CliError::Other(format!("invalid --trusted-pass-issuer DID {did}: {error}"))
            })?
            .to_string();
        if !trusted.contains(&parsed) {
            trusted.push(parsed);
        }
    }
    Ok(trusted)
}

/// Read and CRYPTOGRAPHICALLY verify the issued Chio Pass credentials for an
/// anchor batch.
///
/// FAIL-CLOSED: the anchor batch folds each Pass's `chio_pass_artifact_id` into a
/// PUBLIC membership root, so every issued-Pass file MUST carry a verifying issuer
/// signature AND a valid entitlement shape before its artifact id may be anchored.
/// An unsigned, tampered, or malformed Pass is rejected here, before it can reach
/// the public batch as membership evidence.
///
/// Anchoring is HISTORICAL membership evidence, so the validity-window EXPIRY check
/// is neutralized (see [`verify_anchored_pass_shape`]): an otherwise-valid issued
/// Pass from a just-ended window is accepted at rollover rather than rejected as
/// expired (which would force operators to backdate `--issued-at`). Every other
/// shape/signature invariant is still enforced.
///
/// The signature in [`verify_chio_pass`] only proves the Pass is internally
/// consistent against its OWN embedded issuer, not that the issuer is the operator
/// publishing the batch. Each Pass's issuer is therefore additionally bound to the
/// trusted-issuer set, so an operator cannot fold a foreign or self-issued Pass
/// into its membership root.
fn read_issued_passes(
    issued_pass_paths: &[std::path::PathBuf],
    trusted_issuer_dids: &[String],
) -> Result<Vec<ChioPass>, CliError> {
    issued_pass_paths
        .iter()
        .map(|path| {
            let pass: ChioPass = read_json_artifact(path)?;
            verify_anchored_pass_shape(&pass).map_err(|error| {
                CliError::Other(format!(
                    "issued Pass {} failed verification before anchoring: {error}",
                    path.display()
                ))
            })?;
            if !trusted_issuer_dids.contains(&pass.unsigned.issuer) {
                return Err(CliError::Other(format!(
                    "issued Pass {} was issued by {}, which is not a trusted Pass authority for \
                     this anchor batch; the operator may only anchor Passes it (or an explicitly \
                     pinned issuer) issued",
                    path.display(),
                    pass.unsigned.issuer
                )));
            }
            Ok(pass)
        })
        .collect()
}

/// Validate that a supplied previous checkpoint belongs to THIS operator and is
/// self-consistent before it chains the new per-operator sequence.
///
/// FAIL-CLOSED: the checkpoint builder only hashes the previous body and
/// increments the sequence, so without this gate the CLI could chain its
/// per-operator sequence to a foreign operator's checkpoint. Require the previous
/// checkpoint's `kernel_key` to equal this operator's key AND its signature to
/// verify.
fn validate_previous_checkpoint(
    previous: &KernelCheckpoint,
    operator_public_key: &PublicKey,
) -> Result<(), CliError> {
    if previous.body.kernel_key != *operator_public_key {
        return Err(CliError::Other(
            "previous checkpoint was signed by a different operator key; the per-operator \
             sequence chain may only extend this operator's own checkpoints"
                .to_string(),
        ));
    }
    match verify_checkpoint_signature(previous) {
        Ok(true) => Ok(()),
        Ok(false) => Err(CliError::Other(
            "previous checkpoint signature does not verify against its operator key".to_string(),
        )),
        Err(error) => Err(CliError::Other(format!(
            "previous checkpoint signature could not be verified: {error}"
        ))),
    }
}

/// Prepare (do NOT broadcast) the read-only Pass anchoring root publication.
#[allow(clippy::too_many_arguments)]
fn pass_anchor(
    issued_pass_paths: &[std::path::PathBuf],
    revoked_record_paths: &[std::path::PathBuf],
    revoked_pass_paths: &[std::path::PathBuf],
    trusted_pass_issuer_dids: &[String],
    binding_path: &Path,
    target_path: &Path,
    witness_path: &Path,
    issued_at: u64,
    previous_checkpoint_path: Option<&Path>,
    authority_seed_file: Option<&Path>,
) -> Result<PreparedPassAnchorPublication, CliError> {
    // The operator key signs the anchor batch and checkpoint.
    let seed_path = authority_seed_path(authority_seed_file);
    let operator_keypair = load_or_create_authority_keypair(&seed_path)?;

    let binding: SignedWeb3IdentityBinding = read_json_artifact(binding_path)?;
    let target: EvmAnchorTarget = read_json_artifact(target_path)?;
    let witness: AnchorBatchWitness = read_json_artifact(witness_path)?;

    // The operator key that signs this batch is always a trusted Pass issuer; any
    // explicitly pinned registry issuers are added too. Every issued and revoked
    // Pass folded into the public membership root MUST be issued by a member of
    // this set, so the operator cannot anchor foreign/self-issued Passes.
    let trusted_issuer_dids =
        resolve_trusted_pass_issuers(&operator_keypair.public_key(), trusted_pass_issuer_dids)?;

    // Verify each issued Pass's signature, entitlement shape, AND trusted issuer
    // BEFORE its artifact id is folded into the public anchor batch (fail-closed).
    // Expiry is ignored: anchoring is historical membership evidence, so a Pass from
    // a just-ended window is anchored rather than rejected as expired at rollover.
    let issued_passes = read_issued_passes(issued_pass_paths, &trusted_issuer_dids)?;
    // Each revoked leaf is PROVEN against the original signed Pass it revokes.
    let revoked_records =
        read_revoked_records(revoked_record_paths, revoked_pass_paths, &trusted_issuer_dids)?;

    let previous_checkpoint = previous_checkpoint_path
        .map(read_json_artifact::<KernelCheckpoint>)
        .transpose()?;
    if let Some(previous) = previous_checkpoint.as_ref() {
        validate_previous_checkpoint(previous, &operator_keypair.public_key())?;
    }

    prepare_pass_anchor_publication(
        &operator_keypair,
        &binding,
        &target,
        &issued_passes,
        &revoked_records,
        witness,
        issued_at,
        previous_checkpoint.as_ref(),
    )
}

fn write_report(report: &serde_json::Value, json_output: bool) -> Result<(), CliError> {
    let mut stdout = std::io::stdout();
    let bytes = if json_output {
        serde_json::to_vec_pretty(report)?
    } else {
        serde_json::to_vec(report)?
    };
    std::io::Write::write_all(&mut stdout, &bytes)
        .map_err(|error| CliError::Other(format!("pass report write: {error}")))?;
    std::io::Write::write_all(&mut stdout, b"\n")
        .map_err(|error| CliError::Other(format!("pass report write: {error}")))
}

fn window_json(window: &AttestationWindowId) -> serde_json::Value {
    serde_json::json!({
        "windowYm": window.window_ym,
        "since": window.since,
        "until": window.until,
    })
}

/// Dispatch the `chio pass` subcommand (issue / refresh / anchor).
pub(crate) fn dispatch_pass(
    command: PassCommands,
    json_output: bool,
    receipt_db: Option<&Path>,
    revocation_db: Option<&Path>,
    authority_seed_file: Option<&Path>,
) -> Result<(), CliError> {
    match command {
        PassCommands::Issue {
            subject_public_key,
            tier,
            now,
            accepted_kernel_key,
            out_pass,
            out_capability,
        } => {
            let tier = parse_trust_tier(&tier)?;
            let now = now.unwrap_or_else(unix_now);
            // Fail-closed: the revocation oracle is mandatory so the distribution
            // counters are sourced from persisted trust state, never invented.
            let revocation_db_path = require_revocation_db_path(revocation_db)?;
            let (issuance, counters) = pass_issue(
                &subject_public_key,
                tier,
                now,
                revocation_db_path,
                authority_seed_file,
                &accepted_kernel_key,
            )?;

            // Surface the minted, signed artifacts so the operator can present
            // the credential and feed the issued-Pass JSON into `chio pass
            // anchor`; optionally persist each to a requested file. Fail-closed:
            // an IO or serialization fault denies.
            if let Some(path) = out_pass.as_deref() {
                write_json_artifact(path, &issuance.pass)?;
            }
            if let Some(path) = out_capability.as_deref() {
                write_json_artifact(path, &issuance.capability)?;
            }
            let pass_value = serde_json::to_value(&issuance.pass)?;
            let capability_value = serde_json::to_value(&issuance.capability)?;
            let report = serde_json::json!({
                "schema": "chio.pass.issue.v1",
                "credential": "portable-reputation-credential",
                "capabilityId": issuance.capability.id,
                "window": window_json(&issuance.window),
                "windowIssuedCount": counters.window_issued_count,
                "activePopulation": counters.active_population,
                "revokedPassRoster": counters.revoked_pass_roster,
                "pass": pass_value,
                "capability": capability_value,
            });
            write_report(&report, json_output)
        }
        PassCommands::Refresh {
            subject_public_key,
            tier,
            now,
            prior_window_at,
            reattested,
            reattestation_proof,
            reattestation_challenge,
            accepted_kernel_key,
            out_pass,
            out_capability,
        } => {
            let tier = parse_trust_tier(&tier)?;
            let now = now.unwrap_or_else(unix_now);
            let receipt_db_path = require_receipt_db_path(receipt_db)?;
            // Fail-closed: the revocation oracle is mandatory so a renewed/dormant
            // next-window issuance is persisted into the anti-farm roster.
            let revocation_db_path = require_revocation_db_path(revocation_db)?;
            let result = pass_refresh(
                &subject_public_key,
                tier,
                now,
                prior_window_at,
                reattested,
                reattestation_proof.as_deref(),
                reattestation_challenge.as_deref(),
                receipt_db_path,
                revocation_db_path,
                authority_seed_file,
                &accepted_kernel_key,
            )?;

            // Surface the refreshed, signed artifacts (renewed/dormant outcomes)
            // so the operator can present the renewed credential and feed the
            // issued-Pass JSON into `chio pass anchor`, mirroring `issue`;
            // optionally persist each to a requested file.
            write_refresh_artifacts(&result, out_pass.as_deref(), out_capability.as_deref())?;

            let report = match &result {
                ChioPassRefreshResult::Renewed { decision, issuance } => serde_json::json!({
                    "schema": "chio.pass.refresh.v1",
                    "outcome": "renewed",
                    "capabilityId": issuance.capability.id,
                    "window": window_json(&issuance.window),
                    "nextAllotmentUnits": decision.next_allotment_units,
                    "pass": serde_json::to_value(&issuance.pass)?,
                    "capability": serde_json::to_value(&issuance.capability)?,
                }),
                ChioPassRefreshResult::Dormant { decision, issuance } => serde_json::json!({
                    "schema": "chio.pass.refresh.v1",
                    "outcome": "dormant",
                    "capabilityId": issuance.capability.id,
                    "window": window_json(&issuance.window),
                    "nextAllotmentUnits": decision.next_allotment_units,
                    "pass": serde_json::to_value(&issuance.pass)?,
                    "capability": serde_json::to_value(&issuance.capability)?,
                }),
                ChioPassRefreshResult::NotReattested { decision } => serde_json::json!({
                    "schema": "chio.pass.refresh.v1",
                    "outcome": "not-reattested",
                    "nextAllotmentUnits": decision.next_allotment_units,
                }),
            };
            write_report(&report, json_output)
        }
        PassCommands::Anchor {
            issued_pass,
            revoked_record,
            revoked_pass,
            trusted_pass_issuer,
            binding,
            target,
            witness,
            issued_at,
            previous_checkpoint,
            out_batch,
            out_checkpoint,
            out_publication,
        } => {
            let issued_at = issued_at.unwrap_or_else(unix_now);
            let prepared = pass_anchor(
                &issued_pass,
                &revoked_record,
                &revoked_pass,
                &trusted_pass_issuer,
                &binding,
                &target,
                &witness,
                issued_at,
                previous_checkpoint.as_deref(),
                authority_seed_file,
            )?;

            // Surface the prepared anchoring artifacts so CLI-only use can
            // broadcast the root and later verify inclusion against it. The
            // summary alone is not anchorable; optionally persist the signed
            // batch, the kernel checkpoint, and the prepared publication call
            // data. Fail-closed: an IO or serialization fault denies.
            if let Some(path) = out_batch.as_deref() {
                write_json_artifact(path, &prepared.batch)?;
            }
            if let Some(path) = out_checkpoint.as_deref() {
                write_json_artifact(path, &prepared.checkpoint)?;
            }
            if let Some(path) = out_publication.as_deref() {
                write_json_artifact(path, &prepared.publication)?;
            }
            let report = serde_json::json!({
                "schema": "chio.pass.anchor.v1",
                "anchoredDigests": prepared.anchored_digests,
                "treeRoot": prepared.batch.body.tree_root,
                "checkpointSeq": prepared.checkpoint.body.checkpoint_seq,
                "treeSize": prepared.publication.tree_size,
                "chainId": prepared.publication.chain_id,
                "operatorAddress": prepared.publication.operator_address,
            });
            write_report(&report, json_output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::Keypair;

    const MID_JUNE_2026: u64 = 1_781_524_800; // 2026-06-15T12:00:00Z

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("chio-pass-m1-11-{label}-{nonce}"));
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    /// `chio pass issue` mints a deterministic `chiopass:<hash>` capability id:
    /// the SAME subject minted inside the SAME monthly window yields a
    /// BYTE-IDENTICAL id, end to end through the control-plane entrypoint.
    #[test]
    fn pass_issue_mints_deterministic_chiopass_id() {
        let dir = temp_dir("deterministic");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");

        let subject = Keypair::generate();
        let subject_hex = subject.public_key().to_hex();
        // A registry-resolved kernel key must be pinned: the empty allowlist is
        // rejected fail-closed (the local authority key is never defaulted in).
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];

        let (first, counters) = pass_issue(
            &subject_hex,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("first issuance");
        let (second, _) = pass_issue(
            &subject_hex,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("second issuance");

        // The minted id is the deterministic window-scoped Pass id.
        assert!(
            first.capability.id.starts_with(CHIO_PASS_CAPABILITY_PREFIX),
            "minted id must be a chiopass:<hash> capability id, got {}",
            first.capability.id
        );
        // Same subject + same window => byte-identical id.
        assert_eq!(
            first.capability.id, second.capability.id,
            "same subject and window must mint a byte-identical chiopass id"
        );
        assert_eq!(first.window.window_ym, second.window.window_ym);

        // The empty bootstrap oracle yields under-cap counters that admit.
        assert_eq!(counters.window_issued_count, 0);
        assert_eq!(counters.active_population, 0);

        // The id is subject+window-derived, not authority-derived: a FRESH
        // authority key mints the byte-identical id for the same subject+window.
        let other_seed = dir.join("other-authority.seed");
        let (third, _) = pass_issue(
            &subject_hex,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(other_seed.as_path()),
            &kernel_keys,
        )
        .expect("third issuance under a fresh authority");
        assert_eq!(
            first.capability.id, third.capability.id,
            "the chiopass id depends only on subject and window, not the authority key"
        );

        // A different monthly window mints a DIFFERENT id for the same subject.
        let july_2026: u64 = 1_782_864_000; // 2026-07-01T00:00:00Z
        let (july, _) = pass_issue(
            &subject_hex,
            TrustTier::Attested,
            july_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("july issuance");
        assert_ne!(
            first.capability.id, july.capability.id,
            "a different attestation window must mint a different chiopass id"
        );
    }

    /// The anti-farm distribution counters are sourced from the persisted
    /// issued-Pass roster, never hard-coded at the entrypoint: a second distinct
    /// subject minted in the same window sees the first subject's issuance.
    #[test]
    fn pass_issue_counts_persisted_window_issuances() {
        let dir = temp_dir("counters");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];

        let subject_a = Keypair::generate().public_key().to_hex();
        let (_first, counters_a) = pass_issue(
            &subject_a,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("first issuance");
        // Bootstrap: an empty roster admits under cap.
        assert_eq!(counters_a.window_issued_count, 0);
        assert_eq!(counters_a.active_population, 0);

        // A DISTINCT subject minted in the SAME window observes the persisted
        // first issuance: the counters are no longer hard-coded 0.
        let subject_b = Keypair::generate().public_key().to_hex();
        let (_second, counters_b) = pass_issue(
            &subject_b,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("second issuance");
        assert_eq!(
            counters_b.window_issued_count, 1,
            "the per-window counter must reflect the persisted prior issuance"
        );
        assert_eq!(
            counters_b.active_population, 1,
            "the live-population counter must reflect the persisted prior issuance"
        );

        // Re-minting the SAME subject in the SAME window is idempotent (the
        // deterministic chiopass id is the roster key), so the window count holds.
        let (_again, counters_again) = pass_issue(
            &subject_a,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("idempotent re-issuance");
        assert_eq!(counters_again.window_issued_count, 2);
    }

    /// An idempotent re-issue of the SAME subject/window EXACTLY at the per-window
    /// cap succeeds (no roster growth), while a genuinely NEW subject at the cap is
    /// still denied. Regression: the fast pre-mint precheck must not deny an
    /// already-present id before the authoritative SQLite transaction can admit the
    /// no-growth idempotent update.
    #[test]
    fn idempotent_reissue_at_window_cap_succeeds_new_subject_denied() {
        let dir = temp_dir("at-cap-idempotent");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");
        let authority_keypair =
            load_or_create_authority_keypair(&authority_seed).expect("authority keypair");
        let authority = LocalCapabilityAuthority::new(authority_keypair.clone());
        let oracle = SqliteRevocationStore::open(&revocation_db).expect("revocation oracle");

        // A tiny per-window cap so a SINGLE issuance fills the window; the population
        // cap stays large so the WINDOW cap is the binding gate.
        let kernel_key = Keypair::generate().public_key();
        let mut config = ChioPassConfig::m1_launch_default(vec![kernel_key]);
        config.window_token_capacity = 1;

        let window_ym = attestation_window_containing(MID_JUNE_2026)
            .expect("attestation window")
            .window_ym;

        // First issuance fills the window to its cap of 1.
        let subject_a = Keypair::generate().public_key();
        let (first, _) = issue_chio_pass_under_caps(
            &config,
            &authority,
            &authority_keypair,
            &subject_a,
            TrustTier::Attested,
            MID_JUNE_2026,
            &oracle,
        )
        .expect("first issuance fills the window cap");
        assert_eq!(
            oracle.count_window_issuances(&window_ym).expect("count"),
            1
        );

        // Idempotent re-issue of the SAME subject AT the cap SUCCEEDS (no growth).
        let (again, _) = issue_chio_pass_under_caps(
            &config,
            &authority,
            &authority_keypair,
            &subject_a,
            TrustTier::Attested,
            MID_JUNE_2026,
            &oracle,
        )
        .expect("idempotent re-issue at the cap must succeed");
        assert_eq!(
            first.capability.id, again.capability.id,
            "the re-issue must mint the byte-identical deterministic id"
        );
        assert_eq!(
            oracle.count_window_issuances(&window_ym).expect("count"),
            1,
            "an idempotent re-issue must not grow the roster"
        );

        // A genuinely NEW subject at the cap is still DENIED (the cap is unweakened).
        let subject_b = Keypair::generate().public_key();
        let denied = issue_chio_pass_under_caps(
            &config,
            &authority,
            &authority_keypair,
            &subject_b,
            TrustTier::Attested,
            MID_JUNE_2026,
            &oracle,
        );
        assert!(
            denied.is_err(),
            "a new subject at the window cap must be denied"
        );
        assert_eq!(
            oracle.count_window_issuances(&window_ym).expect("count"),
            1,
            "a denied new subject must not be persisted"
        );
    }

    #[test]
    fn pass_issue_requires_revocation_oracle() {
        // Fail-closed: the issue dispatch denies when the revocation oracle flag
        // is absent, so the distribution counters can never be invented.
        let denied = dispatch_pass(
            PassCommands::Issue {
                subject_public_key: Keypair::generate().public_key().to_hex(),
                tier: "attested".to_string(),
                now: Some(MID_JUNE_2026),
                accepted_kernel_key: vec![],
                out_pass: None,
                out_capability: None,
            },
            true,
            None,
            None,
            None,
        );
        assert!(
            denied.is_err(),
            "issue must fail closed without a revocation oracle"
        );
    }

    /// `chio pass issue` surfaces the minted, signed artifacts: with --out-pass /
    /// --out-capability it writes files that round-trip back to a typed ChioPass
    /// and the window-scoped CapabilityToken, so the operator can present the
    /// credential and feed the issued-Pass JSON into `chio pass anchor`.
    #[test]
    fn pass_issue_writes_minted_artifacts_to_requested_files() {
        let dir = temp_dir("artifacts");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");
        let out_pass = dir.join("issued-pass.json");
        let out_capability = dir.join("capability.json");

        let subject = Keypair::generate().public_key().to_hex();
        let kernel_key = Keypair::generate().public_key().to_hex();

        dispatch_pass(
            PassCommands::Issue {
                subject_public_key: subject,
                tier: "attested".to_string(),
                now: Some(MID_JUNE_2026),
                accepted_kernel_key: vec![kernel_key],
                out_pass: Some(out_pass.clone()),
                out_capability: Some(out_capability.clone()),
            },
            true,
            None,
            Some(revocation_db.as_path()),
            Some(authority_seed.as_path()),
        )
        .expect("issue dispatch succeeds");

        // The minted credential round-trips back to a typed ChioPass (the
        // issued-Pass artifact `chio pass anchor` consumes).
        let pass_bytes = std::fs::read(&out_pass).expect("issued-pass file written");
        let _pass: ChioPass =
            serde_json::from_slice(&pass_bytes).expect("issued-pass deserializes as ChioPass");

        // The minted capability round-trips and carries the deterministic id.
        let capability_bytes = std::fs::read(&out_capability).expect("capability file written");
        let capability: serde_json::Value =
            serde_json::from_slice(&capability_bytes).expect("capability deserializes");
        assert!(capability["id"]
            .as_str()
            .is_some_and(|id| id.starts_with(CHIO_PASS_CAPABILITY_PREFIX)));
    }

    #[test]
    fn resolve_accepted_kernel_keys_fails_closed_without_explicit_key() {
        // FAIL-CLOSED: an empty allowlist is rejected; the local authority key is
        // never defaulted into the genuine-use trust anchor.
        let denied = resolve_accepted_kernel_keys(&[])
            .expect_err("empty accepted-kernel-key allowlist must be denied");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("--accepted-kernel-key")
        ));

        // A pinned registry-resolved key is accepted and parsed back.
        let key = Keypair::generate().public_key();
        let resolved =
            resolve_accepted_kernel_keys(&[key.to_hex()]).expect("explicit kernel key resolves");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].to_hex(), key.to_hex());

        // A malformed key is rejected, never defaulted.
        assert!(resolve_accepted_kernel_keys(&["not-a-key".to_string()]).is_err());
    }

    #[test]
    fn parse_trust_tier_rejects_unknown_fail_closed() {
        assert_eq!(
            parse_trust_tier("attested").expect("attested"),
            TrustTier::Attested
        );
        assert_eq!(
            parse_trust_tier("PREMIER").expect("premier"),
            TrustTier::Premier
        );
        assert!(parse_trust_tier("godmode").is_err());
    }

    /// Build a lifecycle record in `status`, shaped so `validate()` passes.
    fn lifecycle_record(status: PassportLifecycleState) -> PassportLifecycleRecord {
        let subject = DidChio::from_public_key(Keypair::generate().public_key())
            .expect("subject did")
            .to_string();
        let issuer = DidChio::from_public_key(Keypair::generate().public_key())
            .expect("issuer did")
            .to_string();
        let (revoked_at, revoked_reason) = if status == PassportLifecycleState::Revoked {
            (Some(1_781_500_000), Some("key-compromise".to_string()))
        } else {
            (None, None)
        };
        PassportLifecycleRecord {
            passport_id: "chiopass:deadbeefdeadbeef".to_string(),
            subject,
            issuers: vec![issuer],
            issuer_count: 1,
            published_at: 1_781_000_000,
            updated_at: 1_781_400_000,
            status,
            superseded_by: None,
            revoked_at,
            revoked_reason,
            distribution: Default::default(),
            valid_until: "2026-12-31T00:00:00Z".to_string(),
        }
    }

    /// 311 + Finding 5: only actually-revoked lifecycle records whose `passport_id`
    /// is PROVEN by the paired original signed Pass may be anchored as revoked
    /// digests. A genuine record verifies; a stale Active export, a hand-written
    /// record with a fabricated `passport_id`, and an unpaired record are all denied.
    #[test]
    fn read_revoked_records_proves_passport_id_and_status() {
        let dir = temp_dir("revoked-records");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");
        let subject = Keypair::generate().public_key().to_hex();
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];

        // A genuine signed Pass and its revocation record, keyed by the real
        // artifact id; the operator's own issuer DID is the trusted issuer.
        let (issuance, _) = pass_issue(
            &subject,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("issuance");
        let trusted = vec![issuance.pass.unsigned.issuer.clone()];
        let genuine_record = chio_credentials::revoke_chio_pass_record(
            &issuance.pass,
            1_781_600_000,
            "key-compromise".to_string(),
        )
        .expect("genuine revocation record");

        let record_path = dir.join("revoked.json");
        write_json_artifact(&record_path, &genuine_record).expect("write revoked record");
        let pass_path = dir.join("revoked-pass.json");
        write_json_artifact(&pass_path, &issuance.pass).expect("write revoked pass");

        // A proven revoked record (passport_id == artifact id of the paired Pass).
        let records = read_revoked_records(
            std::slice::from_ref(&record_path),
            std::slice::from_ref(&pass_path),
            &trusted,
        )
        .expect("a proven revoked record is accepted");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, PassportLifecycleState::Revoked);

        // Finding 5: a hand-written record with a FABRICATED passport_id, paired
        // with the genuine Pass, is rejected: no genuine signed Pass recomputes to
        // it, so the revoked leaf is unprovable.
        let mut fabricated = genuine_record.clone();
        fabricated.passport_id = "chiopass:deadbeefdeadbeefdeadbeefdeadbeef".to_string();
        let fabricated_path = dir.join("fabricated.json");
        write_json_artifact(&fabricated_path, &fabricated).expect("write fabricated record");
        let denied_fabricated =
            read_revoked_records(&[fabricated_path], std::slice::from_ref(&pass_path), &trusted)
                .expect_err("a fabricated passport_id is denied");
        assert!(matches!(
            denied_fabricated,
            CliError::Other(message)
                if message.contains("does not match the original Pass artifact id")
        ));

        // An Active record (paired with the genuine Pass) is denied on status.
        let active_path = dir.join("active.json");
        write_json_artifact(
            &active_path,
            &lifecycle_record(PassportLifecycleState::Active),
        )
        .expect("write active record");
        let denied_status =
            read_revoked_records(&[active_path], std::slice::from_ref(&pass_path), &trusted)
                .expect_err("a non-revoked record is denied");
        assert!(matches!(
            denied_status,
            CliError::Other(message) if message.contains("not a revoked lifecycle record")
        ));

        // Mismatched record/pass counts (an unpaired record) are denied: the leaf
        // cannot be proven without its original Pass.
        let denied_counts = read_revoked_records(&[record_path], &[], &trusted)
            .expect_err("an unpaired revoked record is denied");
        assert!(matches!(
            denied_counts,
            CliError::Other(message) if message.contains("paired by position")
        ));
    }

    /// 325: a supplied previous checkpoint must belong to THIS operator and carry
    /// a verifying signature before it chains the per-operator sequence.
    #[test]
    fn validate_previous_checkpoint_binds_to_operator() {
        let operator = Keypair::generate();
        let foreign = Keypair::generate();

        // This operator's own, well-signed checkpoint validates.
        let own = chio_kernel::build_checkpoint_with_previous(
            1,
            1,
            1,
            &[b"leaf".to_vec()],
            &operator,
            None,
        )
        .expect("build own checkpoint");
        validate_previous_checkpoint(&own, &operator.public_key())
            .expect("operator's own checkpoint validates");

        // A checkpoint signed by a DIFFERENT operator is denied.
        let foreign_cp = chio_kernel::build_checkpoint_with_previous(
            1,
            1,
            1,
            &[b"leaf".to_vec()],
            &foreign,
            None,
        )
        .expect("build foreign checkpoint");
        let denied = validate_previous_checkpoint(&foreign_cp, &operator.public_key())
            .expect_err("foreign operator's checkpoint is denied");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("different operator key")
        ));

        // A tampered body (signature no longer verifies) is denied even when it
        // still names this operator.
        let mut tampered = chio_kernel::build_checkpoint_with_previous(
            1,
            1,
            1,
            &[b"leaf".to_vec()],
            &operator,
            None,
        )
        .expect("build checkpoint to tamper");
        tampered.body.checkpoint_seq += 1;
        let denied_sig = validate_previous_checkpoint(&tampered, &operator.public_key())
            .expect_err("a tampered checkpoint is denied");
        assert!(matches!(
            denied_sig,
            CliError::Other(message) if message.contains("signature does not verify")
        ));
    }

    /// 669: the re-attestation verdict is never trusted from the bare flag; a
    /// `--reattested` set without a verifying presentation proof fails closed.
    #[test]
    fn pass_refresh_rejects_bare_reattested_without_proof() {
        let dir = temp_dir("reattest-deny");
        let authority_seed = dir.join("authority.seed");
        let subject = Keypair::generate().public_key().to_hex();
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];
        // The proof gate denies before any store is opened, so these paths are
        // never touched.
        let receipt_db = dir.join("receipts.sqlite3");
        let revocation_db = dir.join("revocations.sqlite3");

        let denied = pass_refresh(
            &subject,
            TrustTier::Attested,
            MID_JUNE_2026,
            None,
            true,
            None,
            None,
            &receipt_db,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect_err("bare --reattested without a proof is denied");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("bare flag is not trusted")
        ));
    }

    /// 669: a supplied re-attestation proof that does not verify (here, an
    /// undeserializable artifact) is denied fail-closed; the proof is genuinely
    /// consumed rather than the flag trusted.
    #[test]
    fn pass_refresh_rejects_unverifiable_reattestation_proof() {
        let dir = temp_dir("reattest-bad-proof");
        let authority_seed = dir.join("authority.seed");
        let subject = Keypair::generate().public_key().to_hex();
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];
        let receipt_db = dir.join("receipts.sqlite3");
        let revocation_db = dir.join("revocations.sqlite3");

        let proof_path = dir.join("proof.json");
        std::fs::write(&proof_path, b"{\"not\":\"a-presentation-response\"}")
            .expect("write malformed proof");

        let denied = pass_refresh(
            &subject,
            TrustTier::Attested,
            MID_JUNE_2026,
            None,
            true,
            Some(proof_path.as_path()),
            None,
            &receipt_db,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect_err("an unverifiable re-attestation proof is denied");
        // The proof path was taken (not the bare-flag rejection).
        assert!(!format!("{denied:?}").contains("bare flag is not trusted"));
    }

    /// PASS-1: refresh now persists renewed/dormant issuances into the anti-farm
    /// roster, so the revocation oracle is mandatory; omitting it fails closed.
    #[test]
    fn pass_refresh_dispatch_requires_revocation_oracle() {
        let dir = temp_dir("refresh-requires-oracle");
        let receipt_db = dir.join("receipts.sqlite3");
        let denied = dispatch_pass(
            PassCommands::Refresh {
                subject_public_key: Keypair::generate().public_key().to_hex(),
                tier: "attested".to_string(),
                now: Some(MID_JUNE_2026),
                prior_window_at: None,
                reattested: false,
                reattestation_proof: None,
                reattestation_challenge: None,
                accepted_kernel_key: vec![Keypair::generate().public_key().to_hex()],
                out_pass: None,
                out_capability: None,
            },
            true,
            Some(receipt_db.as_path()),
            None,
            None,
        );
        assert!(
            denied.is_err(),
            "refresh must fail closed without a revocation oracle"
        );
    }

    /// Finding 1: a refresh run at OR JUST AFTER a window rollover scans the
    /// EXPIRING window pinned by `prior_window_at` and mints the contiguous next
    /// window. The round-2 fix only handled the exact instant `now == since`; a run
    /// one second later (2026-07-01T00:00:01Z) silently scanned July and minted
    /// August. With the expiring window pinned, June is scanned and July is minted.
    #[test]
    fn refresh_windows_scan_the_expiring_window_with_explicit_prior() {
        const JULY_2026_START: u64 = 1_782_864_000; // 2026-07-01T00:00:00Z
        const JULY_2026_PLUS_1S: u64 = 1_782_864_001; // 2026-07-01T00:00:01Z

        // The finding's scenario: a refresh at 2026-07-01T00:00:01Z of a June Pass
        // (expiring window pinned to a June instant) scans June and mints July.
        let (prior, next) =
            refresh_windows(JULY_2026_PLUS_1S, Some(MID_JUNE_2026)).expect("rollover windows");
        assert_eq!(
            prior.window_ym, "2026-06",
            "the pinned expiring June window must be scanned, not the brand-new July window"
        );
        assert_eq!(next.window_ym, "2026-07", "the contiguous July window is minted");
        assert_eq!(prior.until, next.since);

        // The exact rollover instant with the expiring window pinned behaves the same.
        let (prior_exact, next_exact) =
            refresh_windows(JULY_2026_START, Some(MID_JUNE_2026)).expect("exact rollover windows");
        assert_eq!(prior_exact.window_ym, "2026-06");
        assert_eq!(next_exact.window_ym, "2026-07");

        // Interior (mid-window) with no explicit prior: `now` is unambiguously inside
        // the expiring window, so June is scanned and July is minted.
        let (prior_mid, next_mid) =
            refresh_windows(MID_JUNE_2026, None).expect("mid-window windows");
        assert_eq!(prior_mid.window_ym, "2026-06");
        assert_eq!(next_mid.window_ym, "2026-07");
        assert_eq!(prior_mid.until, next_mid.since);
    }

    /// Finding 1: a refresh fired INSIDE the rollover early span with NO explicit
    /// `prior_window_at` is ambiguous (the just-ended window or the brand-new one),
    /// so it fails closed and demands the operator pin the expiring window rather
    /// than silently scanning the wrong month.
    #[test]
    fn refresh_windows_fail_closed_in_rollover_span_without_explicit_prior() {
        const JULY_2026_PLUS_1S: u64 = 1_782_864_001; // 2026-07-01T00:00:01Z
        let denied = refresh_windows(JULY_2026_PLUS_1S, None)
            .expect_err("an ambiguous rollover refresh without --prior-window-at is denied");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("--prior-window-at")
        ));
    }

    /// Batch 6 / Finding: an explicit `--prior-window-at` that points at a FUTURE
    /// window (one that has not begun relative to `now`) is denied. Without this
    /// bound, a refresh run in mid-June with `--prior-window-at` in July would scan
    /// the brand-new July window and mint/persist an August Pass, silently reserving
    /// a future window. The CURRENT window and the already-expiring window at a
    /// rollover are still accepted.
    #[test]
    fn refresh_windows_reject_future_explicit_prior() {
        const JULY_2026_START: u64 = 1_782_864_000; // 2026-07-01T00:00:00Z

        // Running on 2026-06-15 with `--prior-window-at` pinned to a July instant: the
        // July window has not begun, so scanning it would mint an August Pass two
        // months ahead. Fail closed.
        let denied = refresh_windows(MID_JUNE_2026, Some(JULY_2026_START))
            .expect_err("a future --prior-window-at is denied");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("FUTURE window")
        ));

        // The CURRENT window (the one containing `now`) is an accepted explicit prior:
        // June is scanned and the contiguous July window is minted.
        let (prior, next) = refresh_windows(MID_JUNE_2026, Some(MID_JUNE_2026))
            .expect("the current window is an accepted explicit prior");
        assert_eq!(prior.window_ym, "2026-06");
        assert_eq!(next.window_ym, "2026-07");

        // The already-expiring window at the exact rollover (now in July, prior pinned
        // to a June instant) is still accepted: June has started and July (the minted
        // next) contains now.
        let (prior_rollover, next_rollover) =
            refresh_windows(JULY_2026_START, Some(MID_JUNE_2026))
                .expect("the expiring window at rollover is accepted");
        assert_eq!(prior_rollover.window_ym, "2026-06");
        assert_eq!(next_rollover.window_ym, "2026-07");
    }

    /// Finding 2: a renewed/dormant refresh persists through the SAME atomic
    /// count/check/insert cap transaction `issue` uses, so a refresh cannot fill
    /// the next window past `window_token_capacity` (or the population cap) before
    /// any first-window `issue` denies. The round-2 refresh persisted via plain
    /// `record_pass_issuance`, bypassing the caps.
    #[test]
    fn refresh_persists_under_caps_and_denies_when_window_full() {
        let dir = temp_dir("refresh-caps");
        let revocation_db = dir.join("revocations.sqlite3");
        let oracle = SqliteRevocationStore::open(&revocation_db).expect("open oracle");
        let next_window = attestation_window_containing(MID_JUNE_2026).expect("next window");

        // Fill the next window to a capacity of 1 with the first refreshed Pass.
        record_refreshed_issuance_under_caps(
            &oracle,
            "chiopass:first",
            &next_window,
            1,
            100,
        )
        .expect("first refreshed issuance is admitted under cap");

        // A DIFFERENT subject's refresh into the now-full window is denied
        // atomically, before any artifact is surfaced.
        let denied_window = record_refreshed_issuance_under_caps(
            &oracle,
            "chiopass:second",
            &next_window,
            1,
            100,
        )
        .expect_err("a refresh past the window capacity is denied");
        assert!(matches!(
            denied_window,
            CliError::Other(message) if message.contains("next-window distribution cap reached")
        ));

        // Re-refreshing the SAME subject/window is idempotent: admitted even at the
        // cap (the deterministic chiopass id adds no new population).
        record_refreshed_issuance_under_caps(
            &oracle,
            "chiopass:first",
            &next_window,
            1,
            100,
        )
        .expect("idempotent re-record of the same id is admitted at cap");

        // The population-cap leg is enforced in the SAME transaction: with a live
        // population of 1 (the first Pass) and an active_population_cap of 1, a NEW
        // id is denied on population, not just the window cap.
        let denied_population = record_refreshed_issuance_under_caps(
            &oracle,
            "chiopass:third",
            &next_window,
            100,
            1,
        )
        .expect_err("a refresh past the population cap is denied");
        assert!(matches!(
            denied_population,
            CliError::Other(message) if message.contains("active population cap reached")
        ));
    }

    /// Finding 4: a late-window refresh fills the NEXT window, whose rows carry a
    /// FUTURE `valid_from = next_window.since`. The population cap must be counted at
    /// the window being filled, not at the refresh wall clock: otherwise every prior
    /// refresh into that same future window (all future-dated) is excluded from the
    /// active-population count and the cap never binds. This test fills a FUTURE
    /// July window (the refresh fires from a late June rollover, so the wall clock is
    /// strictly before `next_window.since`) to an `active_population_cap` of 1 and
    /// asserts a second subject's refresh into it is denied on population.
    #[test]
    fn refresh_into_future_window_is_population_capped_at_that_window() {
        const JULY_2026_START: u64 = 1_782_864_000; // 2026-07-01T00:00:00Z
        let dir = temp_dir("refresh-future-window-caps");
        let revocation_db = dir.join("revocations.sqlite3");
        let oracle = SqliteRevocationStore::open(&revocation_db).expect("open oracle");

        // The window being filled is July 2026; the refresh fires from inside June,
        // so the refresh wall clock is strictly BEFORE the July rows go live.
        let next_window = attestation_window_containing(JULY_2026_START).expect("July window");
        assert_eq!(next_window.window_ym, "2026-07");
        assert!(
            MID_JUNE_2026 < next_window.since,
            "the refresh clock must precede the window being filled"
        );

        // Fill July to an active-population cap of 1.
        record_refreshed_issuance_under_caps(&oracle, "chiopass:july-a", &next_window, 100, 1)
            .expect("first future-window refresh is admitted under the population cap");

        // A DIFFERENT subject's refresh into the SAME future July window is denied on
        // population. Counting at `next_window.since` (where the July rows are live)
        // sees july-a; counting at a June wall clock would exclude it as not-yet-live
        // and wrongly admit july-b.
        let denied = record_refreshed_issuance_under_caps(&oracle, "chiopass:july-b", &next_window, 100, 1)
            .expect_err("a second future-window refresh past the population cap is denied");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("active population cap reached")
        ));
    }

    /// Finding 7: a re-attestation proof supplied WITHOUT an external challenge is
    /// denied fail-closed; only the response's own embedded challenge would
    /// otherwise be checked, which a holder can self-generate.
    #[test]
    fn verify_reattestation_proof_requires_external_challenge() {
        let dir = temp_dir("reattest-no-challenge");
        // The challenge gate denies BEFORE the proof is read, so the proof path
        // need not exist.
        let proof_path = dir.join("proof.json");
        let subject = Keypair::generate().public_key();

        let denied = verify_reattestation_proof(&proof_path, None, &subject, MID_JUNE_2026)
            .expect_err("a proof with no external challenge is denied");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("externally supplied --reattestation-challenge")
        ));
    }

    /// Finding 8: a tampered issued-Pass file (its signature no longer verifies)
    /// is rejected BEFORE its artifact id can be folded into the public anchor
    /// batch; a genuine signed Pass is accepted.
    #[test]
    fn read_issued_passes_rejects_tampered_pass_before_anchoring() {
        let dir = temp_dir("anchor-verify");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");
        let subject = Keypair::generate().public_key().to_hex();
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];

        let (issuance, _) = pass_issue(
            &subject,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("issuance");

        // The operator's own issuer DID is the trusted issuer for this anchor batch.
        let trusted = vec![issuance.pass.unsigned.issuer.clone()];

        // A genuine signed Pass from a trusted issuer is accepted into the input set.
        let valid_path = dir.join("issued-valid.json");
        write_json_artifact(&valid_path, &issuance.pass).expect("write valid pass");
        let accepted = read_issued_passes(std::slice::from_ref(&valid_path), &trusted)
            .expect("a signed Pass from a trusted issuer is accepted for anchoring");
        assert_eq!(accepted.len(), 1);

        // Finding 3: the SAME genuine Pass is rejected when its issuer is NOT a
        // trusted Pass authority for the batch, so an operator cannot fold a
        // foreign/self-issued Pass into its public membership root.
        let foreign_trusted = vec![DidChio::from_public_key(Keypair::generate().public_key())
            .expect("foreign issuer did")
            .to_string()];
        let denied_foreign = read_issued_passes(&[valid_path], &foreign_trusted)
            .expect_err("a Pass from a non-operator issuer is rejected before anchoring");
        assert!(matches!(
            denied_foreign,
            CliError::Other(message) if message.contains("not a trusted Pass authority")
        ));

        // A tampered Pass (signature no longer verifies) is rejected fail-closed.
        let mut tampered = issuance.pass.clone();
        let mut proof_value = tampered.proof.proof_value.clone();
        let first = proof_value.remove(0);
        // Flip the first hex nibble so the signature parses but no longer verifies.
        let replacement = if first == '0' { '1' } else { '0' };
        proof_value.insert(0, replacement);
        tampered.proof.proof_value = proof_value;
        let tampered_path = dir.join("issued-tampered.json");
        write_json_artifact(&tampered_path, &tampered).expect("write tampered pass");
        let denied = read_issued_passes(&[tampered_path], &trusted)
            .expect_err("a tampered issued Pass is rejected before anchoring");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("failed verification before anchoring")
        ));
    }

    /// Finding 5: `chio pass anchor` must accept an otherwise-valid issued Pass
    /// whose validity window has already ENDED (anchoring is historical membership
    /// evidence). The expiry-ignoring shape verifier evaluates the Pass at its OWN
    /// issuance instant, so a window-expired Pass anchors successfully where the
    /// time-windowed `verify_chio_pass` would wrongly reject it as expired. A
    /// tampered Pass still fails the shape/signature checks.
    #[test]
    fn anchored_pass_shape_ignores_expiry_but_still_binds_signature() {
        let dir = temp_dir("anchor-expiry");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");
        let subject = Keypair::generate().public_key().to_hex();
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];

        let (issuance, _) = pass_issue(
            &subject,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("issuance");
        let pass = issuance.pass.clone();

        // An instant AFTER the Pass's window has ended (a rollover anchor run).
        let after_expiry = pass.unsigned.credential_subject.entitlements.window.until + 1;
        let table = TierAllotmentTable::default();
        // The time-windowed verifier rejects the expired-but-valid Pass...
        assert!(
            verify_chio_pass(&pass, after_expiry, &table).is_err(),
            "the time-windowed verifier rejects a window-expired Pass"
        );
        // ...but the expiry-ignoring anchor shape verifier accepts it.
        verify_anchored_pass_shape(&pass)
            .expect("a window-expired issued Pass anchors successfully");

        // A tampered Pass (signature no longer verifies) still fails the shape checks.
        let mut tampered = pass.clone();
        let mut proof_value = tampered.proof.proof_value.clone();
        let first = proof_value.remove(0);
        let replacement = if first == '0' { '1' } else { '0' };
        proof_value.insert(0, replacement);
        tampered.proof.proof_value = proof_value;
        verify_anchored_pass_shape(&tampered)
            .expect_err("a tampered Pass still fails the shape verification before anchoring");
    }

    /// Finding 6: the revoked-leaf verifier now runs the SAME full Pass shape checks
    /// as the issued side (schema, proof type/purpose, entitlement shape), ignoring
    /// only expiry. A credential correctly SIGNED by a trusted issuer but carrying a
    /// malformed proof envelope (proof_purpose tampered AFTER signing - the proof
    /// fields are not covered by the issuer signature) passed the old raw-signature
    /// revoked check yet would be rejected as an issued leaf. It is now rejected
    /// before it can be anchored as a revoked leaf.
    #[test]
    fn verify_revoked_pass_authenticity_rejects_malformed_but_signed_credential() {
        let dir = temp_dir("revoked-shape");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");
        let subject = Keypair::generate().public_key().to_hex();
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];

        let (issuance, _) = pass_issue(
            &subject,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("issuance");
        let trusted = vec![issuance.pass.unsigned.issuer.clone()];

        // A genuine signed Pass from a trusted issuer is provable as a revoked leaf.
        verify_revoked_pass_authenticity(&issuance.pass, &trusted)
            .expect("a genuine revoked leaf is provable");

        // Tamper the proof PURPOSE: the proof envelope is NOT covered by the issuer
        // signature, so the credential is still validly signed (it passed the old
        // raw-signature revoked check) yet now carries a malformed proof envelope.
        let mut malformed = issuance.pass.clone();
        malformed.proof.proof_purpose = "tampered-purpose".to_string();
        let denied = verify_revoked_pass_authenticity(&malformed, &trusted)
            .expect_err("a malformed-but-signed revoked credential is rejected before anchoring");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("shape verification")
        ));
    }

    /// Finding 10: a renewed/dormant refresh persists its full signed artifacts to
    /// the requested `--out-pass` / `--out-capability` files (mirroring `issue`),
    /// rather than dropping everything but the capability id.
    #[test]
    fn refresh_writes_renewed_artifacts_to_requested_files() {
        let dir = temp_dir("refresh-artifacts");
        let revocation_db = dir.join("revocations.sqlite3");
        let authority_seed = dir.join("authority.seed");
        let subject = Keypair::generate().public_key().to_hex();
        let kernel_keys = vec![Keypair::generate().public_key().to_hex()];

        // A real minted issuance stands in for the refresh output.
        let (issuance, _) = pass_issue(
            &subject,
            TrustTier::Attested,
            MID_JUNE_2026,
            &revocation_db,
            Some(authority_seed.as_path()),
            &kernel_keys,
        )
        .expect("issuance");
        let window = issuance.window.clone();
        let next_capability_id = issuance.capability.id.clone();

        let decision = chio_credentials::ChioPassRefreshDecision {
            subject: issuance.pass.unsigned.credential_subject.id.clone(),
            prior_window: window.clone(),
            next_window: window.clone(),
            prior_capability_id: "chiopass:prior".to_string(),
            next_capability_id,
            genuine_use_count: 1,
            reattested: true,
            tier: TrustTier::Attested,
            outcome: chio_credentials::ChioPassRefreshOutcome::Granted,
            next_allotment_units: 1_000,
        };
        let result = ChioPassRefreshResult::Renewed { decision, issuance };

        let out_pass = dir.join("refreshed-pass.json");
        let out_capability = dir.join("refreshed-capability.json");
        write_refresh_artifacts(&result, Some(out_pass.as_path()), Some(out_capability.as_path()))
            .expect("refresh artifacts written");

        // The refreshed credential round-trips back to a typed ChioPass.
        let pass_bytes = std::fs::read(&out_pass).expect("refreshed-pass file written");
        let _pass: ChioPass =
            serde_json::from_slice(&pass_bytes).expect("refreshed pass deserializes");
        // The refreshed capability round-trips and carries the deterministic id.
        let capability_bytes = std::fs::read(&out_capability).expect("capability file written");
        let capability: serde_json::Value =
            serde_json::from_slice(&capability_bytes).expect("capability deserializes");
        assert!(capability["id"]
            .as_str()
            .is_some_and(|id| id.starts_with(CHIO_PASS_CAPABILITY_PREFIX)));

        // A not-reattested refresh mints nothing, so there is nothing to write.
        let not_reattested = ChioPassRefreshResult::NotReattested {
            decision: chio_credentials::ChioPassRefreshDecision {
                subject: "did:chio:none".to_string(),
                prior_window: window.clone(),
                next_window: window,
                prior_capability_id: "chiopass:prior".to_string(),
                next_capability_id: "chiopass:next".to_string(),
                genuine_use_count: 0,
                reattested: false,
                tier: TrustTier::Attested,
                outcome: chio_credentials::ChioPassRefreshOutcome::DeniedNoReattestation,
                next_allotment_units: 0,
            },
        };
        let skip_pass = dir.join("skip-pass.json");
        write_refresh_artifacts(&not_reattested, Some(skip_pass.as_path()), None)
            .expect("not-reattested writes nothing");
        assert!(!skip_pass.exists(), "a not-reattested refresh writes no artifacts");
    }
}
