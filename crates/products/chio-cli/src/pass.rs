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
use std::time::{SystemTime, UNIX_EPOCH};

use chio_anchor::{AnchorBatchWitness, EvmAnchorTarget};
use chio_core::capability::token::AttestationWindowId;
use chio_core::web3::identity::SignedWeb3IdentityBinding;
use chio_core::PublicKey;
use chio_did::DidChio;
use chio_credentials::{
    attestation_window_containing, verify_chio_pass, ChioPass, PassportLifecycleRecord,
    PassportLifecycleState, TierAllotmentTable, TrustTier,
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

    // Source the distribution counters from the persisted issued-Pass roster; the
    // entrypoint never recomputes them. The counters are read BEFORE the mint so
    // the new Pass is not counted against its own cap.
    let oracle = SqliteRevocationStore::open(revocation_db_path)?;
    let window = attestation_window_containing(now)?;
    let counters = oracle_distribution_counters(&oracle, &window, now)?;

    let issuance = issue_chio_pass_command(
        &config,
        &authority,
        &authority_keypair,
        &subject_public_key,
        tier,
        now,
        counters.window_issued_count,
        counters.active_population,
    )?;

    // Atomically admit + persist the issuance under the anti-farm caps. The
    // pre-mint counters above are a fast pre-check; the AUTHORITATIVE admission is
    // this single SQLite transaction, which counts + checks + inserts atomically
    // so two concurrent `chio pass issue` runs (each with its own connection)
    // cannot both pass a stale read, both mint, and exceed the caps. Fail-closed:
    // a store IO fault or a cap-full denial returns Err; the credential was only
    // minted in-memory and is never surfaced. `valid_from` is the window start so
    // the live-population count never trusts a future-window row.
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

/// Derive the (expiring prior, minted next) attestation window pair for a refresh
/// run at `now`.
///
/// The genuine-use scan runs over the EXPIRING window and the next contiguous
/// window is minted. When `now` lands exactly on a month boundary (the first
/// instant of a new window) the window that JUST ended is the one being refreshed,
/// so the prior window is the previous month and the next window is the window
/// containing `now`. Otherwise the prior window is the one containing `now` and the
/// next window is the contiguous rollover.
///
/// Without the boundary case a refresh run at the rollover instant would treat the
/// brand-new (empty) window as the prior window, miss the expiring window's
/// genuine-use receipts, and mint for the wrong month (e.g. on 2026-07-01 it would
/// scan July and mint August instead of scanning June and minting July).
fn refresh_windows(
    now: u64,
) -> Result<(AttestationWindowId, AttestationWindowId), CliError> {
    let current = attestation_window_containing(now)?;
    if now == current.since {
        // Rollover instant: refresh the just-expired previous window into the
        // window that now contains `now`.
        let prior = attestation_window_containing(current.since.saturating_sub(1))?;
        Ok((prior, current))
    } else {
        // Mid-window: refresh the current window into the contiguous next month.
        let next = attestation_window_containing(current.until)?;
        Ok((current, next))
    }
}

/// Roll a Pass forward into its next monthly window from the prior window's
/// genuine-use scan.
#[allow(clippy::too_many_arguments)]
fn pass_refresh(
    subject_public_key_hex: &str,
    tier: TrustTier,
    now: u64,
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
    // Derive the expiring (prior) and minted (next) windows fail-closed at the
    // rollover boundary so the scan never misses the expiring window's receipts.
    let (prior_window, next_window) = refresh_windows(now)?;

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
    // so `count_active_passes` does not undercount live refreshed Passes. The
    // deterministic next-window `chiopass:<hash>` id is the roster key, so this
    // supersedes the prior window's row rather than inflating the population.
    // Fail-closed: a store IO fault denies after the in-memory mint, which is
    // never surfaced.
    if let ChioPassRefreshResult::Renewed { issuance, .. }
    | ChioPassRefreshResult::Dormant { issuance, .. } = &result
    {
        let oracle = SqliteRevocationStore::open(revocation_db_path)?;
        let valid_from = i64::try_from(next_window.since).unwrap_or(0);
        let expires_at = i64::try_from(next_window.until).unwrap_or(i64::MAX);
        oracle.record_pass_issuance(
            &issuance.capability.id,
            &next_window.window_ym,
            valid_from,
            expires_at,
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

/// Read and validate the revoked-Pass lifecycle records for an anchor batch.
///
/// FAIL-CLOSED: the anchor batch treats every entry in this slice as a revoked
/// Pass digest, so each record MUST be a structurally valid AND actually-revoked
/// (`status == Revoked`) lifecycle record. A stale Active/Superseded export can
/// therefore no longer be published into the revoked input set.
fn read_revoked_records(
    revoked_record_paths: &[std::path::PathBuf],
) -> Result<Vec<PassportLifecycleRecord>, CliError> {
    revoked_record_paths
        .iter()
        .map(|path| {
            let record: PassportLifecycleRecord = read_json_artifact(path)?;
            record.validate().map_err(|error| {
                CliError::Other(format!(
                    "revoked Pass lifecycle record {} is invalid: {error}",
                    path.display()
                ))
            })?;
            if record.status != PassportLifecycleState::Revoked {
                return Err(CliError::Other(format!(
                    "revoked Pass anchor input {} is not a revoked lifecycle record (status: {}); \
                     only Revoked records may be anchored as revoked Pass digests",
                    path.display(),
                    record.status.label()
                )));
            }
            Ok(record)
        })
        .collect()
}

/// Read and CRYPTOGRAPHICALLY verify the issued Chio Pass credentials for an
/// anchor batch.
///
/// FAIL-CLOSED: the anchor batch folds each Pass's `chio_pass_artifact_id` into a
/// PUBLIC membership root, so every issued-Pass file MUST carry a verifying issuer
/// signature AND a valid entitlement shape (and be inside its validity window at
/// `now`) before its artifact id may be anchored. An unsigned, tampered, or
/// malformed Pass is rejected here, before it can reach the public batch as
/// membership evidence.
fn read_issued_passes(
    issued_pass_paths: &[std::path::PathBuf],
    now: u64,
) -> Result<Vec<ChioPass>, CliError> {
    // The launch entitlement-shape table the credential was minted against
    // (`ChioPassConfig::m1_launch_default` pins `TierAllotmentTable::default()`).
    let table = TierAllotmentTable::default();
    issued_pass_paths
        .iter()
        .map(|path| {
            let pass: ChioPass = read_json_artifact(path)?;
            verify_chio_pass(&pass, now, &table).map_err(|error| {
                CliError::Other(format!(
                    "issued Pass {} failed verification before anchoring: {error}",
                    path.display()
                ))
            })?;
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

    // Verify each issued Pass's signature and entitlement shape BEFORE its
    // artifact id is folded into the public anchor batch (fail-closed).
    let issued_passes = read_issued_passes(issued_pass_paths, issued_at)?;
    let revoked_records = read_revoked_records(revoked_record_paths)?;

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

    /// 311: only actually-revoked lifecycle records may be anchored as revoked
    /// Pass digests; a stale Active export is denied fail-closed.
    #[test]
    fn read_revoked_records_requires_revoked_status() {
        let dir = temp_dir("revoked-records");

        let revoked_path = dir.join("revoked.json");
        write_json_artifact(
            &revoked_path,
            &lifecycle_record(PassportLifecycleState::Revoked),
        )
        .expect("write revoked record");
        let records = read_revoked_records(&[revoked_path]).expect("revoked record is accepted");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, PassportLifecycleState::Revoked);

        let active_path = dir.join("active.json");
        write_json_artifact(
            &active_path,
            &lifecycle_record(PassportLifecycleState::Active),
        )
        .expect("write active record");
        let denied =
            read_revoked_records(&[active_path]).expect_err("a non-revoked record is denied");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("not a revoked lifecycle record")
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

    /// Finding 6: at the first instant of a new window the refresh scans the
    /// EXPIRING (previous month) window, not the brand-new current window, and
    /// mints the contiguous current window. Mid-window it scans the current window
    /// and mints the next month.
    #[test]
    fn refresh_windows_scan_the_expiring_window_at_rollover() {
        const JULY_2026_START: u64 = 1_782_864_000; // 2026-07-01T00:00:00Z

        // Rollover instant: scan June (expiring), mint July (current).
        let (prior, next) = refresh_windows(JULY_2026_START).expect("rollover windows");
        assert_eq!(
            prior.window_ym, "2026-06",
            "at the first instant of July the expiring June window must be scanned"
        );
        assert_eq!(next.window_ym, "2026-07", "the current July window is minted");
        // The minted window is the contiguous rollover of the scanned window.
        assert_eq!(prior.until, next.since);

        // Mid-window: scan June (current), mint July (next month).
        let (prior_mid, next_mid) = refresh_windows(MID_JUNE_2026).expect("mid-window windows");
        assert_eq!(prior_mid.window_ym, "2026-06");
        assert_eq!(next_mid.window_ym, "2026-07");
        assert_eq!(prior_mid.until, next_mid.since);
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

        // A genuine signed Pass verifies and is accepted into the anchor input set.
        let valid_path = dir.join("issued-valid.json");
        write_json_artifact(&valid_path, &issuance.pass).expect("write valid pass");
        let accepted = read_issued_passes(&[valid_path], MID_JUNE_2026)
            .expect("a signed Pass is accepted for anchoring");
        assert_eq!(accepted.len(), 1);

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
        let denied = read_issued_passes(&[tampered_path], MID_JUNE_2026)
            .expect_err("a tampered issued Pass is rejected before anchoring");
        assert!(matches!(
            denied,
            CliError::Other(message) if message.contains("failed verification before anchoring")
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
