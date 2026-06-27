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
use chio_core::{Keypair, PublicKey};
use chio_credentials::{
    attestation_window_containing, ChioPass, PassportLifecycleRecord, TrustTier,
};
use chio_kernel::{KernelCheckpoint, LocalCapabilityAuthority};
use chio_store_sqlite::{SqliteReceiptStore, SqliteRevocationStore};
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

    // Persist the new issuance into the roster so the SAME oracle enforces the
    // per-window and active-population caps on the next invocation. Fail-closed:
    // a store IO fault denies; the credential was only minted in-memory and is
    // never surfaced.
    let expires_at = i64::try_from(window.until).unwrap_or(i64::MAX);
    oracle.record_pass_issuance(&issuance.capability.id, &window.window_ym, expires_at)?;
    Ok((issuance, counters))
}

/// Roll a Pass forward into its next monthly window from the prior window's
/// genuine-use scan.
fn pass_refresh(
    subject_public_key_hex: &str,
    tier: TrustTier,
    now: u64,
    reattested: bool,
    receipt_db_path: &Path,
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

    // The genuine-use scan reads the receipt store the CLI already has.
    let store = SqliteReceiptStore::open(receipt_db_path)?;
    let prior_window = attestation_window_containing(now)?;
    // The next window is the contiguous monthly rollover (its `since` equals the
    // prior window's `until`).
    let next_window = attestation_window_containing(prior_window.until)?;

    refresh_chio_pass_window(
        &config,
        &store,
        &authority,
        &authority_keypair,
        &subject_public_key,
        tier,
        &prior_window,
        &next_window,
        reattested,
    )
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

    let issued_passes = issued_pass_paths
        .iter()
        .map(|path| read_json_artifact::<ChioPass>(path))
        .collect::<Result<Vec<_>, _>>()?;
    let revoked_records = revoked_record_paths
        .iter()
        .map(|path| read_json_artifact::<PassportLifecycleRecord>(path))
        .collect::<Result<Vec<_>, _>>()?;

    let previous_checkpoint = previous_checkpoint_path
        .map(read_json_artifact::<KernelCheckpoint>)
        .transpose()?;

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
            accepted_kernel_key,
        } => {
            let tier = parse_trust_tier(&tier)?;
            let now = now.unwrap_or_else(unix_now);
            let receipt_db_path = require_receipt_db_path(receipt_db)?;
            let result = pass_refresh(
                &subject_public_key,
                tier,
                now,
                reattested,
                receipt_db_path,
                authority_seed_file,
                &accepted_kernel_key,
            )?;
            let report = match &result {
                ChioPassRefreshResult::Renewed { decision, issuance } => serde_json::json!({
                    "schema": "chio.pass.refresh.v1",
                    "outcome": "renewed",
                    "capabilityId": issuance.capability.id,
                    "window": window_json(&issuance.window),
                    "nextAllotmentUnits": decision.next_allotment_units,
                }),
                ChioPassRefreshResult::Dormant { decision, issuance } => serde_json::json!({
                    "schema": "chio.pass.refresh.v1",
                    "outcome": "dormant",
                    "capabilityId": issuance.capability.id,
                    "window": window_json(&issuance.window),
                    "nextAllotmentUnits": decision.next_allotment_units,
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
}
