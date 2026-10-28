use super::fixture_committed_disclosure::{
    committed_selective_disclosure_proofs, offer_committed_selective_disclosure_proofs,
};
use super::*;

const AGENT_WEB_REPLAY_STORE_PATH_ENV: &str = "CHIO_AGENT_WEB_REPLAY_STORE_PATH";
const MAX_REGENERATION_PASSES: usize = 4;

/// Verifier trust the committed proof-room fixtures are generated under. The
/// signer keys belong to the fixed fixture seeds, and the clocks are pinned so
/// regeneration never reads host time.
const FIXTURE_TRUST_PROFILE: &[(&str, &str)] = &[
    (
        "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET",
        "chio-agent-web-standard-webhooks-fixture-secret-v1",
    ),
    ("CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS", "1770508860"),
    ("CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS", "360"),
    (
        "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS",
        concat!(
            "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de,",
            "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff,",
            "bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6,",
            "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21,",
            "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565"
        ),
    ),
    (
        "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS",
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
    ),
    (
        "CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS",
        concat!(
            "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,",
            "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa,",
            "a6d2455ea3a5771aba9fcb037924114c92f9f325049f6b4269e739d9048bb869"
        ),
    ),
    (
        "CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS",
        concat!(
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
            "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a,",
            "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a"
        ),
    ),
    (
        "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS",
        concat!(
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
            "68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96,",
            "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a,",
            "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a"
        ),
    ),
    (
        "CHIO_RUNTIME_TRUSTED_ROOT_KEYS",
        "5b8649c0cfcdbe78a5ff962edfa48914dfd45af22afe358de1f4dd7e4567d5ca",
    ),
    (
        "CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS",
        "f95c6a5dff031fac7b1a6a54b6610caeb83b39f7e8a66be16ff5faa4a511ed2d",
    ),
    (
        "CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS",
        "3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2",
    ),
    (
        "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS",
        concat!(
            "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,",
            "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa,",
            "a6d2455ea3a5771aba9fcb037924114c92f9f325049f6b4269e739d9048bb869"
        ),
    ),
    (
        "CHIO_SWARM_TRUSTED_WITNESS_KEYS",
        "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de",
    ),
    (
        "CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS",
        "cf1b37e85dc00aee94f10108b37f151e2a37b3ae2a0cae77521f83488db9c4d7",
    ),
    (
        "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS",
        "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
    ),
    (
        "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS",
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    ),
    (
        "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS",
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    ),
    (
        "CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS",
        "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa",
    ),
    (
        "CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS",
        "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa",
    ),
    (
        "CHIO_PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    ),
    (
        "CHIO_PROOF_EXPORT_BUNDLE_SIGNER_SEED_HEX",
        "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS",
        "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS",
        "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS",
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS",
        "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS",
        "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID",
        "chio.official-web3-contracts",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH",
        "0x454a9a92b54a835a2776750196b171501bff6e5c02df1a192616194fc0a095cc",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH",
        "0xfc5d76d87b02096c6ae32ce644a2b98ca0bdf3c56700ad16731fad2062e6bd7f",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH",
        "0xd4f87cc63c00d0640c8f232c8fac5e5cb99bc6cf185ef912225e07fa438614cc",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH",
        "0x03d8f545c330922a33db6473430c50eafd527e04474f31abee2dc1f8c6ab2d36",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH",
        "0x17f7936469584b38404765ac44bd7e2384337983e4bc6448a3500d0637711f09",
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS",
        "eip155:8453,eip155:42161",
    ),
    ("CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS", "1"),
    (
        "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON",
        "{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"latest_block_number\":12345701}",
    ),
    ("CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS", "1743293560"),
];

#[derive(serde::Serialize)]
struct ProofFixtureRegenerateReport {
    schema: &'static str,
    root: String,
    passes: usize,
    changed: Vec<String>,
}

pub(super) fn regenerate_proof_fixtures(
    root: &Path,
    check: bool,
    json_output: bool,
) -> Result<(), CliError> {
    let root = fs::canonicalize(root)?;
    let _environment = fixture_environment(&root);
    let descriptors = regeneration_order(proof_fixtures()?);
    let staging = tempfile::tempdir()?;
    let staging_root = fs::canonicalize(staging.path())?;

    let mut changed = BTreeSet::new();
    let mut passes = 0;
    loop {
        passes += 1;
        offer_committed_selective_disclosure_proofs(committed_selective_disclosure_proofs(
            &root,
            &descriptors,
        )?);
        let pass_changed = regenerate_pass(&root, &descriptors, &staging_root, check)?;
        if pass_changed.is_empty() {
            break;
        }
        if check {
            return Err(CliError::cli_other_error(format!(
                "proof fixtures are stale; run `chio proof fixture regenerate`: {}",
                pass_changed.join(", ")
            )));
        }
        if passes == MAX_REGENERATION_PASSES {
            return Err(CliError::cli_other_error(format!(
                "proof fixture regeneration did not converge after {passes} passes: {}",
                pass_changed.join(", ")
            )));
        }
        changed.extend(pass_changed);
    }

    let report = ProofFixtureRegenerateReport {
        schema: "chio.proof.fixture-regenerate-report.v1",
        root: root.to_string_lossy().into_owned(),
        passes,
        changed: changed.into_iter().collect(),
    };
    let mut stdout = std::io::stdout();
    if json_output {
        serde_json::to_writer(&mut stdout, &report)?;
        stdout.write_all(b"\n")?;
    } else {
        for path in &report.changed {
            writeln!(stdout, "regenerated {path}")?;
        }
        writeln!(
            stdout,
            "{} fixture directories regenerated in {} passes",
            report.changed.len(),
            report.passes
        )?;
    }
    Ok(())
}

fn fixture_environment(root: &Path) -> Vec<EnvVarOverride> {
    let mut overrides = vec![EnvVarOverride::set(PROOF_FIXTURE_ROOT_ENV, root)];
    overrides.extend(
        FIXTURE_TRUST_PROFILE
            .iter()
            .map(|&(name, value)| EnvVarOverride::set(name, value)),
    );
    overrides
}

/// One descriptor per fixture directory, ordered so negatives regenerate
/// before the valid bundles that embed them and generated Proof Room bundles
/// regenerate after their sources.
fn regeneration_order(descriptors: Vec<ProofFixtureDescriptor>) -> Vec<ProofFixtureDescriptor> {
    let mut seen_paths = BTreeSet::new();
    let mut ordered: Vec<ProofFixtureDescriptor> = descriptors
        .into_iter()
        .filter(|descriptor| seen_paths.insert(descriptor.path.clone()))
        .collect();
    ordered.sort_by_key(|descriptor| match descriptor.kind.as_str() {
        "negative-transaction-passport" | "negative-disclosure-crypto-context" => 0,
        "proof-room" => 2,
        _ => 1,
    });
    ordered
}

fn regenerate_pass(
    root: &Path,
    descriptors: &[ProofFixtureDescriptor],
    staging: &Path,
    check: bool,
) -> Result<Vec<String>, CliError> {
    let mut changed = Vec::new();
    for descriptor in descriptors {
        let source_bound = fixture_runtime_check::is_source_bound_runtime_fixture(descriptor)?;
        let target = root.join(installed_fixture_path(descriptor));
        if source_bound && check {
            fixture_runtime_check::verify_committed_runtime_fixture(&target)?;
            continue;
        }
        let work = tempfile::tempdir_in(staging)?;
        let _replay_store = EnvVarOverride::set(
            AGENT_WEB_REPLAY_STORE_PATH_ENV,
            work.path().join("agent-web-replay.sqlite"),
        );
        let out = if source_bound {
            staging.join("qualified-runtime-generation")
        } else {
            work.path().join(&descriptor.id)
        };
        let layout = if target.join("manifest.json").is_file() {
            FixtureLayout::Sealed
        } else {
            FixtureLayout::Unsealed
        };
        if !source_bound || !path_exists_or_is_symlink(&out)? {
            materialize_proof_fixture(descriptor, &out, layout)?;
        }
        if directory_contents(&out)? != directory_contents(&target)? {
            changed.push(installed_fixture_path(descriptor).to_string());
            if !check {
                if path_exists_or_is_symlink(&target)? {
                    fs::remove_dir_all(&target)?;
                }
                copy_dir_contents(&out, &target)?;
            }
        }
    }
    Ok(changed)
}

fn directory_contents(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, CliError> {
    let mut contents = BTreeMap::new();
    if !path_exists_or_is_symlink(root)? {
        return Ok(contents);
    }
    crate::input::collection::walk_files(root, |path, budget| {
        let relative = path.strip_prefix(root).map_err(|source| {
            CliError::with_source(&chio_errors::_generated::error_codes::CLI_IO, source)
        })?;
        contents.insert(relative.to_path_buf(), budget.read(path)?);
        Ok(())
    })?;
    Ok(contents)
}
