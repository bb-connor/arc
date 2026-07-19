use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::security::{
    DurableEnterpriseMigrationStateBinding, EnterpriseEvidenceRunnerIdentity,
    EnterpriseMigrationCanaryEvidenceBody, EnterpriseMigrationCanaryVerificationPolicy,
    EnterpriseMigrationEvidenceBinding, EnterpriseMigrationGateResultDigests,
    SignedEnterpriseMigrationCanaryEvidence, SignedEnterpriseMigrationCutoverAttestation,
    ENTERPRISE_MIGRATION_CANARY_EVIDENCE_SCHEMA,
};
use chio_core_types::{canonical_json_bytes, sha256, Ed25519Backend, Hash, Keypair, PublicKey};
use chio_security_types::{
    ports::{Digest32, RecordId},
    EnterpriseMigrationCasOutcome, EnterpriseMigrationControl, EnterpriseMigrationKey,
    EnterpriseMigrationRegisterOutcome, EnterpriseMigrationScopeKind, EnterpriseMigrationStage,
    EnterpriseMigrationState, EnterpriseMigrationStateStore, EnterpriseMigrationTransitionBody,
};
use chio_store_sqlite::{
    sign_enterprise_migration_transition, SqliteEnterpriseMigrationOpenPolicy,
    SqliteEnterpriseMigrationStateStore,
};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
const COMMITTED_CANARY_FILE: &str = "enterprise-migration-canary.json";
const COMMITTED_CANARY_DIGEST_FILE: &str = "enterprise-migration-canary.json.sha256";
const COMMITTED_BINDING_DIGEST_FILE: &str = "enterprise-migration-binding-digest.txt";
const COMMITTED_LINUX_EVIDENCE_FILES: [&str; 3] = [
    COMMITTED_BINDING_DIGEST_FILE,
    COMMITTED_CANARY_FILE,
    COMMITTED_CANARY_DIGEST_FILE,
];

#[derive(Parser)]
#[command(name = "chio-enterprise-evidence")]
#[command(about = "Create and verify secret-free enterprise migration evidence")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    CreateCanary(CreateCanaryArgs),
    #[command(about = "Verify a standalone canary signature without repository binding")]
    VerifyCanary(VerifyCanaryArgs),
    #[command(about = "Verify externally pinned committed Linux evidence")]
    VerifyCommittedLinuxEvidence(VerifyCommittedLinuxEvidenceArgs),
    VerifyCutover(VerifyCutoverArgs),
}

#[derive(Args)]
struct CreateCanaryArgs {
    #[arg(long)]
    source_commit: String,
    #[arg(long)]
    runner_name: String,
    #[arg(long)]
    runner_os: String,
    #[arg(long)]
    runner_arch: String,
    #[arg(long)]
    runner_labels_digest: String,
    #[arg(long)]
    configuration_digest: String,
    #[arg(long)]
    inventory_digest: String,
    #[arg(long)]
    runner_contract_digest: String,
    #[arg(long)]
    key_log_transparency_digest: String,
    #[arg(long)]
    broker_boundary_digest: String,
    #[arg(long)]
    cage_enforcement_digest: String,
    #[arg(long)]
    committed_adversarial_evidence_digest: String,
    #[arg(long)]
    linux_adversarial_controls_digest: String,
    #[arg(long)]
    migration_state_store_digest: String,
    #[arg(long)]
    migration_database: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    expected_runner_public_key: String,
}

#[derive(Args)]
struct VerifyCanaryArgs {
    #[arg(long)]
    artifact: PathBuf,
    #[arg(long)]
    runner_public_key: String,
}

#[derive(Args)]
struct VerifyCommittedLinuxEvidenceArgs {
    #[arg(long)]
    evidence_directory: PathBuf,
    #[arg(long)]
    runner_public_key: String,
    #[arg(long)]
    expected_source_commit: String,
    #[arg(long)]
    expected_runner_name: String,
    #[arg(long)]
    expected_runner_os: String,
    #[arg(long)]
    expected_runner_arch: String,
    #[arg(long)]
    expected_runner_labels_digest: String,
    #[arg(long)]
    expected_configuration_digest: String,
    #[arg(long)]
    expected_inventory_digest: String,
    #[arg(long)]
    expected_runner_contract_digest: String,
    #[arg(long)]
    expected_key_log_transparency_digest: String,
    #[arg(long)]
    expected_broker_boundary_digest: String,
    #[arg(long)]
    expected_cage_enforcement_digest: String,
    #[arg(long)]
    expected_committed_adversarial_evidence_digest: String,
    #[arg(long)]
    expected_linux_adversarial_controls_digest: String,
    #[arg(long)]
    expected_migration_state_store_digest: String,
    #[arg(long)]
    expected_binding_digest: String,
    #[arg(long)]
    generated_at_not_before_unix_ms: u64,
    #[arg(long)]
    generated_at_not_after_unix_ms: u64,
}

#[derive(Args)]
struct VerifyCutoverArgs {
    #[arg(long)]
    canary: PathBuf,
    #[arg(long)]
    attestation: PathBuf,
    #[arg(long)]
    operator_public_key: String,
    #[arg(long)]
    runner_public_key: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::CreateCanary(args) => create_canary(args),
        Command::VerifyCanary(args) => verify_canary(args),
        Command::VerifyCommittedLinuxEvidence(args) => verify_committed_linux_evidence(args),
        Command::VerifyCutover(args) => verify_cutover(args),
    }
}

fn create_canary(args: CreateCanaryArgs) -> Result<(), Box<dyn Error>> {
    if args.migration_database.try_exists()? {
        return Err("canary migration database already exists".into());
    }
    let configuration_digest = parse_hash(&args.configuration_digest)?;
    let gate_result_digests = EnterpriseMigrationGateResultDigests {
        runner_contract: parse_hash(&args.runner_contract_digest)?,
        key_log_transparency: parse_hash(&args.key_log_transparency_digest)?,
        broker_boundary: parse_hash(&args.broker_boundary_digest)?,
        cage_enforcement: parse_hash(&args.cage_enforcement_digest)?,
        committed_adversarial_evidence: parse_hash(&args.committed_adversarial_evidence_digest)?,
        linux_adversarial_controls: parse_hash(&args.linux_adversarial_controls_digest)?,
        migration_state_store: parse_hash(&args.migration_state_store_digest)?,
    };
    let generated_at_unix_ms = now_unix_ms()?;
    let expected_runner_key = PublicKey::from_hex(&args.expected_runner_public_key)?;
    let runner_keypair = read_signing_key_from_stdin()?;
    if runner_keypair.public_key() != expected_runner_key {
        return Err("runner signing seed does not match the pinned public key".into());
    }
    let store = SqliteEnterpriseMigrationStateStore::open(
        canonical_new_file_path(&args.migration_database)?,
        SqliteEnterpriseMigrationOpenPolicy::new(vec![expected_runner_key.clone()], Vec::new())?,
    )?;
    let durable_migration_states = materialize_canary_migration_states(
        &store,
        &runner_keypair,
        &args.source_commit,
        configuration_digest,
        &gate_result_digests,
        generated_at_unix_ms,
    )?;
    let body = EnterpriseMigrationCanaryEvidenceBody {
        schema: ENTERPRISE_MIGRATION_CANARY_EVIDENCE_SCHEMA.to_owned(),
        evidence_kind: "designated_runner_repository_canary".to_owned(),
        generated_at_unix_ms,
        binding: EnterpriseMigrationEvidenceBinding {
            source_commit: args.source_commit,
            runner: EnterpriseEvidenceRunnerIdentity {
                runner_name: args.runner_name,
                runner_os: args.runner_os,
                runner_arch: args.runner_arch,
                required_labels_digest: parse_hash(&args.runner_labels_digest)?,
            },
            configuration_digest,
            inventory_digest: parse_hash(&args.inventory_digest)?,
            durable_migration_states,
            gate_result_digests,
        },
        repository_mechanics_only: true,
        production_traffic_attested: false,
        production_cutover_attested: false,
        operator_attestation_required: true,
    };

    let signer = Ed25519Backend::new(runner_keypair);
    let canary =
        SignedEnterpriseMigrationCanaryEvidence::sign(body, &signer, &expected_runner_key)?;
    let canonical = canary.canonical_bytes(&expected_runner_key)?;
    write_atomic(&args.output, &canonical)?;
    println!("{}", canary.body.binding.binding_digest()?);
    Ok(())
}

fn verify_canary(args: VerifyCanaryArgs) -> Result<(), Box<dyn Error>> {
    let canonical = read_bounded(&args.artifact)?;
    let runner_key = PublicKey::from_hex(&args.runner_public_key)?;
    let canary =
        SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes(&canonical, &runner_key)?;
    println!("{}", canary.body.binding.binding_digest()?);
    Ok(())
}

fn verify_committed_linux_evidence(
    args: VerifyCommittedLinuxEvidenceArgs,
) -> Result<(), Box<dyn Error>> {
    verify_exact_committed_file_inventory(&args.evidence_directory)?;
    let artifact_path = args.evidence_directory.join(COMMITTED_CANARY_FILE);
    let canonical = read_bounded(&artifact_path)?;
    verify_sha256_sidecar(
        &args.evidence_directory.join(COMMITTED_CANARY_DIGEST_FILE),
        &canonical,
    )?;

    let runner_key = PublicKey::from_hex(&args.runner_public_key)?;
    let policy = EnterpriseMigrationCanaryVerificationPolicy {
        source_commit: args.expected_source_commit,
        runner: EnterpriseEvidenceRunnerIdentity {
            runner_name: args.expected_runner_name,
            runner_os: args.expected_runner_os,
            runner_arch: args.expected_runner_arch,
            required_labels_digest: parse_hash(&args.expected_runner_labels_digest)?,
        },
        configuration_digest: parse_hash(&args.expected_configuration_digest)?,
        inventory_digest: parse_hash(&args.expected_inventory_digest)?,
        gate_result_digests: EnterpriseMigrationGateResultDigests {
            runner_contract: parse_hash(&args.expected_runner_contract_digest)?,
            key_log_transparency: parse_hash(&args.expected_key_log_transparency_digest)?,
            broker_boundary: parse_hash(&args.expected_broker_boundary_digest)?,
            cage_enforcement: parse_hash(&args.expected_cage_enforcement_digest)?,
            committed_adversarial_evidence: parse_hash(
                &args.expected_committed_adversarial_evidence_digest,
            )?,
            linux_adversarial_controls: parse_hash(
                &args.expected_linux_adversarial_controls_digest,
            )?,
            migration_state_store: parse_hash(&args.expected_migration_state_store_digest)?,
        },
        binding_digest: parse_hash(&args.expected_binding_digest)?,
        generated_at_not_before_unix_ms: args.generated_at_not_before_unix_ms,
        generated_at_not_after_unix_ms: args.generated_at_not_after_unix_ms,
    };
    let canary = SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes_against_policy(
        &canonical,
        &runner_key,
        &policy,
    )?;
    let binding_digest = canary.body.binding.binding_digest()?;
    verify_binding_digest_sidecar(
        &args.evidence_directory.join(COMMITTED_BINDING_DIGEST_FILE),
        binding_digest,
    )?;
    println!("{binding_digest}");
    Ok(())
}

fn verify_cutover(args: VerifyCutoverArgs) -> Result<(), Box<dyn Error>> {
    let canary_bytes = read_bounded(&args.canary)?;
    let runner_key = PublicKey::from_hex(&args.runner_public_key)?;
    let canary =
        SignedEnterpriseMigrationCanaryEvidence::from_canonical_bytes(&canary_bytes, &runner_key)?;
    let operator_key = PublicKey::from_hex(&args.operator_public_key)?;
    let attestation_bytes = read_bounded(&args.attestation)?;
    let attestation = SignedEnterpriseMigrationCutoverAttestation::from_canonical_bytes(
        &attestation_bytes,
        &operator_key,
        &canary,
        &runner_key,
    )?;
    println!("{}", attestation.body.pre_promotion_canary_binding_digest);
    Ok(())
}

fn materialize_canary_migration_states(
    store: &SqliteEnterpriseMigrationStateStore,
    signer: &Keypair,
    source_commit: &str,
    configuration_digest: Hash,
    gate_result_digests: &EnterpriseMigrationGateResultDigests,
    started_at_unix_ms: u64,
) -> Result<Vec<DurableEnterpriseMigrationStateBinding>, Box<dyn Error>> {
    let deployment_id = RecordId::new(format!("canary-{source_commit}"))?;
    let controls = [
        (
            EnterpriseMigrationScopeKind::Deployment,
            RecordId::new("designated-runner-canary-deployment")?,
            EnterpriseMigrationControl::KeyLogVerification,
            gate_result_digests.key_log_transparency,
        ),
        (
            EnterpriseMigrationScopeKind::Provider,
            RecordId::new("designated-runner-canary-provider")?,
            EnterpriseMigrationControl::BrokerCredentialCustody,
            gate_result_digests.broker_boundary,
        ),
        (
            EnterpriseMigrationScopeKind::Provider,
            RecordId::new("designated-runner-canary-provider")?,
            EnterpriseMigrationControl::BrokerQuotaEnforcement,
            gate_result_digests.broker_boundary,
        ),
        (
            EnterpriseMigrationScopeKind::ToolServer,
            RecordId::new("designated-runner-canary-server")?,
            EnterpriseMigrationControl::CageEnforcement,
            gate_result_digests.cage_enforcement,
        ),
        (
            EnterpriseMigrationScopeKind::ToolServer,
            RecordId::new("designated-runner-canary-server")?,
            EnterpriseMigrationControl::LegacyConfiguration,
            gate_result_digests.migration_state_store,
        ),
    ];
    let config_digest = Digest32::new(*configuration_digest.as_bytes());
    let mut states = Vec::with_capacity(controls.len());

    for (index, (scope_kind, scope_id, control, evidence_hash)) in controls.into_iter().enumerate()
    {
        let key = EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind,
            scope_id,
            control,
        };
        let evidence_digest = Digest32::new(*evidence_hash.as_bytes());
        let index = u64::try_from(index)?;
        let registered_at = started_at_unix_ms
            .checked_add(index.checked_mul(10).ok_or("canary time overflow")?)
            .ok_or("canary time overflow")?;
        let genesis = EnterpriseMigrationTransitionBody::genesis(
            key.clone(),
            config_digest,
            evidence_digest,
            canary_transition_digest(
                "authorization",
                source_commit,
                &key,
                EnterpriseMigrationStage::Disabled,
                evidence_digest,
            )?,
            canary_transition_digest(
                "intent",
                source_commit,
                &key,
                EnterpriseMigrationStage::Disabled,
                evidence_digest,
            )?,
            registered_at,
            signer.public_key().to_hex(),
        )?;
        let genesis = sign_enterprise_migration_transition(genesis, signer)?;
        match store.register(&genesis)? {
            EnterpriseMigrationRegisterOutcome::Registered(_) => {}
            EnterpriseMigrationRegisterOutcome::Existing(_)
            | EnterpriseMigrationRegisterOutcome::Conflict(_) => {
                return Err("canary migration state was not created from a fresh database".into())
            }
        }
        let disabled = store
            .load(&key)?
            .ok_or("canary disabled migration state is missing")?;
        let shadow_at = registered_at.checked_add(1).ok_or("canary time overflow")?;
        promote(
            store,
            signer,
            source_commit,
            &disabled,
            config_digest,
            evidence_digest,
            shadow_at,
        )?;
        let state = store
            .load(&key)?
            .ok_or("canary shadow migration state is missing")?;
        states.push(DurableEnterpriseMigrationStateBinding::from_state(&state));
    }

    states.sort_by(|left, right| {
        (
            left.deployment_id.as_str(),
            left.scope_kind,
            left.scope_id.as_str(),
            left.control,
        )
            .cmp(&(
                right.deployment_id.as_str(),
                right.scope_kind,
                right.scope_id.as_str(),
                right.control,
            ))
    });
    Ok(states)
}

fn promote(
    store: &SqliteEnterpriseMigrationStateStore,
    signer: &Keypair,
    source_commit: &str,
    prior: &EnterpriseMigrationState,
    posture_digest: Digest32,
    evidence_digest: Digest32,
    promoted_at_unix_ms: u64,
) -> Result<EnterpriseMigrationState, Box<dyn Error>> {
    let target_stage = prior
        .stage
        .next()
        .ok_or("canary migration state is terminal")?;
    let body = EnterpriseMigrationTransitionBody::promotion(
        prior,
        posture_digest,
        evidence_digest,
        canary_transition_digest(
            "authorization",
            source_commit,
            &prior.key,
            target_stage,
            evidence_digest,
        )?,
        canary_transition_digest(
            "intent",
            source_commit,
            &prior.key,
            target_stage,
            evidence_digest,
        )?,
        promoted_at_unix_ms,
        signer.public_key().to_hex(),
    )?;
    let transition = sign_enterprise_migration_transition(body, signer)?;
    match store.compare_and_promote(&transition)? {
        EnterpriseMigrationCasOutcome::Promoted(state) => Ok(state),
        EnterpriseMigrationCasOutcome::Conflict(_) => {
            Err("canary migration compare-and-promote conflicted".into())
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanaryTransitionBinding<'a> {
    domain: &'a str,
    source_commit: &'a str,
    key: &'a EnterpriseMigrationKey,
    target_stage: EnterpriseMigrationStage,
    evidence_digest: Digest32,
}

fn canary_transition_digest(
    domain: &str,
    source_commit: &str,
    key: &EnterpriseMigrationKey,
    target_stage: EnterpriseMigrationStage,
    evidence_digest: Digest32,
) -> Result<Digest32, Box<dyn Error>> {
    let canonical = canonical_json_bytes(&CanaryTransitionBinding {
        domain,
        source_commit,
        key,
        target_stage,
        evidence_digest,
    })?;
    Ok(Digest32::new(*sha256(&canonical).as_bytes()))
}

fn canonical_new_file_path(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or("migration database path has no parent")?;
    let file_name = path
        .file_name()
        .ok_or("migration database path has no file name")?;
    Ok(fs::canonicalize(parent)?.join(file_name))
}

fn parse_hash(value: &str) -> Result<Hash, Box<dyn Error>> {
    let hash = Hash::from_hex(value)?;
    if hash == Hash::zero() {
        return Err("digest must not be zero".into());
    }
    Ok(hash)
}

fn read_signing_key_from_stdin() -> Result<Keypair, Box<dyn Error>> {
    let mut encoded = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(67)
        .read_to_string(&mut encoded)?;
    let without_newline = encoded.strip_suffix('\n').unwrap_or(encoded.as_str());
    let without_newline = without_newline
        .strip_suffix('\r')
        .unwrap_or(without_newline);
    if without_newline.len() != 64
        || !without_newline
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("runner signing seed on stdin must be exactly 32 lowercase-hex bytes".into());
    }
    Ok(Keypair::from_seed_hex(without_newline)?)
}

fn now_unix_ms() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() {
        return Err("enterprise evidence input is not a bounded regular file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
        options.custom_flags(i32::try_from(flags.bits())?);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return Err("enterprise evidence input is not a bounded regular file".into());
    }
    let expected_len = usize::try_from(metadata.len())?;
    let maximum_read = MAX_ARTIFACT_BYTES
        .checked_add(1)
        .ok_or("enterprise evidence byte limit overflow")?;
    let mut bytes = Vec::with_capacity(expected_len);
    (&mut file).take(maximum_read).read_to_end(&mut bytes)?;
    if bytes.len() != expected_len {
        return Err("enterprise evidence input changed while it was read".into());
    }
    Ok(bytes)
}

fn verify_exact_committed_file_inventory(directory: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() {
        return Err("committed Linux evidence path is not a real directory".into());
    }
    let mut observed = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err("committed Linux evidence contains a non-regular file".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "committed Linux evidence contains a non-UTF-8 file name")?;
        observed.push(name);
    }
    observed.sort();
    let expected = COMMITTED_LINUX_EVIDENCE_FILES.map(str::to_owned);
    if observed.as_slice() != expected.as_slice() {
        return Err("committed Linux evidence file inventory is not exact".into());
    }
    Ok(())
}

fn verify_sha256_sidecar(path: &Path, artifact: &[u8]) -> Result<(), Box<dyn Error>> {
    let observed = read_bounded(path)?;
    let expected = format!("{}  {COMMITTED_CANARY_FILE}\n", sha256(artifact).to_hex());
    if observed != expected.as_bytes() {
        return Err("committed Linux evidence SHA-256 sidecar is invalid".into());
    }
    Ok(())
}

fn verify_binding_digest_sidecar(path: &Path, digest: Hash) -> Result<(), Box<dyn Error>> {
    let observed = read_bounded(path)?;
    let expected = format!("{digest}\n");
    if observed != expected.as_bytes() {
        return Err("committed Linux evidence binding-digest sidecar is invalid".into());
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if bytes.is_empty() || u64::try_from(bytes.len())? > MAX_ARTIFACT_BYTES {
        return Err("enterprise evidence output is outside the byte limit".into());
    }
    if path.try_exists()? {
        return Err("enterprise evidence output already exists".into());
    }
    let parent = path
        .parent()
        .ok_or("enterprise evidence output has no parent")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("enterprise evidence output has an invalid file name")?;
    let temporary = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn create_inventory(directory: &Path) {
        fs::write(directory.join(COMMITTED_CANARY_FILE), b"{}").expect("write canary fixture");
        fs::write(
            directory.join(COMMITTED_CANARY_DIGEST_FILE),
            format!("{}  {COMMITTED_CANARY_FILE}\n", sha256(b"{}").to_hex()),
        )
        .expect("write canary digest fixture");
        fs::write(
            directory.join(COMMITTED_BINDING_DIGEST_FILE),
            format!("{}\n", Hash::from_bytes([7; 32])),
        )
        .expect("write binding digest fixture");
    }

    #[test]
    fn committed_linux_evidence_inventory_rejects_missing_extra_and_non_file_entries() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        create_inventory(temporary.path());
        verify_exact_committed_file_inventory(temporary.path()).expect("exact inventory");

        fs::remove_file(temporary.path().join(COMMITTED_CANARY_DIGEST_FILE))
            .expect("remove digest");
        assert!(verify_exact_committed_file_inventory(temporary.path()).is_err());
        fs::write(
            temporary.path().join(COMMITTED_CANARY_DIGEST_FILE),
            b"digest",
        )
        .expect("restore digest");

        fs::write(temporary.path().join("extra.json"), b"{}").expect("write extra file");
        assert!(verify_exact_committed_file_inventory(temporary.path()).is_err());
        fs::remove_file(temporary.path().join("extra.json")).expect("remove extra file");

        fs::remove_file(temporary.path().join(COMMITTED_CANARY_DIGEST_FILE))
            .expect("remove digest before directory mutant");
        fs::create_dir(temporary.path().join(COMMITTED_CANARY_DIGEST_FILE))
            .expect("create directory mutant");
        assert!(verify_exact_committed_file_inventory(temporary.path()).is_err());
    }

    #[test]
    fn committed_linux_evidence_sidecars_are_exact() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        create_inventory(temporary.path());
        let artifact = read_bounded(&temporary.path().join(COMMITTED_CANARY_FILE))
            .expect("read canary fixture");
        verify_sha256_sidecar(
            &temporary.path().join(COMMITTED_CANARY_DIGEST_FILE),
            &artifact,
        )
        .expect("exact SHA-256 sidecar");
        verify_binding_digest_sidecar(
            &temporary.path().join(COMMITTED_BINDING_DIGEST_FILE),
            Hash::from_bytes([7; 32]),
        )
        .expect("exact binding sidecar");

        fs::write(
            temporary.path().join(COMMITTED_CANARY_DIGEST_FILE),
            format!("{} {COMMITTED_CANARY_FILE}\n", sha256(&artifact).to_hex()),
        )
        .expect("mutate SHA-256 sidecar");
        assert!(verify_sha256_sidecar(
            &temporary.path().join(COMMITTED_CANARY_DIGEST_FILE),
            &artifact,
        )
        .is_err());

        fs::write(
            temporary.path().join(COMMITTED_BINDING_DIGEST_FILE),
            format!("{}\n", Hash::from_bytes([8; 32])),
        )
        .expect("mutate binding sidecar");
        assert!(verify_binding_digest_sidecar(
            &temporary.path().join(COMMITTED_BINDING_DIGEST_FILE),
            Hash::from_bytes([7; 32]),
        )
        .is_err());
    }
}
