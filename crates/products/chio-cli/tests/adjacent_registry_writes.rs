#![cfg(target_os = "linux")]

//! The shipped local CLI writers share the registry file lock with HTTP and
//! other processes. A refused overlap leaves bytes and single-use state intact.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Output};

use chio_control_plane::passport_verifier::{
    PassportIssuanceOfferRegistry, VerifierPolicyRegistry,
};
use chio_core::Keypair;
use chio_credentials::{PassportVerifierPolicy, SignedPassportVerifierPolicy};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn run(args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(args)
        .output()?)
}

fn text(path: &Path) -> TestResult<&str> {
    path.to_str().ok_or_else(|| "non-UTF8 test path".into())
}

fn successful(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn busy(output: &Output) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("being written by another writer"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a refused write published an outcome"
    );
}

/// A different process's lock descriptor excludes all shipped local writers.
fn hold(path: &Path) -> TestResult<File> {
    let name = path
        .file_name()
        .ok_or("registry has no filename")?
        .to_string_lossy();
    let lock = path.with_file_name(format!(".{name}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)?;
    Ok(file)
}

fn policy(id: &str) -> TestResult<SignedPassportVerifierPolicy> {
    let now = chio_test_support::clock::unix_seconds();
    Ok(chio_credentials::create_signed_passport_verifier_policy(
        &Keypair::from_seed(&[41; 32]),
        id,
        "verifier",
        now,
        now + 3_600,
        PassportVerifierPolicy::default(),
    )?)
}

#[test]
fn local_policy_create_upsert_and_delete_observe_cross_process_busy_then_progress() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("policies.json");
    let input = directory.path().join("unrelated.json");
    let raw = directory.path().join("policy.yaml");
    let output = directory.path().join("created.json");
    let seed = directory.path().join("verifier.seed");
    let removed = policy("removed")?;
    let unrelated = policy("unrelated")?;
    let mut registry = VerifierPolicyRegistry::default();
    registry.policies.insert("removed".to_string(), removed);
    fs::write(&path, serde_json::to_vec(&registry)?)?;
    fs::write(&input, serde_json::to_vec(&unrelated)?)?;
    fs::write(
        &raw,
        serde_yml::to_string(&PassportVerifierPolicy::default())?,
    )?;
    let create = [
        "--json",
        "passport",
        "policy",
        "create",
        "--policy-id",
        "created",
        "--verifier",
        "verifier",
        "--policy",
        text(&raw)?,
        "--output",
        text(&output)?,
        "--signing-seed-file",
        text(&seed)?,
        "--expires-at",
        "1900000000",
        "--verifier-policies-file",
        text(&path)?,
    ];
    let upsert = [
        "--json",
        "passport",
        "policy",
        "upsert",
        "--input",
        text(&input)?,
        "--verifier-policies-file",
        text(&path)?,
    ];
    let delete = [
        "--json",
        "passport",
        "policy",
        "delete",
        "--policy-id",
        "removed",
        "--verifier-policies-file",
        text(&path)?,
    ];
    let before = fs::read(&path)?;
    let held = hold(&path)?;
    busy(&run(&create)?);
    busy(&run(&upsert)?);
    busy(&run(&delete)?);
    assert_eq!(fs::read(&path)?, before);
    drop(held);
    successful(&run(&create)?);
    successful(&run(&delete)?);
    successful(&run(&upsert)?);
    let reopened = VerifierPolicyRegistry::load(&path)?;
    assert!(reopened.get("removed").is_none());
    assert_eq!(reopened.get("unrelated"), Some(&unrelated));
    assert!(reopened.get("created").is_some());
    Ok(())
}

fn passport() -> TestResult<chio_credentials::AgentPassport> {
    let now = chio_test_support::clock::unix_seconds();
    let subject = Keypair::from_seed(&[81; 32]);
    let scorecard = chio_reputation::compute_local_scorecard(
        &subject.public_key().to_hex(),
        now,
        &chio_reputation::LocalReputationCorpus::default(),
        &chio_reputation::ReputationConfig::default(),
    );
    let credential = chio_credentials::issue_reputation_credential(
        &Keypair::from_seed(&[82; 32]),
        scorecard,
        chio_credentials::ChioCredentialEvidence {
            query: chio_credentials::AttestationWindow {
                since: None,
                until: now,
            },
            receipt_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_roots: Vec::new(),
            receipt_log_urls: Vec::new(),
            lineage_records: 0,
            uncheckpointed_receipts: 0,
            runtime_attestation: None,
        },
        now,
        now + 3_600,
    )?;
    let subject = credential.unsigned.credential_subject.id.clone();
    Ok(chio_credentials::build_agent_passport(
        &subject,
        vec![credential],
    )?)
}

#[test]
fn local_offer_token_and_credential_writers_observe_busy_and_keep_consumption_after_unrelated_update(
) -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("offers.json");
    let passport_path = directory.path().join("passport.json");
    let offer = directory.path().join("offer.json");
    let token = directory.path().join("token.json");
    fs::write(&passport_path, serde_json::to_vec(&passport()?)?)?;
    let create = [
        "--json",
        "passport",
        "issuance",
        "offer",
        "--input",
        text(&passport_path)?,
        "--output",
        text(&offer)?,
        "--issuer-url",
        "https://issuer.example.test",
        "--passport-issuance-offers-file",
        text(&path)?,
    ];
    successful(&run(&create)?);
    let redeem_token = [
        "--json",
        "passport",
        "issuance",
        "token",
        "--offer",
        text(&offer)?,
        "--output",
        text(&token)?,
        "--passport-issuance-offers-file",
        text(&path)?,
    ];
    let before = fs::read(&path)?;
    let held = hold(&path)?;
    busy(&run(&create)?);
    busy(&run(&redeem_token)?);
    assert_eq!(fs::read(&path)?, before);
    drop(held);
    successful(&run(&redeem_token)?);
    let redeem_credential = [
        "--json",
        "passport",
        "issuance",
        "credential",
        "--offer",
        text(&offer)?,
        "--token",
        text(&token)?,
        "--passport-issuance-offers-file",
        text(&path)?,
    ];
    let before = fs::read(&path)?;
    let held = hold(&path)?;
    busy(&run(&redeem_credential)?);
    assert_eq!(fs::read(&path)?, before);
    drop(held);
    successful(&run(&redeem_credential)?);
    let spent = run(&redeem_credential)?;
    assert!(!spent.status.success(), "credential was issued twice");
    assert!(spent.stdout.is_empty());
    let mut create_unrelated = create;
    let unrelated_offer = directory.path().join("unrelated-offer.json");
    // Keep the original wallet offer file so the replay uses the spent code.
    *create_unrelated
        .get_mut(7)
        .ok_or("missing offer output argument")? = text(&unrelated_offer)?;
    successful(&run(&create_unrelated)?);
    let reopened = PassportIssuanceOfferRegistry::load(&path)?;
    assert_eq!(reopened.offers.len(), 1);
    let replay = run(&redeem_token)?;
    assert!(
        !replay.status.success(),
        "an unrelated write restored a spent code"
    );
    assert!(replay.stdout.is_empty());
    Ok(())
}
