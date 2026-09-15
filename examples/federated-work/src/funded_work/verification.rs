//! A decision is minted only after exact Finding, custody and independent W0 checks.
use super::{
    agreement::Policy,
    evidence::{self, Binding, Evidence, Signed, Submission},
    journal::Journal,
};
use crate::common::{digest, Result};
use chio_core_types::{canonical_json_bytes, Keypair};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionBody {
    pub schema: String,
    pub binding: Binding,
    pub commitment: String,
    pub finding_id: String,
    pub checker_sha256: String,
    pub claim_transaction_hash: String,
    pub claim_block_hash: String,
    pub accepted: bool,
    pub finding_assessment: super::finding_acceptance::Assessment,
}
pub type Decision = Signed<DecisionBody>;

pub trait Checker {
    fn check(&self, input: &str) -> Result<Value>;
}

pub struct PythonChecker(pub PathBuf);

const SOURCES: &[(&str, &[u8])] = &[
    (
        "../funded-work/native_checker.py",
        include_bytes!("../../../funded-work/native_checker.py"),
    ),
    (
        "../funded-work/reference_checker.py",
        include_bytes!("../../../funded-work/reference_checker.py"),
    ),
    (
        "../funded-work/checker-profile.json",
        include_bytes!("../../../funded-work/checker-profile.json"),
    ),
    (
        "python_buyer/review.py",
        include_bytes!("../../python_buyer/review.py"),
    ),
    (
        "python_buyer/protocol.py",
        include_bytes!("../../python_buyer/protocol.py"),
    ),
    (
        "python_buyer/subcontract.py",
        include_bytes!("../../python_buyer/subcontract.py"),
    ),
];

pub fn checker_digest() -> String {
    chio_core_types::sha256_hex(
        &SOURCES
            .iter()
            .flat_map(|(_, bytes)| *bytes)
            .copied()
            .collect::<Vec<_>>(),
    )
}

impl Checker for PythonChecker {
    fn check(&self, input: &str) -> Result<Value> {
        if input.len() > 65536 {
            return Err("checker input exceeds profile".into());
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for (name, pinned) in SOURCES {
            if std::fs::read(root.join(name))? != *pinned {
                return Err("independent checker source differs from pinned implementation".into());
            }
        }
        let mut child = Command::new(&self.0)
            .args(["-I", "-B"])
            .arg(root.join("../funded-work/native_checker.py"))
            .env_remove("PYTHONPATH")
            .env_remove("PYTHONHOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or("checker stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("checker stdout unavailable")?;
        let input = input.as_bytes().to_vec();
        let writer = std::thread::spawn(move || -> std::io::Result<()> { stdin.write_all(&input) });
        let (send, receive) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout.take(65537).read_to_end(&mut bytes).map(|_| bytes);
            let _ = send.send(result);
        });
        let read = receive.recv_timeout(Duration::from_secs(15));
        // A child can close stdout and continue running. Poll its actual exit
        // under the same bounded cleanup discipline rather than wait forever.
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if read.is_err() || std::time::Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if status.is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
        writer.join().map_err(|_| "checker writer panicked")??;
        reader.join().map_err(|_| "checker reader panicked")?;
        if !status.is_some_and(|status| status.success()) {
            return Err("independent checker unavailable".into());
        }
        let bytes = read??;
        if bytes.len() > 65536 {
            return Err("checker output exceeds profile".into());
        }
        evidence::decode(&bytes)
    }
}

pub struct Verifier<'a> {
    pub policy: &'a Policy,
    pub custody: &'a Journal,
    pub key: &'a Keypair,
    pub checker: &'a dyn Checker,
}

pub fn decide(
    original: &Evidence,
    submission: &Submission,
    claim: &super::settlement_observer::Verified,
    verifier: &Verifier<'_>,
) -> Result<Decision> {
    let Verifier {
        policy,
        custody,
        key,
        checker,
    } = verifier;
    let entry = custody
        .by_operation(&original.binding.operation_id)?
        .ok_or("original verification entry missing")?;
    let terms = entry.agreement.validate(policy, &entry.request)?;
    if claim.action != super::settlement::Action::Submit
        || claim.allocation_id != original.binding.allocation_id
        || claim.commitment.as_deref() != Some(&format!("0x{}", digest(submission)?))
        || claim.chain_time <= terms.challenge_until
        || claim.chain_time > terms.resolve_by
    {
        return Err(
            "decision requires the observed original claim in its resolution window".into(),
        );
    }
    if key.public_key() != policy.verifier_key || key.public_key() == policy.provider_key {
        return Err("wrong independent decision signer".into());
    }
    let raw = canonical_json_bytes(submission)?;
    let matches_native = evidence::verify(&raw, original, policy, custody)?;
    let finding_assessment = super::finding_acceptance::evaluate(
        &canonical_json_bytes(&submission.body.finding)?,
        &policy.finding_context,
        &entry.agreement.body.finding_context_sha256,
        &entry.agreement.body.required_finding_facets,
        crate::common::now()?,
    )?;
    use super::finding_acceptance::Outcome;
    if matches!(
        finding_assessment.outcome,
        Outcome::Unavailable | Outcome::Unsupported
    ) {
        return Err(format!(
            "Finding requirements cannot authorize a decision: {:?}",
            finding_assessment.outcome
        )
        .into());
    }
    let checked = checker.check(&original.input)?;
    let retrieved = custody.blob(&submission.body.output_sha256)?;
    let decision = evidence::sign(
        DecisionBody {
            schema: "chio.experimental.native-funded-decision.v2".into(),
            binding: original.binding.clone(),
            commitment: format!("0x{}", digest(submission)?),
            finding_id: submission.body.finding.finding_id.clone(),
            checker_sha256: checker_digest(),
            accepted: finding_assessment.outcome == Outcome::Accepted
                && matches_native
                && retrieved == canonical_json_bytes(&checked)?,
            finding_assessment,
            claim_transaction_hash: claim.transaction_hash.clone(),
            claim_block_hash: claim.block_hash.clone(),
        },
        key,
    )?;
    custody.retain(&original.binding.allocation_id, "decision", &decision)?;
    Ok(decision)
}

pub fn verify_decision(
    decision: &Decision,
    submission: &Submission,
    policy: &Policy,
) -> Result<()> {
    let body = &decision.body;
    super::wire::decision(decision)?;
    super::finding_acceptance::validate_assessment(
        &body.finding_assessment,
        &submission.body.finding,
        &policy.finding_context,
        &policy.required_finding_facets,
    )?;
    use super::finding_acceptance::Outcome;
    if matches!(
        body.finding_assessment.outcome,
        Outcome::Unavailable | Outcome::Unsupported
    ) || (body.accepted && body.finding_assessment.outcome != Outcome::Accepted)
    {
        return Err("decision contradicts required Finding assessment".into());
    }
    if body.schema != "chio.experimental.native-funded-decision.v2"
        || body.binding != submission.body.binding
        || body.commitment != format!("0x{}", digest(submission)?)
        || body.finding_id != submission.body.finding.finding_id
        || body.checker_sha256 != checker_digest()
        || !policy
            .verifier_key
            .verify_strict(&canonical_json_bytes(body)?, &decision.signature)
    {
        return Err("decision changed original verified submission or verifier authority".into());
    }
    super::allocation::hash(&body.claim_transaction_hash)?;
    super::allocation::hash(&body.claim_block_hash)?;
    Ok(())
}
