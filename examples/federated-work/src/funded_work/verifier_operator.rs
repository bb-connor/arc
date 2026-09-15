//! Separately enrolled verifier: own claim observation, checker, key and custody.
use super::{
    agreement::{Policy, SignedAgreement},
    checkpoint_files, evidence,
    observer::{FundingSource, Observation},
    verification::{self, Checker, Decision},
    verifier_handoff as handoff,
};
use crate::common::{self, Result};
use chio_core_types::canonical_json_bytes;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

pub const ENROLLMENT_SCHEMA: &str = "chio.experimental.funded-verifier-enrollment.v1";
pub const DATABASE: &str = "verifier-custody.sqlite3";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Enrollment {
    pub schema: String,
    pub policy: Policy,
    pub agreement: SignedAgreement,
}

pub(super) fn validate_enrollment(enrollment: &Enrollment, now: u64) -> Result<()> {
    let policy = &enrollment.policy;
    if enrollment.schema != ENROLLMENT_SCHEMA
        || !super::execution_evidence::enabled(policy)
        || canonical_json_bytes(enrollment)?.len() > super::wire::MAX_ARTIFACT_BYTES
    {
        return Err("unsupported verifier enrollment".into());
    }
    enrollment.agreement.validate_public(policy)?;
    policy.domain.validate()?;
    super::finding_acceptance::validate_context(
        &policy.finding_context,
        &policy.verifier_key,
        &policy.provider_key,
        now,
    )?;
    let context = &policy.finding_context;
    super::authority_enrollment::Pins {
        buyer: policy.buyer_key.clone(),
        provider: policy.provider_key.clone(),
        verifier: policy.verifier_key.clone(),
        checkpoint: context.profile.body.checkpoint_logs[0].signer.key.clone(),
        status: context.governance_standing.status_authority.key.clone(),
        governance: context.governance_authority.key.clone(),
    }
    .validate()
}

pub fn initialize(state: &Path, enrollment: &Enrollment) -> Result<()> {
    validate_enrollment(enrollment, common::now()?)?;
    if common::key(state)?.public_key() != enrollment.policy.verifier_key {
        return Err("verifier seed differs from original public enrollment".into());
    }
    let path = state.join(DATABASE);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&path)?.sync_all()?;
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE;
        CREATE TABLE custody(id INTEGER PRIMARY KEY CHECK(id=1),enrollment BLOB NOT NULL,
            request BLOB,observation BLOB,decision BLOB,
            CHECK((request IS NULL)=(observation IS NULL) AND (request IS NULL)=(decision IS NULL)));
        CREATE TRIGGER custody_no_delete BEFORE DELETE ON custody BEGIN SELECT RAISE(ABORT,'immutable verifier custody'); END;
        CREATE TRIGGER custody_no_replace BEFORE UPDATE ON custody WHEN OLD.request IS NOT NULL OR NEW.enrollment!=OLD.enrollment OR NEW.id!=OLD.id
            BEGIN SELECT RAISE(ABORT,'immutable verifier custody'); END;
        PRAGMA user_version=1;")?;
    db.execute(
        "INSERT INTO custody(id,enrollment) VALUES(1,?1)",
        [canonical_json_bytes(enrollment)?],
    )?;
    db.execute_batch("COMMIT;")?;
    fs::File::open(state)?.sync_all()?;
    Ok(())
}

/// Read only existing custody; never create a database on service startup.
pub(super) fn enrollment(state: &Path) -> Result<Enrollment> {
    let path = state.join(DATABASE);
    if !fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err("verifier custody must be an existing regular file".into());
    }
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version: u32 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != 1 {
        return Err("verifier custody version mismatch".into());
    }
    let raw: Vec<u8> = db.query_row("SELECT enrollment FROM custody WHERE id=1", [], |r| {
        r.get(0)
    })?;
    evidence::decode(&raw)
}

struct Stored {
    enrollment: Vec<u8>,
    request: Option<Vec<u8>>,
    observation: Option<Vec<u8>>,
    decision: Option<Vec<u8>>,
}

pub fn decide(
    state: &Path,
    request: &handoff::Request,
    source: &dyn FundingSource,
    checker: &dyn Checker,
) -> Result<Decision> {
    let path = state.join(DATABASE);
    if !fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err("verifier custody must be an existing regular file".into());
    }
    let mut db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.busy_timeout(std::time::Duration::from_secs(20))?;
    db.execute_batch("PRAGMA synchronous=FULL;")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: u32 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != 1 {
        return Err("verifier custody version mismatch".into());
    }
    let stored = tx.query_row(
        "SELECT enrollment,request,observation,decision FROM custody WHERE id=1",
        [],
        |r| {
            Ok(Stored {
                enrollment: r.get(0)?,
                request: r.get(1)?,
                observation: r.get(2)?,
                decision: r.get(3)?,
            })
        },
    )?;
    let enrollment: Enrollment = evidence::decode(&stored.enrollment)?;
    let bytes = canonical_json_bytes(request)?;
    if bytes.len() > super::wire::MAX_ARTIFACT_BYTES {
        return Err("verifier request exceeds bounded profile".into());
    }
    if let (Some(original), Some(observed), Some(decision)) =
        (&stored.request, &stored.observation, &stored.decision)
    {
        if original != &bytes {
            return Err("verifier already committed another original request".into());
        }
        let decision: Decision = evidence::decode(decision)?;
        let observed: Observation = evidence::decode(observed)?;
        let at = decision.body.finding_assessment.evaluated_at;
        handoff::original(&enrollment, request, at)?;
        verification::verify_public_decision(
            &decision,
            &request.submission,
            &enrollment.policy,
            Some(&request.execution),
        )?;
        let claim = super::settlement_observer::verify(
            &enrollment.policy,
            &handoff::action(&enrollment, request)?,
            &request.claim,
            &observed,
            at,
            at,
        )?;
        handoff::verify_claim_identity(&decision, &claim)?;
        return Ok(decision);
    }
    if stored.request.is_some() || stored.observation.is_some() || stored.decision.is_some() {
        return Err("incomplete original verifier custody".into());
    }
    let original = handoff::original(&enrollment, request, common::now()?)?;
    let key = common::key(state)?;
    if key.public_key() != enrollment.policy.verifier_key {
        return Err("verifier key changed original enrollment".into());
    }
    let action = handoff::action(&enrollment, request)?;
    super::settlement::validate(&request.claim, &action, &enrollment.policy)?;
    let started = common::now()?;
    let observed = source.observe_transaction(&request.claim)?;
    let at = common::now()?;
    let claim = super::settlement_observer::verify(
        &enrollment.policy,
        &action,
        &request.claim,
        &observed,
        started,
        at,
    )?;
    let mut body = verification::assess(
        &verification::DecisionInputs {
            original: &original,
            submission: &request.submission,
            claim: &claim,
            policy: &enrollment.policy,
            agreement: &enrollment.agreement,
        },
        request.input.as_bytes(),
        &canonical_json_bytes(&request.output)?,
        checker,
        at,
    )?;
    // Checking can outlive the original claim or signed authority. Reobserve
    // after it finishes; only this fresh observation enters decision custody.
    let started = common::now()?;
    let observed = source.observe_transaction(&request.claim)?;
    let at = common::now()?;
    let claim = super::settlement_observer::verify(
        &enrollment.policy,
        &action,
        &request.claim,
        &observed,
        started,
        at,
    )?;
    let original = handoff::original(&enrollment, request, at)?;
    let (matches_native, assessment) = verification::assess_evidence(
        &verification::DecisionInputs {
            original: &original,
            submission: &request.submission,
            claim: &claim,
            policy: &enrollment.policy,
            agreement: &enrollment.agreement,
        },
        request.input.as_bytes(),
        &canonical_json_bytes(&request.output)?,
        at,
    )?;
    // The checked bytes are immutable. Refresh authority, never repeat work.
    if body.claim_transaction_hash != claim.transaction_hash
        || body.claim_block_hash != claim.block_hash
    {
        return Err("original claim changed while checking".into());
    }
    body.accepted &=
        matches_native && assessment.outcome == super::finding_acceptance::Outcome::Accepted;
    body.finding_assessment = assessment;
    let decision = evidence::sign(body, &key)?;
    let observation = canonical_json_bytes(&observed)?;
    let decision_bytes = canonical_json_bytes(&decision)?;
    if observation.len() > super::wire::MAX_ARTIFACT_BYTES
        || decision_bytes.len() > super::wire::MAX_ARTIFACT_BYTES
    {
        return Err("verifier result exceeds bounded custody".into());
    }
    tx.execute(
        "UPDATE custody SET request=?1,observation=?2,decision=?3 WHERE id=1 AND request IS NULL",
        params![bytes, observation, decision_bytes],
    )?;
    tx.commit()?;
    Ok(decision)
}

pub fn initialize_file(state: &Path, enrollment: &Path) -> Result<serde_json::Value> {
    let enrollment = evidence::read(enrollment)?;
    initialize(state, &enrollment)?;
    Ok(serde_json::json!({"enrollmentSha256":common::digest(&enrollment)?}))
}

#[cfg(unix)]
pub fn decide_file(
    state: &Path,
    request: &Path,
    socket: &Path,
    output: &Path,
) -> Result<serde_json::Value> {
    let source = super::process::SocketSource(socket.to_owned());
    let checker = verification::PythonChecker(
        std::env::var_os("CHIO_FUNDED_PYTHON")
            .unwrap_or_else(|| "python3".into())
            .into(),
    );
    let decision = decide(state, &evidence::read(request)?, &source, &checker)?;
    checkpoint_files::write(output, &decision)?;
    Ok(serde_json::json!({"decisionSha256":common::digest(&decision.body)?}))
}
