//! Separately enrolled custody for one checkpoint log and one original receipt.
use super::{
    checkpoint_handoff as handoff, execution_evidence::Bundle, finding_acceptance as finding,
};
use crate::common::{self, digest, Result};
use chio_core_types::{canonical_json_bytes, receipt::lineage::SignedExportEnvelope, Keypair};
use chio_finding::{
    FindingAuthorityStatus, FindingReceiptRole, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

pub const ENROLLMENT_SCHEMA: &str = "chio.experimental.execution-checkpoint-enrollment.v1";
pub const DATABASE: &str = "checkpoint-operator.sqlite3";

/// Administrative trust input, never derived from an untrusted signing request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Enrollment {
    pub schema: String,
    pub authority_uuid: String,
    pub context: finding::AcceptanceContext,
}

fn validate_enrollment(enrollment: &Enrollment, now: u64) -> Result<()> {
    if enrollment.schema != ENROLLMENT_SCHEMA
        || enrollment.authority_uuid.is_empty()
        || enrollment.authority_uuid.len() > 512
        || enrollment.authority_uuid.contains('\0')
        || enrollment.context.schema != finding::EXECUTION_CONTEXT_SCHEMA
        || canonical_json_bytes(enrollment)?.len() > super::wire::MAX_ARTIFACT_BYTES
    {
        return Err("unsupported checkpoint operator enrollment".into());
    }
    finding::validate_context(
        &enrollment.context,
        &enrollment.context.profile.body.verifier_report_signer.key,
        &enrollment.context.admitted_kernel_key,
        now,
    )
}

fn keys(state: &Path, enrollment: &Enrollment) -> Result<(Keypair, Keypair)> {
    let checkpoint = common::key(&state.join("checkpoint"))?;
    let status = common::key(&state.join("status"))?;
    let [log] = enrollment.context.profile.body.checkpoint_logs.as_slice() else {
        return Err("operator requires one pre-agreed log".into());
    };
    if checkpoint.public_key() != log.signer.key
        || status.public_key() != enrollment.context.governance_standing.status_authority.key
    {
        return Err("operator keys differ from original enrollment".into());
    }
    Ok((checkpoint, status))
}

/// Explicit bootstrap only. Signing must never create or replace lost custody.
pub fn initialize(state: &Path, enrollment: &Enrollment) -> Result<()> {
    validate_enrollment(enrollment, common::now()?)?;
    keys(state, enrollment)?;
    let path = state.join(DATABASE);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&path)?.sync_all()?;
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE;
         CREATE TABLE custody(id INTEGER PRIMARY KEY CHECK(id=1),
            enrollment BLOB NOT NULL, request BLOB, response BLOB,
            CHECK((request IS NULL) = (response IS NULL)));
         CREATE TRIGGER custody_no_delete BEFORE DELETE ON custody
            BEGIN SELECT RAISE(ABORT, 'checkpoint custody is immutable'); END;
         CREATE TRIGGER custody_no_replace BEFORE UPDATE ON custody
            WHEN OLD.request IS NOT NULL OR NEW.enrollment != OLD.enrollment OR NEW.id != OLD.id
            BEGIN SELECT RAISE(ABORT, 'checkpoint custody is immutable'); END;
         PRAGMA user_version=1;",
    )?;
    connection.execute(
        "INSERT INTO custody(id,enrollment) VALUES(1,?1)",
        [canonical_json_bytes(enrollment)?],
    )?;
    connection.execute_batch("COMMIT;")?;
    fs::File::open(state)?.sync_all()?;
    Ok(())
}

fn validate_request(request: &handoff::Request, enrollment: &Enrollment) -> Result<()> {
    if request.schema != handoff::REQUEST_SCHEMA
        || request.context_sha256 != digest(&enrollment.context)?
        || canonical_json_bytes(request)?.len() > super::wire::MAX_ARTIFACT_BYTES
    {
        return Err("checkpoint request changes enrolled context".into());
    }
    let metadata =
        chio_core_types::receipt::execution_evidence::verify_pre_settlement_execution_receipt(
            &request.receipt,
            std::slice::from_ref(&enrollment.context.admitted_kernel_key),
        )?;
    if metadata.authority_uuid != enrollment.authority_uuid {
        return Err("checkpoint request changes enrolled native authority".into());
    }
    Ok(())
}

/// One serialized first response, committed before publication. Cached responses
/// survive key removal and retain their historical standing without refreshing it.
pub fn sign(state: &Path, request: &handoff::Request) -> Result<Bundle> {
    let path = state.join(DATABASE);
    if !fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err("operator custody must be an existing regular file".into());
    }
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA synchronous=FULL;")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: u32 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != 1 {
        return Err("operator custody version mismatch".into());
    }
    let (enrolled, retained_request, retained_response): (
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) = tx.query_row(
        "SELECT enrollment,request,response FROM custody WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let enrollment: Enrollment = super::evidence::decode(&enrolled)?;
    validate_request(request, &enrollment)?;
    let bytes = canonical_json_bytes(request)?;
    if let (Some(original), Some(response)) = (&retained_request, &retained_response) {
        if original != &bytes {
            return Err("checkpoint log already committed another request".into());
        }
        let bundle: Bundle = super::evidence::decode(response)?;
        let at = handoff::observed_at(&bundle)?;
        validate_enrollment(&enrollment, at)?;
        validate_response(&bundle, request, &enrollment, at)?;
        return Ok(bundle);
    }
    if retained_request.is_some() || retained_response.is_some() {
        return Err("operator custody lost part of its original response".into());
    }
    validate_enrollment(&enrollment, common::now()?)?;
    let (checkpoint_key, status_key) = keys(state, &enrollment)?;
    let receipt = request.receipt.clone();
    let leaves = [canonical_json_bytes(&receipt)?];
    let checkpoint = chio_kernel::checkpoint::build_checkpoint(1, 1, 1, &leaves, &checkpoint_key)?;
    let tree = chio_core_types::merkle::MerkleTree::from_leaves(&leaves)?;
    let inclusion = chio_kernel::checkpoint::build_inclusion_proof(&tree, 0, 1, 1)?;
    let checkpoints = vec![checkpoint];
    let transparency = chio_kernel::checkpoint::validate_checkpoint_transparency(&checkpoints)?;
    let profile = &enrollment.context.profile.body;
    let production = profile
        .receipt_signers
        .iter()
        .find(|r| r.role == FindingReceiptRole::Production)
        .ok_or("operator production authority missing")?;
    let observed_at = common::now()?;
    let signer_statuses = [&production.policy, &profile.checkpoint_logs[0].signer]
        .into_iter()
        .map(|policy| {
            SignedExportEnvelope::sign(
                FindingAuthorityStatus {
                    schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.into(),
                    status_ref: policy.revocation_status_ref.clone(),
                    authority_id: policy.authority_id.clone(),
                    key: policy.key.clone(),
                    key_epoch: policy.key_epoch,
                    revoked_from: None,
                    observed_at,
                },
                &status_key,
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let bundle = Bundle {
        schema: super::execution_evidence::BUNDLE_SCHEMA.into(),
        receipt,
        checkpoints,
        inclusion,
        transparency,
        signer_statuses,
    };
    validate_response(&bundle, request, &enrollment, common::now()?)?;
    tx.execute(
        "UPDATE custody SET request=?1,response=?2 WHERE id=1 AND request IS NULL",
        params![bytes, canonical_json_bytes(&bundle)?],
    )?;
    tx.commit()?;
    Ok(bundle)
}

fn validate_response(
    bundle: &Bundle,
    request: &handoff::Request,
    enrollment: &Enrollment,
    now: u64,
) -> Result<()> {
    if canonical_json_bytes(&bundle.receipt)? != canonical_json_bytes(&request.receipt)? {
        return Err("operator response differs from committed request".into());
    }
    handoff::validate_authorities(&enrollment.context, bundle, now)
}

/// Files use the same bounded canonical decoder as all funded-work artifacts.
pub fn initialize_file(state: &Path, enrollment: &Path) -> Result<serde_json::Value> {
    let enrollment: Enrollment = super::evidence::read(enrollment)?;
    initialize(state, &enrollment)?;
    Ok(
        serde_json::json!({"contextSha256":digest(&enrollment.context)?, "authorityUuid":enrollment.authority_uuid}),
    )
}

pub fn sign_file(state: &Path, request: &Path, response: &Path) -> Result<serde_json::Value> {
    let request: handoff::Request = super::evidence::read(request)?;
    let bundle = sign(state, &request)?;
    let bytes = canonical_json_bytes(&bundle)?;
    super::checkpoint_files::write(response, &bundle)?;
    Ok(
        serde_json::json!({"bundleSha256":chio_core_types::sha256_hex(&bytes), "financialBacking":false}),
    )
}
