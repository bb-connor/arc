//! Signed passports for registry tests.

use super::*;
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, AttestationWindow, ChioCredentialEvidence,
};

pub(crate) type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const ISSUER_SEED: u8 = 71;

/// A passport for the subject derived from `subject_seed`, carrying one
/// reputation credential from a fixed issuer, valid for two hours from
/// `issued_at`.
pub(crate) fn passport_issued_at(subject_seed: u8, issued_at: u64) -> Fallible<AgentPassport> {
    let subject = Keypair::from_seed(&[subject_seed; 32]);
    let scorecard = chio_reputation::compute_local_scorecard(
        &subject.public_key().to_hex(),
        issued_at,
        &chio_reputation::LocalReputationCorpus::default(),
        &chio_reputation::ReputationConfig::default(),
    );
    let credential = issue_reputation_credential(
        &Keypair::from_seed(&[ISSUER_SEED; 32]),
        scorecard,
        ChioCredentialEvidence {
            query: AttestationWindow {
                since: None,
                until: issued_at,
            },
            receipt_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_roots: Vec::new(),
            receipt_log_urls: Vec::new(),
            lineage_records: 0,
            uncheckpointed_receipts: 0,
            runtime_attestation: None,
        },
        issued_at,
        issued_at + 7_200,
    )?;
    let subject_did = credential.unsigned.credential_subject.id.clone();
    Ok(build_agent_passport(&subject_did, vec![credential])?)
}
