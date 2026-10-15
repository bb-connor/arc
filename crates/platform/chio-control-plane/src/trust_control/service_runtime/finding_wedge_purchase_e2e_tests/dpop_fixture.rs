use super::{unix_timestamp_now, AnyError, SERVER_ID};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::Keypair;
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_kernel::{DpopConfig, DpopProof, DpopProofBody, DPOP_SCHEMA};
use chio_store_sqlite::SqliteAuthorityStore;

pub(super) fn fixture_dpop_authority(
    authority: &SqliteAuthorityStore,
) -> Result<chio_kernel::dpop::authority::DpopReplayAuthority, AnyError> {
    Ok(crate::initialize_local_dpop_authority(
        authority,
        &chio_kernel::admission_operation::AdmissionIdentifier::try_new(
            "dpop_authority",
            "finding-wedge-dpop",
        )?,
        &DpopConfig::default(),
        chio_test_support::clock::clock(),
    )?)
}

pub(super) fn dpop_proof(
    authority: &SqliteAuthorityStore,
    capability: &CapabilityToken,
    buyer: &Keypair,
    tool_name: &str,
    arguments: &serde_json::Value,
    nonce: &str,
) -> Result<DpopProof, AnyError> {
    dpop_proof_at(
        authority,
        capability,
        buyer,
        tool_name,
        arguments,
        nonce,
        unix_timestamp_now().unwrap_or_else(|error| panic!("trusted fixture clock: {error}")),
    )
}

pub(super) fn dpop_proof_at(
    authority: &SqliteAuthorityStore,
    capability: &CapabilityToken,
    buyer: &Keypair,
    tool_name: &str,
    arguments: &serde_json::Value,
    nonce: &str,
    issued_at: u64,
) -> Result<DpopProof, AnyError> {
    Ok(DpopProof::sign(
        DpopProofBody {
            replay_authority: fixture_dpop_authority(authority)?,
            schema: DPOP_SCHEMA.to_string(),
            capability_id: capability.id.clone(),
            tool_server: SERVER_ID.to_string(),
            tool_name: tool_name.to_string(),
            action_hash: sha256_hex(&canonical_json_bytes(arguments)?),
            nonce: nonce.to_string(),
            issued_at,
            agent_key: buyer.public_key(),
        },
        buyer,
    )?)
}
