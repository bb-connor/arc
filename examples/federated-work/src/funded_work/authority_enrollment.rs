//! Pre-agreement public authority pins; private keys remain with their own roles.
use super::{
    agreement::Policy, checkpoint_files, finding_acceptance as finding, journal::Journal,
    observer::Domain,
};
use crate::common::{self, Result};
use chio_core_types::{canonical_json_bytes, PublicKey};
use chio_store_sqlite::SqliteAuthorityStore;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pins {
    pub buyer: PublicKey,
    pub provider: PublicKey,
    pub verifier: PublicKey,
    pub checkpoint: PublicKey,
    pub status: PublicKey,
    pub governance: PublicKey,
}

impl Pins {
    pub fn validate(&self) -> Result<()> {
        let keys = [
            &self.buyer,
            &self.provider,
            &self.verifier,
            &self.checkpoint,
            &self.status,
            &self.governance,
        ];
        for (index, key) in keys.iter().enumerate() {
            if key.algorithm() != chio_core_types::crypto::SigningAlgorithm::Ed25519 {
                return Err("public authority profile requires Ed25519 keys".into());
            }
            if keys[..index].contains(key) {
                return Err("public authority roles must have distinct keys".into());
            }
        }
        Ok(())
    }
}

/// Only these two roles' private keys are required to construct public context.
pub fn context(
    governance: &Path,
    status: &Path,
    pins: &Pins,
    expires_at: u64,
) -> Result<finding::AcceptanceContext> {
    pins.validate()?;
    let governance = common::key(governance)?;
    let status = common::key(status)?;
    if governance.public_key() != pins.governance || status.public_key() != pins.status {
        return Err("context signers differ from administrative public pins".into());
    }
    finding::signed_execution_context(
        &pins.verifier,
        &pins.provider,
        pins.checkpoint.clone(),
        finding::ContextSigners {
            governance: &governance,
            status: &status,
        },
        common::now()?,
        expires_at,
    )
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Enrollment {
    schema: String,
    pins: Pins,
    context: finding::AcceptanceContext,
    domain: Domain,
}

fn validate(pins: &Pins, context: &finding::AcceptanceContext, at: u64) -> Result<()> {
    pins.validate()?;
    finding::validate_context(context, &pins.verifier, &pins.provider, at)?;
    if context.schema != finding::EXECUTION_CONTEXT_SCHEMA
        || context.governance_authority.key != pins.governance
        || context.governance_standing.status_authority.key != pins.status
        || context.profile.body.checkpoint_logs.len() != 1
        || context.profile.body.checkpoint_logs[0].signer.key != pins.checkpoint
    {
        return Err("signed execution context differs from administrative public pins".into());
    }
    Ok(())
}

/// The provider directory starts with only its own seed, provisioned by `init`.
/// An interrupted initialization is preserved and denied, never regenerated.
pub fn enroll(
    state: &Path,
    pins: &Pins,
    context: &finding::AcceptanceContext,
    domain: &Domain,
) -> Result<Policy> {
    validate(pins, context, context.profile.body.issued_at)?;
    domain.validate()?;
    if common::key(state)?.public_key() != pins.provider {
        return Err("provider seed differs from selected public identity".into());
    }
    let enrollment = Enrollment {
        schema: "chio.experimental.public-authority-enrollment.v1".into(),
        pins: pins.clone(),
        context: context.clone(),
        domain: domain.clone(),
    };
    let marker = state.join("authority-enrollment.json");
    let retry = marker.try_exists()?;
    if retry {
        let retained: Enrollment = super::evidence::read(&marker)?;
        if canonical_json_bytes(&retained)? != canonical_json_bytes(&enrollment)? {
            return Err("provider enrollment cannot replace original public authority".into());
        }
        if !state.join("funding-policy.json").try_exists()? {
            return Err(
                "provider enrollment is incomplete; original state must be preserved".into(),
            );
        }
    } else {
        validate(pins, context, common::now()?)?;
        if !fs::symlink_metadata(state)?.file_type().is_dir()
            || fs::read_dir(state)?.any(|entry| entry.map_or(true, |e| e.file_name() != "key.seed"))
        {
            return Err("public enrollment requires only the original provider seed".into());
        }
        checkpoint_files::write(&marker, &enrollment)?;
        fs::File::open(state)?.sync_all()?;
        let locks = state.join("locks");
        fs::create_dir(&locks)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locks, fs::Permissions::from_mode(0o700))?;
        }
        SqliteAuthorityStore::provision(state.join("authority.sqlite"), &locks)?;
    }
    let authority =
        SqliteAuthorityStore::open_serving(state.join("authority.sqlite"), state.join("locks"))?;
    let policy = Policy {
        authority_uuid: authority.mutation_fence().store_uuid,
        implementation_sha256: super::native::implementation_digest(),
        buyer_key: pins.buyer.clone(),
        provider_key: pins.provider.clone(),
        verifier_key: pins.verifier.clone(),
        finding_context: context.clone(),
        required_finding_facets: context.profile.body.required_facets.clone(),
        domain: domain.clone(),
    };
    if retry {
        let retained: Policy = super::evidence::read(state.join("funding-policy.json"))?;
        if canonical_json_bytes(&retained)? != canonical_json_bytes(&policy)? {
            return Err("provider policy changed original enrollment or native authority".into());
        }
        Journal::open(&state.join("funding.sqlite"), &policy)?;
    } else {
        Journal::provision(&state.join("funding.sqlite"), &policy)?;
        checkpoint_files::write(&state.join("funding-policy.json"), &policy)?;
        fs::File::open(state)?.sync_all()?;
    }
    Ok(policy)
}

pub fn context_file(
    governance: &Path,
    status: &Path,
    pins: &Path,
    expires: u64,
    output: &Path,
) -> Result<serde_json::Value> {
    let context = context(governance, status, &super::evidence::read(pins)?, expires)?;
    checkpoint_files::write(output, &context)?;
    Ok(serde_json::json!({"contextSha256":common::digest(&context)?}))
}

pub fn enroll_files(
    state: &Path,
    pins: &Path,
    context: &Path,
    domain: &Path,
) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(enroll(
        state,
        &super::evidence::read(pins)?,
        &super::evidence::read(context)?,
        &super::evidence::read(domain)?,
    )?)?)
}
