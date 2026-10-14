//! Persistent knowledge signatures use roles distinct from one-shot crossings.
use super::authority::{invalid, signed_authority};
use super::RecoveryDigestDomain;
use crate::crypto::Ed25519Backend;
use crate::{
    canonical_json_bytes, Keypair, PublicKey, Result, Signature, SigningAlgorithm, SigningBackend,
};
use alloc::vec::Vec;
use chio_security_types::{knowledge::*, recovery::*};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ARTIFACT_CERTIFICATE_SIGNATURE_DOMAIN: &str = "chio:artifact-certificate:v1";
pub const ARTIFACT_ARCHIVE_SIGNATURE_DOMAIN: &str = "chio:artifact-archive:v1";

signed_authority!(
    SignedArtifactCertificateV1,
    ArtifactCertificateV1,
    ARTIFACT_CERTIFICATE_SIGNATURE_DOMAIN,
    |body: &ArtifactCertificateV1| body.validate().map_err(|_| invalid())
);
signed_authority!(
    SignedArtifactArchiveManifestV1,
    ArtifactArchiveManifestV1,
    ARTIFACT_ARCHIVE_SIGNATURE_DOMAIN,
    |body: &ArtifactArchiveManifestV1| body.validate().map_err(|_| invalid())
);

pub fn artifact_provenance_digest(body: &ArtifactVersionV1) -> Result<ProvenanceDigest> {
    body.validate().map_err(|_| invalid())?;
    knowledge_digest(RecoveryDigestDomain::ArtifactProvenance, body)
        .map(ProvenanceDigest::from_bytes)
}
pub fn artifact_version_reference(body: &ArtifactVersionV1) -> Result<ArtifactVersionRefV1> {
    Ok(ArtifactVersionRefV1 {
        scope: body.scope.clone(),
        artifact: body.artifact.clone(),
        version: body.version.clone(),
        provenance: artifact_provenance_digest(body)?,
    })
}
pub fn artifact_archive_digest(body: &ArtifactArchiveManifestV1) -> Result<ProvenanceDigest> {
    body.validate().map_err(|_| invalid())?;
    knowledge_digest(RecoveryDigestDomain::ArtifactArchive, body).map(ProvenanceDigest::from_bytes)
}
pub fn knowledge_content_digest(bytes: &[u8]) -> CanonicalPayloadDigest {
    CanonicalPayloadDigest::from_bytes(Sha256::digest(bytes).into())
}

pub fn knowledge_semantic_influence(
    base: CanonicalPayloadDigest,
    observed: Option<&ArtifactInfluenceV1>,
) -> Result<CanonicalPayloadDigest> {
    match observed {
        None => Ok(base),
        Some(influence) => knowledge_digest(
            RecoveryDigestDomain::KnowledgeSemanticInfluence,
            &(base, influence),
        )
        .map(CanonicalPayloadDigest::from_bytes),
    }
}
pub fn knowledge_digest<T: Serialize>(domain: RecoveryDigestDomain, body: &T) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(domain.prefix());
    hash.update(canonical_json_bytes(body)?);
    Ok(hash.finalize().into())
}

/// Pure exact-content verification. Selecting the root and establishing native
/// producer authority remain responsibilities of the trusted serving owner.
pub fn verify_artifact_certificate(
    signed: &SignedArtifactCertificateV1,
    root: &PublicKey,
    metadata: &ArtifactVersionV1,
    now_unix_ms: u64,
) -> Result<()> {
    metadata.validate().map_err(|_| invalid())?;
    let body = signed.body();
    body.validate().map_err(|_| invalid())?;
    if signed.authority_key() != root
        || !signed.verify_signature()?
        || body.scope != metadata.scope
        || body.artifact != metadata.artifact
        || body.version != metadata.version
        || body.producer != metadata.producer
        || body.content != metadata.content
        || body.size_bytes != metadata.size_bytes
        || body.schema != metadata.schema
        || body.dependencies != metadata.dependencies
        || body.influence != metadata.influence
        || now_unix_ms < body.issued_at_unix_ms.get()
        || now_unix_ms >= body.valid_until_unix_ms.get()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Every dependency must precede its consumer. This bounded complete DAG check
/// neither imports authority nor accesses storage, clocks, providers or effects.
pub fn verify_artifact_archive(
    signed: &SignedArtifactArchiveManifestV1,
    root: &PublicKey,
    scope: &RecoveryScopeV1,
) -> Result<()> {
    let body = signed.body();
    body.validate().map_err(|_| invalid())?;
    if signed.authority_key() != root || !signed.verify_signature()? || &body.scope != scope {
        return Err(invalid());
    }
    let references = body
        .versions
        .as_slice()
        .iter()
        .map(artifact_version_reference)
        .collect::<Result<Vec<_>>>()?;
    if !references.contains(&body.root) {
        return Err(invalid());
    }
    for (index, version) in body.versions.as_slice().iter().enumerate() {
        if version.scope != *scope
            || !version
                .dependencies
                .as_slice()
                .iter()
                .all(|dependency| references[..index].contains(dependency))
        {
            return Err(invalid());
        }
    }
    Ok(())
}
