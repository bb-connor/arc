//! A standalone manifest row exactly as the prior-44 generic writer retained
//! it, before manifests belonged to a citing publication.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Retains the authenticated manifest as one canonical record with one
    /// event and one global commit, citing no publication.
    pub fn retain_prior_format_import_manifest_fixture(
        &self,
        actor: &AuthenticatedRecoveryActor,
        manifest: &SignedArtifactArchiveManifestV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProvenanceDigest, AdmissionOperationStoreError> {
        mutate(self, actor, fence, now, |tx, profile, _| {
            let digest = authenticate_import_manifest(&tx, profile, manifest)?;
            let key = manifest_key(&profile.scope, digest)?;
            if load::<SignedArtifactArchiveManifestV1>(&tx, &key)?.is_none() {
                protected::retain_prior_format_import_fixture(
                    &tx,
                    &self.serving_owner,
                    &key,
                    &scope_key(&profile.scope)?,
                    &protected::encode(manifest)?,
                )?;
            }
            Ok((tx, digest))
        })
    }

    /// Retains an origin map row naming `reference`, with no publication
    /// finalize behind it.
    pub fn retain_prior_format_import_map_fixture(
        &self,
        actor: &AuthenticatedRecoveryActor,
        digest: ProvenanceDigest,
        origin: &ArtifactVersionRefV1,
        reference: &ArtifactVersionRefV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        mutate(self, actor, fence, now, |tx, profile, _| {
            protected::retain_prior_format_import_fixture(
                &tx,
                &self.serving_owner,
                &map_key(&profile.scope, digest, origin)?,
                &scope_key(&profile.scope)?,
                &protected::encode(reference)?,
            )?;
            Ok((tx, ()))
        })
    }
}
