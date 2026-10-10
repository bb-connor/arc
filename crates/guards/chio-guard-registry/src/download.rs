//! Digest-pinned downloads with bounds applied by the transport before retention.
use crate::oci::{
    GuardOciRef, GuardRegistryClient, GuardRegistryError, PulledGuardArtifact, RegistryCredentials,
    RegistryNotFoundBehavior, RegistryRead, Result, Sha256Digest, GUARD_CONFIG_MEDIA_TYPE,
    GUARD_MANIFEST_LAYER_MEDIA_TYPE, GUARD_MODULE_LAYER_MEDIA_TYPE, GUARD_WIT_LAYER_MEDIA_TYPE,
};
use crate::{
    cache::{descriptor_for_layer, validate_descriptor, validate_top_level_manifest_shape},
    input::{MAX_ARTIFACT_BYTES, MAX_JSON_BYTES},
};
use oci_distribution::{
    client::{Config, ImageData, ImageLayer},
    manifest::{OciDescriptor, OciImageManifest},
};
use sha2::{Digest, Sha256};

impl GuardRegistryClient {
    pub(crate) async fn pull_manifest_bytes(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
        digest: &str,
        accept: &str,
    ) -> Result<Vec<u8>> {
        let _: Sha256Digest = digest.parse()?;
        let url = format!(
            "{}://{}/v2/{}/manifests/{digest}",
            self.scheme_for(reference.registry()),
            reference.registry(),
            reference.repository()
        );
        let bytes = self
            .registry_get(
                reference,
                credentials,
                RegistryRead {
                    url: &url,
                    query: &[],
                    accept,
                    max_bytes: MAX_JSON_BYTES as u64,
                    not_found: RegistryNotFoundBehavior::Error,
                },
            )
            .await?
            .ok_or(GuardRegistryError::InvalidClientConfig(
                "registry omitted manifest",
            ))?;
        let actual = format!("sha256:{:x}", Sha256::digest(&bytes));
        if actual != digest {
            return Err(GuardRegistryError::ManifestDigestMismatch {
                expected: digest.to_string(),
                actual,
            });
        }
        Ok(bytes)
    }

    pub(crate) async fn pull_bounded_artifact(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
    ) -> Result<PulledGuardArtifact> {
        let bytes = self
            .pull_manifest_bytes(
                reference,
                credentials,
                reference.digest().as_str(),
                crate::publish::GUARD_OCI_MANIFEST_MEDIA_TYPE,
            )
            .await?;
        let manifest: OciImageManifest = crate::input::external(&bytes)?;
        validate_top_level_manifest_shape(&manifest)?;
        if manifest.layers.len() != 3 {
            return Err(GuardRegistryError::LayerCount {
                actual: manifest.layers.len(),
            });
        }
        if manifest.config.media_type != GUARD_CONFIG_MEDIA_TYPE {
            return Err(GuardRegistryError::ConfigMediaType {
                expected: GUARD_CONFIG_MEDIA_TYPE,
                actual: manifest.config.media_type.clone(),
            });
        }
        let descriptors = [
            (
                "wit.bin",
                GUARD_WIT_LAYER_MEDIA_TYPE,
                descriptor_for_layer(&manifest.layers, "wit.bin", GUARD_WIT_LAYER_MEDIA_TYPE)?,
            ),
            (
                "module.wasm",
                GUARD_MODULE_LAYER_MEDIA_TYPE,
                descriptor_for_layer(
                    &manifest.layers,
                    "module.wasm",
                    GUARD_MODULE_LAYER_MEDIA_TYPE,
                )?,
            ),
            (
                "guard-manifest.json",
                GUARD_MANIFEST_LAYER_MEDIA_TYPE,
                descriptor_for_layer(
                    &manifest.layers,
                    "guard-manifest.json",
                    GUARD_MANIFEST_LAYER_MEDIA_TYPE,
                )?,
            ),
        ];
        let mut remaining = MAX_ARTIFACT_BYTES;
        for descriptor in std::iter::once(&manifest.config)
            .chain(descriptors.iter().map(|(_, _, descriptor)| *descriptor))
        {
            let size = usize::try_from(descriptor.size).map_err(|_| {
                GuardRegistryError::InvalidClientConfig("negative registry descriptor size")
            })?;
            remaining =
                remaining
                    .checked_sub(size)
                    .ok_or(GuardRegistryError::InvalidClientConfig(
                        "guard artifact exceeds aggregate byte limit",
                    ))?;
            let _: Sha256Digest = descriptor.digest.parse()?;
            if (descriptor.media_type == GUARD_CONFIG_MEDIA_TYPE
                || descriptor.media_type == GUARD_MANIFEST_LAYER_MEDIA_TYPE)
                && size > MAX_JSON_BYTES
            {
                return Err(GuardRegistryError::InvalidClientConfig(
                    "guard JSON layer exceeds byte limit",
                ));
            }
        }
        let config = Config::new(
            self.pull_descriptor(
                reference,
                credentials,
                "config.json",
                GUARD_CONFIG_MEDIA_TYPE,
                &manifest.config,
            )
            .await?,
            manifest.config.media_type.clone(),
            manifest.config.annotations.clone(),
        );
        let mut layers = Vec::with_capacity(descriptors.len());
        for (name, media, descriptor) in descriptors {
            let bytes = self
                .pull_descriptor(reference, credentials, name, media, descriptor)
                .await?;
            layers.push(ImageLayer::new(
                bytes,
                media.to_string(),
                descriptor.annotations.clone(),
            ));
        }
        PulledGuardArtifact::from_image_data(
            reference.clone(),
            ImageData {
                layers,
                config,
                digest: Some(reference.digest().as_str().to_string()),
                manifest: Some(manifest),
            },
        )
    }

    async fn pull_descriptor(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
        name: &'static str,
        expected_media_type: &'static str,
        descriptor: &OciDescriptor,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "{}://{}/v2/{}/blobs/{}",
            self.scheme_for(reference.registry()),
            reference.registry(),
            reference.repository(),
            descriptor.digest
        );
        let bound = u64::try_from(descriptor.size).map_err(|_| {
            GuardRegistryError::InvalidClientConfig("negative registry descriptor size")
        })?;
        let bytes = self
            .registry_get(
                reference,
                credentials,
                RegistryRead {
                    url: &url,
                    query: &[],
                    accept: &descriptor.media_type,
                    max_bytes: bound,
                    not_found: RegistryNotFoundBehavior::Error,
                },
            )
            .await?
            .ok_or(GuardRegistryError::InvalidClientConfig(
                "registry omitted blob",
            ))?;
        validate_descriptor(name, descriptor, expected_media_type, &bytes)?;
        Ok(bytes)
    }
}
