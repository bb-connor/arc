//! Chio guard registry support.
//!
//! This crate owns the OCI distribution surface for `.arcguard` wasm-component
//! artifacts. It intentionally stops at registry transport and artifact shape
//! checks; Sigstore verification is wired by later M06 tickets through
//! `chio-attest-verify`.

pub mod oci;
pub mod publish;

pub use oci::{
    GuardArtifactLayer, GuardOciRef, GuardRegistryClient, GuardRegistryConfig, GuardRegistryError,
    PulledGuardArtifact, RegistryCredentials, Sha256Digest, GUARD_ARTIFACT_MEDIA_TYPE,
    GUARD_CONFIG_MEDIA_TYPE, GUARD_MANIFEST_LAYER_MEDIA_TYPE, GUARD_MANIFEST_LAYER_ROLE,
    GUARD_MODULE_LAYER_MEDIA_TYPE, GUARD_MODULE_LAYER_ROLE, GUARD_WIT_LAYER_MEDIA_TYPE,
    GUARD_WIT_LAYER_ROLE,
};
pub use publish::{
    GuardArtifactConfig, GuardPublishArtifact, GuardPublishArtifactInput, GuardPublishRef,
    GuardPublishResponse, GUARD_LAYER_ROLE_ANNOTATION, GUARD_OCI_MANIFEST_MEDIA_TYPE,
    GUARD_SIGNER_SUBJECT_ANNOTATION, GUARD_WIT_WORLD, GUARD_WIT_WORLD_ANNOTATION,
};
