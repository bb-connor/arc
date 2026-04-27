//! Chio guard registry support.
//!
//! This crate owns the OCI distribution surface for `.arcguard` wasm-component
//! artifacts. It intentionally stops at registry transport and artifact shape
//! checks; Sigstore verification is wired by later M06 tickets through
//! `chio-attest-verify`.

pub mod cache;
pub mod oci;
pub mod publish;
pub mod pull;

pub use cache::{
    CachedGuardArtifact, GuardCache, GuardCacheArtifact, GuardCacheLayout, CACHE_CONFIG_JSON_FILE,
    CACHE_FILE_NAMES, CACHE_MANIFEST_JSON_FILE, CACHE_MODULE_WASM_FILE,
    CACHE_SIGSTORE_BUNDLE_JSON_FILE, CACHE_WIT_BIN_FILE,
};
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
pub use pull::{GuardPullRequest, GuardPullResponse, RESERVED_SIGSTORE_BUNDLE_JSON};
