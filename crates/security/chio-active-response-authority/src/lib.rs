#![deny(unsafe_code)]

mod config;
mod runtime;
mod store;

pub use config::{
    load_runtime_config, ActiveDefenseDeploymentConfig, ActiveDefenseDeploymentStage,
    AuthorityRuntimeConfig, SecretBrokerDeploymentBinding, ACTIVE_DEFENSE_DEPLOYMENT_CONFIG_SCHEMA,
    AUTHORITY_RUNTIME_CONFIG_SCHEMA,
};
pub use runtime::AuthorityDaemonRuntime;
pub use store::{
    artifact_lookup_key, build_authority_store, compute_authority_store_digest,
    selection_lookup_key, AuthorityStore, AuthorityStoreBundle, AuthorityStoreManifest,
    PreAdmittedArtifactRecord, PreAdmittedAuthorityHandler, PreAdmittedPolicyRecord,
    AUTHORITY_STORE_BUNDLE_SCHEMA, AUTHORITY_STORE_MANIFEST_SCHEMA,
};

#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("active-response authority configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("active-response authority custody failed: {0}")]
    Custody(String),
    #[error("active-response authority store failed: {0}")]
    Store(String),
    #[error("active-response authority invariant failed: {0}")]
    Invariant(String),
    #[error("active-response authority runtime failed: {0}")]
    Runtime(String),
    #[error("active-response input was not pre-admitted")]
    NotPreAdmitted,
}

pub type Result<T> = std::result::Result<T, AuthorityError>;
