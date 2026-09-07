//! Stable control-plane errors and structured diagnostic projection.

use chio_errors::_generated::error_codes::{
    ATTEST_PROVENANCE_MISSING, CAPABILITY_SCOPE_EXCEEDED, CAPABILITY_SUBJECT_MISMATCH, CLI_IO,
    CLI_JSON, CLI_OTHER, CLI_YAML, GUARD_DENIED, GUARD_WASM_TRAP, MANIFEST_SCHEMA_INVALID,
    MANIFEST_SIGNATURE_INVALID, POLICY_CONSTRAINT_INVALID, POLICY_DECISION_DENIED,
    PROVIDER_TOOL_SERVER_ERROR, REPLAY_DETERMINISTIC_MISMATCH, REPLAY_FIXTURE_DRIFT,
    REPLAY_TRACE_NOT_FOUND, TRANSPORT_HTTP_FAILED, TRANSPORT_INVALID_REQUEST_SHAPE,
};
use chio_errors::{ChioError, ErrorCodeSpec};
use chio_kernel::transport::TransportError;
use chio_kernel::StructuredErrorReport;

use crate::policy;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Core(#[from] chio_core::error::Error),

    #[error("{0}")]
    Policy(#[from] policy::PolicyError),

    #[error("adapter error: {0}")]
    Adapter(#[from] chio_mcp_adapter::edge::AdapterError),

    #[error("kernel error: {0}")]
    Kernel(#[from] chio_kernel::KernelError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] chio_kernel::CheckpointError),

    #[error("evidence export error: {0}")]
    EvidenceExport(#[from] chio_kernel::EvidenceExportError),

    #[error("credential error: {0}")]
    Credential(#[from] chio_credentials::CredentialError),

    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] chio_kernel::ReceiptStoreError),

    #[error("conformance load error: {0}")]
    ConformanceLoad(#[from] chio_conformance::LoadError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] chio_kernel::RevocationStoreError),

    #[error("authority store error: {0}")]
    AuthorityStore(#[from] chio_kernel::AuthorityStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] chio_kernel::BudgetStoreError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("sqlite serving-owner error: {0}")]
    SqliteServingOwner(#[from] chio_store_sqlite::SqliteServingOwnerError),

    #[error("durable admission error: {0}")]
    DurableAdmission(#[from] chio_kernel::admission_operation::AdmissionOperationError),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    Chio(#[from] ChioError),

    #[error("{0}")]
    Other(String),
}

impl CliError {
    pub fn registry_error(spec: &'static ErrorCodeSpec, message: impl Into<String>) -> Self {
        Self::Chio(ChioError::from_spec(spec, message))
    }

    pub fn capability_error(message: impl Into<String>) -> Self {
        Self::cli_other_error(message)
    }

    pub fn capability_scope_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CAPABILITY_SCOPE_EXCEEDED, message)
    }

    pub fn capability_subject_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CAPABILITY_SUBJECT_MISMATCH, message)
    }

    pub fn policy_error(message: impl Into<String>) -> Self {
        Self::registry_error(&POLICY_DECISION_DENIED, message)
    }

    pub fn policy_constraint_error(message: impl Into<String>) -> Self {
        Self::registry_error(&POLICY_CONSTRAINT_INVALID, message)
    }

    pub fn guard_error(message: impl Into<String>) -> Self {
        Self::registry_error(&GUARD_DENIED, message)
    }

    pub fn guard_wasm_error(message: impl Into<String>) -> Self {
        Self::registry_error(&GUARD_WASM_TRAP, message)
    }

    pub fn replay_trace_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_TRACE_NOT_FOUND, message)
    }

    pub fn replay_mismatch_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_DETERMINISTIC_MISMATCH, message)
    }

    pub fn replay_fixture_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_FIXTURE_DRIFT, message)
    }

    pub fn provider_error(message: impl Into<String>) -> Self {
        Self::registry_error(&PROVIDER_TOOL_SERVER_ERROR, message)
    }

    pub fn attest_error(message: impl Into<String>) -> Self {
        Self::registry_error(&ATTEST_PROVENANCE_MISSING, message)
    }

    pub fn manifest_schema_error(message: impl Into<String>) -> Self {
        Self::registry_error(&MANIFEST_SCHEMA_INVALID, message)
    }

    pub fn manifest_signature_error(message: impl Into<String>) -> Self {
        Self::registry_error(&MANIFEST_SIGNATURE_INVALID, message)
    }

    pub fn transport_error(message: impl Into<String>) -> Self {
        Self::registry_error(&TRANSPORT_HTTP_FAILED, message)
    }

    pub fn transport_shape_error(message: impl Into<String>) -> Self {
        Self::registry_error(&TRANSPORT_INVALID_REQUEST_SHAPE, message)
    }

    pub fn cli_io_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_IO, message)
    }

    pub fn cli_json_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_JSON, message)
    }

    pub fn cli_yaml_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_YAML, message)
    }

    pub fn cli_other_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_OTHER, message)
    }

    fn report_with_context(
        &self,
        code: &str,
        context: serde_json::Value,
        suggested_fix: impl Into<String>,
    ) -> StructuredErrorReport {
        StructuredErrorReport::new(code, self.to_string(), context, suggested_fix)
    }

    pub fn report(&self) -> StructuredErrorReport {
        match self {
            Self::Core(error) => self.report_with_context(
                "CHIO-CLI-CORE",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the Chio artifact or request payload that triggered the core validation failure and correct it before retrying.",
            ),
            Self::Policy(error) => self.report_with_context(
                "CHIO-CLI-POLICY",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the policy file contents or path so the requested command can load a valid policy document.",
            ),
            Self::Adapter(error) => self.report_with_context(
                "CHIO-CLI-ADAPTER",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the MCP adapter configuration and upstream server compatibility before retrying.",
            ),
            Self::Kernel(error) => error.report(),
            Self::Checkpoint(error) => self.report_with_context(
                "CHIO-CLI-CHECKPOINT",
                serde_json::json!({ "source": error.to_string() }),
                "Check the checkpoint input and configured receipt store, then retry once the checkpoint lane is valid.",
            ),
            Self::EvidenceExport(error) => self.report_with_context(
                "CHIO-CLI-EVIDENCE-EXPORT",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the evidence export inputs, output path, and receipt-store state before retrying.",
            ),
            Self::Credential(error) => self.report_with_context(
                "CHIO-CLI-CREDENTIAL",
                serde_json::json!({ "source": error.to_string() }),
                "Validate the credential, issuer, and subject inputs before retrying the command.",
            ),
            Self::ReceiptStore(error) => self.report_with_context(
                "CHIO-CLI-RECEIPT-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured receipt store path, permissions, and schema health before retrying.",
            ),
            Self::ConformanceLoad(error) => self.report_with_context(
                "CHIO-CLI-CONFORMANCE-LOAD",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the conformance corpus path or file contents so the requested scenarios can be loaded successfully.",
            ),
            Self::RevocationStore(error) => self.report_with_context(
                "CHIO-CLI-REVOCATION-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured revocation store path, permissions, and schema health before retrying.",
            ),
            Self::AuthorityStore(error) => self.report_with_context(
                "CHIO-CLI-AUTHORITY-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured authority store path, permissions, and schema health before retrying.",
            ),
            Self::BudgetStore(error) => self.report_with_context(
                "CHIO-CLI-BUDGET-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured budget store path, permissions, and schema health before retrying.",
            ),
            Self::Sqlite(error) => self.report_with_context(
                "CHIO-CLI-SQLITE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the SQLite path, file permissions, and database schema state before retrying.",
            ),
            Self::SqliteServingOwner(error) => self.report_with_context(
                "CHIO-CLI-SQLITE-SERVING-OWNER",
                serde_json::json!({ "source": error.to_string() }),
                "Check the session database path, its serving lock directory, and whether another process already owns the database.",
            ),
            Self::DurableAdmission(error) => self.report_with_context(
                "CHIO-CLI-DURABLE-ADMISSION",
                serde_json::json!({ "source": error.to_string() }),
                "Configure a durable session database and retry after its admission state is available and fenced.",
            ),
            Self::Transport(error) => self.report_with_context(
                "CHIO-CLI-TRANSPORT",
                serde_json::json!({ "source": error.to_string() }),
                "Verify the remote endpoint or subprocess transport is reachable and speaking the expected protocol.",
            ),
            Self::Io(error) => self.report_with_context(
                "CHIO-CLI-IO",
                serde_json::json!({ "source": error.to_string() }),
                "Check file paths, permissions, and parent directories before retrying.",
            ),
            Self::Json(error) => self.report_with_context(
                "CHIO-CLI-JSON",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the JSON input so it is syntactically valid and matches the expected Chio schema.",
            ),
            Self::Yaml(error) => self.report_with_context(
                "CHIO-CLI-YAML",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the YAML syntax or schema mismatch in the provided configuration before retrying.",
            ),
            Self::Reqwest(error) => self.report_with_context(
                "CHIO-CLI-HTTP",
                serde_json::json!({ "source": error.to_string() }),
                "Check network reachability, TLS settings, and remote endpoint availability before retrying.",
            ),
            Self::Chio(error) => {
                let diagnostic = error.diagnostic();
                let spec = diagnostic.registry_spec();
                StructuredErrorReport::new(
                    diagnostic.code().as_str(),
                    diagnostic.message(),
                    serde_json::json!({
                        "domain": diagnostic.domain().as_str(),
                        "severity": diagnostic.severity().as_str(),
                        "string_code": spec.map(|entry| entry.string_code),
                        "stability": spec.map(|entry| entry.stability),
                    }),
                    diagnostic
                        .help()
                        .or_else(|| spec.map(|entry| entry.help))
                        .unwrap_or(
                            "Inspect the Chio diagnostic and retry after correcting the request.",
                        ),
                )
            }
            Self::Other(message) => self.report_with_context(
                "CHIO-CLI-OTHER",
                serde_json::json!({ "detail": message }),
                "Read the error detail, correct the conflicting inputs or missing prerequisite, and retry the command.",
            ),
        }
    }
}
