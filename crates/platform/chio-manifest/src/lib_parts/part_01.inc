use chio_core::crypto::{Keypair, PublicKey, Signature};
pub use chio_core::manifest::{
    DeclassificationPurpose, LatencyHint, PricingModel, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolFlowValidationError, ToolPricing,
};
use serde::{Deserialize, Serialize};

pub use validation::validate_manifest;
pub use admission::{
    load_existing_verified_manifest_registry, AdmittedToolSecurity, AuthoritativeToolPolicy,
    RuntimeToolTopology, VerifiedCageManifest, VerifiedManifestAdmissionError,
    VerifiedManifestLoadError, VerifiedManifestRegistry,
};
pub use input_schema::{
    trusted_server_tool_input_schema, ToolInputSchemaError, ToolInputSchemaValidator,
    VerifiedManifestInvocationError, SERVER_TOOL_INPUT_SCHEMA_CATALOG_VERSION,
};

/// Supported Chio tool-manifest schema identifier.
pub const TOOL_MANIFEST_SCHEMA: &str = chio_core::signed_artifact::CHIO_TOOL_MANIFEST_V2_SCHEMA;
const LEGACY_TOOL_MANIFEST_SCHEMA: &str = "chio.manifest.v1";

fn deserialize_present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Err(serde::de::Error::custom(
            "explicit null is not a canonical manifest representation",
        ));
    }
    T::deserialize(value)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

fn deserialize_non_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.is_empty() {
        Err(serde::de::Error::custom(
            "explicit empty array is not a canonical manifest representation",
        ))
    } else {
        Ok(values)
    }
}

/// A signed declaration of the tools a Chio tool server provides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    /// Schema version. Must equal [`TOOL_MANIFEST_SCHEMA`].
    pub schema: String,

    /// The server's unique identifier.
    pub server_id: chio_core::ServerId,

    /// Human-readable server name.
    pub name: String,

    /// Server description.
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,

    /// Semantic version of this tool server.
    pub version: String,

    /// The tools this server provides.
    pub tools: Vec<ToolDefinition>,

    /// Provider-native server tools this manifest explicitly allows.
    ///
    /// Anthropic server tools are larger trust-boundary surfaces than regular
    /// client-hosted tools. They default to deny unless the manifest lists the
    /// stable logical tool name here.
    #[serde(
        default,
        deserialize_with = "deserialize_non_empty_vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub server_tools: Vec<ServerTool>,

    /// Permissions this server requires from the host environment
    /// (filesystem paths, network access, environment variables, etc.).
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub required_permissions: Option<RequiredPermissions>,

    /// Hex-encoded Ed25519 public key of this tool server.
    pub public_key: String,
}

impl ToolManifest {
    /// Return whether a provider-native server tool is explicitly allowlisted.
    pub fn allows_server_tool(&self, server_tool: ServerTool) -> bool {
        self.server_tools.contains(&server_tool)
    }

    /// Whether the named tool is annotated as having no side effects. A tool
    /// absent from the manifest reads as not read-only: only a positive
    /// annotation may exempt a call from side-effect handling, so unknown
    /// tools keep the fail-safe side-effecting classification.
    pub fn tool_is_read_only(&self, tool_name: &str) -> bool {
        self.tools
            .iter()
            .find(|tool| tool.name == tool_name)
            .is_some_and(|tool| tool.annotations.read_only)
    }

    /// Return whether admission requires an installed information-flow runtime.
    #[must_use]
    pub fn requires_flow_runtime(&self) -> bool {
        self.tools.iter().any(|tool| tool.flow.is_some())
    }
}

/// Provider-native server tools that require manifest allowlisting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerTool {
    /// Anthropic `computer_use_*` server tool.
    ComputerUse,
    /// Anthropic `bash_*` server tool.
    Bash,
    /// Anthropic `text_editor_*` server tool.
    TextEditor,
}

impl ServerTool {
    /// Stable manifest spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ServerTool::ComputerUse => "computer_use",
            ServerTool::Bash => "bash",
            ServerTool::TextEditor => "text_editor",
        }
    }

    /// Map Anthropic server-tool wire names to stable manifest entries.
    ///
    /// Anthropic versions server-tool names with a trailing date, for example
    /// `bash_20241022`. Treat known categories as server tools so version bumps
    /// stay fail-closed behind the same allowlist entry.
    pub fn from_anthropic_wire_name(name: &str) -> Option<Self> {
        if name == "computer_use" || has_anthropic_date_suffix(name, "computer_use_") {
            Some(ServerTool::ComputerUse)
        } else if name == "bash" || has_anthropic_date_suffix(name, "bash_") {
            Some(ServerTool::Bash)
        } else if name == "text_editor" || has_anthropic_date_suffix(name, "text_editor_") {
            Some(ServerTool::TextEditor)
        } else {
            None
        }
    }
}

/// Security metadata retained by protocol bridges whose public dialect cannot
/// carry the normative manifest fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeSecurityMetadata {
    flow: Option<ToolFlowDeclaration>,
    effective_egress: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_id: Option<chio_core::ServerId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool_name: Option<String>,
}

impl BridgeSecurityMetadata {
    #[must_use]
    pub fn from_tool(tool: &ToolDefinition) -> Self {
        Self {
            flow: tool.flow.clone(),
            effective_egress: tool.flow.as_ref().is_some_and(|flow| flow.egress),
            manifest_digest: None,
            server_id: None,
            tool_name: None,
        }
    }

    #[must_use]
    pub fn from_flow(flow: Option<ToolFlowDeclaration>) -> Self {
        let effective_egress = flow.as_ref().is_some_and(|declaration| declaration.egress);
        Self {
            flow,
            effective_egress,
            manifest_digest: None,
            server_id: None,
            tool_name: None,
        }
    }

    #[must_use]
    pub const fn unconstrained() -> Self {
        Self {
            flow: None,
            effective_egress: false,
            manifest_digest: None,
            server_id: None,
            tool_name: None,
        }
    }

    #[must_use]
    pub fn flow(&self) -> Option<&ToolFlowDeclaration> {
        self.flow.as_ref()
    }

    #[must_use]
    pub const fn effective_egress(&self) -> bool {
        self.effective_egress
    }

    #[must_use]
    pub const fn has_registry_coordinates(&self) -> bool {
        self.manifest_digest.is_some() && self.server_id.is_some() && self.tool_name.is_some()
    }

    #[must_use]
    pub fn manifest_digest(&self) -> Option<&str> {
        self.manifest_digest.as_deref()
    }

    #[must_use]
    pub fn server_id(&self) -> Option<&str> {
        self.server_id.as_deref()
    }

    #[must_use]
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }

    /// Merge this sidecar into internal kernel metadata.
    ///
    /// This operation preserves the sidecar bytes but does not establish that
    /// they came from a verified registry. Execution boundaries must validate
    /// the complete value against a live [`VerifiedManifestRegistry`] before
    /// calling it.
    pub fn merge_into_kernel_metadata(
        &self,
        metadata: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ManifestError> {
        let mut object = match metadata {
            None => serde_json::Map::new(),
            Some(serde_json::Value::Object(object)) => object,
            Some(_) => {
                return Err(ManifestError::InvalidManifestField(
                    "bridge kernel metadata",
                ));
            }
        };
        let sidecar = serde_json::to_value(self)
            .map_err(|_| ManifestError::InvalidManifestField("bridge security metadata"))?;
        if object.contains_key("chio_manifest_security_v1") {
            return Err(ManifestError::InvalidManifestField(
                "reserved bridge security metadata",
            ));
        }
        object.insert("chio_manifest_security_v1".to_string(), sidecar);
        Ok(serde_json::Value::Object(object))
    }
}

fn has_anthropic_date_suffix(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 8 && suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Permissions that a tool server requires from its sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredPermissions {
    /// Filesystem paths the server needs to read.
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub read_paths: Option<Vec<String>>,

    /// Filesystem paths the server needs to write.
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub write_paths: Option<Vec<String>>,

    /// Network destinations the server needs to reach.
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_destinations: Option<Vec<NetworkDestination>>,

    /// Environment variables the server reads.
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub environment_variables: Option<Vec<EnvironmentVariableName>>,

    /// Closed native syscall profile required for launch.
    pub native_syscall_profile: NativeSyscallProfile,
}

/// Normalized network host and explicit destination port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDestination {
    host: NormalizedHost,
    port: u16,
}

impl NetworkDestination {
    pub fn new(host: impl AsRef<str>, port: u16) -> Result<Self, ManifestError> {
        if port == 0 {
            return Err(ManifestError::InvalidRequiredPermission {
                field: "required_permissions.network_destinations.port",
                value: port.to_string(),
            });
        }
        Ok(Self {
            host: NormalizedHost::new(host)?,
            port,
        })
    }

    #[must_use]
    pub fn host(&self) -> &NormalizedHost {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Canonical network host used by cage permission matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct NormalizedHost(String);

impl NormalizedHost {
    pub fn new(host: impl AsRef<str>) -> Result<Self, ManifestError> {
        Self::parse(host.as_ref(), true)
    }

    fn from_legacy(host: impl AsRef<str>) -> Result<Self, ManifestError> {
        Self::parse(host.as_ref(), false)
    }

    fn parse(host: &str, require_canonical: bool) -> Result<Self, ManifestError> {
        if host.is_empty()
            || host.trim() != host
            || host.chars().any(char::is_control)
            || host.contains('*')
            || host.contains('/')
        {
            return Err(ManifestError::InvalidRequiredPermission {
                field: "required_permissions.network_destinations.host",
                value: host.to_string(),
            });
        }
        let parsed =
            url::Host::parse(host).map_err(|_| ManifestError::InvalidRequiredPermission {
                field: "required_permissions.network_destinations.host",
                value: host.to_string(),
            })?;
        let canonical = parsed.to_string().to_ascii_lowercase();
        if require_canonical && canonical != host {
            return Err(ManifestError::InvalidRequiredPermission {
                field: "required_permissions.network_destinations.host",
                value: host.to_string(),
            });
        }
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NormalizedHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(serde::de::Error::custom)
    }
}

/// Validated environment-variable name. Values are never part of a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct EnvironmentVariableName(String);

const FORBIDDEN_ENVIRONMENT_PREFIXES: &[&str] = &["LD_", "DYLD_", "BASH_FUNC_", "MALLOC_"];
const FORBIDDEN_ENVIRONMENT_NAMES: &[&str] = &[
    "BASH_ENV",
    "DOCKER_CONFIG",
    "ENV",
    "GCONV_PATH",
    "GEM_HOME",
    "GEM_PATH",
    "GIT_ASKPASS",
    "GLIBC_TUNABLES",
    "GPG_AGENT_INFO",
    "IFS",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "KRB5CCNAME",
    "LOCPATH",
    "NETRC",
    "NLSPATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NPM_CONFIG_USERCONFIG",
    "PERL5OPT",
    "PERL5LIB",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYLIB",
    "RUBYOPT",
    "RUSTC_WRAPPER",
    "SSLKEYLOGFILE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SSH_AUTH_SOCK",
    "SUDO_ASKPASS",
    "ZDOTDIR",
    "_JAVA_OPTIONS",
];
const CREDENTIAL_ENVIRONMENT_MARKERS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTHORIZATION",
];

fn is_forbidden_environment_variable(name: &str) -> bool {
    let normalized = name.to_ascii_uppercase();
    let name = normalized.as_str();
    FORBIDDEN_ENVIRONMENT_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || FORBIDDEN_ENVIRONMENT_NAMES.contains(&name)
        || CREDENTIAL_ENVIRONMENT_MARKERS
            .iter()
            .any(|marker| name.contains(marker))
}

impl EnvironmentVariableName {
    pub fn new(name: impl Into<String>) -> Result<Self, ManifestError> {
        let name = name.into();
        let mut bytes = name.bytes();
        let valid_start = bytes.next().is_some_and(|byte| {
            byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_lowercase()
        });
        let valid_rest = bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
        let forbidden = is_forbidden_environment_variable(&name);
        if !valid_start || !valid_rest || forbidden {
            return Err(ManifestError::InvalidRequiredPermission {
                field: "required_permissions.environment_variables",
                value: name,
            });
        }
        Ok(Self(name))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EnvironmentVariableName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Reviewed native syscall profiles accepted by cage admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSyscallProfile {
    NativeMinimalV1,
    NativeStandardV1,
    BrokeredNativeV1,
}

/// A manifest wrapped in its Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    /// The tool manifest.
    pub manifest: ToolManifest,

    /// Ed25519 signature over the canonical JSON encoding of `manifest`.
    pub signature: Signature,

    /// The signing key (for verification without out-of-band lookup).
    pub signer_key: PublicKey,
}

/// Errors specific to manifest operations.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("signing error: {0}")]
    Signing(#[from] chio_core::Error),

    #[error("manifest contains no tools")]
    EmptyManifest,

    #[error("duplicate tool name: {0}")]
    DuplicateToolName(String),

    #[error("invalid tool name: {0}")]
    InvalidToolName(String),

    #[error("invalid manifest field: {0}")]
    InvalidManifestField(&'static str),

    #[error("tool input schema is not a JSON object: {0}")]
    InvalidInputSchema(String),

    #[error("tool output schema is not a JSON object: {0}")]
    InvalidOutputSchema(String),

    #[error("duplicate server tool allowlist entry: {0}")]
    DuplicateServerTool(String),

    #[error("invalid required permission {field}: {value}")]
    InvalidRequiredPermission { field: &'static str, value: String },

    #[error("duplicate required permission {field}: {value}")]
    DuplicateRequiredPermission { field: &'static str, value: String },

    #[error("manifest schema version is not supported: {0}")]
    UnsupportedSchema(String),

    #[error("legacy manifest requires operator amendment before v2 signing: {0}")]
    LegacyMigration(String),

    #[error(
        "legacy permission migration requires an explicit native profile and destination ports"
    )]
    PendingLegacyPermissionAmendment,

    #[error("signature verification failed")]
    VerificationFailed,
}

/// Deterministic unsigned v2 result from the private v1 parser.
#[derive(Debug, Clone)]
pub struct ManifestMigration {
    manifest: ToolManifest,
    legacy_network_hosts: Vec<NormalizedHost>,
    requires_permission_amendment: bool,
}

impl ManifestMigration {
    pub fn manifest(&self) -> Result<&ToolManifest, ManifestError> {
        if self.requires_permission_amendment {
            Err(ManifestError::PendingLegacyPermissionAmendment)
        } else {
            Ok(&self.manifest)
        }
    }

    #[must_use]
    pub const fn requires_operator_resigning(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn requires_permission_amendment(&self) -> bool {
        self.requires_permission_amendment
    }

    #[must_use]
    pub fn legacy_network_hosts(&self) -> Vec<&str> {
        self.legacy_network_hosts
            .iter()
            .map(NormalizedHost::as_str)
            .collect()
    }

    pub fn into_manifest(self) -> Result<ToolManifest, ManifestError> {
        if self.requires_permission_amendment {
            Err(ManifestError::PendingLegacyPermissionAmendment)
        } else {
            Ok(self.manifest)
        }
    }

    pub fn amend_permissions(
        mut self,
        native_syscall_profile: NativeSyscallProfile,
        network_destinations: Vec<NetworkDestination>,
    ) -> Result<ToolManifest, ManifestError> {
        if !self.requires_permission_amendment {
            return Err(ManifestError::LegacyMigration(
                "legacy manifest has no permissions to amend".to_string(),
            ));
        }
        let supplied_hosts = network_destinations
            .iter()
            .map(|destination| destination.host().clone())
            .collect::<std::collections::BTreeSet<_>>();
        let expected_hosts = self
            .legacy_network_hosts
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if supplied_hosts != expected_hosts {
            return Err(ManifestError::LegacyMigration(
                "operator-supplied destination hosts do not exactly match legacy network hosts"
                    .to_string(),
            ));
        }
        let permissions = self.manifest.required_permissions.as_mut().ok_or_else(|| {
            ManifestError::LegacyMigration("permission draft is missing".to_string())
        })?;
        permissions.native_syscall_profile = native_syscall_profile;
        permissions.network_destinations = if network_destinations.is_empty() {
            None
        } else {
            Some(network_destinations)
        };
        self.requires_permission_amendment = false;
        validate_manifest(&self.manifest)?;
        Ok(self.manifest)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyToolManifestV1 {
    schema: String,
    server_id: chio_core::ServerId,
    name: String,
    description: Option<String>,
    version: String,
    tools: Vec<LegacyToolDefinitionV1>,
    #[serde(default)]
    server_tools: Vec<ServerTool>,
    required_permissions: Option<LegacyRequiredPermissionsV1>,
    public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyToolDefinitionV1 {
    name: String,
    description: String,
    input_schema: serde_json::Value,
    #[serde(default)]
    output_schema: Option<serde_json::Value>,
    #[serde(default)]
    pricing: Option<ToolPricing>,
    #[serde(default)]
    has_side_effects: Option<bool>,
    #[serde(default)]
    annotations: Option<LegacyToolAnnotationsV1>,
    #[serde(default)]
    latency_hint: Option<LatencyHint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyToolAnnotationsV1 {
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    destructive: bool,
    #[serde(default)]
    idempotent: bool,
    #[serde(default)]
    requires_approval: bool,
    #[serde(default)]
    estimated_duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRequiredPermissionsV1 {
    read_paths: Option<Vec<String>>,
    write_paths: Option<Vec<String>>,
    network_hosts: Option<Vec<String>>,
    environment_variables: Option<Vec<String>>,
}

/// Convert an exact v1 platform manifest into unsigned v2 content.
///
/// The migrated manifest must be reviewed and signed by an operator before it
/// can pass v2 admission.
pub fn migrate_legacy_manifest_v1(bytes: &[u8]) -> Result<ManifestMigration, ManifestError> {
    let legacy: LegacyToolManifestV1 = serde_json::from_slice(bytes)
        .map_err(|error| ManifestError::LegacyMigration(format!("invalid v1 manifest: {error}")))?;
    if legacy.schema != LEGACY_TOOL_MANIFEST_SCHEMA {
        return Err(ManifestError::UnsupportedSchema(legacy.schema));
    }
    let (required_permissions, legacy_network_hosts, requires_permission_amendment) =
        migrate_legacy_permissions(legacy.required_permissions)?;

    let tools = legacy
        .tools
        .into_iter()
        .map(migrate_legacy_tool)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: legacy.server_id,
        name: legacy.name,
        description: legacy.description,
        version: legacy.version,
        tools,
        server_tools: legacy.server_tools,
        required_permissions,
        public_key: legacy.public_key,
    };
    validate_manifest(&manifest)?;
    Ok(ManifestMigration {
        manifest,
        legacy_network_hosts,
        requires_permission_amendment,
    })
}

fn migrate_legacy_permissions(
    permissions: Option<LegacyRequiredPermissionsV1>,
) -> Result<(Option<RequiredPermissions>, Vec<NormalizedHost>, bool), ManifestError> {
    let Some(permissions) = permissions else {
        return Ok((None, Vec::new(), false));
    };
    let has_permissions = permissions
        .read_paths
        .as_ref()
        .is_some_and(|values| !values.is_empty())
        || permissions
            .write_paths
            .as_ref()
            .is_some_and(|values| !values.is_empty())
        || permissions
            .network_hosts
            .as_ref()
            .is_some_and(|values| !values.is_empty())
        || permissions
            .environment_variables
            .as_ref()
            .is_some_and(|values| !values.is_empty());
    if !has_permissions {
        return Ok((None, Vec::new(), false));
    }

    let environment_variables = permissions
        .environment_variables
        .map(|names| {
            names
                .into_iter()
                .map(EnvironmentVariableName::new)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let mut legacy_network_hosts = Vec::new();
    let mut seen_network_hosts = std::collections::BTreeSet::new();
    for host in permissions.network_hosts.unwrap_or_default() {
        let host = NormalizedHost::from_legacy(host)?;
        if !seen_network_hosts.insert(host.clone()) {
            return Err(ManifestError::DuplicateRequiredPermission {
                field: "required_permissions.network_hosts",
                value: host.as_str().to_string(),
            });
        }
        legacy_network_hosts.push(host);
    }
    let required_permissions = RequiredPermissions {
        read_paths: permissions.read_paths,
        write_paths: permissions.write_paths,
        network_destinations: None,
        environment_variables,
        native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
    };
    Ok((Some(required_permissions), legacy_network_hosts, true))
}

fn migrate_legacy_tool(tool: LegacyToolDefinitionV1) -> Result<ToolDefinition, ManifestError> {
    let (annotations, duration) = match (tool.has_side_effects, tool.annotations) {
        (Some(_), Some(_)) => {
            return Err(ManifestError::LegacyMigration(
                "legacy tool carries both side-effect and annotation authorities".to_string(),
            ));
        }
        (Some(has_side_effects), None) => (
            if has_side_effects {
                ToolAnnotations {
                    read_only: false,
                    destructive: true,
                    idempotent: false,
                    requires_approval: true,
                }
            } else {
                ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                }
            },
            None,
        ),
        (None, Some(legacy)) => (
            ToolAnnotations {
                read_only: legacy.read_only,
                destructive: legacy.destructive,
                idempotent: legacy.idempotent,
                requires_approval: legacy.requires_approval,
            },
            legacy.estimated_duration_ms,
        ),
        (None, None) => {
            return Err(ManifestError::LegacyMigration(
                "legacy tool has no behavior authority".to_string(),
            ));
        }
    };
    if tool.latency_hint.is_some() && duration.is_some() {
        return Err(ManifestError::LegacyMigration(
            "legacy tool carries two latency authorities".to_string(),
        ));
    }
    let latency_hint = tool.latency_hint.or_else(|| duration.map(migrate_duration));
    Ok(ToolDefinition {
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        pricing: tool.pricing,
        annotations,
        latency_hint,
        flow: None,
    })
}

const fn migrate_duration(duration_ms: u64) -> LatencyHint {
    match duration_ms {
        0..=1 => LatencyHint::Instant,
        2..=999 => LatencyHint::Fast,
        1_000..=59_999 => LatencyHint::Moderate,
        _ => LatencyHint::Slow,
    }
}

/// Sign a manifest with an Ed25519 keypair.
pub fn sign_manifest(
    manifest: &ToolManifest,
    keypair: &Keypair,
) -> Result<SignedManifest, ManifestError> {
    validate_manifest(manifest)?;
    let signer_key = keypair.public_key();
    ensure_embedded_public_key_matches(manifest, &signer_key)?;
    let (signature, _bytes) = keypair.sign_canonical(manifest)?;
    Ok(SignedManifest {
        manifest: manifest.clone(),
        signature,
        signer_key,
    })
}

/// Verify a signed manifest against a known public key.
pub fn verify_manifest(
    signed: &SignedManifest,
    public_key: &PublicKey,
) -> Result<(), ManifestError> {
    validate_manifest(&signed.manifest)?;
    ensure_embedded_public_key_matches(&signed.manifest, &signed.signer_key)?;
    if signed.signer_key != *public_key {
        return Err(ManifestError::VerificationFailed);
    }
    let valid = public_key.verify_canonical(&signed.manifest, &signed.signature)?;
    if valid {
        Ok(())
    } else {
        Err(ManifestError::VerificationFailed)
    }
}

fn ensure_embedded_public_key_matches(
    manifest: &ToolManifest,
    signer_key: &PublicKey,
) -> Result<(), ManifestError> {
    let embedded_key = embedded_public_key(manifest)?;
    if embedded_key == *signer_key {
        Ok(())
    } else {
        Err(ManifestError::VerificationFailed)
    }
}

fn embedded_public_key(manifest: &ToolManifest) -> Result<PublicKey, ManifestError> {
    PublicKey::from_hex(&manifest.public_key).map_err(|_| ManifestError::VerificationFailed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::capability::scope::MonetaryAmount;
    use chio_core::crypto::Keypair;

    fn sample_manifest() -> ToolManifest {
        ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.into(),
            server_id: "srv-hello".into(),
            name: "Hello Tool Server".into(),
            description: Some("A demo tool server".into()),
            version: "0.1.0".into(),
            tools: vec![ToolDefinition {
                name: "greet".into(),
                description: "Returns a greeting".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" }
                    },
                    "required": ["name"]
                }),
                output_schema: None,
                pricing: Some(ToolPricing {
                    pricing_model: PricingModel::PerInvocation,
                    base_price: None,
                    unit_price: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    billing_unit: Some("invocation".into()),
                }),
                annotations: ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: true,
                    requires_approval: false,
                },
                latency_hint: Some(LatencyHint::Instant),
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: Keypair::from_seed(&[7u8; 32]).public_key().to_hex(),
        }
    }

    #[test]
    fn validate_valid_manifest() {
        let m = sample_manifest();
        validate_manifest(&m).unwrap_or_else(|e| panic!("validation: {e}"));
    }

    #[test]
    fn flow_declaration_requires_flow_runtime() {
        let mut manifest = sample_manifest();
        assert!(!manifest.requires_flow_runtime());

        manifest.tools[0].flow = Some(ToolFlowDeclaration::public_egress());
        assert!(manifest.requires_flow_runtime());
    }

    #[test]
    fn validate_empty_manifest() {
        let mut m = sample_manifest();
        m.tools.clear();
        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::EmptyManifest)
        ));
    }

    #[test]
    fn validate_duplicate_tool_name() {
        let mut m = sample_manifest();
        let tool = m.tools[0].clone();
        m.tools.push(tool);
        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::DuplicateToolName(_))
        ));
    }

    #[test]
    fn validate_rejects_padded_tool_name() {
        let mut m = sample_manifest();
        m.tools[0].name = " greet".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidToolName(_))
        ));
    }

    #[test]
    fn validate_allows_unsigned_demo_public_key() {
        let mut m = sample_manifest();
        m.public_key = "hello-a2a-manifest".into();

        validate_manifest(&m).unwrap_or_else(|e| panic!("validation: {e}"));
    }

    #[test]
    fn validate_rejects_blank_manifest_identity() {
        let mut m = sample_manifest();
        m.server_id = " ".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField("server_id"))
        ));
    }

    #[test]
    fn validate_rejects_padded_manifest_identity() {
        let mut m = sample_manifest();
        m.version = " 0.1.0".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField("version"))
        ));
    }

    #[test]
    fn validate_rejects_manifest_identity_control_characters() {
        let mut m = sample_manifest();
        m.server_id = "srv-hello\nbad".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField("server_id"))
        ));
    }

    #[test]
    fn validate_rejects_tool_name_control_characters() {
        let mut m = sample_manifest();
        m.tools[0].name = "greet\nbad".into();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidToolName(_))
        ));
    }

    #[test]
    fn validate_rejects_non_object_input_schema() {
        let mut m = sample_manifest();
        m.tools[0].input_schema = serde_json::json!(["not", "an", "object"]);

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidInputSchema(tool)) if tool == "greet"
        ));
    }

    #[test]
    fn validate_rejects_non_object_output_schema() {
        let mut m = sample_manifest();
        m.tools[0].output_schema = Some(serde_json::json!("not an object"));

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidOutputSchema(tool)) if tool == "greet"
        ));
    }

    #[test]
    fn validate_rejects_empty_required_permission_entry() {
        let mut m = sample_manifest();
        m.required_permissions = Some(RequiredPermissions {
            read_paths: Some(vec![String::new()]),
            write_paths: None,
            network_destinations: None,
            environment_variables: None,
            native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
        });

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidRequiredPermission {
                field: "required_permissions.read_paths",
                ..
            })
        ));
    }

    #[test]
    fn validate_rejects_duplicate_required_permission_entry() {
        let mut m = sample_manifest();
        m.required_permissions = Some(RequiredPermissions {
            read_paths: None,
            write_paths: None,
            network_destinations: Some(vec![
                NetworkDestination::new("api.example.com", 443).unwrap(),
                NetworkDestination::new("api.example.com", 443).unwrap(),
            ]),
            environment_variables: None,
            native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
        });

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::DuplicateRequiredPermission {
                field: "required_permissions.network_destinations",
                value,
            }) if value == "api.example.com:443"
        ));
    }

    #[test]
    fn validate_rejects_required_permission_control_characters() {
        let mut m = sample_manifest();
        m.required_permissions = Some(RequiredPermissions {
            read_paths: Some(vec!["/tmp/in\nbad".into()]),
            write_paths: None,
            network_destinations: None,
            environment_variables: None,
            native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
        });

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidRequiredPermission {
                field: "required_permissions.read_paths",
                ..
            })
        ));
    }

    #[test]
    fn validate_rejects_per_invocation_pricing_without_unit_price() {
        let mut m = sample_manifest();
        m.tools[0].pricing.as_mut().unwrap().unit_price = None;

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField(
                "tools.pricing.unit_price"
            ))
        ));
    }

    #[test]
    fn validate_rejects_hybrid_pricing_without_base_price() {
        let mut m = sample_manifest();
        let pricing = m.tools[0].pricing.as_mut().unwrap();
        pricing.pricing_model = PricingModel::Hybrid;
        pricing.base_price = None;
        pricing.unit_price = Some(MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        });
        pricing.billing_unit = Some("document".to_string());

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField(
                "tools.pricing.base_price"
            ))
        ));
    }

    #[test]
    fn validate_rejects_padded_pricing_billing_unit() {
        let mut m = sample_manifest();
        m.tools[0].pricing.as_mut().unwrap().billing_unit = Some(" invocation".to_string());

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField(
                "tools.pricing.billing_unit"
            ))
        ));
    }

    #[test]
    fn validate_rejects_invalid_pricing_currency() {
        let mut m = sample_manifest();
        m.tools[0]
            .pricing
            .as_mut()
            .unwrap()
            .unit_price
            .as_mut()
            .unwrap()
            .currency = "usd".to_string();

        assert!(matches!(
            validate_manifest(&m),
            Err(ManifestError::InvalidManifestField(
                "tools.pricing.currency"
            ))
        ));
    }

    #[test]
    fn sign_and_verify_manifest() {
        let kp = Keypair::generate();

        let mut m = sample_manifest();
        m.public_key = kp.public_key().to_hex();
        let signed = sign_manifest(&m, &kp).unwrap_or_else(|e| panic!("sign: {e}"));
        verify_manifest(&signed, &kp.public_key()).unwrap_or_else(|e| panic!("verify: {e}"));
    }

    #[test]
    fn sign_manifest_rejects_mismatched_embedded_public_key() {
        let signer = Keypair::generate();
        let other = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = other.public_key().to_hex();

        assert!(matches!(
            sign_manifest(&m, &signer),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn sign_manifest_rejects_invalid_embedded_public_key() {
        let signer = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = "not-a-public-key".into();

        assert!(matches!(
            sign_manifest(&m, &signer),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_manifest_rejects_mismatched_embedded_public_key() {
        let trusted = Keypair::generate();
        let other = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = other.public_key().to_hex();
        let (signature, _bytes) = trusted
            .sign_canonical(&m)
            .unwrap_or_else(|e| panic!("sign: {e}"));
        let signed = SignedManifest {
            manifest: m,
            signature,
            signer_key: trusted.public_key(),
        };

        assert!(matches!(
            verify_manifest(&signed, &trusted.public_key()),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_manifest_rejects_invalid_embedded_public_key() {
        let trusted = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = "not-a-public-key".into();
        let (signature, _bytes) = trusted
            .sign_canonical(&m)
            .unwrap_or_else(|e| panic!("sign: {e}"));
        let signed = SignedManifest {
            manifest: m,
            signature,
            signer_key: trusted.public_key(),
        };

        assert!(matches!(
            verify_manifest(&signed, &trusted.public_key()),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_manifest_rejects_mismatched_signed_signer_key() {
        let trusted = Keypair::generate();
        let other = Keypair::generate();

        let mut m = sample_manifest();
        m.public_key = trusted.public_key().to_hex();
        let mut signed = sign_manifest(&m, &trusted).unwrap_or_else(|e| panic!("sign: {e}"));
        signed.signer_key = other.public_key();

        assert!(matches!(
            verify_manifest(&signed, &trusted.public_key()),
            Err(ManifestError::VerificationFailed)
        ));
    }

    #[test]
    fn signed_manifest_rejects_unknown_envelope_fields() {
        let kp = Keypair::generate();
        let mut m = sample_manifest();
        m.public_key = kp.public_key().to_hex();
        let signed = sign_manifest(&m, &kp).unwrap_or_else(|e| panic!("sign: {e}"));
        let mut encoded =
            serde_json::to_value(&signed).unwrap_or_else(|e| panic!("encode signed manifest: {e}"));
        encoded
            .as_object_mut()
            .unwrap_or_else(|| panic!("signed manifest encodes as object"))
            .insert("unsigned_policy_hint".to_string(), serde_json::json!(true));

        let error = serde_json::from_value::<SignedManifest>(encoded).unwrap_err();

        assert!(
            error.to_string().contains("unknown field"),
            "expected unknown-field parse error, got {error}"
        );
    }

    #[test]
    fn required_permissions_reject_unknown_fields() {
        let result = serde_json::from_value::<RequiredPermissions>(serde_json::json!({
            "read_paths": ["/tmp"],
            "extra_permission": true
        }));
        assert!(result.is_err());
    }

    #[test]
    fn event_permissions_reject_until_event_actions_land() {
        let result = serde_json::from_value::<RequiredPermissions>(serde_json::json!({
            "event_publish": [{"broker_kind": "kafka"}]
        }));
        assert!(result.is_err());
    }
}
