use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use chio_core::crypto::PublicKey;
use chio_security_types::InformationLabel;
use serde::Serialize;

use crate::{
    input_schema::trusted_server_tool_input_schema, verify_manifest, BridgeSecurityMetadata,
    DeclassificationPurpose, ManifestError, SignedManifest, ToolInputSchemaError,
    ToolInputSchemaValidator, VerifiedManifestInvocationError,
};

const MAX_SIGNED_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Operator-owned flow policy already selected from an authenticated policy snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritativeToolPolicy {
    input_clearances: Vec<InformationLabel>,
    output_floor: InformationLabel,
    declassification_purposes: BTreeSet<DeclassificationPurpose>,
}

impl AuthoritativeToolPolicy {
    #[must_use]
    pub fn public_only() -> Self {
        Self {
            input_clearances: vec![InformationLabel::bottom()],
            output_floor: InformationLabel::bottom(),
            declassification_purposes: BTreeSet::new(),
        }
    }

    pub fn new(
        input_clearances: Vec<InformationLabel>,
        output_floor: InformationLabel,
        declassification_purposes: BTreeSet<DeclassificationPurpose>,
    ) -> Result<Self, VerifiedManifestAdmissionError> {
        if input_clearances
            .iter()
            .any(|clearance| matches!(clearance, InformationLabel::Top))
        {
            return Err(VerifiedManifestAdmissionError::TopPolicyClearance);
        }
        if matches!(output_floor, InformationLabel::Top) {
            return Err(VerifiedManifestAdmissionError::TopPolicyOutputFloor);
        }
        Ok(Self {
            input_clearances,
            output_floor,
            declassification_purposes,
        })
    }

    #[must_use]
    pub fn input_clearances(&self) -> &[InformationLabel] {
        &self.input_clearances
    }

    #[must_use]
    pub fn output_floor(&self) -> &InformationLabel {
        &self.output_floor
    }
}

/// Runtime-derived topology. This value is not accepted from protocol discovery data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeToolTopology {
    /// The tool executes in a local process without a broker egress boundary.
    Local,
    /// The tool executes behind a remote transport boundary.
    Remote,
    /// The tool executes locally but all external access crosses the native broker.
    Brokered,
}

impl RuntimeToolTopology {
    #[must_use]
    pub const fn local() -> Self {
        Self::Local
    }

    #[must_use]
    pub const fn remote() -> Self {
        Self::Remote
    }

    #[must_use]
    pub const fn brokered() -> Self {
        Self::Brokered
    }

    #[must_use]
    pub const fn runtime_egress(self) -> bool {
        !matches!(self, Self::Local)
    }
}

/// Flow constraints derived only after signature, policy, and topology admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmittedToolSecurity {
    effective_egress: bool,
    policy_clearances: Vec<InformationLabel>,
    manifest_clearance: Option<InformationLabel>,
    effective_output_floor: InformationLabel,
    declassification_purposes: BTreeSet<DeclassificationPurpose>,
}

impl AdmittedToolSecurity {
    /// Return whether this admitted policy/topology requires flow mediation.
    #[must_use]
    pub fn requires_flow_runtime(&self) -> bool {
        self.effective_egress
            || self.manifest_clearance.is_some()
            || !self.effective_output_floor.is_bottom()
            || !self.declassification_purposes.is_empty()
            || self
                .policy_clearances
                .iter()
                .any(|clearance| !clearance.is_bottom())
    }

    #[must_use]
    pub const fn effective_egress(&self) -> bool {
        self.effective_egress
    }

    #[must_use]
    pub fn policy_clearances(&self) -> &[InformationLabel] {
        &self.policy_clearances
    }

    #[must_use]
    pub const fn manifest_clearance(&self) -> Option<&InformationLabel> {
        self.manifest_clearance.as_ref()
    }

    #[must_use]
    pub fn effective_output_floor(&self) -> &InformationLabel {
        &self.effective_output_floor
    }

    #[must_use]
    pub fn declassification_purposes(&self) -> &BTreeSet<DeclassificationPurpose> {
        &self.declassification_purposes
    }

    pub fn authorize_source(
        &self,
        source: &InformationLabel,
    ) -> Result<(), VerifiedManifestAdmissionError> {
        if !self.effective_egress
            && self.policy_clearances.is_empty()
            && self.manifest_clearance.is_none()
        {
            return Ok(());
        }
        if matches!(source, InformationLabel::Top) {
            return Err(VerifiedManifestAdmissionError::TopSource);
        }
        if self
            .policy_clearances
            .iter()
            .any(|clearance| !source.flows_to(clearance))
            || self
                .manifest_clearance
                .as_ref()
                .is_some_and(|clearance| !source.flows_to(clearance))
        {
            return Err(VerifiedManifestAdmissionError::SourceExceedsClearance);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct VerifiedManifestEntry {
    signed: SignedManifest,
    manifest_digest: String,
    input_validators: BTreeMap<String, ToolInputSchemaValidator>,
    server_tool_input_validators: BTreeMap<crate::ServerTool, ToolInputSchemaValidator>,
    tool_topologies: BTreeMap<String, RuntimeToolTopology>,
    server_tool_topologies: BTreeMap<crate::ServerTool, RuntimeToolTopology>,
    security: BTreeMap<String, AdmittedToolSecurity>,
    server_tool_security: BTreeMap<crate::ServerTool, AdmittedToolSecurity>,
}

/// Registry-issued authorization for compiling one exact native cage manifest.
///
/// Fields are private and there is no public constructor. The value can only be
/// issued after the registry has verified the signature and matched every tool
/// topology to the manifest's reviewed native syscall profile.
#[derive(Debug)]
pub struct VerifiedCageManifest<'a> {
    signed: &'a SignedManifest,
    manifest_digest: &'a str,
    signed_manifest_digest: String,
    registry_digest: String,
    authorization_digest: String,
    topology: RuntimeToolTopology,
}

impl VerifiedCageManifest<'_> {
    #[must_use]
    pub const fn signed_manifest(&self) -> &SignedManifest {
        self.signed
    }

    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.signed.manifest.server_id
    }

    #[must_use]
    pub const fn manifest_digest(&self) -> &str {
        self.manifest_digest
    }

    #[must_use]
    pub fn signed_manifest_digest(&self) -> &str {
        &self.signed_manifest_digest
    }

    #[must_use]
    pub fn registry_digest(&self) -> &str {
        &self.registry_digest
    }

    #[must_use]
    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    #[must_use]
    pub const fn topology(&self) -> RuntimeToolTopology {
        self.topology
    }
}

/// Registry whose only insertion API verifies v2 signatures and composes policy with topology.
#[derive(Clone, Debug, Default)]
pub struct VerifiedManifestRegistry {
    manifests: BTreeMap<chio_core::ServerId, VerifiedManifestEntry>,
}

impl VerifiedManifestRegistry {
    /// Return whether any admitted manifest, policy, or topology needs flow mediation.
    #[must_use]
    pub fn requires_flow_runtime(&self) -> bool {
        self.manifests.values().any(|entry| {
            entry.signed.manifest.requires_flow_runtime()
                || entry
                    .security
                    .values()
                    .any(AdmittedToolSecurity::requires_flow_runtime)
                || entry
                    .server_tool_security
                    .values()
                    .any(AdmittedToolSecurity::requires_flow_runtime)
        })
    }

    /// Authorize one exact registry entry for native cage compilation.
    ///
    /// Native minimal and standard profiles require every regular tool to have
    /// authenticated local topology. The brokered profile requires every tool
    /// to have authenticated brokered topology. Remote, mixed, missing, and
    /// provider-native server-tool topologies fail closed.
    pub fn authorize_cage_manifest(
        &self,
        server_id: &str,
    ) -> Result<VerifiedCageManifest<'_>, VerifiedManifestAdmissionError> {
        #[derive(Serialize)]
        struct AuthorizationBinding<'a> {
            schema: &'static str,
            registry_digest: &'a str,
            signed_manifest_digest: &'a str,
            manifest_digest: &'a str,
            server_id: &'a str,
            tool_topologies: &'a BTreeMap<String, RuntimeToolTopology>,
            native_syscall_profile: crate::NativeSyscallProfile,
        }

        let entry = self.manifests.get(server_id).ok_or_else(|| {
            VerifiedManifestAdmissionError::CageServerNotRegistered(server_id.to_string())
        })?;
        if !entry.signed.manifest.server_tools.is_empty()
            || !entry.server_tool_topologies.is_empty()
        {
            return Err(
                VerifiedManifestAdmissionError::CageProviderServerToolsUnsupported(
                    server_id.to_string(),
                ),
            );
        }
        let permissions = entry
            .signed
            .manifest
            .required_permissions
            .as_ref()
            .ok_or_else(|| {
                VerifiedManifestAdmissionError::CagePermissionsMissing(server_id.to_string())
            })?;
        let required_topology = match permissions.native_syscall_profile {
            crate::NativeSyscallProfile::NativeMinimalV1
            | crate::NativeSyscallProfile::NativeStandardV1 => RuntimeToolTopology::Local,
            crate::NativeSyscallProfile::BrokeredNativeV1 => RuntimeToolTopology::Brokered,
        };
        let exact_tool_set = entry.tool_topologies.len() == entry.signed.manifest.tools.len()
            && entry.signed.manifest.tools.iter().all(|tool| {
                entry.tool_topologies.get(&tool.name).copied() == Some(required_topology)
            });
        if !exact_tool_set {
            return Err(VerifiedManifestAdmissionError::CageTopologyMismatch {
                server_id: server_id.to_string(),
                required: required_topology,
            });
        }

        let signed_manifest_digest =
            chio_core::sha256_hex(&chio_core::canonical_json_bytes(&entry.signed)?);
        let registry_digest = self.registry_digest()?;
        let authorization_digest =
            chio_core::sha256_hex(&chio_core::canonical_json_bytes(&AuthorizationBinding {
                schema: "chio.manifest.cage-authorization.v1",
                registry_digest: &registry_digest,
                signed_manifest_digest: &signed_manifest_digest,
                manifest_digest: &entry.manifest_digest,
                server_id: &entry.signed.manifest.server_id,
                tool_topologies: &entry.tool_topologies,
                native_syscall_profile: permissions.native_syscall_profile,
            })?);
        Ok(VerifiedCageManifest {
            signed: &entry.signed,
            manifest_digest: &entry.manifest_digest,
            signed_manifest_digest,
            registry_digest,
            authorization_digest,
            topology: required_topology,
        })
    }

    fn registry_digest(&self) -> Result<String, VerifiedManifestAdmissionError> {
        #[derive(Serialize)]
        struct RegistryEntryBinding<'a> {
            server_id: &'a str,
            signed_manifest_digest: String,
            manifest_digest: &'a str,
            tool_topologies: &'a BTreeMap<String, RuntimeToolTopology>,
            server_tool_topologies: &'a BTreeMap<crate::ServerTool, RuntimeToolTopology>,
            security: &'a BTreeMap<String, AdmittedToolSecurity>,
            server_tool_security: &'a BTreeMap<crate::ServerTool, AdmittedToolSecurity>,
        }

        #[derive(Serialize)]
        struct RegistryBinding<'a> {
            schema: &'static str,
            entries: Vec<RegistryEntryBinding<'a>>,
        }

        let entries = self
            .manifests
            .values()
            .map(|entry| {
                let signed_manifest_digest =
                    chio_core::sha256_hex(&chio_core::canonical_json_bytes(&entry.signed)?);
                Ok(RegistryEntryBinding {
                    server_id: &entry.signed.manifest.server_id,
                    signed_manifest_digest,
                    manifest_digest: &entry.manifest_digest,
                    tool_topologies: &entry.tool_topologies,
                    server_tool_topologies: &entry.server_tool_topologies,
                    security: &entry.security,
                    server_tool_security: &entry.server_tool_security,
                })
            })
            .collect::<Result<Vec<_>, VerifiedManifestAdmissionError>>()?;
        Ok(chio_core::sha256_hex(&chio_core::canonical_json_bytes(
            &RegistryBinding {
                schema: "chio.manifest.verified-registry.v1",
                entries,
            },
        )?))
    }

    pub fn register_public_only(
        &mut self,
        signed: SignedManifest,
        registered_key: &PublicKey,
        topology: RuntimeToolTopology,
    ) -> Result<(), VerifiedManifestAdmissionError> {
        let policies = signed
            .manifest
            .tools
            .iter()
            .map(|tool| (tool.name.clone(), AuthoritativeToolPolicy::public_only()))
            .chain(signed.manifest.server_tools.iter().map(|tool| {
                (
                    tool.as_str().to_string(),
                    AuthoritativeToolPolicy::public_only(),
                )
            }))
            .collect();
        let topologies = signed
            .manifest
            .tools
            .iter()
            .map(|tool| (tool.name.clone(), topology))
            .chain(
                signed
                    .manifest
                    .server_tools
                    .iter()
                    .map(|tool| (tool.as_str().to_string(), topology)),
            )
            .collect();
        self.register(signed, registered_key, &policies, &topologies)
    }

    pub fn register(
        &mut self,
        signed: SignedManifest,
        registered_key: &PublicKey,
        policies: &BTreeMap<String, AuthoritativeToolPolicy>,
        topologies: &BTreeMap<String, RuntimeToolTopology>,
    ) -> Result<(), VerifiedManifestAdmissionError> {
        verify_manifest(&signed, registered_key)?;
        let manifest_digest =
            chio_core::sha256_hex(&chio_core::canonical_json_bytes(&signed.manifest)?);
        let server_id = signed.manifest.server_id.clone();
        if self.manifests.contains_key(&server_id) {
            return Err(VerifiedManifestAdmissionError::DuplicateServer(server_id));
        }

        let mut input_validators = BTreeMap::new();
        let mut security = BTreeMap::new();
        let mut tool_topologies = BTreeMap::new();
        for tool in &signed.manifest.tools {
            let input_validator =
                ToolInputSchemaValidator::compile(&tool.name, &tool.input_schema)?;
            let policy = policies
                .get(&tool.name)
                .ok_or_else(|| VerifiedManifestAdmissionError::MissingPolicy(tool.name.clone()))?;
            let topology = topologies.get(&tool.name).ok_or_else(|| {
                VerifiedManifestAdmissionError::MissingTopology(tool.name.clone())
            })?;
            let manifest_flow = tool.flow.as_ref();
            let effective_egress = topology.runtime_egress()
                || manifest_flow.is_some_and(|declaration| declaration.egress);
            if effective_egress && policy.input_clearances.is_empty() {
                return Err(VerifiedManifestAdmissionError::MissingPolicyClearance(
                    tool.name.clone(),
                ));
            }
            if let Some(manifest_clearance) =
                manifest_flow.and_then(|declaration| declaration.input_clearance.as_ref())
            {
                if policy
                    .input_clearances
                    .iter()
                    .any(|policy_clearance| !manifest_clearance.flows_to(policy_clearance))
                {
                    return Err(
                        VerifiedManifestAdmissionError::ManifestClearanceWidensPolicy(
                            tool.name.clone(),
                        ),
                    );
                }
            }

            let manifest_output = manifest_flow
                .and_then(|declaration| declaration.output_label.as_ref())
                .cloned()
                .unwrap_or_else(InformationLabel::bottom);
            let effective_output_floor = policy
                .output_floor
                .join_restrictions(&manifest_output)
                .map_err(|_| VerifiedManifestAdmissionError::OutputJoinFailed(tool.name.clone()))?;
            if matches!(effective_output_floor, InformationLabel::Top) {
                return Err(VerifiedManifestAdmissionError::TopEffectiveOutput(
                    tool.name.clone(),
                ));
            }

            let manifest_purposes = manifest_flow
                .map(|declaration| &declaration.declassification_purposes)
                .cloned()
                .unwrap_or_default();
            let declassification_purposes = policy
                .declassification_purposes
                .intersection(&manifest_purposes)
                .cloned()
                .collect();
            security.insert(
                tool.name.clone(),
                AdmittedToolSecurity {
                    effective_egress,
                    policy_clearances: policy.input_clearances.clone(),
                    manifest_clearance: manifest_flow
                        .and_then(|declaration| declaration.input_clearance.clone()),
                    effective_output_floor,
                    declassification_purposes,
                },
            );
            input_validators.insert(tool.name.clone(), input_validator);
            tool_topologies.insert(tool.name.clone(), *topology);
        }
        let mut server_tool_security = BTreeMap::new();
        let mut server_tool_input_validators = BTreeMap::new();
        let mut server_tool_topologies = BTreeMap::new();
        for server_tool in &signed.manifest.server_tools {
            let name = server_tool.as_str();
            let input_validator = ToolInputSchemaValidator::compile(
                name,
                &trusted_server_tool_input_schema(*server_tool),
            )?;
            let policy = policies
                .get(name)
                .ok_or_else(|| VerifiedManifestAdmissionError::MissingPolicy(name.to_string()))?;
            let topology = topologies
                .get(name)
                .ok_or_else(|| VerifiedManifestAdmissionError::MissingTopology(name.to_string()))?;
            if *topology != RuntimeToolTopology::Remote {
                return Err(
                    VerifiedManifestAdmissionError::ServerToolRequiresRemoteTopology(
                        name.to_string(),
                    ),
                );
            }
            if policy.input_clearances.is_empty() {
                return Err(VerifiedManifestAdmissionError::MissingPolicyClearance(
                    name.to_string(),
                ));
            }
            if matches!(policy.output_floor, InformationLabel::Top) {
                return Err(VerifiedManifestAdmissionError::TopEffectiveOutput(
                    name.to_string(),
                ));
            }
            server_tool_security.insert(
                *server_tool,
                AdmittedToolSecurity {
                    effective_egress: true,
                    policy_clearances: policy.input_clearances.clone(),
                    manifest_clearance: None,
                    effective_output_floor: policy.output_floor.clone(),
                    declassification_purposes: BTreeSet::new(),
                },
            );
            server_tool_input_validators.insert(*server_tool, input_validator);
            server_tool_topologies.insert(*server_tool, *topology);
        }
        self.manifests.insert(
            server_id,
            VerifiedManifestEntry {
                signed,
                manifest_digest,
                input_validators,
                server_tool_input_validators,
                tool_topologies,
                server_tool_topologies,
                security,
                server_tool_security,
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn verified_manifest(&self, server_id: &str) -> Option<&SignedManifest> {
        self.manifests.get(server_id).map(|entry| &entry.signed)
    }

    pub fn verified_manifests(&self) -> impl ExactSizeIterator<Item = &SignedManifest> {
        self.manifests.values().map(|entry| &entry.signed)
    }

    #[must_use]
    pub fn tool_security(&self, server_id: &str, tool_name: &str) -> Option<&AdmittedToolSecurity> {
        self.manifests
            .get(server_id)
            .and_then(|entry| entry.security.get(tool_name))
    }

    #[must_use]
    pub fn tool_security_for_server_tool(
        &self,
        server_id: &str,
        wire_tool_name: &str,
    ) -> Option<&AdmittedToolSecurity> {
        let server_tool = crate::ServerTool::from_anthropic_wire_name(wire_tool_name)?;
        self.manifests
            .get(server_id)
            .and_then(|entry| entry.server_tool_security.get(&server_tool))
    }

    #[must_use]
    pub fn bridge_security(
        &self,
        server_id: &str,
        tool_name: &str,
    ) -> Option<BridgeSecurityMetadata> {
        let entry = self.manifests.get(server_id)?;
        let tool = entry
            .signed
            .manifest
            .tools
            .iter()
            .find(|tool| tool.name == tool_name)?;
        let security = entry.security.get(tool_name)?;
        Some(BridgeSecurityMetadata {
            flow: tool.flow.clone(),
            effective_egress: security.effective_egress,
            manifest_digest: Some(entry.manifest_digest.clone()),
            server_id: Some(entry.signed.manifest.server_id.clone()),
            tool_name: Some(tool.name.clone()),
        })
    }

    #[must_use]
    pub fn bridge_security_for_server_tool(
        &self,
        server_id: &str,
        wire_tool_name: &str,
    ) -> Option<BridgeSecurityMetadata> {
        let server_tool = crate::ServerTool::from_anthropic_wire_name(wire_tool_name)?;
        let entry = self.manifests.get(server_id)?;
        if !entry.signed.manifest.server_tools.contains(&server_tool) {
            return None;
        }
        let security = entry.server_tool_security.get(&server_tool)?;
        Some(BridgeSecurityMetadata {
            flow: None,
            effective_egress: security.effective_egress,
            manifest_digest: Some(entry.manifest_digest.clone()),
            server_id: Some(entry.signed.manifest.server_id.clone()),
            tool_name: Some(server_tool.as_str().to_string()),
        })
    }

    /// Validate a bridge sidecar against the exact security value derived from
    /// the live signed-manifest registry for the requested execution target.
    pub fn validate_bridge_security(
        &self,
        requested_server: &str,
        requested_tool: &str,
        metadata: &BridgeSecurityMetadata,
    ) -> Result<(), VerifiedManifestAdmissionError> {
        let regular = self.bridge_security(requested_server, requested_tool);
        let server_tool = self.bridge_security_for_server_tool(requested_server, requested_tool);
        match (regular, server_tool) {
            (Some(expected), None) | (None, Some(expected)) if expected == *metadata => Ok(()),
            _ => Err(VerifiedManifestAdmissionError::BridgeSecurityMismatch {
                server_id: requested_server.to_string(),
                tool_name: requested_tool.to_string(),
            }),
        }
    }

    /// Validate one invocation against its exact admitted security binding and
    /// input schema. Regular tools use the schema retained from the signed
    /// manifest. Provider-native tools use Chio's pinned built-in catalog.
    pub fn validate_invocation_arguments(
        &self,
        requested_server: &str,
        requested_tool: &str,
        metadata: &BridgeSecurityMetadata,
        arguments: &serde_json::Value,
    ) -> Result<(), VerifiedManifestInvocationError> {
        self.validate_bridge_security(requested_server, requested_tool, metadata)?;
        let (validator, is_server_tool) = self
            .manifests
            .get(requested_server)
            .and_then(|entry| {
                entry
                    .input_validators
                    .get(requested_tool)
                    .map(|validator| (validator, false))
                    .or_else(|| {
                        crate::ServerTool::from_anthropic_wire_name(requested_tool).and_then(
                            |server_tool| {
                                entry
                                    .server_tool_input_validators
                                    .get(&server_tool)
                                    .map(|validator| (validator, true))
                            },
                        )
                    })
            })
            .ok_or_else(|| VerifiedManifestInvocationError::SchemaUnavailable {
                server_id: requested_server.to_string(),
                tool_name: requested_tool.to_string(),
            })?;
        if !arguments.is_object() {
            return Err(VerifiedManifestInvocationError::ArgumentsNotObject {
                server_id: requested_server.to_string(),
                tool_name: requested_tool.to_string(),
            });
        }
        if !validator.is_valid(arguments) {
            if is_server_tool {
                return Err(
                    VerifiedManifestInvocationError::TrustedServerToolSchemaMismatch {
                        server_id: requested_server.to_string(),
                        tool_name: requested_tool.to_string(),
                    },
                );
            }
            return Err(VerifiedManifestInvocationError::SchemaMismatch {
                server_id: requested_server.to_string(),
                tool_name: requested_tool.to_string(),
            });
        }
        Ok(())
    }
}

/// Load one already-signed manifest from an existing regular file and admit it
/// against an independently configured public key.
pub fn load_existing_verified_manifest_registry(
    path: &Path,
    registered_public_key_hex: &str,
    expected_server_id: &str,
    topology: RuntimeToolTopology,
) -> Result<VerifiedManifestRegistry, VerifiedManifestLoadError> {
    let signed = read_existing_signed_manifest(path)?;
    if signed.manifest.server_id != expected_server_id {
        return Err(VerifiedManifestLoadError::ServerIdMismatch {
            expected: expected_server_id.to_string(),
            actual: signed.manifest.server_id.to_string(),
        });
    }
    let registered_key = PublicKey::from_hex(registered_public_key_hex)
        .map_err(VerifiedManifestLoadError::RegisteredPublicKey)?;
    let mut registry = VerifiedManifestRegistry::default();
    registry.register_public_only(signed, &registered_key, topology)?;
    Ok(registry)
}

fn read_existing_signed_manifest(path: &Path) -> Result<SignedManifest, VerifiedManifestLoadError> {
    let file = open_existing_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| VerifiedManifestLoadError::ReadMetadata {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(VerifiedManifestLoadError::NotRegularFile(
            path.to_path_buf(),
        ));
    }
    if metadata.len() > MAX_SIGNED_MANIFEST_BYTES {
        return Err(VerifiedManifestLoadError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_SIGNED_MANIFEST_BYTES,
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SIGNED_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| VerifiedManifestLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_SIGNED_MANIFEST_BYTES {
        return Err(VerifiedManifestLoadError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_SIGNED_MANIFEST_BYTES,
        });
    }
    serde_json::from_slice(&bytes).map_err(|source| VerifiedManifestLoadError::Decode {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn open_existing_no_follow(path: &Path) -> Result<File, VerifiedManifestLoadError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|source| VerifiedManifestLoadError::Open {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn open_existing_no_follow(path: &Path) -> Result<File, VerifiedManifestLoadError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| {
        VerifiedManifestLoadError::ReadMetadata {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(VerifiedManifestLoadError::NotRegularFile(
            path.to_path_buf(),
        ));
    }
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| VerifiedManifestLoadError::Open {
            path: path.to_path_buf(),
            source,
        })
}

#[derive(Debug, thiserror::Error)]
pub enum VerifiedManifestLoadError {
    #[error("failed to open existing signed manifest {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read signed manifest metadata {path}: {source}")]
    ReadMetadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("signed manifest path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("signed manifest {path} exceeds the {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("failed to read signed manifest {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to decode signed manifest {path}: {source}")]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid registered manifest public key: {0}")]
    RegisteredPublicKey(chio_core::Error),
    #[error("signed manifest server id mismatch: expected {expected}, found {actual}")]
    ServerIdMismatch { expected: String, actual: String },
    #[error("signed manifest admission failed: {0}")]
    Admission(#[from] VerifiedManifestAdmissionError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifiedManifestAdmissionError {
    #[error("manifest verification failed: {0}")]
    Manifest(#[from] ManifestError),
    #[error("manifest input schema compilation failed: {0}")]
    InputSchema(#[from] ToolInputSchemaError),
    #[error("canonical manifest encoding failed: {0}")]
    Canonical(#[from] chio_core::Error),
    #[error("manifest server is already registered: {0}")]
    DuplicateServer(String),
    #[error("authenticated policy is missing for tool: {0}")]
    MissingPolicy(String),
    #[error("runtime topology is missing for tool: {0}")]
    MissingTopology(String),
    #[error("effective egress tool has no operator clearance: {0}")]
    MissingPolicyClearance(String),
    #[error("manifest input clearance widens authenticated policy for tool: {0}")]
    ManifestClearanceWidensPolicy(String),
    #[error("provider-native server tool requires remote runtime topology: {0}")]
    ServerToolRequiresRemoteTopology(String),
    #[error("native cage server is absent from the verified manifest registry: {0}")]
    CageServerNotRegistered(String),
    #[error("native cage manifest has no explicit platform permissions: {0}")]
    CagePermissionsMissing(String),
    #[error("native cage does not execute provider-native server tools: {0}")]
    CageProviderServerToolsUnsupported(String),
    #[error("native cage topology for {server_id} does not match required {required:?} placement")]
    CageTopologyMismatch {
        server_id: String,
        required: RuntimeToolTopology,
    },
    #[error("top is not an operational policy clearance")]
    TopPolicyClearance,
    #[error("top is not an operational policy output floor")]
    TopPolicyOutputFloor,
    #[error("effective output label join failed for tool: {0}")]
    OutputJoinFailed(String),
    #[error("effective output label is top for tool: {0}")]
    TopEffectiveOutput(String),
    #[error("top-labeled input cannot cross an egress boundary")]
    TopSource,
    #[error("input source label exceeds an admitted clearance")]
    SourceExceedsClearance,
    #[error("bridge security does not match live registry entry for {server_id}/{tool_name}")]
    BridgeSecurityMismatch {
        server_id: String,
        tool_name: String,
    },
}
