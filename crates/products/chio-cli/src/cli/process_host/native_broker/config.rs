//! Explicit broker route and shared host authority configuration.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring: Option<super::super::keyring::Config>,
    pub security: chio_process::ProcessSecurityProfile,
    pub routes: Vec<RouteConfig>,
    pub authority_seed_file: PathBuf,
    pub authority_public_key: PublicKey,
    pub classifier: ClassifierConfig,
    pub operator_input_floor: InformationLabel,
    pub fence_ttl_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteConfig {
    pub quota: BrokerQuotaVerifierConfig,
    pub broker_identity: PublicKey,
    pub revocation_authority_domain: String,
    pub ipc_timeout_ms: u64,
    pub authority_socket_name: String,
    pub preparation: Option<super::preparation::PreparationConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClassifierConfig {
    pub id: String,
    pub version: String,
    pub rules: Vec<ClassifierRule>,
    pub category_labels: BTreeMap<String, InformationLabel>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClassifierRule {
    pub category: String,
    pub expression: String,
    pub confidence_basis_points: u16,
}

impl Config {
    pub(crate) fn route(&self, server: &str, tool: &str) -> Result<&RouteConfig, CliError> {
        self.routes
            .iter()
            .find(|route| route.quota.server_id == server && route.quota.tool_name == tool)
            .ok_or_else(|| error("broker route is not installed"))
    }

    pub fn validate_grant_quota(
        &self,
        scope: &chio_core_types::capability::scope::ChioScope,
    ) -> Result<(), CliError> {
        use chio_core_types::capability::scope::Operation;
        for route in &self.routes {
            if let Some(preparation) = &route.preparation {
                preparation.validate()?;
            }
            let mut matched = false;
            for grant in &scope.grants {
                if (grant.server_id == route.quota.server_id || grant.server_id == "*")
                    && (grant.tool_name == route.quota.tool_name || grant.tool_name == "*")
                    && grant.operations.contains(&Operation::Invoke)
                {
                    matched = true;
                    if grant.max_invocations.is_none_or(|limit| limit == 0) {
                        return Err(error(
                            "native broker grants require a positive invocation quota",
                        ));
                    }
                }
            }
            if !matched {
                return Err(error("native broker route has no invocation grant"));
            }
        }
        Ok(())
    }

    pub fn validate(&self, host: &HostConfig) -> Result<(), CliError> {
        if let Some(keyring) = &self.keyring {
            keyring.validate()?;
            if !host.children.is_empty() || !host.spawn_templates.is_empty() {
                return Err(error(
                    "governed broker hosts currently require one root process",
                ));
            }
        }
        self.security.validate().map_err(error)?;
        if !self.authority_seed_file.is_absolute() {
            return Err(error("broker authority seed path must be absolute"));
        }
        if !cfg!(target_os = "linux")
            || self.routes.is_empty()
            || self.routes.len() > chio_secret_broker::kernel_admission::MAX_BROKER_ROUTES
            || host.servers.len() != self.routes.len()
            || !host.mailboxes.is_empty()
            || !host.spawn_templates.is_empty()
        {
            return Err(error(
                "native broker hosts require Linux and explicit bounded broker routes",
            ));
        }
        if self.fence_ttl_ms == 0 || self.fence_ttl_ms > 30_000 {
            return Err(error("flow fence deadline must be within 1..=30000 ms"));
        }
        let mut servers = std::collections::BTreeSet::new();
        let mut audiences = std::collections::BTreeSet::new();
        let mut sockets = std::collections::BTreeSet::new();
        for route in &self.routes {
            if !servers.insert(&route.quota.server_id)
                || !audiences.insert(&route.quota.audience)
                || !sockets.insert(&route.authority_socket_name)
                || !host
                    .servers
                    .iter()
                    .any(|server| server.id == route.quota.server_id)
                || route.ipc_timeout_ms == 0
                || route.ipc_timeout_ms > 30_000
                || route.authority_socket_name.is_empty()
                || route.authority_socket_name.len() > 48
                || matches!(route.authority_socket_name.as_str(), "." | "..")
                || !route
                    .authority_socket_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                return Err(error(
                    "broker routes require unique servers, audiences and bounded socket names",
                ));
            }
            BrokerQuotaVerifier::new(
                route.quota.clone(),
                Arc::new(chio_secret_broker::daemon::SystemClock),
            )
            .map_err(error)?;
        }
        self.classification()?;
        Ok(())
    }

    pub(super) fn classification(
        &self,
    ) -> Result<(StructuredClassificationAdapter, FlowResolverConfig), CliError> {
        if self.classifier.rules.is_empty() {
            return Err(error(
                "native broker hosts require an explicit classifier rule set",
            ));
        }
        if self
            .classifier
            .rules
            .iter()
            .any(|rule| !self.classifier.category_labels.contains_key(&rule.category))
        {
            return Err(error(
                "native broker classifier rules require explicit category labels",
            ));
        }
        let rules = self
            .classifier
            .rules
            .iter()
            .map(|rule| {
                RegexClassificationRule::new(
                    &rule.category,
                    &rule.expression,
                    rule.confidence_basis_points,
                )
                .map_err(error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let classifier =
            RegexStructuredClassifier::new(&self.classifier.id, &self.classifier.version, rules)
                .map_err(error)?;
        let labels = self
            .classifier
            .category_labels
            .iter()
            .map(|(name, label)| Ok((RecordId::new(name).map_err(error)?, label.clone())))
            .collect::<Result<BTreeMap<_, _>, CliError>>()?;
        let mapping = chio_flow::CategoryLabelMap::new(
            ClassifierId::new(&self.classifier.id).map_err(error)?,
            ClassifierVersion::new(&self.classifier.version).map_err(error)?,
            labels,
        )
        .map_err(error)?;
        let config = FlowResolverConfig::new(
            self.operator_input_floor.clone(),
            mapping,
            BTreeMap::new(),
            self.fence_ttl_ms,
        )
        .map_err(error)?;
        Ok((
            StructuredClassificationAdapter::new(Arc::new(classification::BrokerBodyClassifier(
                classifier,
            ))),
            config,
        ))
    }

    pub(super) fn authority_signer(&self) -> Result<Arc<Ed25519Backend>, CliError> {
        read_signer(&self.authority_seed_file, &self.authority_public_key)
    }
}

pub(super) fn read_signer(
    path: &Path,
    public_key: &PublicKey,
) -> Result<Arc<Ed25519Backend>, CliError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.uid()
            != chio_cage::BrokerPeerIdentity::current_process()
                .map_err(error)?
                .uid
    {
        return Err(error(
            "broker authority seed must be a private regular file owned by the host",
        ));
    }
    let mut seed = zeroize::Zeroizing::new(String::new());
    file.take(66).read_to_string(&mut seed)?;
    if metadata.len() > 65 {
        return Err(error("broker authority seed is oversized"));
    }
    let key = chio_core_types::Keypair::from_seed_hex(seed.trim()).map_err(error)?;
    if &key.public_key() != public_key {
        return Err(error(
            "broker authority seed differs from the operator's signing-key pin",
        ));
    }
    Ok(Arc::new(Ed25519Backend::new(key)))
}
