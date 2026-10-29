use super::*;

#[derive(Clone)]
pub struct TrustFiscalRuntimeConfig {
    pub genesis_policy: chio_fiscal::FiscalGenesisPolicy,
    pub anchor_url: String,
    pub anchor_bearer_token: String,
    pub anchor_timeout: Duration,
    pub admission_authority_id: String,
    pub admission_signer_key_epoch: u64,
    pub admission_signing_seed_path: PathBuf,
}

impl std::fmt::Debug for TrustFiscalRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustFiscalRuntimeConfig")
            .field("policy_id", &self.genesis_policy.policy_id)
            .field("anchor_url", &self.anchor_url)
            .field("anchor_bearer_token", &"[REDACTED]")
            .field("anchor_timeout", &self.anchor_timeout)
            .field("admission_authority_id", &self.admission_authority_id)
            .field(
                "admission_signer_key_epoch",
                &self.admission_signer_key_epoch,
            )
            .field(
                "admission_signing_seed_path",
                &self.admission_signing_seed_path,
            )
            .finish()
    }
}

impl TrustFiscalRuntimeConfig {
    pub fn from_policy_file(
        policy_path: &Path,
        anchor_url: String,
        anchor_bearer_token: String,
        anchor_timeout: Duration,
        admission_authority_id: String,
        admission_signer_key_epoch: u64,
        admission_signing_seed_path: PathBuf,
    ) -> Result<Self, CliError> {
        let bytes = std::fs::read(policy_path).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to read fiscal genesis policy {}: {error}",
                policy_path.display()
            ))
        })?;
        let genesis_policy =
            chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 64 * 1024 * 1024)
                .and_then(|input| input.decode_signed())
                .map_err(CliError::from)?;
        Ok(Self {
            genesis_policy,
            anchor_url,
            anchor_bearer_token,
            anchor_timeout,
            admission_authority_id,
            admission_signer_key_epoch,
            admission_signing_seed_path,
        })
    }
}

#[derive(Clone)]
pub struct TrustServiceConfig {
    pub listen: SocketAddr,
    /// Listener confidentiality and explicit plaintext policy.
    pub transport: chio_http_serve::ServerTransportConfig,
    /// Caller credentials, the internal listener and the pinned cluster
    /// peers. Every route authenticates against this and nothing else.
    pub access: Arc<crate::trust_control::caller_credentials::TrustAccess>,
    pub receipt_db_path: Option<PathBuf>,
    /// Maximum private receipt query snapshot database bytes (at least 1 MiB).
    pub receipt_query_snapshot_quota_bytes: u64,
    pub revocation_db_path: Option<PathBuf>,
    pub authority_seed_path: Option<PathBuf>,
    pub authority_db_path: Option<PathBuf>,
    /// Witnessed key-log runtime configuration for seed-file authority custody.
    /// When present, direct seed signing is disabled after startup.
    pub authority_keyring_config_path: Option<PathBuf>,
    /// Private receipt rollback anchors on a separate filesystem device.
    pub authority_keyring_receipt_anchor_root: Option<PathBuf>,
    pub budget_db_path: Option<PathBuf>,
    /// Per-peer `issued_at` high-water marks of accepted cluster peer
    /// requests. Required whenever cluster peers are pinned.
    pub cluster_peer_replay_db_path: Option<PathBuf>,
    pub joint_authority_db_path: Option<PathBuf>,
    pub fiscal_runtime: Option<TrustFiscalRuntimeConfig>,
    pub enterprise_providers_file: Option<PathBuf>,
    pub federation_policies_file: Option<PathBuf>,
    pub scim_lifecycle_file: Option<PathBuf>,
    pub verifier_policies_file: Option<PathBuf>,
    pub verifier_challenge_db_path: Option<PathBuf>,
    pub passport_statuses_file: Option<PathBuf>,
    /// Revocation partner registry. Every passport door re-reads it, and the
    /// mirror of each partner's revocation feed sits beside it.
    pub revocation_partners_file: Option<PathBuf>,
    pub passport_issuance_offers_file: Option<PathBuf>,
    pub certification_registry_file: Option<PathBuf>,
    pub certification_discovery_file: Option<PathBuf>,
    pub issuance_policy: Option<crate::policy::ReputationIssuancePolicy>,
    pub runtime_assurance_policy: Option<crate::policy::RuntimeAssuranceIssuancePolicy>,
    pub advertise_url: Option<String>,
    pub allow_local_peer_urls: bool,
    pub certification_public_metadata_ttl_seconds: u64,
    pub cluster_sync_interval: Duration,
    /// Explicit future-issue skew for signed authority replication (0 to 60
    /// seconds). Expiry and local clock floors receive no tolerance.
    pub authority_replication_max_future_skew_seconds: u64,
    pub roster_policy: Option<RosterPolicy>,
    /// Process memory budget for the trust control service. Its
    /// `admission_key_cap` bounds the federation admission rate limiter, so
    /// lowering it here actually tightens that guard rather than being silently
    /// overridden by the compiled-in default.
    pub memory_budget: chio_kernel::MemoryBudgetConfig,
    /// Cognition-market authority roster. `None` keeps every
    /// finding surface at 409; the field exists only under the ship-dark
    /// feature.
    pub finding_market: Option<super::finding_market_config::FindingMarketConfig>,
}

const MIN_RECEIPT_QUERY_SNAPSHOT_QUOTA_BYTES: u64 = 1024 * 1024;

impl TrustServiceConfig {
    /// Node ids of the pinned cluster peers, in order.
    #[must_use]
    pub fn peer_urls(&self) -> Vec<String> {
        self.access
            .peers()
            .iter()
            .map(|peer| peer.node_id.clone())
            .collect()
    }

    /// Whether this node replicates with any peer.
    #[must_use]
    pub fn is_clustered(&self) -> bool {
        self.access.peers().iter().next().is_some()
    }

    pub(crate) fn authority_replication_clock_policy(
        &self,
    ) -> Result<chio_kernel::authority::replication::AuthorityEnvelopeClockPolicy, CliError> {
        chio_kernel::authority::replication::AuthorityEnvelopeClockPolicy::new(
            self.authority_replication_max_future_skew_seconds,
        )
        .map_err(CliError::from)
    }

    /// Operator startup validation. A keyring takes custody of the authority
    /// seed it is started with; startup then clears the seed from the serving
    /// configuration, so only this check requires it.
    pub(crate) fn validate_bootstrap(&self) -> Result<(), CliError> {
        if self.authority_keyring_config_path.is_some() && self.authority_seed_path.is_none() {
            return Err(CliError::cli_other_error(
                "authority keyring configuration requires --authority-seed-file".to_string(),
            ));
        }
        self.validate()
    }

    /// Serving invariants, which also hold once a keyring owns the seed.
    pub fn validate(&self) -> Result<(), CliError> {
        self.transport
            .validate(self.listen)
            .map_err(std::io::Error::other)?;
        self.authority_replication_clock_policy()?;
        if self.receipt_query_snapshot_quota_bytes < MIN_RECEIPT_QUERY_SNAPSHOT_QUOTA_BYTES {
            return Err(CliError::cli_other_error(format!(
                "--receipt-query-snapshot-quota-bytes must be at least {MIN_RECEIPT_QUERY_SNAPSHOT_QUOTA_BYTES} bytes (1 MiB)"
            )));
        }
        self.access
            .config()
            .validate_listeners(self.listen)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        if let Some(identity) = self.access.peers().identity() {
            let advertised = self
                .advertise_url
                .as_deref()
                .map(super::super::report_validation::normalize_cluster_url)
                .transpose()?;
            if advertised.as_deref() != Some(identity.node_id.as_str()) {
                return Err(CliError::cli_other_error(
                    "--advertise-url must equal the access configuration [cluster] node_id"
                        .to_string(),
                ));
            }
        }
        if self.authority_seed_path.is_some() && self.authority_db_path.is_some() {
            return Err(CliError::cli_other_error(
                "use either --authority-seed-file or --authority-db, not both".to_string(),
            ));
        }
        if self.authority_keyring_config_path.is_some() {
            if self.authority_db_path.is_some()
                || self.receipt_db_path.is_none()
                || self.authority_keyring_receipt_anchor_root.is_none()
                || !self.access.credentials().any_holds(
                    crate::trust_control::caller_credentials::CredentialKind::Deployment,
                    crate::trust_control::caller_credentials::Scope::CapabilitiesIssue,
                )
            {
                return Err(CliError::cli_other_error(
                    "authority keyring configuration requires --receipt-db, --authority-keyring-receipt-anchor-root, and a deployment credential with capabilities:issue and forbids --authority-db"
                        .to_string(),
                ));
            }
            if self.is_clustered() {
                return Err(CliError::cli_other_error(
                    "clustered keyring authority issuance is unavailable until selector leases share the cluster consensus domain"
                        .to_string(),
                ));
            }
        }
        if self.authority_keyring_receipt_anchor_root.is_some()
            && self.authority_keyring_config_path.is_none()
        {
            return Err(CliError::cli_other_error(
                "authority keyring receipt anchors require --authority-keyring-config".to_string(),
            ));
        }
        if self.cluster_sync_interval.is_zero() {
            return Err(CliError::cli_other_error(
                "cluster sync interval must be non-zero".to_string(),
            ));
        }
        if self.certification_public_metadata_ttl_seconds == 0 {
            return Err(CliError::cli_other_error(
                "certification public metadata TTL must be non-zero".to_string(),
            ));
        }
        if let Some(finding_market) = &self.finding_market {
            finding_market.validate()?;
        }
        if self.joint_authority_db_path.is_some()
            && (self.budget_db_path.is_some() || self.revocation_db_path.is_some())
        {
            return Err(CliError::cli_other_error(
                "a joint authority database replaces separate budget and revocation databases"
                    .to_string(),
            ));
        }
        if self.is_clustered() && self.cluster_peer_replay_db_path.is_none() {
            return Err(CliError::cli_other_error(
                super::super::route_authorization::CLUSTER_PEER_REPLAY_DB_REQUIRED.to_string(),
            ));
        }
        if self.joint_authority_db_path.is_some() && self.is_clustered() {
            return Err(CliError::cli_other_error(
                "a local joint authority database cannot run with peer cluster replication"
                    .to_string(),
            ));
        }
        if let Some(fiscal) = &self.fiscal_runtime {
            if self.joint_authority_db_path.is_none() {
                return Err(CliError::cli_other_error(
                    "fiscal runtime requires the joint authority database".to_string(),
                ));
            }
            if fiscal.anchor_timeout.is_zero() {
                return Err(CliError::cli_other_error(
                    "fiscal anchor timeout must be non-zero".to_string(),
                ));
            }
            validate_control_secret(&fiscal.anchor_bearer_token, "fiscal anchor bearer token")?;
            if fiscal.admission_authority_id.trim().is_empty()
                || fiscal.admission_authority_id.trim() != fiscal.admission_authority_id
                || fiscal.admission_signer_key_epoch == 0
            {
                return Err(CliError::cli_other_error(
                    "fiscal admission authority configuration is invalid".to_string(),
                ));
            }
        }
        let mut database_paths = Vec::new();
        for (label, path) in [
            (
                "joint authority database",
                self.joint_authority_db_path.as_deref(),
            ),
            ("receipt database", self.receipt_db_path.as_deref()),
            ("revocation database", self.revocation_db_path.as_deref()),
            (
                "capability authority database",
                self.authority_db_path.as_deref(),
            ),
            ("budget database", self.budget_db_path.as_deref()),
            (
                "cluster peer replay database",
                self.cluster_peer_replay_db_path.as_deref(),
            ),
            (
                "verifier challenge database",
                self.verifier_challenge_db_path.as_deref(),
            ),
        ] {
            if let Some(path) = path {
                database_paths.push((label, path));
            }
        }
        crate::validate_distinct_database_paths(&database_paths)?;
        Ok(())
    }
}

pub(crate) fn validate_control_secret(secret: &str, label: &str) -> Result<(), CliError> {
    if secret.trim().is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be non-empty"
        )));
    }
    if secret.trim() != secret {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain surrounding whitespace"
        )));
    }
    if secret.chars().any(char::is_control) {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod service_config_tests {
    use super::*;
    use crate::trust_control::caller_credentials::tests::set_test_peers;
    use chio_test_support::prelude::*;

    fn base_config() -> TrustServiceConfig {
        let listen = match "127.0.0.1:0".parse() {
            Ok(addr) => addr,
            Err(error) => panic!("test listen address should parse: {error}"),
        };
        TrustServiceConfig {
            transport: Default::default(),
            listen,
            access: crate::trust_control::caller_credentials::tests::test_access("token"),
            receipt_db_path: None,
            receipt_query_snapshot_quota_bytes: 2_147_483_648,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            authority_keyring_config_path: None,
            authority_keyring_receipt_anchor_root: None,
            budget_db_path: None,
            cluster_peer_replay_db_path: None,
            joint_authority_db_path: None,
            fiscal_runtime: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            revocation_partners_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: PUBLIC_DISCOVERY_TTL_SECS,
            cluster_sync_interval: Duration::from_millis(25),
            authority_replication_max_future_skew_seconds: 0,
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            finding_market: None,
        }
    }

    #[test]
    fn trust_service_config_refuses_receipt_query_snapshot_quota_below_minimum() {
        for quota in [0, 1, 1_048_575] {
            let mut config = base_config();
            config.receipt_query_snapshot_quota_bytes = quota;
            let error = config
                .validate()
                .test_expect_err("snapshot quotas below 1 MiB must fail service configuration");
            assert!(error
                .to_string()
                .contains("--receipt-query-snapshot-quota-bytes must be at least 1048576"));
        }
    }

    #[test]
    fn trust_service_config_preserves_explicit_nonzero_snapshot_quota_bytes() {
        for quota in [1_048_576, 2_147_483_648, 4_294_967_296, u64::MAX] {
            let mut config = base_config();
            config.receipt_query_snapshot_quota_bytes = quota;
            config
                .validate()
                .test_expect("a nonzero u64 quota belongs to core capacity validation");
            assert_eq!(config.receipt_query_snapshot_quota_bytes, quota);
        }
    }

    fn fiscal_runtime_config() -> TrustFiscalRuntimeConfig {
        let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../spec/schemas/chio-fiscal/v1/fixtures/genesis-policy.positive.json");
        TrustFiscalRuntimeConfig::from_policy_file(
            &policy_path,
            "https://fiscal-anchor.example".to_owned(),
            "fiscal-anchor-token".to_owned(),
            Duration::from_secs(5),
            "fiscal-admission".to_owned(),
            1,
            PathBuf::from("fiscal-admission.seed"),
        )
        .test_expect("fiscal fixture config")
    }

    #[test]
    fn fiscal_runtime_config_is_redacted_and_requires_joint_authority() {
        let fiscal = fiscal_runtime_config();
        assert!(!format!("{fiscal:?}").contains("fiscal-anchor-token"));
        let mut config = base_config();
        config.fiscal_runtime = Some(fiscal);

        let error = config
            .validate()
            .test_expect_err("fiscal runtime without joint authority must fail");
        assert!(error
            .to_string()
            .contains("fiscal runtime requires the joint authority database"));
    }

    #[test]
    fn keyring_authority_requires_complete_single_node_custody() {
        let mut config = base_config();
        config.access = crate::trust_control::caller_credentials::tests::test_access_with_scopes(
            "token",
            &["reports:read"],
        );
        config.authority_keyring_config_path = Some(PathBuf::from("keyring.yml"));
        let incomplete = config
            .validate()
            .test_expect_err("keyring without custody must fail");
        assert!(incomplete.to_string().contains(
            "authority keyring configuration requires --receipt-db, --authority-keyring-receipt-anchor-root"
        ));

        config.receipt_db_path = Some(PathBuf::from("receipts.sqlite3"));
        let without_issuer = config
            .validate()
            .test_expect_err("keyring without a capability issuer credential must fail");
        assert!(without_issuer
            .to_string()
            .contains("a deployment credential with capabilities:issue"));
        config.access = crate::trust_control::caller_credentials::tests::test_access("token");
        let unanchored = config
            .validate()
            .test_expect_err("keyring receipt custody requires independent rollback anchors");
        assert!(unanchored
            .to_string()
            .contains("--authority-keyring-receipt-anchor-root"));
        config.authority_keyring_receipt_anchor_root = Some(PathBuf::from("/anchors/keyring"));
        config
            .validate()
            .test_expect("keyring-owned seed config is a valid serving config");
        let seedless = config
            .validate_bootstrap()
            .test_expect_err("keyring startup without an authority seed must fail");
        assert!(
            matches!(&seedless, CliError::Chio(error) if error.message() == "authority keyring configuration requires --authority-seed-file"),
            "{seedless}"
        );
        config.authority_seed_path = Some(PathBuf::from("authority.seed"));
        config
            .validate_bootstrap()
            .test_expect("complete single-node keyring config is valid at startup");

        set_test_peers(
            &mut config,
            "https://self.example",
            &["https://peer.example"],
        );
        let clustered = config
            .validate()
            .test_expect_err("keyring cluster without selector consensus must fail");
        assert!(clustered
            .to_string()
            .contains("selector leases share the cluster consensus domain"));
    }

    #[test]
    fn trust_service_config_rejects_split_stores_with_joint_authority() {
        let mut config = base_config();
        config.joint_authority_db_path = Some(PathBuf::from("joint.sqlite3"));
        config.budget_db_path = Some(PathBuf::from("budget.sqlite3"));

        let error = config
            .validate()
            .test_expect_err("split budget store must conflict with joint authority");

        assert!(error
            .to_string()
            .contains("joint authority database replaces separate budget and revocation"));
    }

    #[test]
    fn trust_service_config_rejects_joint_authority_with_peer_cluster() {
        let mut config = base_config();
        config.joint_authority_db_path = Some(PathBuf::from("joint.sqlite3"));
        set_test_peers(
            &mut config,
            "https://self.example",
            &["https://peer.example"],
        );

        let error = config
            .validate()
            .test_expect_err("joint authority must not use peer cluster replication");

        assert_eq!(
            error.to_string(),
            CliError::cli_other_error(
                "a local joint authority database cannot run with peer cluster replication"
            )
            .to_string()
        );
    }

    #[test]
    fn trust_service_config_requires_a_peer_replay_database_when_clustered() {
        let mut config = base_config();
        set_test_peers(
            &mut config,
            "https://self.example",
            &["https://peer.example"],
        );
        config.cluster_peer_replay_db_path = None;

        let error = config
            .validate()
            .test_expect_err("clustered node without a peer replay database must fail");

        assert_eq!(
            error.to_string(),
            CliError::cli_other_error("clustered trust control requires --cluster-peer-replay-db")
                .to_string()
        );
    }

    #[test]
    fn trust_service_config_rejects_a_peer_replay_database_alias() {
        let mut config = base_config();
        set_test_peers(
            &mut config,
            "https://self.example",
            &["https://peer.example"],
        );
        config.budget_db_path = Some(PathBuf::from("replay.sqlite3"));
        config.cluster_peer_replay_db_path = Some(PathBuf::from("./replay.sqlite3"));

        let error = config
            .validate()
            .test_expect_err("peer replay database must not alias the budget store");

        assert!(
            error.to_string().contains("cluster peer replay database"),
            "{error}"
        );
    }

    #[test]
    fn trust_service_config_rejects_joint_authority_path_aliases() {
        let mut config = base_config();
        config.joint_authority_db_path = Some(PathBuf::from("authority.sqlite3"));
        config.receipt_db_path = Some(PathBuf::from("./authority.sqlite3"));

        let error = config
            .validate()
            .test_expect_err("joint authority must not alias the receipt store");

        assert!(error
            .to_string()
            .contains("joint authority database must not alias receipt database"));
    }

    #[test]
    fn trust_service_config_rejects_zero_public_certification_metadata_ttl() {
        let mut config = base_config();
        config.certification_public_metadata_ttl_seconds = 0;

        let error = config.validate().test_unwrap_err();

        assert!(
            error
                .to_string()
                .contains("certification public metadata TTL must be non-zero"),
            "unexpected zero TTL error: {error}",
        );
    }
}
