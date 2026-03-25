use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use pact_core::sha256_hex;
use pact_kernel::{
    KernelError, NestedFlowBridge, ToolCallChunk, ToolCallStream, ToolServerConnection,
    ToolServerStreamResult,
};
use pact_manifest::{validate_manifest, LatencyHint, ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use url::form_urlencoded::{byte_serialize, Serializer as UrlFormSerializer};
use url::Url;

const DEFAULT_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const A2A_VERSION_HEADER: &str = "A2A-Version";
const A2A_PROTOCOL_MAJOR: &str = "1.";
const A2A_PROTOCOL_VERSION_HEADER_VALUE: &str = "1.0";
const SSE_CONTENT_TYPE: &str = "text/event-stream";
const OAUTH_CACHE_SKEW_SECS: u64 = 30;
const TASK_REGISTRY_VERSION: &str = "pact.a2a-task-registry.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct A2aRequestHeader {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct A2aRequestQueryParam {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct A2aRequestCookie {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct A2aOAuthClientCredentials {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Clone)]
struct A2aCachedBearerToken {
    cache_key: String,
    access_token: String,
    expires_at: Option<SystemTime>,
}

#[derive(Debug, Clone)]
struct A2aMutualTlsIdentity {
    cert_chain_pem: String,
    private_key_pem: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum A2aTlsMode {
    Default,
    MutualTls,
}

#[derive(Debug, Clone)]
struct A2aResolvedRequestAuth {
    headers: Vec<A2aRequestHeader>,
    query_params: Vec<A2aRequestQueryParam>,
    cookies: Vec<A2aRequestCookie>,
    tls_mode: A2aTlsMode,
}

#[derive(Debug, Clone)]
struct A2aTransportConfig {
    default_tls_config: Option<Arc<ureq::rustls::ClientConfig>>,
    mutual_tls_config: Option<Arc<ureq::rustls::ClientConfig>>,
}

#[derive(Debug, Clone, Default)]
pub struct A2aPartnerPolicy {
    partner_id: String,
    required_tenant: Option<String>,
    required_skills: Vec<String>,
    required_security_scheme_names: Vec<String>,
    allowed_interface_origins: Vec<String>,
}

impl A2aPartnerPolicy {
    #[must_use]
    pub fn new(partner_id: impl Into<String>) -> Self {
        Self {
            partner_id: partner_id.into(),
            required_tenant: None,
            required_skills: Vec::new(),
            required_security_scheme_names: Vec::new(),
            allowed_interface_origins: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_required_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.required_tenant = Some(tenant.into());
        self
    }

    #[must_use]
    pub fn require_skill(mut self, skill_id: impl Into<String>) -> Self {
        let skill_id = skill_id.into();
        if !skill_id.trim().is_empty()
            && !self.required_skills.iter().any(|existing| existing == &skill_id)
        {
            self.required_skills.push(skill_id);
        }
        self
    }

    #[must_use]
    pub fn require_security_scheme(mut self, scheme_name: impl Into<String>) -> Self {
        let scheme_name = scheme_name.into();
        if !scheme_name.trim().is_empty()
            && !self
                .required_security_scheme_names
                .iter()
                .any(|existing| existing == &scheme_name)
        {
            self.required_security_scheme_names.push(scheme_name);
        }
        self
    }

    #[must_use]
    pub fn allow_interface_origin(mut self, origin: impl Into<String>) -> Self {
        let origin = origin.into();
        if !origin.trim().is_empty()
            && !self
                .allowed_interface_origins
                .iter()
                .any(|existing| existing == &origin)
        {
            self.allowed_interface_origins.push(origin);
        }
        self
    }
}

#[derive(Debug, Clone)]
pub struct A2aAdapterConfig {
    agent_card_url: String,
    public_key: String,
    request_headers: Vec<A2aRequestHeader>,
    request_query_params: Vec<A2aRequestQueryParam>,
    request_cookies: Vec<A2aRequestCookie>,
    oauth_client_credentials: Option<A2aOAuthClientCredentials>,
    oauth_scopes: Vec<String>,
    oauth_token_endpoint_override: Option<String>,
    tls_root_ca_pems: Vec<String>,
    mutual_tls_identity: Option<A2aMutualTlsIdentity>,
    timeout: Duration,
    server_id: Option<String>,
    server_version: String,
    partner_policy: Option<A2aPartnerPolicy>,
    task_registry_path: Option<PathBuf>,
}

impl A2aAdapterConfig {
    #[must_use]
    pub fn new(agent_card_url: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            agent_card_url: agent_card_url.into(),
            public_key: public_key.into(),
            request_headers: Vec::new(),
            request_query_params: Vec::new(),
            request_cookies: Vec::new(),
            oauth_client_credentials: None,
            oauth_scopes: Vec::new(),
            oauth_token_endpoint_override: None,
            tls_root_ca_pems: Vec::new(),
            mutual_tls_identity: None,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            server_id: None,
            server_version: "0.1.0".to_string(),
            partner_policy: None,
            task_registry_path: None,
        }
    }

    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        upsert_request_header(
            &mut self.request_headers,
            "Authorization".to_string(),
            format!("Bearer {}", token.into()),
        );
        self
    }

    #[must_use]
    pub fn with_http_basic_auth(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        upsert_request_header(
            &mut self.request_headers,
            "Authorization".to_string(),
            basic_request_header_value(username.into(), password.into()),
        );
        self
    }

    #[must_use]
    pub fn with_request_header(
        mut self,
        header_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_header(&mut self.request_headers, header_name.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_api_key_header(
        mut self,
        header_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_header(&mut self.request_headers, header_name.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_request_query_param(
        mut self,
        param_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_query_param(
            &mut self.request_query_params,
            param_name.into(),
            value.into(),
        );
        self
    }

    #[must_use]
    pub fn with_api_key_query_param(
        mut self,
        param_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_query_param(
            &mut self.request_query_params,
            param_name.into(),
            value.into(),
        );
        self
    }

    #[must_use]
    pub fn with_request_cookie(
        mut self,
        cookie_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_cookie(&mut self.request_cookies, cookie_name.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_api_key_cookie(
        mut self,
        cookie_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_cookie(&mut self.request_cookies, cookie_name.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_oauth_client_credentials(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.oauth_client_credentials = Some(A2aOAuthClientCredentials {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        });
        self
    }

    #[must_use]
    pub fn with_oauth_scope(mut self, scope: impl Into<String>) -> Self {
        let scope = scope.into();
        if !scope.trim().is_empty() && !self.oauth_scopes.iter().any(|existing| existing == &scope)
        {
            self.oauth_scopes.push(scope);
        }
        self
    }

    #[must_use]
    pub fn with_oauth_token_endpoint(mut self, token_endpoint: impl Into<String>) -> Self {
        self.oauth_token_endpoint_override = Some(token_endpoint.into());
        self
    }

    #[must_use]
    pub fn with_tls_root_ca_pem(mut self, root_ca_pem: impl Into<String>) -> Self {
        let root_ca_pem = root_ca_pem.into();
        if !root_ca_pem.trim().is_empty() {
            self.tls_root_ca_pems.push(root_ca_pem);
        }
        self
    }

    #[must_use]
    pub fn with_mtls_client_auth_pem(
        mut self,
        cert_chain_pem: impl Into<String>,
        private_key_pem: impl Into<String>,
    ) -> Self {
        self.mutual_tls_identity = Some(A2aMutualTlsIdentity {
            cert_chain_pem: cert_chain_pem.into(),
            private_key_pem: private_key_pem.into(),
        });
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_server_id(mut self, server_id: impl Into<String>) -> Self {
        self.server_id = Some(server_id.into());
        self
    }

    #[must_use]
    pub fn with_server_version(mut self, server_version: impl Into<String>) -> Self {
        self.server_version = server_version.into();
        self
    }

    #[must_use]
    pub fn with_partner_policy(mut self, policy: A2aPartnerPolicy) -> Self {
        self.partner_policy = Some(policy);
        self
    }

    #[must_use]
    pub fn with_task_registry_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.task_registry_path = Some(path.into());
        self
    }
}

#[derive(Debug)]
pub struct A2aAdapter {
    manifest: ToolManifest,
    agent_card: A2aAgentCard,
    agent_card_url: Url,
    selected_interface: A2aAgentInterface,
    selected_binding: A2aProtocolBinding,
    configured_headers: Vec<A2aRequestHeader>,
    configured_query_params: Vec<A2aRequestQueryParam>,
    configured_cookies: Vec<A2aRequestCookie>,
    oauth_client_credentials: Option<A2aOAuthClientCredentials>,
    oauth_scopes: Vec<String>,
    oauth_token_endpoint_override: Option<String>,
    transport_config: A2aTransportConfig,
    token_cache: Mutex<Vec<A2aCachedBearerToken>>,
    timeout: Duration,
    request_counter: AtomicU64,
    partner_policy: Option<A2aPartnerPolicy>,
    task_registry: Option<A2aTaskRegistry>,
}

impl A2aAdapter {
    pub fn discover(config: A2aAdapterConfig) -> Result<Self, AdapterError> {
        let agent_card_url = normalize_agent_card_url(&config.agent_card_url)?;
        let transport_config = A2aTransportConfig {
            default_tls_config: build_optional_default_tls_config(&config.tls_root_ca_pems)?,
            mutual_tls_config: build_optional_mutual_tls_config(
                &config.tls_root_ca_pems,
                config.mutual_tls_identity.as_ref(),
            )?,
        };
        let discovery_tls_mode = if transport_config.mutual_tls_config.is_some() {
            A2aTlsMode::MutualTls
        } else {
            A2aTlsMode::Default
        };
        let discovery_request_auth = A2aResolvedRequestAuth {
            headers: config.request_headers.clone(),
            query_params: config.request_query_params.clone(),
            cookies: config.request_cookies.clone(),
            tls_mode: discovery_tls_mode,
        };
        let agent_card = fetch_json::<A2aAgentCard>(
            &agent_card_url,
            &discovery_request_auth,
            config.timeout,
            &transport_config,
        )?;
        if agent_card.skills.is_empty() {
            return Err(AdapterError::NoSkillsAdvertised);
        }

        let (selected_interface, selected_binding) = select_supported_interface(
            &agent_card.supported_interfaces,
            config.partner_policy.as_ref(),
        )?;
        if let Some(policy) = config.partner_policy.as_ref() {
            validate_partner_policy(policy, &agent_card, &selected_interface)?;
        }
        let server_id = config
            .server_id
            .unwrap_or_else(|| derive_pact_server_id(&agent_card_url));
        let manifest = build_manifest(
            &server_id,
            &config.server_version,
            &config.public_key,
            &agent_card,
            &selected_binding,
        )?;

        Ok(Self {
            manifest,
            agent_card,
            agent_card_url,
            selected_interface,
            selected_binding,
            configured_headers: config.request_headers,
            configured_query_params: config.request_query_params,
            configured_cookies: config.request_cookies,
            oauth_client_credentials: config.oauth_client_credentials,
            oauth_scopes: config.oauth_scopes,
            oauth_token_endpoint_override: config.oauth_token_endpoint_override,
            transport_config,
            token_cache: Mutex::new(Vec::new()),
            timeout: config.timeout,
            request_counter: AtomicU64::new(0),
            partner_policy: config.partner_policy,
            task_registry: config
                .task_registry_path
                .as_ref()
                .map(A2aTaskRegistry::open)
                .transpose()?,
        })
    }

    #[must_use]
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    #[must_use]
    pub fn agent_card(&self) -> &A2aAgentCard {
        &self.agent_card
    }

    #[must_use]
    pub fn agent_card_url(&self) -> &Url {
        &self.agent_card_url
    }

    #[must_use]
    pub fn selected_interface(&self) -> &A2aAgentInterface {
        &self.selected_interface
    }

    fn partner_label(&self) -> String {
        self.partner_policy
            .as_ref()
            .map(|policy| policy.partner_id.clone())
            .filter(|value| !value.trim().is_empty())
            .or_else(|| self.agent_card_url.host_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "a2a-partner".to_string())
    }

    fn auth_context(&self, skill: &A2aAgentSkill) -> String {
        let tenant = self.selected_interface.tenant.as_deref().unwrap_or("none");
        format!(
            "partner `{}` skill `{}` interface `{}` tenant `{tenant}`",
            self.partner_label(),
            skill.id,
            self.selected_interface.url
        )
    }

    fn validate_task_binding(
        &self,
        tool_name: &str,
        task_id: &str,
        operation: &str,
    ) -> Result<(), AdapterError> {
        let Some(registry) = self.task_registry.as_ref() else {
            return Ok(());
        };
        registry.validate_follow_up(
            task_id,
            tool_name,
            self.server_id(),
            &self.selected_interface,
            &self.selected_binding,
            operation,
        )
    }

    fn record_task_activity(
        &self,
        tool_name: &str,
        response: &Value,
        source: &str,
    ) -> Result<(), AdapterError> {
        let Some(registry) = self.task_registry.as_ref() else {
            return Ok(());
        };
        registry.record_from_value(
            response,
            source,
            tool_name,
            self.server_id(),
            &self.selected_interface,
            &self.selected_binding,
            &self.partner_label(),
        )
    }

    fn resolve_request_auth(
        &self,
        skill: &A2aAgentSkill,
    ) -> Result<A2aResolvedRequestAuth, AdapterError> {
        let Some(raw_requirements) = skill
            .security_requirements
            .as_ref()
            .or(self.agent_card.security_requirements.as_ref())
        else {
            return Ok(A2aResolvedRequestAuth {
                headers: self.configured_headers.clone(),
                query_params: self.configured_query_params.clone(),
                cookies: self.configured_cookies.clone(),
                tls_mode: A2aTlsMode::Default,
            });
        };
        let requirements = parse_security_requirements(raw_requirements)?;
        if requirements.is_empty() {
            return Ok(A2aResolvedRequestAuth {
                headers: Vec::new(),
                query_params: Vec::new(),
                cookies: Vec::new(),
                tls_mode: A2aTlsMode::Default,
            });
        }
        let Some(raw_schemes) = self.agent_card.security_schemes.as_ref() else {
            return Err(AdapterError::AuthNegotiation(format!(
                "{} declares security requirements but omits securitySchemes",
                self.auth_context(skill)
            )));
        };
        let schemes = parse_security_schemes(raw_schemes)?;
        let static_bearer = configured_bearer_header(&self.configured_headers);
        let static_basic = configured_basic_auth_header(&self.configured_headers);
        let mut errors = Vec::new();

        for requirement in requirements {
            if requirement.is_empty() {
                return Ok(A2aResolvedRequestAuth {
                    headers: Vec::new(),
                    query_params: Vec::new(),
                    cookies: Vec::new(),
                    tls_mode: A2aTlsMode::Default,
                });
            }
            let mut headers = Vec::new();
            let mut query_params = Vec::new();
            let mut cookies = Vec::new();
            let mut tls_mode = A2aTlsMode::Default;
            let mut supported = true;
            for entry in requirement {
                let Some(scheme) = schemes
                    .iter()
                    .find(|scheme| scheme.name == entry.scheme_name)
                else {
                    return Err(AdapterError::AuthNegotiation(format!(
                        "{} references unknown security scheme `{}`",
                        self.auth_context(skill),
                        entry.scheme_name
                    )));
                };
                let header = match &scheme.kind {
                    A2aSecuritySchemeKind::BearerToken => {
                        static_bearer.clone().map(Some).ok_or_else(|| {
                            AdapterError::AuthNegotiation(format!(
                                "missing bearer token for `{}`",
                                entry.scheme_name
                            ))
                        })
                    }
                    A2aSecuritySchemeKind::BasicAuth => {
                        static_basic.clone().map(Some).ok_or_else(|| {
                            AdapterError::AuthNegotiation(format!(
                                "missing HTTP Basic credentials for `{}`",
                                entry.scheme_name
                            ))
                        })
                    }
                    A2aSecuritySchemeKind::OAuthBearerToken { token_endpoint } => {
                        if let Some(header) = static_bearer.clone() {
                            Ok(Some(header))
                        } else {
                            self.acquire_oauth_bearer_header(
                                &entry.scheme_name,
                                token_endpoint.as_deref(),
                                &entry.scopes,
                            )
                            .map(Some)
                        }
                    }
                    A2aSecuritySchemeKind::OpenIdBearerToken { discovery_url } => {
                        if let Some(header) = static_bearer.clone() {
                            Ok(Some(header))
                        } else {
                            self.acquire_openid_bearer_header(
                                &entry.scheme_name,
                                discovery_url.as_str(),
                                &entry.scopes,
                            )
                            .map(Some)
                        }
                    }
                    A2aSecuritySchemeKind::ApiKeyHeader { header_name } => {
                        let Some(header) =
                            configured_named_header(&self.configured_headers, header_name)
                        else {
                            errors.push(format!(
                                "missing API key header `{header_name}` for `{}`",
                                entry.scheme_name
                            ));
                            supported = false;
                            break;
                        };
                        Ok(Some(header))
                    }
                    A2aSecuritySchemeKind::ApiKeyQuery { param_name } => {
                        let Some(query_param) =
                            configured_named_query_param(&self.configured_query_params, param_name)
                        else {
                            errors.push(format!(
                                "missing API key query parameter `{param_name}` for `{}`",
                                entry.scheme_name
                            ));
                            supported = false;
                            break;
                        };
                        query_params.push(query_param);
                        Ok(None)
                    }
                    A2aSecuritySchemeKind::ApiKeyCookie { cookie_name } => {
                        let Some(cookie) =
                            configured_named_cookie(&self.configured_cookies, cookie_name)
                        else {
                            errors.push(format!(
                                "missing API key cookie `{cookie_name}` for `{}`",
                                entry.scheme_name
                            ));
                            supported = false;
                            break;
                        };
                        cookies.push(cookie);
                        Ok(None)
                    }
                    A2aSecuritySchemeKind::MutualTls => {
                        if self.transport_config.mutual_tls_config.is_none() {
                            Err(AdapterError::AuthNegotiation(format!(
                                "missing mutual TLS client identity for `{}`",
                                entry.scheme_name
                            )))
                        } else {
                            tls_mode = A2aTlsMode::MutualTls;
                            Ok(None)
                        }
                    }
                    A2aSecuritySchemeKind::Unsupported(reason) => {
                        Err(AdapterError::AuthNegotiation(format!(
                            "unsupported A2A security scheme `{}`: {reason}",
                            entry.scheme_name
                        )))
                    }
                };
                match header {
                    Ok(header) => {
                        if let Some(header) = header {
                            headers.push(header);
                        }
                    }
                    Err(error) => {
                        errors.push(error.to_string());
                        supported = false;
                        break;
                    }
                }
            }
            if supported {
                dedupe_request_headers(&mut headers);
                dedupe_request_query_params(&mut query_params);
                dedupe_request_cookies(&mut cookies);
                return Ok(A2aResolvedRequestAuth {
                    headers,
                    query_params,
                    cookies,
                    tls_mode,
                });
            }
        }

        Err(AdapterError::AuthNegotiation(format!(
            "failed to negotiate A2A auth requirements for {}: {}",
            self.auth_context(skill),
            errors.join("; ")
        )))
    }

    fn acquire_oauth_bearer_header(
        &self,
        scheme_name: &str,
        token_endpoint: Option<&str>,
        required_scopes: &[String],
    ) -> Result<A2aRequestHeader, AdapterError> {
        let Some(credentials) = self.oauth_client_credentials.as_ref() else {
            return Err(AdapterError::AuthNegotiation(format!(
                "missing bearer token or OAuth client credentials for `{scheme_name}`"
            )));
        };
        let token_endpoint = token_endpoint
            .or(self.oauth_token_endpoint_override.as_deref())
            .ok_or_else(|| {
                AdapterError::AuthNegotiation(format!(
                    "A2A OAuth scheme `{scheme_name}` does not declare a token endpoint and no override was configured"
                ))
            })?;
        let token_endpoint = parse_remote_url(
            token_endpoint,
            &format!("OAuth token endpoint for `{scheme_name}`"),
        )?;
        let scopes = merged_oauth_scopes(required_scopes, &self.oauth_scopes);
        let cache_key = oauth_cache_key(scheme_name, &token_endpoint, &scopes);
        if let Some(access_token) = self.lookup_cached_bearer_token(&cache_key)? {
            return Ok(bearer_request_header(access_token));
        }

        let response = request_client_credentials_token(
            &token_endpoint,
            credentials,
            &scopes,
            self.timeout,
            &self.transport_config,
        )?;
        if let Some(token_type) = response.token_type.as_deref() {
            if !token_type.eq_ignore_ascii_case("bearer") {
                return Err(AdapterError::AuthNegotiation(format!(
                    "token endpoint for `{scheme_name}` returned unsupported token type `{token_type}`"
                )));
            }
        }
        self.store_cached_bearer_token(
            cache_key,
            response.access_token.clone(),
            response.expires_in,
        )?;
        Ok(bearer_request_header(response.access_token))
    }

    fn acquire_openid_bearer_header(
        &self,
        scheme_name: &str,
        discovery_url: &str,
        required_scopes: &[String],
    ) -> Result<A2aRequestHeader, AdapterError> {
        let discovery_url = parse_remote_url(
            discovery_url,
            &format!("OpenID discovery URL for `{scheme_name}`"),
        )?;
        let metadata = fetch_json::<A2aOpenIdConfiguration>(
            &discovery_url,
            &A2aResolvedRequestAuth {
                headers: Vec::new(),
                query_params: Vec::new(),
                cookies: Vec::new(),
                tls_mode: A2aTlsMode::Default,
            },
            self.timeout,
            &self.transport_config,
        )?;
        self.acquire_oauth_bearer_header(
            scheme_name,
            Some(metadata.token_endpoint.as_str()),
            required_scopes,
        )
    }

    fn lookup_cached_bearer_token(&self, cache_key: &str) -> Result<Option<String>, AdapterError> {
        let now = SystemTime::now();
        let mut cache = self.token_cache.lock().map_err(|_| {
            AdapterError::AuthNegotiation("OAuth token cache lock poisoned".to_string())
        })?;
        cache.retain(|entry| {
            entry
                .expires_at
                .map(|expires_at| expires_at > now)
                .unwrap_or(true)
        });
        Ok(cache
            .iter()
            .find(|entry| entry.cache_key == cache_key)
            .map(|entry| entry.access_token.clone()))
    }

    fn store_cached_bearer_token(
        &self,
        cache_key: String,
        access_token: String,
        expires_in: Option<u64>,
    ) -> Result<(), AdapterError> {
        let expires_at = expires_in.and_then(|expires_in| {
            let effective_ttl = expires_in.saturating_sub(OAUTH_CACHE_SKEW_SECS);
            if effective_ttl == 0 {
                None
            } else {
                Some(SystemTime::now() + Duration::from_secs(effective_ttl))
            }
        });
        let mut cache = self.token_cache.lock().map_err(|_| {
            AdapterError::AuthNegotiation("OAuth token cache lock poisoned".to_string())
        })?;
        if let Some(existing) = cache.iter_mut().find(|entry| entry.cache_key == cache_key) {
            existing.access_token = access_token;
            existing.expires_at = expires_at;
        } else {
            cache.push(A2aCachedBearerToken {
                cache_key,
                access_token,
                expires_at,
            });
        }
        Ok(())
    }

    fn invoke_skill(
        &self,
        tool_name: &str,
        skill: &A2aAgentSkill,
        arguments: Value,
    ) -> Result<Value, AdapterError> {
        let request_auth = self.resolve_request_auth(skill)?;
        match parse_tool_input(arguments)? {
            A2aToolInvocation::SendMessage(input) => {
                if let Some(task_id) = input.task_id.as_deref() {
                    self.validate_task_binding(tool_name, task_id, "send_message.task_id")?;
                }
                let request = self.build_send_message_request(skill, input)?;
                let response = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => self.invoke_jsonrpc(request, &request_auth),
                    A2aProtocolBinding::HttpJson => self.invoke_http_json(request, &request_auth),
                }?;
                let value = serde_json::to_value(response).map_err(|error| {
                    AdapterError::Protocol(format!("failed to encode A2A response: {error}"))
                })?;
                self.record_task_activity(tool_name, &value, "send_message")?;
                Ok(value)
            }
            A2aToolInvocation::GetTask(input) => {
                self.validate_task_binding(tool_name, &input.id, "get_task")?;
                let task = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => self.get_task_jsonrpc(input, &request_auth)?,
                    A2aProtocolBinding::HttpJson => {
                        self.get_task_http_json(input, &request_auth)?
                    }
                };
                let value = json!({ "task": task });
                self.record_task_activity(tool_name, &value, "get_task")?;
                Ok(value)
            }
            A2aToolInvocation::SubscribeTask(_) => Err(AdapterError::InvalidToolInput(
                "`subscribe_task` requires a streaming tool invocation".to_string(),
            )),
            A2aToolInvocation::CancelTask(input) => {
                self.validate_task_binding(tool_name, &input.id, "cancel_task")?;
                let task = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.cancel_task_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.cancel_task_http_json(input, &request_auth)?
                    }
                };
                let value = json!({ "task": task });
                self.record_task_activity(tool_name, &value, "cancel_task")?;
                Ok(value)
            }
            A2aToolInvocation::CreatePushNotificationConfig(input) => {
                self.ensure_push_notifications_supported()?;
                self.validate_task_binding(
                    tool_name,
                    &input.task_id,
                    "create_push_notification_config",
                )?;
                let config = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.create_push_notification_config_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.create_push_notification_config_http_json(input, &request_auth)?
                    }
                };
                Ok(json!({ "push_notification_config": config }))
            }
            A2aToolInvocation::GetPushNotificationConfig(input) => {
                self.ensure_push_notifications_supported()?;
                self.validate_task_binding(
                    tool_name,
                    &input.task_id,
                    "get_push_notification_config",
                )?;
                let config = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.get_push_notification_config_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.get_push_notification_config_http_json(input, &request_auth)?
                    }
                };
                Ok(json!({ "push_notification_config": config }))
            }
            A2aToolInvocation::ListPushNotificationConfigs(input) => {
                self.ensure_push_notifications_supported()?;
                self.validate_task_binding(
                    tool_name,
                    &input.task_id,
                    "list_push_notification_configs",
                )?;
                let response = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.list_push_notification_configs_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.list_push_notification_configs_http_json(input, &request_auth)?
                    }
                };
                Ok(json!({
                    "push_notification_configs": response.configs,
                    "next_page_token": response.next_page_token
                }))
            }
            A2aToolInvocation::DeletePushNotificationConfig(input) => {
                self.ensure_push_notifications_supported()?;
                self.validate_task_binding(
                    tool_name,
                    &input.task_id,
                    "delete_push_notification_config",
                )?;
                match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.delete_push_notification_config_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.delete_push_notification_config_http_json(input, &request_auth)?
                    }
                }
                Ok(json!({ "deleted": true }))
            }
        }
    }

    fn ensure_push_notifications_supported(&self) -> Result<(), AdapterError> {
        if self.agent_card.capabilities.push_notifications {
            Ok(())
        } else {
            Err(AdapterError::Protocol(
                "A2A agent card does not advertise push notification support".to_string(),
            ))
        }
    }

    fn ensure_state_transition_history_supported(&self) -> Result<(), AdapterError> {
        if self.agent_card.capabilities.state_transition_history {
            Ok(())
        } else {
            Err(AdapterError::Protocol(
                "A2A agent card does not advertise state transition history support".to_string(),
            ))
        }
    }

    fn build_send_message_request(
        &self,
        skill: &A2aAgentSkill,
        input: A2aSendToolInput,
    ) -> Result<A2aSendMessageRequest, AdapterError> {
        if input.history_length.is_some() {
            self.ensure_state_transition_history_supported()?;
        }
        let mut parts = Vec::new();
        if let Some(message) = input.message {
            parts.push(A2aPart {
                text: Some(message),
                raw: None,
                url: None,
                data: None,
                metadata: None,
                filename: None,
                media_type: Some("text/plain".to_string()),
            });
        }
        if let Some(data) = input.data {
            parts.push(A2aPart {
                text: None,
                raw: None,
                url: None,
                data: Some(data),
                metadata: None,
                filename: None,
                media_type: Some("application/json".to_string()),
            });
        }
        if parts.is_empty() {
            return Err(AdapterError::InvalidToolInput(
                "A2A tools require at least one of `message` or `data`".to_string(),
            ));
        }

        let accepted_output_modes = skill
            .output_modes
            .clone()
            .filter(|modes| !modes.is_empty())
            .unwrap_or_else(|| self.agent_card.default_output_modes.clone());
        let configuration = if accepted_output_modes.is_empty()
            && input.history_length.is_none()
            && input.return_immediately.is_none()
        {
            None
        } else {
            Some(A2aSendMessageConfiguration {
                accepted_output_modes: if accepted_output_modes.is_empty() {
                    None
                } else {
                    Some(accepted_output_modes)
                },
                history_length: input.history_length,
                return_immediately: input.return_immediately,
            })
        };

        Ok(A2aSendMessageRequest {
            tenant: self.selected_interface.tenant.clone(),
            message: A2aMessage {
                message_id: next_message_id(
                    &self.request_counter,
                    self.manifest.server_id.as_str(),
                    skill.id.as_str(),
                ),
                context_id: input.context_id,
                task_id: input.task_id,
                role: "ROLE_USER".to_string(),
                parts,
                metadata: validate_object_metadata("message_metadata", input.message_metadata)?,
                extensions: None,
                reference_task_ids: input.reference_task_ids,
            },
            configuration,
            metadata: Some(merge_skill_routing_metadata(input.metadata, skill)?),
        })
    }

    fn get_task_jsonrpc(
        &self,
        input: A2aGetTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<Value, AdapterError> {
        if input.history_length.is_some() {
            self.ensure_state_transition_history_supported()?;
        }
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "GetTask",
            params: A2aGetTaskRequest {
                id: input.id,
                tenant: self.selected_interface.tenant.clone(),
                history_length: input.history_length,
            },
        };
        let response: A2aJsonRpcResponse<Value> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        let task = response.result.ok_or_else(|| {
            AdapterError::Protocol("A2A JSON-RPC GetTask response omitted `result`".to_string())
        })?;
        validate_task_response(task)
    }

    fn get_task_http_json(
        &self,
        input: A2aGetTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<Value, AdapterError> {
        if input.history_length.is_some() {
            self.ensure_state_transition_history_supported()?;
        }
        let endpoint = build_get_task_url(
            self.selected_interface.url.as_str(),
            input.id.as_str(),
            self.selected_interface.tenant.as_deref(),
            input.history_length,
        )?;
        let task = fetch_json(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        validate_task_response(task)
    }

    fn cancel_task_jsonrpc(
        &self,
        input: A2aCancelTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<Value, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "CancelTask",
            params: A2aCancelTaskRequest {
                tenant: self.selected_interface.tenant.clone(),
                id: validate_identifier("cancel_task.id", input.id)?,
                metadata: validate_object_metadata("cancel_task.metadata", input.metadata)?,
            },
        };
        let response: A2aJsonRpcResponse<Value> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        let task = response.result.ok_or_else(|| {
            AdapterError::Protocol("A2A JSON-RPC CancelTask response omitted `result`".to_string())
        })?;
        validate_task_response(task)
    }

    fn cancel_task_http_json(
        &self,
        input: A2aCancelTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<Value, AdapterError> {
        let task_id = validate_identifier("cancel_task.id", input.id)?;
        let endpoint = build_cancel_task_url(
            self.selected_interface.url.as_str(),
            task_id.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        let body = A2aCancelTaskRequest {
            tenant: None,
            id: task_id,
            metadata: validate_object_metadata("cancel_task.metadata", input.metadata)?,
        };
        let task = post_json(
            endpoint.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        validate_task_response(task)
    }

    fn create_push_notification_config_jsonrpc(
        &self,
        input: A2aCreatePushNotificationConfigToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let config = self.build_push_notification_config(input)?;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "CreateTaskPushNotificationConfig",
            params: config,
        };
        let response: A2aJsonRpcResponse<A2aTaskPushNotificationConfig> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        response.result.ok_or_else(|| {
            AdapterError::Protocol(
                "A2A JSON-RPC CreateTaskPushNotificationConfig response omitted `result`"
                    .to_string(),
            )
        })
    }

    fn create_push_notification_config_http_json(
        &self,
        input: A2aCreatePushNotificationConfigToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        let config = self.build_push_notification_config(input)?;
        let endpoint = build_push_notification_configs_url(
            self.selected_interface.url.as_str(),
            config.task_id.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        post_json(
            endpoint.as_str(),
            &config,
            request_auth,
            self.timeout,
            &self.transport_config,
        )
    }

    fn get_push_notification_config_jsonrpc(
        &self,
        input: A2aPushNotificationConfigRefToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "GetTaskPushNotificationConfig",
            params: A2aGetTaskPushNotificationConfigRequest {
                tenant: self.selected_interface.tenant.clone(),
                task_id: validate_identifier(
                    "get_push_notification_config.task_id",
                    input.task_id,
                )?,
                id: validate_identifier("get_push_notification_config.id", input.id)?,
            },
        };
        let response: A2aJsonRpcResponse<A2aTaskPushNotificationConfig> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        response.result.ok_or_else(|| {
            AdapterError::Protocol(
                "A2A JSON-RPC GetTaskPushNotificationConfig response omitted `result`".to_string(),
            )
        })
    }

    fn get_push_notification_config_http_json(
        &self,
        input: A2aPushNotificationConfigRefToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        let endpoint = build_push_notification_config_url(
            self.selected_interface.url.as_str(),
            validate_identifier("get_push_notification_config.task_id", input.task_id)?.as_str(),
            validate_identifier("get_push_notification_config.id", input.id)?.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        fetch_json(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
        )
    }

    fn list_push_notification_configs_jsonrpc(
        &self,
        input: A2aListPushNotificationConfigsToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aListTaskPushNotificationConfigsResponse, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "ListTaskPushNotificationConfigs",
            params: A2aListTaskPushNotificationConfigsRequest {
                tenant: self.selected_interface.tenant.clone(),
                task_id: validate_identifier(
                    "list_push_notification_configs.task_id",
                    input.task_id,
                )?,
                page_size: input.page_size,
                page_token: input.page_token,
            },
        };
        let response: A2aJsonRpcResponse<A2aListTaskPushNotificationConfigsResponse> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        response.result.ok_or_else(|| {
            AdapterError::Protocol(
                "A2A JSON-RPC ListTaskPushNotificationConfigs response omitted `result`"
                    .to_string(),
            )
        })
    }

    fn list_push_notification_configs_http_json(
        &self,
        input: A2aListPushNotificationConfigsToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aListTaskPushNotificationConfigsResponse, AdapterError> {
        let endpoint = build_list_push_notification_configs_url(
            self.selected_interface.url.as_str(),
            validate_identifier("list_push_notification_configs.task_id", input.task_id)?.as_str(),
            self.selected_interface.tenant.as_deref(),
            input.page_size,
            input.page_token.as_deref(),
        )?;
        fetch_json(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
        )
    }

    fn delete_push_notification_config_jsonrpc(
        &self,
        input: A2aPushNotificationConfigRefToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<(), AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "DeleteTaskPushNotificationConfig",
            params: A2aDeleteTaskPushNotificationConfigRequest {
                tenant: self.selected_interface.tenant.clone(),
                task_id: validate_identifier(
                    "delete_push_notification_config.task_id",
                    input.task_id,
                )?,
                id: validate_identifier("delete_push_notification_config.id", input.id)?,
            },
        };
        let response: A2aJsonRpcResponse<Value> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        Ok(())
    }

    fn delete_push_notification_config_http_json(
        &self,
        input: A2aPushNotificationConfigRefToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<(), AdapterError> {
        let endpoint = build_push_notification_config_url(
            self.selected_interface.url.as_str(),
            validate_identifier("delete_push_notification_config.task_id", input.task_id)?.as_str(),
            validate_identifier("delete_push_notification_config.id", input.id)?.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        delete_empty(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
        )
    }

    fn build_push_notification_config(
        &self,
        input: A2aCreatePushNotificationConfigToolInput,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        Ok(A2aTaskPushNotificationConfig {
            tenant: self.selected_interface.tenant.clone(),
            id: match input.id {
                Some(id) => Some(validate_identifier(
                    "create_push_notification_config.id",
                    id,
                )?),
                None => None,
            },
            task_id: validate_identifier("create_push_notification_config.task_id", input.task_id)?,
            url: validate_notification_target_url(input.url.as_str())?,
            token: input.token.filter(|value| !value.trim().is_empty()),
            authentication: validate_authentication_info(input.authentication)?,
        })
    }

    fn invoke_stream_jsonrpc(
        &self,
        request: A2aSendMessageRequest,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<ToolServerStreamResult, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "SendStreamingMessage",
            params: request,
        };
        post_sse_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
            |value| {
                let response: A2aJsonRpcResponse<Value> =
                    serde_json::from_value(value).map_err(|error| {
                        AdapterError::Protocol(format!(
                            "failed to decode A2A JSON-RPC stream event: {error}"
                        ))
                    })?;
                if response.jsonrpc != "2.0" {
                    return Err(AdapterError::Protocol(format!(
                        "unexpected JSON-RPC version {}",
                        response.jsonrpc
                    )));
                }
                if let Some(error) = response.error {
                    return Err(AdapterError::Remote(format!(
                        "A2A JSON-RPC error {}: {}",
                        error.code, error.message
                    )));
                }
                response.result.ok_or_else(|| {
                    AdapterError::Protocol("A2A JSON-RPC stream event omitted `result`".to_string())
                })
            },
        )
    }

    fn invoke_stream_http_json(
        &self,
        request: A2aSendMessageRequest,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<ToolServerStreamResult, AdapterError> {
        let endpoint = build_send_message_url(
            self.selected_interface.url.as_str(),
            self.selected_interface.tenant.as_deref(),
            true,
        )?;
        post_sse_json(
            endpoint.as_str(),
            &request,
            request_auth,
            self.timeout,
            &self.transport_config,
            Ok,
        )
    }

    fn invoke_jsonrpc(
        &self,
        request: A2aSendMessageRequest,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aSendMessageResponse, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "SendMessage",
            params: request,
        };
        let response: A2aJsonRpcResponse<A2aSendMessageResponse> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        let response = response.result.ok_or_else(|| {
            AdapterError::Protocol("A2A JSON-RPC response omitted `result`".to_string())
        })?;
        validate_send_message_response(response)
    }

    fn invoke_http_json(
        &self,
        request: A2aSendMessageRequest,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aSendMessageResponse, AdapterError> {
        let endpoint = build_send_message_url(
            self.selected_interface.url.as_str(),
            self.selected_interface.tenant.as_deref(),
            false,
        )?;
        let response = post_json(
            endpoint.as_str(),
            &request,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        validate_send_message_response(response)
    }

    fn subscribe_task_jsonrpc(
        &self,
        input: A2aSubscribeTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<ToolServerStreamResult, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "SubscribeToTask",
            params: A2aSubscribeToTaskRequest {
                tenant: self.selected_interface.tenant.clone(),
                id: input.id,
            },
        };
        post_sse_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
            |value| {
                let response: A2aJsonRpcResponse<Value> =
                    serde_json::from_value(value).map_err(|error| {
                        AdapterError::Protocol(format!(
                            "failed to decode A2A JSON-RPC stream event: {error}"
                        ))
                    })?;
                if response.jsonrpc != "2.0" {
                    return Err(AdapterError::Protocol(format!(
                        "unexpected JSON-RPC version {}",
                        response.jsonrpc
                    )));
                }
                if let Some(error) = response.error {
                    return Err(AdapterError::Remote(format!(
                        "A2A JSON-RPC error {}: {}",
                        error.code, error.message
                    )));
                }
                response.result.ok_or_else(|| {
                    AdapterError::Protocol("A2A JSON-RPC stream event omitted `result`".to_string())
                })
            },
        )
    }

    fn subscribe_task_http_json(
        &self,
        input: A2aSubscribeTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<ToolServerStreamResult, AdapterError> {
        let endpoint = build_subscribe_task_url(
            self.selected_interface.url.as_str(),
            input.id.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        get_sse(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
            Ok,
        )
    }
}

impl ToolServerConnection for A2aAdapter {
    fn server_id(&self) -> &str {
        &self.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.manifest
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect()
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let Some(skill) = self
            .agent_card
            .skills
            .iter()
            .find(|skill| skill.id == tool_name)
        else {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        };
        let response = self
            .invoke_skill(tool_name, skill, arguments)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        Ok(response)
    }

    fn invoke_stream(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let Some(skill) = self
            .agent_card
            .skills
            .iter()
            .find(|skill| skill.id == tool_name)
        else {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        };
        let invocation = parse_tool_input(arguments)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        let request_auth = self
            .resolve_request_auth(skill)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        match invocation {
            A2aToolInvocation::SendMessage(input) => {
                if !input.stream {
                    return Ok(None);
                }
                if !self.agent_card.capabilities.streaming {
                    return Err(KernelError::ToolServerError(
                        "A2A server does not advertise streaming support".to_string(),
                    ));
                }
                if let Some(task_id) = input.task_id.as_deref() {
                    self.validate_task_binding(tool_name, task_id, "send_streaming_message.task_id")
                        .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                }

                let request = self
                    .build_send_message_request(skill, input)
                    .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                let result = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.invoke_stream_jsonrpc(request, &request_auth)
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.invoke_stream_http_json(request, &request_auth)
                    }
                }
                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                match &result {
                    ToolServerStreamResult::Complete(stream)
                    | ToolServerStreamResult::Incomplete { stream, .. } => {
                        for chunk in &stream.chunks {
                            self.record_task_activity(tool_name, &chunk.data, "stream_event")
                                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                        }
                    }
                }
                Ok(Some(result))
            }
            A2aToolInvocation::SubscribeTask(input) => {
                if !self.agent_card.capabilities.streaming {
                    return Err(KernelError::ToolServerError(
                        "A2A server does not advertise streaming support".to_string(),
                    ));
                }
                self.validate_task_binding(tool_name, &input.id, "subscribe_task")
                    .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                let result = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.subscribe_task_jsonrpc(input, &request_auth)
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.subscribe_task_http_json(input, &request_auth)
                    }
                }
                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                match &result {
                    ToolServerStreamResult::Complete(stream)
                    | ToolServerStreamResult::Incomplete { stream, .. } => {
                        for chunk in &stream.chunks {
                            self.record_task_activity(tool_name, &chunk.data, "subscribe_event")
                                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                        }
                    }
                }
                Ok(Some(result))
            }
            A2aToolInvocation::GetTask(_)
            | A2aToolInvocation::CancelTask(_)
            | A2aToolInvocation::CreatePushNotificationConfig(_)
            | A2aToolInvocation::GetPushNotificationConfig(_)
            | A2aToolInvocation::ListPushNotificationConfigs(_)
            | A2aToolInvocation::DeletePushNotificationConfig(_) => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aAgentCard {
    pub name: String,
    pub description: String,
    pub supported_interfaces: Vec<A2aAgentInterface>,
    pub version: String,
    #[serde(default)]
    pub capabilities: A2aAgentCapabilities,
    #[serde(default)]
    pub security_schemes: Option<Value>,
    #[serde(default)]
    pub security_requirements: Option<Value>,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub skills: Vec<A2aAgentSkill>,
    #[serde(default)]
    pub documentation_url: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aAgentCapabilities {
    #[serde(default)]
    pub streaming: bool,
    #[serde(default)]
    pub push_notifications: bool,
    #[serde(default)]
    pub state_transition_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aAgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    #[serde(default)]
    pub examples: Option<Vec<String>>,
    #[serde(default)]
    pub input_modes: Option<Vec<String>>,
    #[serde(default)]
    pub output_modes: Option<Vec<String>>,
    #[serde(default)]
    pub security_requirements: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aAgentInterface {
    pub url: String,
    pub protocol_binding: String,
    pub protocol_version: String,
    #[serde(default)]
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aSendMessageRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub message: A2aMessage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<A2aSendMessageConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aGetTaskRequest {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aSubscribeToTaskRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aCancelTaskRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aAuthenticationInfo {
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTaskPushNotificationConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub task_id: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<A2aAuthenticationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aGetTaskPushNotificationConfigRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub task_id: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aDeleteTaskPushNotificationConfigRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub task_id: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aListTaskPushNotificationConfigsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aListTaskPushNotificationConfigsResponse {
    pub configs: Vec<A2aTaskPushNotificationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct A2aOAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aOpenIdConfiguration {
    token_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aSendMessageConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_output_modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_immediately: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aMessage {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    pub role: String,
    pub parts: Vec<A2aPart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_task_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aPart {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aSendMessageResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct A2aJsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: T,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct A2aJsonRpcResponse<T> {
    jsonrpc: String,
    result: Option<T>,
    error: Option<A2aJsonRpcError>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aJsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum A2aProtocolBinding {
    JsonRpc,
    HttpJson,
}

#[derive(Debug)]
struct A2aTaskRegistry {
    path: PathBuf,
    lock: Mutex<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct A2aPersistedTaskRegistry {
    version: String,
    #[serde(default)]
    tasks: BTreeMap<String, A2aTaskRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct A2aTaskRecord {
    task_id: String,
    tool_name: String,
    server_id: String,
    interface_url: String,
    protocol_binding: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    partner: String,
    first_seen_at: u64,
    last_seen_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_state: Option<String>,
    last_source: String,
}

impl Default for A2aPersistedTaskRegistry {
    fn default() -> Self {
        Self {
            version: TASK_REGISTRY_VERSION.to_string(),
            tasks: BTreeMap::new(),
        }
    }
}

impl A2aTaskRegistry {
    fn open(path: &PathBuf) -> Result<Self, AdapterError> {
        let registry = Self {
            path: path.clone(),
            lock: Mutex::new(()),
        };
        let _ = registry.load()?;
        Ok(registry)
    }

    fn load(&self) -> Result<A2aPersistedTaskRegistry, AdapterError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let registry: A2aPersistedTaskRegistry = serde_json::from_slice(&bytes)
                    .map_err(|error| AdapterError::Lifecycle(format!(
                        "failed to parse A2A task registry {}: {error}",
                        self.path.display()
                    )))?;
                if registry.version != TASK_REGISTRY_VERSION {
                    return Err(AdapterError::Lifecycle(format!(
                        "unsupported A2A task registry version `{}` in {}",
                        registry.version,
                        self.path.display()
                    )));
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(A2aPersistedTaskRegistry::default())
            }
            Err(error) => Err(AdapterError::Lifecycle(format!(
                "failed to read A2A task registry {}: {error}",
                self.path.display()
            ))),
        }
    }

    fn save(&self, registry: &A2aPersistedTaskRegistry) -> Result<(), AdapterError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AdapterError::Lifecycle(format!(
                    "failed to create A2A task registry directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(
            &self.path,
            serde_json::to_vec_pretty(registry).map_err(|error| {
                AdapterError::Lifecycle(format!(
                    "failed to encode A2A task registry {}: {error}",
                    self.path.display()
                ))
            })?,
        )
        .map_err(|error| {
            AdapterError::Lifecycle(format!(
                "failed to write A2A task registry {}: {error}",
                self.path.display()
            ))
        })
    }

    fn validate_follow_up(
        &self,
        task_id: &str,
        tool_name: &str,
        server_id: &str,
        selected_interface: &A2aAgentInterface,
        selected_binding: &A2aProtocolBinding,
        operation: &str,
    ) -> Result<(), AdapterError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AdapterError::Lifecycle("A2A task registry lock poisoned".to_string()))?;
        let registry = self.load()?;
        let Some(record) = registry.tasks.get(task_id) else {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} requires a previously recorded A2A task `{task_id}` in {}",
                self.path.display()
            )));
        };
        if record.tool_name != tool_name {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` from tool `{}` through `{tool_name}`",
                record.tool_name
            )));
        }
        if record.server_id != server_id {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` from server `{}` through `{server_id}`",
                record.server_id
            )));
        }
        if record.interface_url != selected_interface.url {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` against interface `{}` instead of `{}`",
                selected_interface.url, record.interface_url
            )));
        }
        if record.protocol_binding != binding_label(selected_binding) {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` over binding `{}` instead of `{}`",
                binding_label(selected_binding),
                record.protocol_binding
            )));
        }
        if record.tenant.as_deref() != selected_interface.tenant.as_deref() {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` with tenant `{}` instead of `{}`",
                selected_interface.tenant.as_deref().unwrap_or("none"),
                record.tenant.as_deref().unwrap_or("none")
            )));
        }
        Ok(())
    }

    fn record_from_value(
        &self,
        value: &Value,
        source: &str,
        tool_name: &str,
        server_id: &str,
        selected_interface: &A2aAgentInterface,
        selected_binding: &A2aProtocolBinding,
        partner: &str,
    ) -> Result<(), AdapterError> {
        let mut seen = Vec::new();
        if let Some(task) = value.get("task") {
            let task_id = task.get("id").and_then(Value::as_str);
            let state = task
                .get("status")
                .and_then(|status| status.get("state"))
                .and_then(Value::as_str);
            if let Some(task_id) = task_id {
                seen.push((task_id.to_string(), state.map(str::to_string)));
            }
        }
        if let Some(update) = value.get("statusUpdate") {
            let task_id = update.get("taskId").and_then(Value::as_str);
            let state = update
                .get("status")
                .and_then(|status| status.get("state"))
                .and_then(Value::as_str);
            if let Some(task_id) = task_id {
                seen.push((task_id.to_string(), state.map(str::to_string)));
            }
        }
        if let Some(update) = value.get("artifactUpdate") {
            if let Some(task_id) = update.get("taskId").and_then(Value::as_str) {
                seen.push((task_id.to_string(), None));
            }
        }
        if seen.is_empty() {
            return Ok(());
        }

        let _guard = self
            .lock
            .lock()
            .map_err(|_| AdapterError::Lifecycle("A2A task registry lock poisoned".to_string()))?;
        let mut registry = self.load()?;
        let now = unix_timestamp_now();
        for (task_id, state) in seen {
            let entry = registry.tasks.entry(task_id.clone()).or_insert_with(|| A2aTaskRecord {
                task_id: task_id.clone(),
                tool_name: tool_name.to_string(),
                server_id: server_id.to_string(),
                interface_url: selected_interface.url.clone(),
                protocol_binding: binding_label(selected_binding).to_string(),
                tenant: selected_interface.tenant.clone(),
                partner: partner.to_string(),
                first_seen_at: now,
                last_seen_at: now,
                last_state: None,
                last_source: source.to_string(),
            });
            entry.last_seen_at = now;
            entry.last_source = source.to_string();
            entry.last_state = state.or_else(|| entry.last_state.clone());
            entry.tool_name = tool_name.to_string();
            entry.server_id = server_id.to_string();
            entry.interface_url = selected_interface.url.clone();
            entry.protocol_binding = binding_label(selected_binding).to_string();
            entry.tenant = selected_interface.tenant.clone();
            entry.partner = partner.to_string();
        }
        self.save(&registry)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct A2aToolInput {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default, alias = "contextId")]
    context_id: Option<String>,
    #[serde(default, alias = "taskId")]
    task_id: Option<String>,
    #[serde(default, alias = "referenceTaskIds")]
    reference_task_ids: Option<Vec<String>>,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default, alias = "messageMetadata")]
    message_metadata: Option<Value>,
    #[serde(default, alias = "historyLength")]
    history_length: Option<u32>,
    #[serde(default, alias = "returnImmediately")]
    return_immediately: Option<bool>,
    #[serde(default)]
    stream: Option<bool>,
    #[serde(default, alias = "getTask")]
    get_task: Option<A2aGetTaskToolInput>,
    #[serde(default, alias = "subscribeTask")]
    subscribe_task: Option<A2aSubscribeTaskToolInput>,
    #[serde(default, alias = "cancelTask")]
    cancel_task: Option<A2aCancelTaskToolInput>,
    #[serde(default, alias = "createPushNotificationConfig")]
    create_push_notification_config: Option<A2aCreatePushNotificationConfigToolInput>,
    #[serde(default, alias = "getPushNotificationConfig")]
    get_push_notification_config: Option<A2aPushNotificationConfigRefToolInput>,
    #[serde(default, alias = "listPushNotificationConfigs")]
    list_push_notification_configs: Option<A2aListPushNotificationConfigsToolInput>,
    #[serde(default, alias = "deletePushNotificationConfig")]
    delete_push_notification_config: Option<A2aPushNotificationConfigRefToolInput>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aGetTaskToolInput {
    id: String,
    #[serde(default, alias = "historyLength")]
    history_length: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aSubscribeTaskToolInput {
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aCancelTaskToolInput {
    id: String,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aAuthenticationInfoToolInput {
    scheme: String,
    #[serde(default)]
    credentials: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aCreatePushNotificationConfigToolInput {
    task_id: String,
    #[serde(default)]
    id: Option<String>,
    url: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    authentication: Option<A2aAuthenticationInfoToolInput>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aPushNotificationConfigRefToolInput {
    task_id: String,
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aListPushNotificationConfigsToolInput {
    task_id: String,
    #[serde(default, alias = "pageSize")]
    page_size: Option<u32>,
    #[serde(default, alias = "pageToken")]
    page_token: Option<String>,
}

#[derive(Debug, Clone)]
struct A2aSendToolInput {
    message: Option<String>,
    data: Option<Value>,
    context_id: Option<String>,
    task_id: Option<String>,
    reference_task_ids: Option<Vec<String>>,
    metadata: Option<Value>,
    message_metadata: Option<Value>,
    history_length: Option<u32>,
    return_immediately: Option<bool>,
    stream: bool,
}

#[derive(Debug, Clone)]
enum A2aToolInvocation {
    SendMessage(A2aSendToolInput),
    GetTask(A2aGetTaskToolInput),
    SubscribeTask(A2aSubscribeTaskToolInput),
    CancelTask(A2aCancelTaskToolInput),
    CreatePushNotificationConfig(A2aCreatePushNotificationConfigToolInput),
    GetPushNotificationConfig(A2aPushNotificationConfigRefToolInput),
    ListPushNotificationConfigs(A2aListPushNotificationConfigsToolInput),
    DeletePushNotificationConfig(A2aPushNotificationConfigRefToolInput),
}

#[derive(Debug, Clone)]
struct A2aParsedSecurityScheme {
    name: String,
    kind: A2aSecuritySchemeKind,
}

#[derive(Debug, Clone)]
struct A2aSecurityRequirementEntry {
    scheme_name: String,
    scopes: Vec<String>,
}

#[derive(Debug, Clone)]
enum A2aSecuritySchemeKind {
    BearerToken,
    BasicAuth,
    OAuthBearerToken { token_endpoint: Option<String> },
    OpenIdBearerToken { discovery_url: String },
    ApiKeyHeader { header_name: String },
    ApiKeyQuery { param_name: String },
    ApiKeyCookie { cookie_name: String },
    MutualTls,
    Unsupported(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("invalid A2A URL: {0}")]
    InvalidUrl(String),

    #[error("A2A protocol binding is not supported: {0}")]
    UnsupportedBinding(String),

    #[error("A2A protocol version is not supported: {0}")]
    UnsupportedVersion(String),

    #[error("no supported A2A interfaces were advertised")]
    NoSupportedInterfaces,

    #[error("A2A agent card advertised no skills")]
    NoSkillsAdvertised,

    #[error("invalid A2A tool input: {0}")]
    InvalidToolInput(String),

    #[error("A2A remote request failed: {0}")]
    Remote(String),

    #[error("A2A protocol error: {0}")]
    Protocol(String),

    #[error("A2A auth negotiation failed: {0}")]
    AuthNegotiation(String),

    #[error("A2A partner admission failed: {0}")]
    PartnerAdmission(String),

    #[error("A2A lifecycle correlation failed: {0}")]
    Lifecycle(String),
}

fn build_manifest(
    server_id: &str,
    server_version: &str,
    public_key: &str,
    agent_card: &A2aAgentCard,
    binding: &A2aProtocolBinding,
) -> Result<ToolManifest, AdapterError> {
    let binding_name = match binding {
        A2aProtocolBinding::JsonRpc => "JSONRPC",
        A2aProtocolBinding::HttpJson => "HTTP+JSON",
    };
    let manifest = ToolManifest {
        schema: "pact.manifest.v1".to_string(),
        server_id: server_id.to_string(),
        name: format!("{} (A2A)", agent_card.name),
        description: Some(format!(
            "{}\n\nDiscovered from A2A Agent Card. Skill routing uses metadata.pact.targetSkillId on top of the core A2A SendMessage request. Preferred binding: {binding_name}.",
            agent_card.description
        )),
        version: server_version.to_string(),
        tools: agent_card.skills.iter().map(build_tool_definition).collect(),
        required_permissions: None,
        public_key: public_key.to_string(),
    };
    validate_manifest(&manifest)
        .map_err(|error| AdapterError::Protocol(format!("invalid generated manifest: {error}")))?;
    Ok(manifest)
}

fn build_tool_definition(skill: &A2aAgentSkill) -> ToolDefinition {
    let mut description = skill.description.clone();
    if !skill.tags.is_empty() {
        description.push_str(&format!("\n\nTags: {}", skill.tags.join(", ")));
    }
    if let Some(examples) = &skill.examples {
        if !examples.is_empty() {
            description.push_str(&format!("\n\nExamples: {}", examples.join(" | ")));
        }
    }

    ToolDefinition {
        name: skill.id.clone(),
        description,
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Plain-text user content to send as an A2A text Part."
                },
                "data": {
                    "description": "Structured JSON payload to send as an A2A data Part."
                },
                "context_id": { "type": "string" },
                "task_id": { "type": "string" },
                "reference_task_ids": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "metadata": {
                    "type": "object",
                    "description": "Top-level A2A SendMessageRequest metadata. The adapter will merge metadata.pact.targetSkillId."
                },
                "message_metadata": {
                    "type": "object",
                    "description": "Metadata attached directly to the A2A Message."
                },
                "history_length": {
                    "type": "integer",
                    "minimum": 0
                },
                "return_immediately": { "type": "boolean" },
                "stream": {
                    "type": "boolean",
                    "description": "When true, use A2A SendStreamingMessage and surface each A2A StreamResponse as one PACT stream chunk."
                },
                "get_task": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "id": { "type": "string" },
                        "history_length": {
                            "type": "integer",
                            "minimum": 0
                        }
                    },
                    "required": ["id"],
                    "description": "Adapter-local follow-up mode that issues A2A GetTask instead of SendMessage."
                },
                "subscribe_task": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "id": { "type": "string" }
                    },
                    "required": ["id"],
                    "description": "Adapter-local streaming follow-up mode that issues A2A SubscribeToTask instead of SendMessage."
                },
                "cancel_task": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "id": { "type": "string" },
                        "metadata": { "type": "object" }
                    },
                    "required": ["id"],
                    "description": "Adapter-local follow-up mode that issues A2A CancelTask."
                },
                "create_push_notification_config": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "task_id": { "type": "string" },
                        "id": { "type": "string" },
                        "url": { "type": "string" },
                        "token": { "type": "string" },
                        "authentication": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "scheme": { "type": "string" },
                                "credentials": { "type": "string" }
                            },
                            "required": ["scheme"]
                        }
                    },
                    "required": ["task_id", "url"],
                    "description": "Adapter-local follow-up mode that issues A2A CreateTaskPushNotificationConfig."
                },
                "get_push_notification_config": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "task_id": { "type": "string" },
                        "id": { "type": "string" }
                    },
                    "required": ["task_id", "id"],
                    "description": "Adapter-local follow-up mode that issues A2A GetTaskPushNotificationConfig."
                },
                "list_push_notification_configs": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "task_id": { "type": "string" },
                        "page_size": { "type": "integer", "minimum": 0 },
                        "page_token": { "type": "string" }
                    },
                    "required": ["task_id"],
                    "description": "Adapter-local follow-up mode that issues A2A ListTaskPushNotificationConfigs."
                },
                "delete_push_notification_config": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "task_id": { "type": "string" },
                        "id": { "type": "string" }
                    },
                    "required": ["task_id", "id"],
                    "description": "Adapter-local follow-up mode that issues A2A DeleteTaskPushNotificationConfig."
                }
            },
            "oneOf": [
                { "required": ["delete_push_notification_config"] },
                { "required": ["list_push_notification_configs"] },
                { "required": ["get_push_notification_config"] },
                { "required": ["create_push_notification_config"] },
                { "required": ["cancel_task"] },
                { "required": ["subscribe_task"] },
                { "required": ["get_task"] },
                {
                    "anyOf": [
                        { "required": ["message"] },
                        { "required": ["data"] }
                    ]
                }
            ]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "task": { "type": "object" },
                "message": { "type": "object" },
                "push_notification_config": { "type": "object" },
                "push_notification_configs": {
                    "type": "array",
                    "items": { "type": "object" }
                },
                "next_page_token": { "type": "string" },
                "deleted": { "type": "boolean" }
            }
        })),
        pricing: None,
        has_side_effects: true,
        latency_hint: Some(LatencyHint::Moderate),
    }
}

fn interface_origin(url: &str) -> Result<String, AdapterError> {
    let url = Url::parse(url).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?;
    let host = url.host_str().ok_or_else(|| {
        AdapterError::InvalidUrl(format!("A2A interface URL is missing a host: {url}"))
    })?;
    let mut origin = format!("{}://{host}", url.scheme());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn partner_policy_allows_interface(
    policy: Option<&A2aPartnerPolicy>,
    interface: &A2aAgentInterface,
) -> Result<bool, AdapterError> {
    let Some(policy) = policy else {
        return Ok(true);
    };
    if policy.allowed_interface_origins.is_empty() {
        return Ok(true);
    }
    let origin = interface_origin(&interface.url)?;
    Ok(policy
        .allowed_interface_origins
        .iter()
        .any(|allowed| allowed == &origin))
}

fn validate_partner_policy(
    policy: &A2aPartnerPolicy,
    agent_card: &A2aAgentCard,
    selected_interface: &A2aAgentInterface,
) -> Result<(), AdapterError> {
    if let Some(required_tenant) = policy.required_tenant.as_deref() {
        if selected_interface.tenant.as_deref() != Some(required_tenant) {
            return Err(AdapterError::PartnerAdmission(format!(
                "partner `{}` requires tenant `{required_tenant}`, but the selected interface advertises `{}`",
                policy.partner_id,
                selected_interface.tenant.as_deref().unwrap_or("none")
            )));
        }
    }
    for skill_id in &policy.required_skills {
        if !agent_card.skills.iter().any(|skill| &skill.id == skill_id) {
            return Err(AdapterError::PartnerAdmission(format!(
                "partner `{}` requires advertised skill `{skill_id}`, but it was missing from the Agent Card",
                policy.partner_id
            )));
        }
    }
    if !policy.required_security_scheme_names.is_empty() {
        let raw_schemes = agent_card.security_schemes.as_ref().ok_or_else(|| {
            AdapterError::PartnerAdmission(format!(
                "partner `{}` requires explicit security schemes, but the Agent Card omits securitySchemes",
                policy.partner_id
            ))
        })?;
        let schemes = parse_security_schemes(raw_schemes)?;
        let requirements = agent_card
            .security_requirements
            .as_ref()
            .map(parse_security_requirements)
            .transpose()?;
        for scheme_name in &policy.required_security_scheme_names {
            if !schemes.iter().any(|scheme| &scheme.name == scheme_name) {
                return Err(AdapterError::PartnerAdmission(format!(
                    "partner `{}` requires security scheme `{scheme_name}`, but it was not declared",
                    policy.partner_id
                )));
            }
            if let Some(requirements) = requirements.as_ref() {
                let referenced = requirements.iter().any(|requirement| {
                    requirement
                        .iter()
                        .any(|entry| &entry.scheme_name == scheme_name)
                });
                if !referenced {
                    return Err(AdapterError::PartnerAdmission(format!(
                        "partner `{}` requires security scheme `{scheme_name}`, but no A2A security requirement references it",
                        policy.partner_id
                    )));
                }
            }
        }
    }
    Ok(())
}

fn select_supported_interface(
    interfaces: &[A2aAgentInterface],
    partner_policy: Option<&A2aPartnerPolicy>,
) -> Result<(A2aAgentInterface, A2aProtocolBinding), AdapterError> {
    for interface in interfaces {
        if !interface.protocol_version.starts_with(A2A_PROTOCOL_MAJOR) {
            continue;
        }
        let binding = match interface.protocol_binding.to_ascii_uppercase().as_str() {
            "JSONRPC" => A2aProtocolBinding::JsonRpc,
            "HTTP+JSON" => A2aProtocolBinding::HttpJson,
            _ => continue,
        };
        let url = Url::parse(&interface.url)
            .map_err(|error| AdapterError::InvalidUrl(error.to_string()))?;
        validate_remote_url(&url)?;
        if !partner_policy_allows_interface(partner_policy, interface)? {
            continue;
        }
        return Ok((interface.clone(), binding));
    }

    if let Some(interface) = interfaces.first() {
        if !interface.protocol_version.starts_with(A2A_PROTOCOL_MAJOR) {
            return Err(AdapterError::UnsupportedVersion(
                interface.protocol_version.clone(),
            ));
        }
        if let Some(policy) = partner_policy {
            if !policy.allowed_interface_origins.is_empty() {
                return Err(AdapterError::PartnerAdmission(format!(
                    "partner `{}` did not advertise any supported interface under {}",
                    policy.partner_id,
                    policy.allowed_interface_origins.join(", ")
                )));
            }
        }
        return Err(AdapterError::UnsupportedBinding(
            interface.protocol_binding.clone(),
        ));
    }
    Err(AdapterError::NoSupportedInterfaces)
}

fn parse_tool_input(arguments: Value) -> Result<A2aToolInvocation, AdapterError> {
    let input: A2aToolInput = serde_json::from_value(arguments)
        .map_err(|error| AdapterError::InvalidToolInput(error.to_string()))?;
    let mixed_send_fields = send_message_fields_present(&input);
    let active_management_modes = [
        input.get_task.is_some(),
        input.subscribe_task.is_some(),
        input.cancel_task.is_some(),
        input.create_push_notification_config.is_some(),
        input.get_push_notification_config.is_some(),
        input.list_push_notification_configs.is_some(),
        input.delete_push_notification_config.is_some(),
    ]
    .into_iter()
    .filter(|active| *active)
    .count();

    if active_management_modes > 1 {
        return Err(AdapterError::InvalidToolInput(
            "A2A follow-up and task-management modes are mutually exclusive".to_string(),
        ));
    }

    if let Some(subscribe_task) = input.subscribe_task {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`subscribe_task` is mutually exclusive with SendMessage and `get_task` fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::SubscribeTask(subscribe_task));
    }

    if let Some(get_task) = input.get_task {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`get_task` is mutually exclusive with SendMessage fields".to_string(),
            ));
        }
        return Ok(A2aToolInvocation::GetTask(get_task));
    }

    if let Some(cancel_task) = input.cancel_task {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`cancel_task` is mutually exclusive with SendMessage fields".to_string(),
            ));
        }
        return Ok(A2aToolInvocation::CancelTask(cancel_task));
    }

    if let Some(create_push_notification_config) = input.create_push_notification_config {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`create_push_notification_config` is mutually exclusive with SendMessage fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::CreatePushNotificationConfig(
            create_push_notification_config,
        ));
    }

    if let Some(get_push_notification_config) = input.get_push_notification_config {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`get_push_notification_config` is mutually exclusive with SendMessage fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::GetPushNotificationConfig(
            get_push_notification_config,
        ));
    }

    if let Some(list_push_notification_configs) = input.list_push_notification_configs {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`list_push_notification_configs` is mutually exclusive with SendMessage fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::ListPushNotificationConfigs(
            list_push_notification_configs,
        ));
    }

    if let Some(delete_push_notification_config) = input.delete_push_notification_config {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`delete_push_notification_config` is mutually exclusive with SendMessage fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::DeletePushNotificationConfig(
            delete_push_notification_config,
        ));
    }

    Ok(A2aToolInvocation::SendMessage(A2aSendToolInput {
        message: input.message,
        data: input.data,
        context_id: input.context_id,
        task_id: input.task_id,
        reference_task_ids: input.reference_task_ids,
        metadata: input.metadata,
        message_metadata: input.message_metadata,
        history_length: input.history_length,
        return_immediately: input.return_immediately,
        stream: input.stream.unwrap_or(false),
    }))
}

fn send_message_fields_present(input: &A2aToolInput) -> bool {
    input.message.is_some()
        || input.data.is_some()
        || input.context_id.is_some()
        || input.task_id.is_some()
        || input.reference_task_ids.is_some()
        || input.metadata.is_some()
        || input.message_metadata.is_some()
        || input.history_length.is_some()
        || input.return_immediately.is_some()
        || input.stream.unwrap_or(false)
}

fn parse_security_requirements(
    raw: &Value,
) -> Result<Vec<Vec<A2aSecurityRequirementEntry>>, AdapterError> {
    let requirements = raw.as_array().ok_or_else(|| {
        AdapterError::Protocol("A2A securityRequirements must be an array".to_string())
    })?;
    requirements
        .iter()
        .map(|requirement| {
            let schemes = requirement
                .get("schemes")
                .and_then(Value::as_object)
                .or_else(|| requirement.as_object())
                .ok_or_else(|| {
                    AdapterError::Protocol(
                        "A2A security requirement entry must be an object".to_string(),
                    )
                })?;
            schemes
                .iter()
                .map(|(name, scopes)| {
                    Ok(A2aSecurityRequirementEntry {
                        scheme_name: name.clone(),
                        scopes: parse_required_scopes(scopes)?,
                    })
                })
                .collect()
        })
        .collect()
}

fn parse_security_schemes(raw: &Value) -> Result<Vec<A2aParsedSecurityScheme>, AdapterError> {
    let schemes = raw.as_object().ok_or_else(|| {
        AdapterError::Protocol("A2A securitySchemes must be an object".to_string())
    })?;
    schemes
        .iter()
        .map(|(name, value)| {
            Ok(A2aParsedSecurityScheme {
                name: name.clone(),
                kind: parse_security_scheme_kind(value),
            })
        })
        .collect()
}

fn parse_security_scheme_kind(raw: &Value) -> A2aSecuritySchemeKind {
    let Some(object) = raw.as_object() else {
        return A2aSecuritySchemeKind::Unsupported(
            "scheme definition is not an object".to_string(),
        );
    };

    if let Some(http_auth) = object
        .get("httpAuthSecurityScheme")
        .or_else(|| object.get("http_auth_security_scheme"))
    {
        let scheme = http_auth
            .get("scheme")
            .or_else(|| http_auth.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        return if scheme.eq_ignore_ascii_case("bearer") {
            A2aSecuritySchemeKind::BearerToken
        } else if scheme.eq_ignore_ascii_case("basic") {
            A2aSecuritySchemeKind::BasicAuth
        } else {
            A2aSecuritySchemeKind::Unsupported(format!(
                "HTTP auth scheme `{scheme}` is not supported"
            ))
        };
    }

    if let Some(api_key) = object
        .get("apiKeySecurityScheme")
        .or_else(|| object.get("api_key_security_scheme"))
    {
        let location = api_key
            .get("location")
            .or_else(|| api_key.get("in"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let header_name = api_key
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        return match location.to_ascii_lowercase().as_str() {
            "header" if !header_name.trim().is_empty() => {
                A2aSecuritySchemeKind::ApiKeyHeader { header_name }
            }
            "query" if !header_name.trim().is_empty() => A2aSecuritySchemeKind::ApiKeyQuery {
                param_name: header_name,
            },
            "cookie" if !header_name.trim().is_empty() => A2aSecuritySchemeKind::ApiKeyCookie {
                cookie_name: header_name,
            },
            "header" => A2aSecuritySchemeKind::Unsupported(
                "API key header scheme omitted header name".to_string(),
            ),
            "query" => A2aSecuritySchemeKind::Unsupported(
                "API key query scheme omitted parameter name".to_string(),
            ),
            "cookie" => A2aSecuritySchemeKind::Unsupported(
                "API key cookie scheme omitted cookie name".to_string(),
            ),
            _ => A2aSecuritySchemeKind::Unsupported(format!(
                "API key location `{location}` is not supported"
            )),
        };
    }

    if let Some(oauth2) = object
        .get("oauth2SecurityScheme")
        .or_else(|| object.get("oauth2_security_scheme"))
    {
        return A2aSecuritySchemeKind::OAuthBearerToken {
            token_endpoint: extract_oauth_token_endpoint(oauth2),
        };
    }

    if let Some(openid) = object
        .get("openIdConnectSecurityScheme")
        .or_else(|| object.get("open_id_connect_security_scheme"))
    {
        let discovery_url =
            extract_string_field(openid, &["openIdConnectUrl", "open_id_connect_url"]);
        return match discovery_url {
            Some(discovery_url) if !discovery_url.trim().is_empty() => {
                A2aSecuritySchemeKind::OpenIdBearerToken { discovery_url }
            }
            _ => A2aSecuritySchemeKind::Unsupported(
                "OpenID Connect scheme omitted discovery URL".to_string(),
            ),
        };
    }

    if object.contains_key("mtlsSecurityScheme") || object.contains_key("mtls_security_scheme") {
        return A2aSecuritySchemeKind::MutualTls;
    }

    A2aSecuritySchemeKind::Unsupported("unknown security scheme shape".to_string())
}

fn parse_required_scopes(raw: &Value) -> Result<Vec<String>, AdapterError> {
    match raw {
        Value::Null => Ok(Vec::new()),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(ToString::to_string).ok_or_else(|| {
                    AdapterError::Protocol(
                        "A2A security requirement scopes must be strings".to_string(),
                    )
                })
            })
            .collect(),
        _ => Err(AdapterError::Protocol(
            "A2A security requirement scopes must be an array".to_string(),
        )),
    }
}

fn extract_string_field(raw: &Value, field_names: &[&str]) -> Option<String> {
    let object = raw.as_object()?;
    field_names.iter().find_map(|field_name| {
        object
            .get(*field_name)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    })
}

fn extract_oauth_token_endpoint(raw: &Value) -> Option<String> {
    extract_string_field(raw, &["tokenUrl", "token_url"]).or_else(|| {
        raw.get("flows")
            .and_then(|flows| {
                flows
                    .get("clientCredentials")
                    .or_else(|| flows.get("client_credentials"))
            })
            .and_then(|client_credentials| {
                extract_string_field(client_credentials, &["tokenUrl", "token_url"])
            })
    })
}

fn configured_bearer_header(headers: &[A2aRequestHeader]) -> Option<A2aRequestHeader> {
    headers
        .iter()
        .find(|header| {
            header.name.eq_ignore_ascii_case("Authorization")
                && header.value.to_ascii_lowercase().starts_with("bearer ")
        })
        .cloned()
}

fn configured_basic_auth_header(headers: &[A2aRequestHeader]) -> Option<A2aRequestHeader> {
    headers
        .iter()
        .find(|header| {
            header.name.eq_ignore_ascii_case("Authorization")
                && header.value.to_ascii_lowercase().starts_with("basic ")
        })
        .cloned()
}

fn configured_named_header(
    headers: &[A2aRequestHeader],
    header_name: &str,
) -> Option<A2aRequestHeader> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(header_name))
        .cloned()
}

fn configured_named_query_param(
    query_params: &[A2aRequestQueryParam],
    param_name: &str,
) -> Option<A2aRequestQueryParam> {
    query_params
        .iter()
        .find(|query_param| query_param.name == param_name)
        .cloned()
}

fn configured_named_cookie(
    cookies: &[A2aRequestCookie],
    cookie_name: &str,
) -> Option<A2aRequestCookie> {
    cookies
        .iter()
        .find(|cookie| cookie.name == cookie_name)
        .cloned()
}

fn dedupe_request_headers(headers: &mut Vec<A2aRequestHeader>) {
    let mut deduped = Vec::new();
    for header in headers.drain(..) {
        if !deduped.iter().any(|existing: &A2aRequestHeader| {
            existing.name.eq_ignore_ascii_case(&header.name) && existing.value == header.value
        }) {
            deduped.push(header);
        }
    }
    *headers = deduped;
}

fn dedupe_request_query_params(query_params: &mut Vec<A2aRequestQueryParam>) {
    let mut deduped = Vec::new();
    for query_param in query_params.drain(..) {
        if !deduped
            .iter()
            .any(|existing: &A2aRequestQueryParam| existing == &query_param)
        {
            deduped.push(query_param);
        }
    }
    *query_params = deduped;
}

fn dedupe_request_cookies(cookies: &mut Vec<A2aRequestCookie>) {
    let mut deduped = Vec::new();
    for cookie in cookies.drain(..) {
        if !deduped
            .iter()
            .any(|existing: &A2aRequestCookie| existing == &cookie)
        {
            deduped.push(cookie);
        }
    }
    *cookies = deduped;
}

fn upsert_request_header(headers: &mut Vec<A2aRequestHeader>, name: String, value: String) {
    if let Some(existing) = headers
        .iter_mut()
        .find(|header| header.name.eq_ignore_ascii_case(&name))
    {
        existing.value = value;
    } else {
        headers.push(A2aRequestHeader { name, value });
    }
}

fn upsert_request_query_param(
    query_params: &mut Vec<A2aRequestQueryParam>,
    name: String,
    value: String,
) {
    if let Some(existing) = query_params
        .iter_mut()
        .find(|query_param| query_param.name == name)
    {
        existing.value = value;
    } else {
        query_params.push(A2aRequestQueryParam { name, value });
    }
}

fn upsert_request_cookie(cookies: &mut Vec<A2aRequestCookie>, name: String, value: String) {
    if let Some(existing) = cookies.iter_mut().find(|cookie| cookie.name == name) {
        existing.value = value;
    } else {
        cookies.push(A2aRequestCookie { name, value });
    }
}

fn merge_skill_routing_metadata(
    metadata: Option<Value>,
    skill: &A2aAgentSkill,
) -> Result<Value, AdapterError> {
    let mut object = match metadata {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(object)) => object,
        Some(other) => {
            return Err(AdapterError::InvalidToolInput(format!(
                "`metadata` must be an object, got {other}"
            )))
        }
    };

    let mut pact_namespace = match object.remove("pact") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(object)) => object,
        Some(_) => {
            return Err(AdapterError::InvalidToolInput(
                "`metadata.pact` must be an object when provided".to_string(),
            ))
        }
    };
    pact_namespace.insert("targetSkillId".to_string(), Value::String(skill.id.clone()));
    pact_namespace.insert(
        "targetSkillName".to_string(),
        Value::String(skill.name.clone()),
    );
    object.insert("pact".to_string(), Value::Object(pact_namespace));
    Ok(Value::Object(object))
}

fn validate_object_metadata(
    field_name: &str,
    metadata: Option<Value>,
) -> Result<Option<Value>, AdapterError> {
    match metadata {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(Value::Object(object))),
        Some(_) => Err(AdapterError::InvalidToolInput(format!(
            "`{field_name}` must be an object when provided"
        ))),
    }
}

fn validate_send_message_response(
    mut response: A2aSendMessageResponse,
) -> Result<A2aSendMessageResponse, AdapterError> {
    let has_task = response.task.is_some();
    let has_message = response.message.is_some();
    if has_task == has_message {
        return Err(AdapterError::Protocol(
            "A2A SendMessage response must contain exactly one of `task` or `message`".to_string(),
        ));
    }
    if let Some(task) = response.task.take() {
        response.task = Some(validate_task_response(task)?);
    }
    Ok(response)
}

fn validate_task_response(task: Value) -> Result<Value, AdapterError> {
    let Some(id) = task.get("id").and_then(Value::as_str) else {
        return Err(AdapterError::Protocol(
            "A2A task response must contain string `id`".to_string(),
        ));
    };
    if id.trim().is_empty() {
        return Err(AdapterError::Protocol(
            "A2A task response `id` must not be empty".to_string(),
        ));
    }
    validate_non_empty_string(
        task.get("status")
            .and_then(|status| status.get("state"))
            .and_then(Value::as_str),
        "A2A task response must contain string `status.state`",
        "A2A task response `status.state` must not be empty",
    )?;
    Ok(task)
}

fn validate_stream_response(response: Value) -> Result<(Value, bool), AdapterError> {
    let has_task = response.get("task").is_some();
    let has_message = response.get("message").is_some();
    let has_status_update = response.get("statusUpdate").is_some();
    let has_artifact_update = response.get("artifactUpdate").is_some();
    let present_count = [
        has_task,
        has_message,
        has_status_update,
        has_artifact_update,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if present_count != 1 {
        return Err(AdapterError::Protocol(
            "A2A stream event must contain exactly one of `task`, `message`, `statusUpdate`, or `artifactUpdate`".to_string(),
        ));
    }

    let terminal_or_interrupted = if let Some(task) = response.get("task") {
        validate_task_value(task)?;
        task_state_is_terminal_or_interrupted(
            task.get("status")
                .and_then(|status| status.get("state"))
                .and_then(Value::as_str),
        )
    } else if has_message {
        true
    } else if let Some(update) = response.get("statusUpdate") {
        validate_status_update(update)?;
        task_state_is_terminal_or_interrupted(
            update
                .get("status")
                .and_then(|status| status.get("state"))
                .and_then(Value::as_str),
        )
    } else {
        if let Some(update) = response.get("artifactUpdate") {
            validate_artifact_update(update)?;
        }
        false
    };

    Ok((response, terminal_or_interrupted))
}

fn validate_task_value(task: &Value) -> Result<(), AdapterError> {
    validate_non_empty_string(
        task.get("id").and_then(Value::as_str),
        "A2A task response must contain string `id`",
        "A2A task response `id` must not be empty",
    )?;
    validate_non_empty_string(
        task.get("status")
            .and_then(|status| status.get("state"))
            .and_then(Value::as_str),
        "A2A task response must contain string `status.state`",
        "A2A task response `status.state` must not be empty",
    )
}

fn validate_status_update(update: &Value) -> Result<(), AdapterError> {
    validate_non_empty_string(
        update.get("taskId").and_then(Value::as_str),
        "A2A status update must contain string `taskId`",
        "A2A status update `taskId` must not be empty",
    )?;
    validate_non_empty_string(
        update
            .get("status")
            .and_then(|status| status.get("state"))
            .and_then(Value::as_str),
        "A2A status update must contain string `status.state`",
        "A2A status update `status.state` must not be empty",
    )
}

fn validate_artifact_update(update: &Value) -> Result<(), AdapterError> {
    validate_non_empty_string(
        update.get("taskId").and_then(Value::as_str),
        "A2A artifact update must contain string `taskId`",
        "A2A artifact update `taskId` must not be empty",
    )?;
    if update.get("artifact").and_then(Value::as_object).is_none() {
        return Err(AdapterError::Protocol(
            "A2A artifact update must contain object `artifact`".to_string(),
        ));
    }
    Ok(())
}

fn validate_non_empty_string(
    value: Option<&str>,
    missing_message: &str,
    empty_message: &str,
) -> Result<(), AdapterError> {
    let Some(value) = value else {
        return Err(AdapterError::Protocol(missing_message.to_string()));
    };
    if value.trim().is_empty() {
        return Err(AdapterError::Protocol(empty_message.to_string()));
    }
    Ok(())
}

fn task_state_is_terminal_or_interrupted(state: Option<&str>) -> bool {
    matches!(
        state,
        Some(
            "TASK_STATE_COMPLETED"
                | "TASK_STATE_FAILED"
                | "TASK_STATE_CANCELED"
                | "TASK_STATE_REJECTED"
                | "TASK_STATE_INPUT_REQUIRED"
                | "TASK_STATE_AUTH_REQUIRED"
        )
    )
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn binding_label(binding: &A2aProtocolBinding) -> &'static str {
    match binding {
        A2aProtocolBinding::JsonRpc => "JSONRPC",
        A2aProtocolBinding::HttpJson => "HTTP+JSON",
    }
}

fn next_message_id(counter: &AtomicU64, server_id: &str, skill_id: &str) -> String {
    let seq = counter.fetch_add(1, Ordering::Relaxed) + 1;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("pact-a2a-{server_id}-{skill_id}-{nanos}-{seq}")
}

fn derive_pact_server_id(agent_card_url: &Url) -> String {
    let host = agent_card_url
        .host_str()
        .unwrap_or("a2a")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let hash = sha256_hex(agent_card_url.as_str().as_bytes());
    format!("a2a-{host}-{}", &hash[..12])
}

fn normalize_agent_card_url(value: &str) -> Result<Url, AdapterError> {
    let mut url = Url::parse(value).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?;
    validate_remote_url(&url)?;
    if url.path().ends_with(".json") {
        return Ok(url);
    }
    let new_path = if url.path().is_empty() || url.path() == "/" {
        DEFAULT_AGENT_CARD_PATH.to_string()
    } else {
        format!(
            "{}/.well-known/agent-card.json",
            url.path().trim_end_matches('/')
        )
    };
    url.set_path(&new_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn build_get_task_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
    history_length: Option<u32>,
) -> Result<Url, AdapterError> {
    let encoded_id: String = byte_serialize(task_id.as_bytes()).collect();
    let mut url = join_tenant_url_path(base, tenant, &format!("/tasks/{encoded_id}"))?;
    if let Some(history_length) = history_length {
        url.query_pairs_mut()
            .append_pair("historyLength", &history_length.to_string());
    }
    Ok(url)
}

fn build_subscribe_task_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
) -> Result<Url, AdapterError> {
    let encoded_id: String = byte_serialize(task_id.as_bytes()).collect();
    join_tenant_url_path(base, tenant, &format!("/tasks/{encoded_id}:subscribe"))
}

fn build_send_message_url(
    base: &str,
    tenant: Option<&str>,
    streaming: bool,
) -> Result<Url, AdapterError> {
    join_tenant_url_path(
        base,
        tenant,
        if streaming {
            "/message:stream"
        } else {
            "/message:send"
        },
    )
}

fn build_cancel_task_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
) -> Result<Url, AdapterError> {
    let encoded_id: String = byte_serialize(task_id.as_bytes()).collect();
    join_tenant_url_path(base, tenant, &format!("/tasks/{encoded_id}:cancel"))
}

fn build_push_notification_configs_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
) -> Result<Url, AdapterError> {
    let encoded_task_id: String = byte_serialize(task_id.as_bytes()).collect();
    join_tenant_url_path(
        base,
        tenant,
        &format!("/tasks/{encoded_task_id}/pushNotificationConfigs"),
    )
}

fn build_push_notification_config_url(
    base: &str,
    task_id: &str,
    config_id: &str,
    tenant: Option<&str>,
) -> Result<Url, AdapterError> {
    let encoded_task_id: String = byte_serialize(task_id.as_bytes()).collect();
    let encoded_config_id: String = byte_serialize(config_id.as_bytes()).collect();
    join_tenant_url_path(
        base,
        tenant,
        &format!("/tasks/{encoded_task_id}/pushNotificationConfigs/{encoded_config_id}"),
    )
}

fn build_list_push_notification_configs_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
    page_size: Option<u32>,
    page_token: Option<&str>,
) -> Result<Url, AdapterError> {
    let mut url = build_push_notification_configs_url(base, task_id, tenant)?;
    if let Some(page_size) = page_size {
        url.query_pairs_mut()
            .append_pair("pageSize", &page_size.to_string());
    }
    if let Some(page_token) = page_token {
        url.query_pairs_mut().append_pair("pageToken", page_token);
    }
    Ok(url)
}

fn join_tenant_url_path(
    base: &str,
    tenant: Option<&str>,
    suffix: &str,
) -> Result<Url, AdapterError> {
    let mut url = Url::parse(base).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?;
    validate_remote_url(&url)?;
    let mut joined = url.path().trim_end_matches('/').to_string();
    if let Some(tenant) = tenant {
        let encoded_tenant: String = byte_serialize(tenant.as_bytes()).collect();
        joined.push('/');
        joined.push_str(&encoded_tenant);
    }
    joined.push_str(suffix);
    url.set_path(&joined);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn validate_remote_url(url: &Url) -> Result<(), AdapterError> {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    let localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if scheme == "https" || (scheme == "http" && localhost) {
        Ok(())
    } else {
        Err(AdapterError::InvalidUrl(format!(
            "A2A URLs must use https, or http on localhost during local testing: {}",
            url
        )))
    }
}

fn parse_remote_url(value: &str, field_name: &str) -> Result<Url, AdapterError> {
    let url = Url::parse(value).map_err(|error| {
        AdapterError::AuthNegotiation(format!("{field_name} is not a valid URL: {error}"))
    })?;
    validate_remote_url(&url).map_err(|error| {
        AdapterError::AuthNegotiation(format!(
            "{field_name} must use https, or localhost http: {error}"
        ))
    })?;
    Ok(url)
}

fn validate_notification_target_url(value: &str) -> Result<String, AdapterError> {
    let url = Url::parse(value).map_err(|error| {
        AdapterError::InvalidToolInput(format!("invalid push notification URL: {error}"))
    })?;
    validate_remote_url(&url).map_err(|error| {
        AdapterError::InvalidToolInput(format!(
            "push notification URL must use https, or http on localhost during local testing: {error}"
        ))
    })?;
    Ok(url.to_string())
}

fn validate_identifier(field_name: &str, value: String) -> Result<String, AdapterError> {
    if value.trim().is_empty() {
        Err(AdapterError::InvalidToolInput(format!(
            "`{field_name}` must not be empty"
        )))
    } else {
        Ok(value)
    }
}

fn validate_authentication_info(
    input: Option<A2aAuthenticationInfoToolInput>,
) -> Result<Option<A2aAuthenticationInfo>, AdapterError> {
    match input {
        None => Ok(None),
        Some(input) => Ok(Some(A2aAuthenticationInfo {
            scheme: validate_identifier("authentication.scheme", input.scheme)?,
            credentials: input.credentials.filter(|value| !value.trim().is_empty()),
        })),
    }
}

fn bearer_request_header(access_token: String) -> A2aRequestHeader {
    A2aRequestHeader {
        name: "Authorization".to_string(),
        value: format!("Bearer {access_token}"),
    }
}

fn basic_request_header_value(username: String, password: String) -> String {
    format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{username}:{password}"))
    )
}

fn merged_oauth_scopes(required_scopes: &[String], configured_scopes: &[String]) -> Vec<String> {
    let mut scopes = Vec::new();
    for scope in required_scopes.iter().chain(configured_scopes.iter()) {
        if !scope.trim().is_empty() && !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.clone());
        }
    }
    scopes
}

fn oauth_cache_key(scheme_name: &str, token_endpoint: &Url, scopes: &[String]) -> String {
    let mut normalized_scopes = scopes.to_vec();
    normalized_scopes.sort();
    normalized_scopes.dedup();
    format!(
        "{scheme_name}|{}|{}",
        token_endpoint,
        normalized_scopes.join(" ")
    )
}

fn request_client_credentials_token(
    token_endpoint: &Url,
    credentials: &A2aOAuthClientCredentials,
    scopes: &[String],
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<A2aOAuthTokenResponse, AdapterError> {
    let basic_header = A2aRequestHeader {
        name: "Authorization".to_string(),
        value: format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!(
                "{}:{}",
                credentials.client_id, credentials.client_secret
            ))
        ),
    };
    let basic_body = build_client_credentials_form(scopes, None);
    match post_form_json::<A2aOAuthTokenResponse>(
        token_endpoint,
        basic_body.as_str(),
        &[basic_header],
        timeout,
        transport_config,
        A2aTlsMode::Default,
    ) {
        Ok(response) => Ok(response),
        Err(AdapterError::Remote(message))
            if message.starts_with("HTTP 400:") || message.starts_with("HTTP 401:") =>
        {
            let fallback_body = build_client_credentials_form(
                scopes,
                Some((&credentials.client_id, &credentials.client_secret)),
            );
            post_form_json::<A2aOAuthTokenResponse>(
                token_endpoint,
                fallback_body.as_str(),
                &[],
                timeout,
                transport_config,
                A2aTlsMode::Default,
            )
        }
        Err(error) => Err(error),
    }
}

fn build_client_credentials_form(scopes: &[String], credentials: Option<(&str, &str)>) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    serializer.append_pair("grant_type", "client_credentials");
    if !scopes.is_empty() {
        serializer.append_pair("scope", &scopes.join(" "));
    }
    if let Some((client_id, client_secret)) = credentials {
        serializer.append_pair("client_id", client_id);
        serializer.append_pair("client_secret", client_secret);
    }
    serializer.finish()
}

fn fetch_json<T: for<'de> Deserialize<'de>>(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    let request = agent
        .get(request_url.as_str())
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    let response = request.call().map_err(map_ureq_error)?;
    response.into_json().map_err(|error| {
        AdapterError::Protocol(format!(
            "failed to decode A2A JSON from {}: {error}",
            request_url
        ))
    })
}

fn delete_empty(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<(), AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    let request = agent
        .delete(request_url.as_str())
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    request.call().map_err(map_ureq_error)?;
    Ok(())
}

fn get_sse<F>(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    let request = agent
        .get(request_url.as_str())
        .set("Accept", SSE_CONTENT_TYPE)
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    let response = request.call().map_err(map_ureq_error)?;
    let content_type = response.header("Content-Type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains(SSE_CONTENT_TYPE) {
        return Err(AdapterError::Protocol(format!(
            "expected {SSE_CONTENT_TYPE} response, got {content_type}"
        )));
    }
    parse_sse_stream(response.into_reader(), decode_event)
}

fn post_json<T: for<'de> Deserialize<'de>, B: Serialize>(
    url: &str,
    body: &B,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(
        Url::parse(url).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?,
        request_auth,
    );
    let request = agent
        .post(request_url.as_str())
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    let response = request.send_json(serde_json::to_value(body).map_err(|error| {
        AdapterError::Protocol(format!("failed to serialize A2A request: {error}"))
    })?);
    response
        .map_err(map_ureq_error)?
        .into_json()
        .map_err(|error| AdapterError::Protocol(format!("failed to decode A2A response: {error}")))
}

fn post_form_json<T: for<'de> Deserialize<'de>>(
    url: &Url,
    body: &str,
    request_headers: &[A2aRequestHeader],
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    tls_mode: A2aTlsMode,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, tls_mode)?;
    let request = agent
        .post(url.as_str())
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("Accept", "application/json");
    let request = apply_request_headers(request, request_headers);
    request
        .send_string(body)
        .map_err(map_ureq_error)?
        .into_json()
        .map_err(|error| {
            AdapterError::Protocol(format!(
                "failed to decode OAuth token response from {}: {error}",
                url
            ))
        })
}

fn post_sse_json<T: Serialize, F>(
    url: &str,
    body: &T,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(
        Url::parse(url).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?,
        request_auth,
    );
    let request = agent
        .post(request_url.as_str())
        .set("Content-Type", "application/json")
        .set("Accept", SSE_CONTENT_TYPE)
        .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
    let request = apply_request_auth(request, request_auth);
    let response = request.send_json(serde_json::to_value(body).map_err(|error| {
        AdapterError::Protocol(format!("failed to serialize A2A request: {error}"))
    })?);
    let response = response.map_err(map_ureq_error)?;
    let content_type = response.header("Content-Type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains(SSE_CONTENT_TYPE) {
        return Err(AdapterError::Protocol(format!(
            "expected {SSE_CONTENT_TYPE} response, got {content_type}"
        )));
    }
    parse_sse_stream(response.into_reader(), decode_event)
}

fn build_optional_default_tls_config(
    root_ca_pems: &[String],
) -> Result<Option<Arc<ureq::rustls::ClientConfig>>, AdapterError> {
    if root_ca_pems.is_empty() {
        return Ok(None);
    }
    Ok(Some(Arc::new(build_client_tls_config(root_ca_pems, None)?)))
}

fn build_optional_mutual_tls_config(
    root_ca_pems: &[String],
    mutual_tls_identity: Option<&A2aMutualTlsIdentity>,
) -> Result<Option<Arc<ureq::rustls::ClientConfig>>, AdapterError> {
    let Some(mutual_tls_identity) = mutual_tls_identity else {
        return Ok(None);
    };
    Ok(Some(Arc::new(build_client_tls_config(
        root_ca_pems,
        Some(mutual_tls_identity),
    )?)))
}

fn build_client_tls_config(
    root_ca_pems: &[String],
    mutual_tls_identity: Option<&A2aMutualTlsIdentity>,
) -> Result<ureq::rustls::ClientConfig, AdapterError> {
    let root_store = build_root_cert_store(root_ca_pems)?;
    let builder = ureq::rustls::ClientConfig::builder().with_root_certificates(root_store);
    if let Some(mutual_tls_identity) = mutual_tls_identity {
        let cert_chain = parse_pem_certificates(
            mutual_tls_identity.cert_chain_pem.as_str(),
            "mutual TLS client certificate chain",
        )?;
        let private_key = parse_pem_private_key(
            mutual_tls_identity.private_key_pem.as_str(),
            "mutual TLS client private key",
        )?;
        builder
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|error| {
                AdapterError::AuthNegotiation(format!(
                    "failed to build mutual TLS client identity: {error}"
                ))
            })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

fn build_root_cert_store(
    root_ca_pems: &[String],
) -> Result<ureq::rustls::RootCertStore, AdapterError> {
    let mut root_store = ureq::rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };
    for root_ca_pem in root_ca_pems {
        for certificate in parse_pem_certificates(root_ca_pem, "custom TLS root CA")? {
            root_store.add(certificate).map_err(|error| {
                AdapterError::AuthNegotiation(format!(
                    "failed to add custom TLS root CA certificate: {error}"
                ))
            })?;
        }
    }
    Ok(root_store)
}

fn parse_pem_certificates(
    pem: &str,
    field_name: &str,
) -> Result<Vec<ureq::rustls::pki_types::CertificateDer<'static>>, AdapterError> {
    let mut reader = pem.as_bytes();
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AdapterError::AuthNegotiation(format!("failed to parse {field_name}: {error}"))
        })?;
    if certificates.is_empty() {
        return Err(AdapterError::AuthNegotiation(format!(
            "{field_name} did not contain any PEM certificates"
        )));
    }
    Ok(certificates)
}

fn parse_pem_private_key(
    pem: &str,
    field_name: &str,
) -> Result<ureq::rustls::pki_types::PrivateKeyDer<'static>, AdapterError> {
    let mut reader = pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut reader)
        .map_err(|error| {
            AdapterError::AuthNegotiation(format!("failed to parse {field_name}: {error}"))
        })?
        .ok_or_else(|| {
            AdapterError::AuthNegotiation(format!(
                "{field_name} did not contain a supported PEM private key"
            ))
        })?;
    Ok(private_key)
}

fn build_agent(
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    tls_mode: A2aTlsMode,
) -> Result<ureq::Agent, AdapterError> {
    let builder = ureq::AgentBuilder::new().timeout(timeout);
    let builder = match tls_mode {
        A2aTlsMode::Default => match transport_config.default_tls_config.as_ref() {
            Some(tls_config) => builder.tls_config(Arc::clone(tls_config)),
            None => builder,
        },
        A2aTlsMode::MutualTls => {
            let tls_config = transport_config.mutual_tls_config.as_ref().ok_or_else(|| {
                AdapterError::AuthNegotiation(
                    "mutual TLS transport was selected without a client identity".to_string(),
                )
            })?;
            builder.tls_config(Arc::clone(tls_config))
        }
    };
    Ok(builder.build())
}

fn parse_sse_stream<R: Read, F>(
    reader: R,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut data_lines = Vec::new();
    let mut chunks = Vec::new();
    let mut saw_terminal_or_interrupted = false;

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).map_err(|error| {
            AdapterError::Remote(format!("failed to read A2A SSE stream: {error}"))
        })?;
        if bytes_read == 0 {
            if !data_lines.is_empty() {
                process_sse_event(
                    &mut chunks,
                    &mut saw_terminal_or_interrupted,
                    &mut data_lines,
                    &decode_event,
                )?;
            }
            break;
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            process_sse_event(
                &mut chunks,
                &mut saw_terminal_or_interrupted,
                &mut data_lines,
                &decode_event,
            )?;
            continue;
        }
        if trimmed.starts_with(':') {
            continue;
        }
        if let Some(data) = trimmed.strip_prefix("data:") {
            data_lines.push(data.trim_start().to_string());
        }
    }

    let stream = ToolCallStream { chunks };
    if stream.chunks.is_empty() {
        return Ok(ToolServerStreamResult::Incomplete {
            stream,
            reason: "A2A streaming response ended without any stream events".to_string(),
        });
    }

    if saw_terminal_or_interrupted {
        Ok(ToolServerStreamResult::Complete(stream))
    } else {
        Ok(ToolServerStreamResult::Incomplete {
            stream,
            reason: "A2A streaming response ended before a terminal or interrupted task state"
                .to_string(),
        })
    }
}

fn process_sse_event<F>(
    chunks: &mut Vec<ToolCallChunk>,
    saw_terminal_or_interrupted: &mut bool,
    data_lines: &mut Vec<String>,
    decode_event: &F,
) -> Result<(), AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    if data_lines.is_empty() {
        return Ok(());
    }

    let payload = data_lines.join("\n");
    data_lines.clear();
    let event = serde_json::from_str::<Value>(&payload).map_err(|error| {
        AdapterError::Protocol(format!("failed to decode A2A SSE event JSON: {error}"))
    })?;
    let stream_response = decode_event(event)?;
    let (stream_response, terminal_or_interrupted) = validate_stream_response(stream_response)?;
    *saw_terminal_or_interrupted |= terminal_or_interrupted;
    chunks.push(ToolCallChunk {
        data: stream_response,
    });
    Ok(())
}

fn apply_request_headers(
    mut request: ureq::Request,
    request_headers: &[A2aRequestHeader],
) -> ureq::Request {
    for header in request_headers {
        request = request.set(header.name.as_str(), header.value.as_str());
    }
    request
}

fn apply_request_auth(
    mut request: ureq::Request,
    request_auth: &A2aResolvedRequestAuth,
) -> ureq::Request {
    request = apply_request_headers(request, &request_auth.headers);
    if !request_auth.cookies.is_empty() {
        let cookie_value = build_cookie_header(request_auth);
        request = request.set("Cookie", cookie_value.as_str());
    }
    request
}

fn build_cookie_header(request_auth: &A2aResolvedRequestAuth) -> String {
    let mut cookie_fragments = request_auth
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Cookie"))
        .map(|header| header.value.clone())
        .collect::<Vec<_>>();
    cookie_fragments.extend(
        request_auth
            .cookies
            .iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value)),
    );
    cookie_fragments.join("; ")
}

fn apply_request_auth_url(mut url: Url, request_auth: &A2aResolvedRequestAuth) -> Url {
    if request_auth.query_params.is_empty() {
        return url;
    }
    let auth_names = request_auth
        .query_params
        .iter()
        .map(|query_param| query_param.name.as_str())
        .collect::<Vec<_>>();
    let existing_pairs = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .filter(|(name, _)| !auth_names.iter().any(|auth_name| auth_name == name))
        .collect::<Vec<_>>();
    url.set_query(None);
    {
        let mut query_pairs = url.query_pairs_mut();
        for (name, value) in existing_pairs {
            query_pairs.append_pair(name.as_str(), value.as_str());
        }
        for query_param in &request_auth.query_params {
            query_pairs.append_pair(query_param.name.as_str(), query_param.value.as_str());
        }
    }
    url
}

fn map_ureq_error(error: ureq::Error) -> AdapterError {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_else(|_| String::new());
            AdapterError::Remote(format!("HTTP {status}: {}", body.trim()))
        }
        ureq::Error::Transport(error) => AdapterError::Remote(error.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;

    use pact_core::capability::{
        CapabilityToken, CapabilityTokenBody, Operation, PactScope, ToolGrant,
    };
    use pact_core::crypto::Keypair;
    use pact_core::receipt::Decision;
    use pact_kernel::{
        KernelConfig, PactKernel, ToolCallRequest, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair as RcgenKeyPair,
    };

    fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
    }

    #[test]
    fn adapter_discovers_jsonrpc_and_invokes_skill() {
        let server = FakeA2aServer::spawn_jsonrpc();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_bearer_token("secret-token")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        assert_eq!(adapter.tool_names(), vec!["research".to_string()]);
        let result = adapter
            .invoke(
                "research",
                json!({
                    "message": "Find recent results on treatment-resistant depression",
                    "metadata": { "trace_id": "trace-1" },
                    "message_metadata": { "priority": "high" },
                    "history_length": 3
                }),
                None,
            )
            .expect("invoke research skill");

        assert_eq!(
            result["message"]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("GET /.well-known/agent-card.json HTTP/1.1"));
        assert!(requests[1].contains("POST /rpc HTTP/1.1"));
        assert!(requests[1].contains("Authorization: Bearer secret-token"));
        assert!(requests[1].contains("A2A-Version: 1.0"));
        assert!(requests[1].contains("\"method\":\"SendMessage\""));
        assert!(requests[1].contains("\"targetSkillId\":\"research\""));
        server.join();
    }

    #[test]
    fn adapter_generic_request_auth_surfaces_apply_to_discovery_and_invoke() {
        let server = FakeA2aServer::spawn_http_json();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_request_header("X-Partner", "partner-alpha")
                .with_request_query_param("partner", "alpha")
                .with_request_cookie("partner_session", "cookie-alpha")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "message": "Find recent results on treatment-resistant depression"
                }),
                None,
            )
            .expect("invoke research skill");

        assert_eq!(
            result["task"]["artifacts"][0]["parts"][0]["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /.well-known/agent-card.json?partner=alpha "));
        assert!(requests[0].contains("X-Partner: partner-alpha"));
        assert!(requests[0].contains("Cookie: partner_session=cookie-alpha"));
        assert!(requests[1].starts_with("POST /message:send?partner=alpha "));
        assert!(requests[1].contains("X-Partner: partner-alpha"));
        assert!(requests[1].contains("Cookie: partner_session=cookie-alpha"));
        server.join();
    }

    #[test]
    fn partner_policy_rejects_wrong_tenant_on_discovery() {
        let server = FakeA2aServer::spawn_jsonrpc_bearer_required();
        let manifest_key = Keypair::generate();
        let error = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_partner_policy(
                    A2aPartnerPolicy::new("partner-alpha").with_required_tenant("tenant-required"),
                )
                .with_timeout(Duration::from_secs(2)),
        )
        .expect_err("partner policy should fail closed on tenant mismatch");

        assert!(error
            .to_string()
            .contains("requires tenant `tenant-required`"));
        server.join();
    }

    #[test]
    fn task_registry_allows_follow_up_after_restart_and_rejects_unknown_tasks() {
        let registry_path = unique_path("pact-a2a-task-registry", ".json");
        let server = FakeA2aServer::spawn_jsonrpc_task_follow_up();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");

        let initial = adapter
            .invoke(
                "research",
                json!({
                    "message": "Begin longer research task",
                    "return_immediately": true
                }),
                None,
            )
            .expect("initial invoke");
        assert_eq!(initial["task"]["status"]["state"], "TASK_STATE_WORKING");

        let adapter_after_restart = A2aAdapter {
            manifest: adapter.manifest.clone(),
            agent_card: adapter.agent_card.clone(),
            agent_card_url: adapter.agent_card_url.clone(),
            selected_interface: adapter.selected_interface.clone(),
            selected_binding: adapter.selected_binding,
            configured_headers: adapter.configured_headers.clone(),
            configured_query_params: adapter.configured_query_params.clone(),
            configured_cookies: adapter.configured_cookies.clone(),
            oauth_client_credentials: adapter.oauth_client_credentials.clone(),
            oauth_scopes: adapter.oauth_scopes.clone(),
            oauth_token_endpoint_override: adapter.oauth_token_endpoint_override.clone(),
            transport_config: adapter.transport_config.clone(),
            token_cache: Mutex::new(Vec::new()),
            timeout: adapter.timeout,
            request_counter: AtomicU64::new(0),
            partner_policy: adapter.partner_policy.clone(),
            task_registry: Some(A2aTaskRegistry::open(&registry_path).expect("reopen registry")),
        };
        let follow_up = adapter_after_restart
            .invoke(
                "research",
                json!({
                    "get_task": {
                        "id": "task-1",
                        "history_length": 1
                    }
                }),
                None,
            )
            .expect("follow-up invoke after restart");
        assert_eq!(follow_up["task"]["status"]["state"], "TASK_STATE_COMPLETED");

        let unknown_error = adapter_after_restart
            .invoke(
                "research",
                json!({
                    "get_task": {
                        "id": "task-unknown"
                    }
                }),
                None,
            )
            .expect_err("unknown follow-up should fail closed");
        assert!(unknown_error
            .to_string()
            .contains("requires a previously recorded A2A task"));

        let _ = fs::remove_file(registry_path);
        server.join();
    }

    #[test]
    fn adapter_invokes_http_json_binding() {
        let server = FakeA2aServer::spawn_http_json();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "data": { "query": "hypertension staging guidelines" },
                    "return_immediately": true
                }),
                None,
            )
            .expect("invoke research skill over HTTP+JSON");

        assert_eq!(result["task"]["id"], "task-1");
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("POST /message:send HTTP/1.1"));
        assert!(requests[1].contains("\"targetSkillId\":\"research\""));
        server.join();
    }

    #[test]
    fn adapter_rejects_insecure_non_localhost_urls() {
        let manifest_key = Keypair::generate();
        let error = A2aAdapter::discover(A2aAdapterConfig::new(
            "http://example.com",
            manifest_key.public_key().to_hex(),
        ))
        .expect_err("insecure remote URL should fail");
        assert!(error.to_string().contains("https"));
    }

    #[test]
    fn adapter_jsonrpc_get_task_follow_up() {
        let server = FakeA2aServer::spawn_jsonrpc_task_follow_up();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let initial = adapter
            .invoke(
                "research",
                json!({
                    "message": "Start a long-running research task",
                    "return_immediately": true
                }),
                None,
            )
            .expect("start follow-up task");
        assert_eq!(initial["task"]["id"], "task-1");
        assert_eq!(initial["task"]["status"]["state"], "TASK_STATE_WORKING");

        let follow_up = adapter
            .invoke(
                "research",
                json!({
                    "get_task": {
                        "id": "task-1",
                        "history_length": 2
                    }
                }),
                None,
            )
            .expect("poll A2A task");
        assert_eq!(follow_up["task"]["id"], "task-1");
        assert_eq!(follow_up["task"]["status"]["state"], "TASK_STATE_COMPLETED");
        assert_eq!(
            follow_up["task"]["artifacts"][0]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].contains("\"method\":\"SendMessage\""));
        assert!(requests[2].contains("\"method\":\"GetTask\""));
        assert!(requests[2].contains("\"historyLength\":2"));
        server.join();
    }

    #[test]
    fn adapter_http_json_get_task_follow_up() {
        let server = FakeA2aServer::spawn_http_json_task_follow_up();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let initial = adapter
            .invoke(
                "research",
                json!({
                    "message": "Start a long-running research task",
                    "return_immediately": true
                }),
                None,
            )
            .expect("start follow-up task");
        assert_eq!(initial["task"]["id"], "task-1");
        assert_eq!(initial["task"]["status"]["state"], "TASK_STATE_WORKING");

        let follow_up = adapter
            .invoke(
                "research",
                json!({
                    "get_task": {
                        "id": "task-1",
                        "history_length": 2
                    }
                }),
                None,
            )
            .expect("poll A2A task");
        assert_eq!(follow_up["task"]["id"], "task-1");
        assert_eq!(follow_up["task"]["status"]["state"], "TASK_STATE_COMPLETED");

        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].contains("POST /message:send HTTP/1.1"));
        assert!(
            requests[2].starts_with("GET /tasks/task-1?historyLength=2 HTTP/1.1"),
            "unexpected follow-up request: {}",
            requests[2].lines().next().unwrap_or_default()
        );
        assert!(requests[2].contains("A2A-Version: 1.0"));
        server.join();
    }

    #[test]
    fn adapter_rejects_mixed_send_and_get_task_input() {
        let error = parse_tool_input(json!({
            "message": "hello",
            "get_task": { "id": "task-1" }
        }))
        .expect_err("mixed invocation modes should fail");
        assert!(error
            .to_string()
            .contains("mutually exclusive with SendMessage fields"));
    }

    #[test]
    fn adapter_rejects_mixed_send_and_subscribe_task_input() {
        let error = parse_tool_input(json!({
            "message": "hello",
            "subscribe_task": { "id": "task-1" }
        }))
        .expect_err("mixed subscribe invocation should fail");
        assert!(error
            .to_string()
            .contains("mutually exclusive with SendMessage and `get_task` fields"));
    }

    #[test]
    fn build_send_message_request_propagates_interface_tenant() {
        let agent_card = A2aAgentCard {
            name: "Research Agent".to_string(),
            description: "Answers research questions over A2A".to_string(),
            supported_interfaces: vec![],
            version: "1.0.0".to_string(),
            capabilities: A2aAgentCapabilities::default(),
            security_schemes: None,
            security_requirements: None,
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![A2aAgentSkill {
                id: "research".to_string(),
                name: "Research".to_string(),
                description: "Search and synthesize results".to_string(),
                tags: vec!["search".to_string()],
                examples: None,
                input_modes: None,
                output_modes: None,
                security_requirements: None,
            }],
            documentation_url: None,
            icon_url: None,
        };
        let selected_interface = A2aAgentInterface {
            url: "http://localhost:9000/rpc".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            protocol_version: "1.0".to_string(),
            tenant: Some("tenant-alpha".to_string()),
        };
        let manifest = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &agent_card,
            &A2aProtocolBinding::JsonRpc,
        )
        .expect("build manifest");
        let adapter = A2aAdapter {
            manifest,
            agent_card: agent_card.clone(),
            agent_card_url: normalize_agent_card_url("http://localhost:9000")
                .expect("normalize agent card URL"),
            selected_interface,
            selected_binding: A2aProtocolBinding::JsonRpc,
            configured_headers: Vec::new(),
            configured_query_params: Vec::new(),
            configured_cookies: Vec::new(),
            oauth_client_credentials: None,
            oauth_scopes: Vec::new(),
            oauth_token_endpoint_override: None,
            transport_config: A2aTransportConfig {
                default_tls_config: None,
                mutual_tls_config: None,
            },
            token_cache: Mutex::new(Vec::new()),
            timeout: Duration::from_secs(2),
            request_counter: AtomicU64::new(0),
            partner_policy: None,
            task_registry: None,
        };

        let request = adapter
            .build_send_message_request(
                &agent_card.skills[0],
                A2aSendToolInput {
                    message: Some("hello".to_string()),
                    data: None,
                    context_id: None,
                    task_id: None,
                    reference_task_ids: None,
                    metadata: None,
                    message_metadata: None,
                    history_length: None,
                    return_immediately: None,
                    stream: false,
                },
            )
            .expect("build send message request");

        assert_eq!(request.tenant.as_deref(), Some("tenant-alpha"));
    }

    #[test]
    fn build_send_message_request_rejects_history_length_without_capability() {
        let adapter = local_test_adapter(
            A2aAgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
            },
            A2aProtocolBinding::JsonRpc,
            Some("tenant-alpha"),
        );
        let error = adapter
            .build_send_message_request(
                &adapter.agent_card.skills[0],
                A2aSendToolInput {
                    message: Some("hello".to_string()),
                    data: None,
                    context_id: None,
                    task_id: None,
                    reference_task_ids: None,
                    metadata: None,
                    message_metadata: None,
                    history_length: Some(2),
                    return_immediately: None,
                    stream: false,
                },
            )
            .expect_err("history_length without capability should fail");
        assert!(error
            .to_string()
            .contains("state transition history support"));
    }

    #[test]
    fn get_task_rejects_history_length_without_capability() {
        let adapter = local_test_adapter(
            A2aAgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
            },
            A2aProtocolBinding::HttpJson,
            None,
        );
        let error = adapter
            .get_task_http_json(
                A2aGetTaskToolInput {
                    id: "task-1".to_string(),
                    history_length: Some(1),
                },
                &A2aResolvedRequestAuth {
                    headers: Vec::new(),
                    query_params: Vec::new(),
                    cookies: Vec::new(),
                    tls_mode: A2aTlsMode::Default,
                },
            )
            .expect_err("history_length without capability should fail");
        assert!(error
            .to_string()
            .contains("state transition history support"));
    }

    fn local_test_adapter(
        capabilities: A2aAgentCapabilities,
        selected_binding: A2aProtocolBinding,
        tenant: Option<&str>,
    ) -> A2aAdapter {
        let agent_card = A2aAgentCard {
            name: "Research Agent".to_string(),
            description: "Answers research questions over A2A".to_string(),
            supported_interfaces: vec![],
            version: "1.0.0".to_string(),
            capabilities,
            security_schemes: None,
            security_requirements: None,
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![A2aAgentSkill {
                id: "research".to_string(),
                name: "Research".to_string(),
                description: "Search and synthesize results".to_string(),
                tags: vec!["search".to_string()],
                examples: None,
                input_modes: None,
                output_modes: None,
                security_requirements: None,
            }],
            documentation_url: None,
            icon_url: None,
        };
        let selected_interface = A2aAgentInterface {
            url: match selected_binding {
                A2aProtocolBinding::JsonRpc => "http://localhost:9000/rpc".to_string(),
                A2aProtocolBinding::HttpJson => "http://localhost:9000".to_string(),
            },
            protocol_binding: match selected_binding {
                A2aProtocolBinding::JsonRpc => "JSONRPC".to_string(),
                A2aProtocolBinding::HttpJson => "HTTP+JSON".to_string(),
            },
            protocol_version: "1.0".to_string(),
            tenant: tenant.map(ToString::to_string),
        };
        let manifest = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &agent_card,
            &selected_binding,
        )
        .expect("build manifest");
        A2aAdapter {
            manifest,
            agent_card,
            agent_card_url: normalize_agent_card_url("http://localhost:9000")
                .expect("normalize agent card URL"),
            selected_interface,
            selected_binding,
            configured_headers: Vec::new(),
            configured_query_params: Vec::new(),
            configured_cookies: Vec::new(),
            oauth_client_credentials: None,
            oauth_scopes: Vec::new(),
            oauth_token_endpoint_override: None,
            transport_config: A2aTransportConfig {
                default_tls_config: None,
                mutual_tls_config: None,
            },
            token_cache: Mutex::new(Vec::new()),
            timeout: Duration::from_secs(2),
            request_counter: AtomicU64::new(0),
            partner_policy: None,
            task_registry: None,
        }
    }

    #[test]
    fn validate_send_message_response_rejects_task_without_status_state() {
        let error = validate_send_message_response(A2aSendMessageResponse {
            task: Some(json!({
                "id": "task-1"
            })),
            message: None,
        })
        .expect_err("task without status.state should fail");
        assert!(error.to_string().contains("status.state"));
    }

    #[test]
    fn validate_stream_response_rejects_status_update_without_task_id() {
        let error = validate_stream_response(json!({
            "statusUpdate": {
                "status": { "state": "TASK_STATE_COMPLETED" }
            }
        }))
        .expect_err("statusUpdate without taskId should fail");
        assert!(error.to_string().contains("taskId"));
    }

    #[test]
    fn validate_stream_response_rejects_artifact_update_without_task_id() {
        let error = validate_stream_response(json!({
            "artifactUpdate": {
                "artifact": {
                    "artifactId": "artifact-1"
                }
            }
        }))
        .expect_err("artifactUpdate without taskId should fail");
        assert!(error.to_string().contains("taskId"));
    }

    #[test]
    fn build_get_task_url_appends_tenant_and_history_length() {
        let url = build_get_task_url(
            "http://localhost:9000",
            "task-1",
            Some("tenant-alpha"),
            Some(2),
        )
        .expect("build get task URL");

        assert_eq!(
            url.as_str(),
            "http://localhost:9000/tenant-alpha/tasks/task-1?historyLength=2"
        );
    }

    #[test]
    fn build_send_message_url_appends_tenant_path_segment() {
        let send_url =
            build_send_message_url("http://localhost:9000/api", Some("tenant-alpha"), false)
                .expect("build send message URL");
        let stream_url =
            build_send_message_url("http://localhost:9000/api", Some("tenant-alpha"), true)
                .expect("build stream message URL");

        assert_eq!(
            send_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/message:send"
        );
        assert_eq!(
            stream_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/message:stream"
        );
    }

    #[test]
    fn build_cancel_task_url_appends_tenant_path_segment() {
        let url =
            build_cancel_task_url("http://localhost:9000/api", "task-1", Some("tenant-alpha"))
                .expect("build cancel task URL");

        assert_eq!(
            url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1:cancel"
        );
    }

    #[test]
    fn build_push_notification_urls_append_tenant_path_segment() {
        let collection_url = build_push_notification_configs_url(
            "http://localhost:9000/api",
            "task-1",
            Some("tenant-alpha"),
        )
        .expect("build push notification configs URL");
        let config_url = build_push_notification_config_url(
            "http://localhost:9000/api",
            "task-1",
            "config-1",
            Some("tenant-alpha"),
        )
        .expect("build push notification config URL");
        let list_url = build_list_push_notification_configs_url(
            "http://localhost:9000/api",
            "task-1",
            Some("tenant-alpha"),
            Some(25),
            Some("page-2"),
        )
        .expect("build list push notification configs URL");

        assert_eq!(
            collection_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs"
        );
        assert_eq!(
            config_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs/config-1"
        );
        assert_eq!(
            list_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2"
        );
    }

    #[test]
    fn adapter_invoke_stream_returns_none_without_stream_flag() {
        let server = FakeA2aServer::spawn_jsonrpc();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Do not stream this"
                }),
                None,
            )
            .expect("invoke_stream should not fail");
        assert!(stream.is_none());
        let _ = adapter
            .invoke(
                "research",
                json!({
                    "message": "finish request log"
                }),
                None,
            )
            .expect("invoke blocking request");
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_streaming_invocation_returns_complete_stream() {
        let server = FakeA2aServer::spawn_jsonrpc_streaming_complete();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .expect("invoke stream")
            .expect("stream result");

        let ToolServerStreamResult::Complete(stream) = stream else {
            panic!("expected complete stream");
        };
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[0].data["task"]["status"]["state"],
            "TASK_STATE_WORKING"
        );
        assert_eq!(
            stream.chunks[1].data["artifactUpdate"]["artifact"]["parts"][0]["text"],
            "partial research result"
        );
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"SendStreamingMessage\""));
        assert!(requests[1].contains("Accept: text/event-stream"));
        server.join();
    }

    #[test]
    fn adapter_http_json_streaming_invocation_returns_complete_stream() {
        let server = FakeA2aServer::spawn_http_json_streaming_complete();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .expect("invoke stream")
            .expect("stream result");

        let ToolServerStreamResult::Complete(stream) = stream else {
            panic!("expected complete stream");
        };
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("POST /message:stream HTTP/1.1"));
        assert!(requests[1].contains("Accept: text/event-stream"));
        server.join();
    }

    #[test]
    fn adapter_streaming_closure_without_terminal_state_is_incomplete() {
        let server = FakeA2aServer::spawn_jsonrpc_streaming_incomplete();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .expect("invoke stream")
            .expect("stream result");

        let ToolServerStreamResult::Incomplete { stream, reason } = stream else {
            panic!("expected incomplete stream");
        };
        assert_eq!(stream.chunk_count(), 2);
        assert!(reason.contains("terminal or interrupted"));
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_subscribe_task_returns_complete_stream() {
        let server = FakeA2aServer::spawn_jsonrpc_subscribe_complete();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
            .expect("invoke subscribe stream")
            .expect("stream result");

        let ToolServerStreamResult::Complete(stream) = stream else {
            panic!("expected complete stream");
        };
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"SubscribeToTask\""));
        assert!(requests[1].contains("Accept: text/event-stream"));
        server.join();
    }

    #[test]
    fn adapter_http_json_subscribe_task_returns_complete_stream() {
        let server = FakeA2aServer::spawn_http_json_subscribe_complete();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
            .expect("invoke subscribe stream")
            .expect("stream result");

        let ToolServerStreamResult::Complete(stream) = stream else {
            panic!("expected complete stream");
        };
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("GET /tasks/task-1:subscribe HTTP/1.1"));
        assert!(requests[1].contains("Accept: text/event-stream"));
        server.join();
    }

    #[test]
    fn adapter_subscribe_task_closure_without_terminal_state_is_incomplete() {
        let server = FakeA2aServer::spawn_jsonrpc_subscribe_incomplete();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
            .expect("invoke subscribe stream")
            .expect("stream result");

        let ToolServerStreamResult::Incomplete { stream, reason } = stream else {
            panic!("expected incomplete stream");
        };
        assert_eq!(stream.chunk_count(), 2);
        assert!(reason.contains("terminal or interrupted"));
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_cancel_task_returns_cancelled_task() {
        let server = FakeA2aServer::spawn_jsonrpc_cancel_task();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "cancel_task": {
                        "id": "task-1",
                        "metadata": { "reason": "user-request" }
                    }
                }),
                None,
            )
            .expect("cancel task");

        assert_eq!(result["task"]["id"], "task-1");
        assert_eq!(result["task"]["status"]["state"], "TASK_STATE_CANCELED");

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"CancelTask\""));
        assert!(requests[1].contains("\"reason\":\"user-request\""));
        server.join();
    }

    #[test]
    fn adapter_http_json_cancel_task_returns_cancelled_task() {
        let server = FakeA2aServer::spawn_http_json_cancel_task();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "cancel_task": {
                        "id": "task-1",
                        "metadata": { "reason": "user-request" }
                    }
                }),
                None,
            )
            .expect("cancel task");

        assert_eq!(result["task"]["id"], "task-1");
        assert_eq!(result["task"]["status"]["state"], "TASK_STATE_CANCELED");

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("POST /tasks/task-1:cancel HTTP/1.1"));
        assert!(requests[1].contains("\"reason\":\"user-request\""));
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_push_notification_config_crud_roundtrip() {
        let server = FakeA2aServer::spawn_jsonrpc_push_notification_crud();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let created = adapter
            .invoke(
                "research",
                json!({
                    "create_push_notification_config": {
                        "task_id": "task-1",
                        "url": "https://callbacks.example.com/pact",
                        "token": "notify-token",
                        "authentication": {
                            "scheme": "bearer",
                            "credentials": "callback-secret"
                        }
                    }
                }),
                None,
            )
            .expect("create push notification config");
        assert_eq!(
            created["push_notification_config"]["id"],
            Value::String("config-1".to_string())
        );

        let fetched = adapter
            .invoke(
                "research",
                json!({
                    "get_push_notification_config": {
                        "task_id": "task-1",
                        "id": "config-1"
                    }
                }),
                None,
            )
            .expect("get push notification config");
        assert_eq!(
            fetched["push_notification_config"]["url"],
            "https://callbacks.example.com/pact"
        );

        let listed = adapter
            .invoke(
                "research",
                json!({
                    "list_push_notification_configs": {
                        "task_id": "task-1",
                        "page_size": 25,
                        "page_token": "page-2"
                    }
                }),
                None,
            )
            .expect("list push notification configs");
        assert_eq!(
            listed["push_notification_configs"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(listed["next_page_token"], "next-page");

        let deleted = adapter
            .invoke(
                "research",
                json!({
                    "delete_push_notification_config": {
                        "task_id": "task-1",
                        "id": "config-1"
                    }
                }),
                None,
            )
            .expect("delete push notification config");
        assert_eq!(deleted["deleted"], Value::Bool(true));

        let requests = server.requests();
        assert_eq!(requests.len(), 5);
        assert!(requests[1].contains("\"method\":\"CreateTaskPushNotificationConfig\""));
        assert!(requests[2].contains("\"method\":\"GetTaskPushNotificationConfig\""));
        assert!(requests[3].contains("\"method\":\"ListTaskPushNotificationConfigs\""));
        assert!(requests[4].contains("\"method\":\"DeleteTaskPushNotificationConfig\""));
        server.join();
    }

    #[test]
    fn adapter_http_json_push_notification_config_crud_roundtrip() {
        let server = FakeA2aServer::spawn_http_json_push_notification_crud();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let created = adapter
            .invoke(
                "research",
                json!({
                    "create_push_notification_config": {
                        "task_id": "task-1",
                        "url": "https://callbacks.example.com/pact",
                        "token": "notify-token",
                        "authentication": {
                            "scheme": "bearer",
                            "credentials": "callback-secret"
                        }
                    }
                }),
                None,
            )
            .expect("create push notification config");
        assert_eq!(
            created["push_notification_config"]["authentication"]["scheme"],
            "bearer"
        );

        let fetched = adapter
            .invoke(
                "research",
                json!({
                    "get_push_notification_config": {
                        "task_id": "task-1",
                        "id": "config-1"
                    }
                }),
                None,
            )
            .expect("get push notification config");
        assert_eq!(
            fetched["push_notification_config"]["id"],
            Value::String("config-1".to_string())
        );

        let listed = adapter
            .invoke(
                "research",
                json!({
                    "list_push_notification_configs": {
                        "task_id": "task-1",
                        "page_size": 25,
                        "page_token": "page-2"
                    }
                }),
                None,
            )
            .expect("list push notification configs");
        assert_eq!(
            listed["push_notification_configs"][0]["authentication"]["credentials"],
            "callback-secret"
        );

        let deleted = adapter
            .invoke(
                "research",
                json!({
                    "delete_push_notification_config": {
                        "task_id": "task-1",
                        "id": "config-1"
                    }
                }),
                None,
            )
            .expect("delete push notification config");
        assert_eq!(deleted["deleted"], Value::Bool(true));

        let requests = server.requests();
        assert_eq!(requests.len(), 5);
        assert!(requests[1].starts_with("POST /tasks/task-1/pushNotificationConfigs HTTP/1.1"));
        assert!(
            requests[2].starts_with("GET /tasks/task-1/pushNotificationConfigs/config-1 HTTP/1.1")
        );
        assert!(requests[3].starts_with(
            "GET /tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2 HTTP/1.1"
        ));
        assert!(requests[4]
            .starts_with("DELETE /tasks/task-1/pushNotificationConfigs/config-1 HTTP/1.1"));
        server.join();
    }

    #[test]
    fn adapter_rejects_insecure_push_notification_callback_url() {
        let server = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let error = adapter
            .invoke(
                "research",
                json!({
                    "create_push_notification_config": {
                        "task_id": "task-1",
                        "url": "http://example.com/callback"
                    }
                }),
                None,
            )
            .expect_err("insecure callback URL should fail closed");
        assert!(error
            .to_string()
            .contains("push notification URL must use https"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[test]
    fn adapter_oauth2_client_credentials_fetches_token_and_caches_it() {
        let server = FakeA2aServer::spawn_jsonrpc_oauth_client_credentials_required();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_oauth_client_credentials("client-id", "client-secret")
                .with_oauth_scope("offline_access")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let first = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect("first OAuth-backed invoke");
        assert_eq!(
            first["message"]["parts"][0]["text"],
            "completed research request"
        );

        let second = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question again"
                }),
                None,
            )
            .expect("second OAuth-backed invoke");
        assert_eq!(
            second["message"]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 4);
        assert!(requests[1].starts_with("POST /oauth/token HTTP/1.1"));
        assert!(requests[1].contains("grant_type=client_credentials"));
        assert!(requests[1].contains("a2a.invoke"));
        assert!(requests[1].contains("offline_access"));
        assert!(requests[2].contains("Authorization: Bearer oauth-access-token"));
        assert!(requests[3].contains("Authorization: Bearer oauth-access-token"));
        server.join();
    }

    #[test]
    fn adapter_openid_client_credentials_fetches_discovery_and_token() {
        let server = FakeA2aServer::spawn_jsonrpc_openid_client_credentials_required();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_oauth_client_credentials("client-id", "client-secret")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect("OpenID-backed invoke");
        assert_eq!(
            result["message"]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 4);
        assert!(requests[1].starts_with("GET /openid/.well-known/openid-configuration HTTP/1.1"));
        assert!(requests[2].starts_with("POST /oauth/token HTTP/1.1"));
        assert!(requests[2].contains("grant_type=client_credentials"));
        assert!(requests[2].contains("openid"));
        assert!(requests[2].contains("profile"));
        assert!(requests[3].contains("Authorization: Bearer oidc-access-token"));
        server.join();
    }

    #[test]
    fn adapter_required_bearer_security_without_configured_token_fails_closed() {
        let server = FakeA2aServer::spawn_jsonrpc_bearer_required();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(A2aAdapterConfig::new(
            server.base_url(),
            manifest_key.public_key().to_hex(),
        ))
        .expect("discover JSONRPC adapter");

        let error = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect_err("missing bearer token should fail closed");
        assert!(error.to_string().contains("missing bearer token"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[test]
    fn adapter_http_basic_security_is_negotiated_from_agent_card() {
        let server = FakeA2aServer::spawn_http_json_basic_required();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_http_basic_auth("a2a-user", "secret-pass")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect("HTTP Basic auth should satisfy requirement");
        assert_eq!(
            result["task"]["artifacts"][0]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains(&basic_request_header_value(
            "a2a-user".to_string(),
            "secret-pass".to_string()
        )));
        server.join();
    }

    #[test]
    fn adapter_http_basic_security_without_configured_credentials_fails_closed() {
        let (security_schemes, security_requirements) =
            agent_card_security_metadata(TestScenario::BasicRequired, "http://localhost");
        let agent_card = A2aAgentCard {
            name: "Research Agent".to_string(),
            description: "Answers research questions over A2A".to_string(),
            version: "1.0.0".to_string(),
            supported_interfaces: vec![A2aAgentInterface {
                url: "http://localhost:9000".to_string(),
                protocol_binding: "HTTP+JSON".to_string(),
                protocol_version: "1.0".to_string(),
                tenant: None,
            }],
            security_schemes: Some(security_schemes),
            security_requirements: Some(security_requirements),
            capabilities: A2aAgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![A2aAgentSkill {
                id: "research".to_string(),
                name: "Research".to_string(),
                description: "Search and synthesize results".to_string(),
                tags: vec!["search".to_string()],
                examples: None,
                input_modes: None,
                output_modes: None,
                security_requirements: None,
            }],
            documentation_url: None,
            icon_url: None,
        };
        let manifest = build_manifest(
            "basic-auth-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &agent_card,
            &A2aProtocolBinding::HttpJson,
        )
        .expect("build manifest");
        let adapter = A2aAdapter {
            manifest,
            agent_card,
            agent_card_url: normalize_agent_card_url("http://localhost:9000")
                .expect("normalize agent card URL"),
            selected_interface: A2aAgentInterface {
                url: "http://localhost:9000".to_string(),
                protocol_binding: "HTTP+JSON".to_string(),
                protocol_version: "1.0".to_string(),
                tenant: None,
            },
            selected_binding: A2aProtocolBinding::HttpJson,
            configured_headers: Vec::new(),
            configured_query_params: Vec::new(),
            configured_cookies: Vec::new(),
            oauth_client_credentials: None,
            oauth_scopes: Vec::new(),
            oauth_token_endpoint_override: None,
            transport_config: A2aTransportConfig {
                default_tls_config: None,
                mutual_tls_config: None,
            },
            token_cache: Mutex::new(Vec::new()),
            timeout: Duration::from_secs(2),
            request_counter: AtomicU64::new(0),
            partner_policy: None,
            task_registry: None,
        };

        let error = adapter
            .resolve_request_auth(&adapter.agent_card.skills[0])
            .expect_err("missing HTTP Basic credentials should fail closed");
        assert!(error.to_string().contains("missing HTTP Basic credentials"));
    }

    #[test]
    fn adapter_api_key_header_security_is_negotiated_from_agent_card() {
        let server = FakeA2aServer::spawn_http_json_api_key_required();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_api_key_header("X-A2A-Key", "secret-key")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect("API key header should satisfy requirement");
        assert_eq!(
            result["task"]["artifacts"][0]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("X-A2A-Key: secret-key"));
        assert!(!requests[1].contains("Authorization: Bearer"));
        server.join();
    }

    #[test]
    fn adapter_api_key_query_security_is_negotiated_from_agent_card() {
        let server = FakeA2aServer::spawn_http_json_api_key_query_required();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_api_key_query_param("a2a_key", "secret-key")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect("API key query param should satisfy requirement");
        assert_eq!(
            result["task"]["artifacts"][0]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("POST /message:send?a2a_key=secret-key "));
        assert!(!requests[1].contains("Authorization: Bearer"));
        server.join();
    }

    #[test]
    fn adapter_api_key_cookie_security_is_negotiated_from_agent_card() {
        let server = FakeA2aServer::spawn_http_json_api_key_cookie_required();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_api_key_cookie("a2a_session", "secret-cookie")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect("API key cookie should satisfy requirement");
        assert_eq!(
            result["task"]["artifacts"][0]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("Cookie: a2a_session=secret-cookie"));
        assert!(!requests[1].contains("Authorization: Bearer"));
        server.join();
    }

    #[test]
    fn adapter_api_key_query_security_without_configured_value_fails_closed() {
        let (security_schemes, security_requirements) =
            agent_card_security_metadata(TestScenario::ApiKeyQueryRequired, "http://localhost");
        let agent_card = A2aAgentCard {
            name: "Research Agent".to_string(),
            description: "Answers research questions over A2A".to_string(),
            version: "1.0.0".to_string(),
            supported_interfaces: vec![A2aAgentInterface {
                url: "http://localhost:9000".to_string(),
                protocol_binding: "HTTP+JSON".to_string(),
                protocol_version: "1.0".to_string(),
                tenant: None,
            }],
            security_schemes: Some(security_schemes),
            security_requirements: Some(security_requirements),
            capabilities: A2aAgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![A2aAgentSkill {
                id: "research".to_string(),
                name: "Research".to_string(),
                description: "Search and synthesize results".to_string(),
                tags: vec!["search".to_string()],
                examples: None,
                input_modes: None,
                output_modes: None,
                security_requirements: None,
            }],
            documentation_url: None,
            icon_url: None,
        };
        let manifest = build_manifest(
            "query-auth-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &agent_card,
            &A2aProtocolBinding::HttpJson,
        )
        .expect("build manifest");
        let adapter = A2aAdapter {
            manifest,
            agent_card,
            agent_card_url: normalize_agent_card_url("http://localhost:9000")
                .expect("normalize agent card URL"),
            selected_interface: A2aAgentInterface {
                url: "http://localhost:9000".to_string(),
                protocol_binding: "HTTP+JSON".to_string(),
                protocol_version: "1.0".to_string(),
                tenant: None,
            },
            selected_binding: A2aProtocolBinding::HttpJson,
            configured_headers: Vec::new(),
            configured_query_params: Vec::new(),
            configured_cookies: Vec::new(),
            oauth_client_credentials: None,
            oauth_scopes: Vec::new(),
            oauth_token_endpoint_override: None,
            transport_config: A2aTransportConfig {
                default_tls_config: None,
                mutual_tls_config: None,
            },
            token_cache: Mutex::new(Vec::new()),
            timeout: Duration::from_secs(2),
            request_counter: AtomicU64::new(0),
            partner_policy: None,
            task_registry: None,
        };

        let error = adapter
            .resolve_request_auth(&adapter.agent_card.skills[0])
            .expect_err("missing API key query param should fail closed");
        assert!(error
            .to_string()
            .contains("missing API key query parameter"));
    }

    #[test]
    fn adapter_mtls_security_without_configured_identity_fails_closed() {
        let server = FakeA2aServer::spawn_jsonrpc_mtls_required();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(A2aAdapterConfig::new(
            server.base_url(),
            manifest_key.public_key().to_hex(),
        ))
        .expect("discover JSONRPC adapter");

        let error = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect_err("unsupported auth should fail closed");
        assert!(error.to_string().contains("mutual TLS"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_mtls_security_uses_client_certificate_for_discovery_and_invoke() {
        let server = FakeMtlsA2aServer::spawn_jsonrpc();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_tls_root_ca_pem(server.root_ca_pem())
                .with_mtls_client_auth_pem(
                    server.client_cert_chain_pem(),
                    server.client_private_key_pem(),
                )
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC mTLS adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "message": "answer the question"
                }),
                None,
            )
            .expect("mTLS-backed invoke");
        assert_eq!(
            result["message"]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /.well-known/agent-card.json HTTP/1.1"));
        assert!(requests[1].starts_with("POST /rpc HTTP/1.1"));
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_invocation_produces_allow_receipt() {
        let server = FakeA2aServer::spawn_jsonrpc();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();
        let expected_server_id = server_id.clone();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-a2a".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: PactScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.clone(),
                        tool_name: "research".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(5),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..PactScope::default()
                },
                issued_at: 100,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            &issuer,
        )
        .expect("sign capability");

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Summarize the current blood pressure guidance",
                    "metadata": { "origin": "kernel-test" }
                }),
                dpop_proof: None,
            })
            .expect("evaluate A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Decision::Allow);
        assert_eq!(response.receipt.body().tool_name, "research");
        assert_eq!(response.receipt.body().tool_server, expected_server_id);
        assert_eq!(
            response.output.expect("tool output").into_value()["message"]["parts"][0]["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"targetSkillId\":\"research\""));
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_query_api_key_invocation_produces_allow_receipt() {
        let server = FakeA2aServer::spawn_http_json_api_key_query_required();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_api_key_query_param("a2a_key", "secret-key")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover query-auth adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-query-auth");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-query-auth".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "answer the question"
                }),
                dpop_proof: None,
            })
            .expect("evaluate query-auth A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Decision::Allow);
        assert_eq!(
            response.output.expect("tool output").into_value()["task"]["artifacts"][0]["parts"][0]
                ["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("POST /message:send?a2a_key=secret-key "));
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_basic_auth_invocation_produces_allow_receipt() {
        let server = FakeA2aServer::spawn_http_json_basic_required();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_http_basic_auth("a2a-user", "secret-pass")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover basic-auth adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-basic-auth");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-basic-auth".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "answer the question"
                }),
                dpop_proof: None,
            })
            .expect("evaluate basic-auth A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Decision::Allow);
        assert_eq!(
            response.output.expect("tool output").into_value()["task"]["artifacts"][0]["parts"][0]
                ["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains(&basic_request_header_value(
            "a2a-user".to_string(),
            "secret-pass".to_string()
        )));
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_mtls_invocation_produces_allow_receipt() {
        let server = FakeMtlsA2aServer::spawn_jsonrpc();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_tls_root_ca_pem(server.root_ca_pem())
                .with_mtls_client_auth_pem(
                    server.client_cert_chain_pem(),
                    server.client_private_key_pem(),
                )
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover mTLS adapter");
        let server_id = adapter.server_id().to_string();
        let expected_server_id = server_id.clone();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-mtls");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-mtls".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Summarize the current blood pressure guidance"
                }),
                dpop_proof: None,
            })
            .expect("evaluate mTLS A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Decision::Allow);
        assert_eq!(response.receipt.body().tool_server, expected_server_id);
        assert_eq!(
            response.output.expect("tool output").into_value()["message"]["parts"][0]["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"targetSkillId\":\"research\""));
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_get_task_follow_up_produces_allow_receipt() {
        let server = FakeA2aServer::spawn_jsonrpc_task_follow_up();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();
        let expected_server_id = server_id.clone();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-a2a-follow-up".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: PactScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.clone(),
                        tool_name: "research".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(5),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..PactScope::default()
                },
                issued_at: 100,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            &issuer,
        )
        .expect("sign capability");

        let initial = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-start".to_string(),
                capability: capability.clone(),
                tool_name: "research".to_string(),
                server_id: server_id.clone(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Begin longer research task",
                    "return_immediately": true
                }),
                dpop_proof: None,
            })
            .expect("evaluate initial A2A tool call");
        assert_eq!(initial.verdict, Verdict::Allow);
        assert_eq!(initial.receipt.body().decision, Decision::Allow);
        assert_eq!(initial.receipt.body().tool_server, expected_server_id);
        assert_eq!(
            initial.output.expect("initial task output").into_value()["task"]["status"]["state"],
            "TASK_STATE_WORKING"
        );

        let follow_up = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-poll".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "get_task": {
                        "id": "task-1",
                        "history_length": 1
                    }
                }),
                dpop_proof: None,
            })
            .expect("evaluate follow-up A2A tool call");

        assert_eq!(follow_up.verdict, Verdict::Allow);
        assert_eq!(follow_up.receipt.body().decision, Decision::Allow);
        assert_eq!(follow_up.receipt.body().tool_name, "research");
        assert_eq!(
            follow_up
                .output
                .expect("follow-up task output")
                .into_value()["task"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[2].contains("\"method\":\"GetTask\""));
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_cancel_task_produces_allow_receipt() {
        let server = FakeA2aServer::spawn_jsonrpc_cancel_task();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-cancel");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-cancel".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "cancel_task": {
                        "id": "task-1",
                        "metadata": { "reason": "user-request" }
                    }
                }),
                dpop_proof: None,
            })
            .expect("evaluate cancel-task A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Decision::Allow);
        assert_eq!(
            response.output.expect("cancel task output").into_value()["task"]["status"]["state"],
            "TASK_STATE_CANCELED"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"CancelTask\""));
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_streaming_invocation_produces_allow_receipt() {
        let server = FakeA2aServer::spawn_jsonrpc_streaming_complete();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-stream");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-stream".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                dpop_proof: None,
            })
            .expect("evaluate streaming A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Decision::Allow);
        let stream = response.output.expect("stream output").into_stream();
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_incomplete_streaming_invocation_produces_incomplete_receipt() {
        let server = FakeA2aServer::spawn_jsonrpc_streaming_incomplete();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability =
            test_capability(&issuer, &subject, &server_id, "cap-a2a-stream-incomplete");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-stream-incomplete".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                dpop_proof: None,
            })
            .expect("evaluate incomplete streaming A2A tool call");

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(matches!(
            response.receipt.body().decision,
            Decision::Incomplete { .. }
        ));
        let stream = response
            .output
            .expect("partial stream output")
            .into_stream();
        assert_eq!(stream.chunk_count(), 2);
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_subscribe_task_produces_allow_receipt() {
        let server = FakeA2aServer::spawn_jsonrpc_subscribe_complete();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-subscribe");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-subscribe".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                dpop_proof: None,
            })
            .expect("evaluate subscribe-to-task A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Decision::Allow);
        let stream = response.output.expect("stream output").into_stream();
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );
        server.join();
    }

    #[test]
    fn kernel_e2e_a2a_incomplete_subscribe_task_produces_incomplete_receipt() {
        let server = FakeA2aServer::spawn_jsonrpc_subscribe_incomplete();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(
            &issuer,
            &subject,
            &server_id,
            "cap-a2a-subscribe-incomplete",
        );
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-subscribe-incomplete".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                dpop_proof: None,
            })
            .expect("evaluate incomplete subscribe-to-task A2A tool call");

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(matches!(
            response.receipt.body().decision,
            Decision::Incomplete { .. }
        ));
        let stream = response
            .output
            .expect("partial stream output")
            .into_stream();
        assert_eq!(stream.chunk_count(), 2);
        server.join();
    }

    #[test]
    fn kernel_e2e_missing_required_bearer_security_denies_request() {
        let server = FakeA2aServer::spawn_jsonrpc_bearer_required();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(A2aAdapterConfig::new(
            server.base_url(),
            manifest_key.public_key().to_hex(),
        ))
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-auth-deny");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-auth-deny".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "answer the question"
                }),
                dpop_proof: None,
            })
            .expect("evaluate A2A tool call");

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("missing bearer token"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[test]
    fn kernel_e2e_oauth_client_credentials_allows_request() {
        let server = FakeA2aServer::spawn_jsonrpc_oauth_client_credentials_single_invoke();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_oauth_client_credentials("client-id", "client-secret")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = PactKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-oauth");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-oauth".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "answer the question"
                }),
                dpop_proof: None,
            })
            .expect("evaluate OAuth-backed A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Decision::Allow);
        assert_eq!(
            response.output.expect("tool output").into_value()["message"]["parts"][0]["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].starts_with("POST /oauth/token HTTP/1.1"));
        assert!(requests[2].contains("Authorization: Bearer oauth-access-token"));
        server.join();
    }

    #[derive(Clone, Copy)]
    enum TestBinding {
        JsonRpc,
        HttpJson,
    }

    #[derive(Clone, Copy)]
    enum TestScenario {
        BlockingMessage,
        TaskFollowUp,
        CancelTask,
        PushNotificationCrud,
        PushNotificationCapabilityOnly,
        OAuthClientCredentialsRequired,
        OAuthClientCredentialsSingleInvoke,
        OpenIdClientCredentialsRequired,
        StreamingComplete,
        StreamingIncomplete,
        SubscribeComplete,
        SubscribeIncomplete,
        BearerRequired,
        BasicRequired,
        ApiKeyRequired,
        ApiKeyQueryRequired,
        ApiKeyCookieRequired,
        MutualTlsRequired,
    }

    enum TestResponse {
        Json(Value),
        EventStream(String),
    }

    struct FakeA2aServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        handle: thread::JoinHandle<()>,
    }

    impl FakeA2aServer {
        fn spawn_jsonrpc() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::BlockingMessage)
        }

        fn spawn_jsonrpc_task_follow_up() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::TaskFollowUp)
        }

        fn spawn_http_json() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::BlockingMessage)
        }

        fn spawn_http_json_task_follow_up() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::TaskFollowUp)
        }

        fn spawn_jsonrpc_cancel_task() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::CancelTask)
        }

        fn spawn_http_json_cancel_task() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::CancelTask)
        }

        fn spawn_jsonrpc_push_notification_crud() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::PushNotificationCrud)
        }

        fn spawn_http_json_push_notification_crud() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::PushNotificationCrud)
        }

        fn spawn_jsonrpc_push_notification_capability_only() -> Self {
            Self::spawn(
                TestBinding::JsonRpc,
                TestScenario::PushNotificationCapabilityOnly,
            )
        }

        fn spawn_jsonrpc_oauth_client_credentials_required() -> Self {
            Self::spawn(
                TestBinding::JsonRpc,
                TestScenario::OAuthClientCredentialsRequired,
            )
        }

        fn spawn_jsonrpc_oauth_client_credentials_single_invoke() -> Self {
            Self::spawn(
                TestBinding::JsonRpc,
                TestScenario::OAuthClientCredentialsSingleInvoke,
            )
        }

        fn spawn_jsonrpc_openid_client_credentials_required() -> Self {
            Self::spawn(
                TestBinding::JsonRpc,
                TestScenario::OpenIdClientCredentialsRequired,
            )
        }

        fn spawn_jsonrpc_streaming_complete() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::StreamingComplete)
        }

        fn spawn_http_json_streaming_complete() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::StreamingComplete)
        }

        fn spawn_jsonrpc_streaming_incomplete() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::StreamingIncomplete)
        }

        fn spawn_jsonrpc_subscribe_complete() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::SubscribeComplete)
        }

        fn spawn_http_json_subscribe_complete() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::SubscribeComplete)
        }

        fn spawn_jsonrpc_subscribe_incomplete() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::SubscribeIncomplete)
        }

        fn spawn_jsonrpc_bearer_required() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::BearerRequired)
        }

        fn spawn_http_json_basic_required() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::BasicRequired)
        }

        fn spawn_http_json_api_key_required() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyRequired)
        }

        fn spawn_http_json_api_key_query_required() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyQueryRequired)
        }

        fn spawn_http_json_api_key_cookie_required() -> Self {
            Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyCookieRequired)
        }

        fn spawn_jsonrpc_mtls_required() -> Self {
            Self::spawn(TestBinding::JsonRpc, TestScenario::MutualTlsRequired)
        }

        fn spawn(binding: TestBinding, scenario: TestScenario) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake A2A listener");
            let address = listener.local_addr().expect("listener address");
            let base_url = format!("http://{address}");
            let base_url_for_thread = base_url.clone();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);
            let (ready_tx, ready_rx) = mpsc::channel();

            let handle = thread::spawn(move || {
                ready_tx.send(()).expect("server ready");
                let expected_requests = match scenario {
                    TestScenario::BlockingMessage => 2,
                    TestScenario::TaskFollowUp => 3,
                    TestScenario::CancelTask => 2,
                    TestScenario::PushNotificationCrud => 5,
                    TestScenario::PushNotificationCapabilityOnly => 1,
                    TestScenario::OAuthClientCredentialsRequired => 4,
                    TestScenario::OAuthClientCredentialsSingleInvoke => 3,
                    TestScenario::OpenIdClientCredentialsRequired => 4,
                    TestScenario::StreamingComplete
                    | TestScenario::StreamingIncomplete
                    | TestScenario::SubscribeComplete
                    | TestScenario::SubscribeIncomplete
                    | TestScenario::BasicRequired
                    | TestScenario::ApiKeyRequired
                    | TestScenario::ApiKeyQueryRequired
                    | TestScenario::ApiKeyCookieRequired => 2,
                    TestScenario::BearerRequired | TestScenario::MutualTlsRequired => 1,
                };
                for _ in 0..expected_requests {
                    let (mut stream, _) = listener.accept().expect("accept request");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("set read timeout");
                    let request = read_http_request(&mut stream);
                    requests_for_thread
                        .lock()
                        .expect("lock request log")
                        .push(request.clone());
                    let first_line = request.lines().next().unwrap_or_default();
                    let response_body = if first_line
                        .starts_with("GET /.well-known/agent-card.json")
                    {
                        let interface = match binding {
                            TestBinding::JsonRpc => json!([{
                                "url": format!("{base_url_for_thread}/rpc"),
                                "protocolBinding": "JSONRPC",
                                "protocolVersion": "1.0"
                            }]),
                            TestBinding::HttpJson => json!([{
                                "url": base_url_for_thread,
                                "protocolBinding": "HTTP+JSON",
                                "protocolVersion": "1.0"
                            }]),
                        };
                        let (security_schemes, security_requirements) =
                            agent_card_security_metadata(scenario, &base_url_for_thread);
                        json!({
                                "name": "Research Agent",
                                "description": "Answers research questions over A2A",
                                "supportedInterfaces": interface,
                                "version": "1.0.0",
                                "capabilities": {
                                    "streaming": matches!(scenario, TestScenario::StreamingComplete | TestScenario::StreamingIncomplete | TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete),
                                    "pushNotifications": matches!(scenario, TestScenario::PushNotificationCrud | TestScenario::PushNotificationCapabilityOnly),
                                    "stateTransitionHistory": matches!(scenario, TestScenario::BlockingMessage | TestScenario::TaskFollowUp)
                                },
                                "defaultInputModes": ["text/plain", "application/json"],
                                "defaultOutputModes": ["application/json"],
                                "skills": [{
                                    "id": "research",
                                    "name": "Research",
                                    "description": "Search and synthesize results",
                                    "tags": ["search", "synthesis"],
                                    "examples": ["Summarize recent cardiology evidence"],
                                    "inputModes": ["text/plain", "application/json"],
                                    "outputModes": ["application/json"]
                                }],
                                "securitySchemes": security_schemes,
                                "securityRequirements": security_requirements
                            })
                            .into()
                    } else if first_line.starts_with("POST /rpc") {
                        response_for_jsonrpc(&request, scenario)
                    } else if first_line.starts_with("GET /openid/.well-known/openid-configuration")
                    {
                        response_for_openid_configuration(&request, scenario, &base_url_for_thread)
                    } else if first_line.starts_with("POST /oauth/token") {
                        response_for_oauth_token(&request, scenario)
                    } else if first_line.starts_with("POST /tasks/")
                        && first_line.contains(":cancel ")
                    {
                        response_for_http_cancel_task(&request, scenario)
                    } else if first_line.starts_with("POST /tasks/")
                        && first_line.contains("/pushNotificationConfigs ")
                    {
                        response_for_http_create_push_notification_config(&request, scenario)
                    } else if first_line.starts_with("POST /message:stream") {
                        response_for_http_stream(&request, scenario)
                    } else if first_line.starts_with("GET /tasks/")
                        && first_line.contains(":subscribe ")
                    {
                        response_for_http_subscribe(&request, scenario)
                    } else if first_line.starts_with("GET /tasks/")
                        && first_line.contains("/pushNotificationConfigs/")
                    {
                        response_for_http_get_push_notification_config(&request, scenario)
                    } else if first_line.starts_with("GET /tasks/")
                        && first_line.contains("/pushNotificationConfigs")
                    {
                        response_for_http_list_push_notification_configs(&request, scenario)
                    } else if first_line.starts_with("POST /message:send") {
                        response_for_http_send(&request, scenario)
                    } else if first_line.starts_with("DELETE /tasks/")
                        && first_line.contains("/pushNotificationConfigs/")
                    {
                        response_for_http_delete_push_notification_config(&request, scenario)
                    } else if first_line.starts_with("GET /tasks/") {
                        response_for_http_get_task(&request, scenario)
                    } else {
                        json!({
                            "error": format!("unexpected request: {first_line}")
                        })
                        .into()
                    };
                    match response_body {
                        TestResponse::Json(body) => {
                            write_http_json_response(&mut stream, 200, &body)
                        }
                        TestResponse::EventStream(body) => {
                            write_http_event_stream_response(&mut stream, 200, &body)
                        }
                    }
                }
            });

            ready_rx.recv().expect("server should start");
            Self {
                base_url,
                requests,
                handle,
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().expect("lock requests").clone()
        }

        fn join(self) {
            self.handle.join().expect("join fake A2A server");
        }
    }

    struct MtlsTestMaterials {
        root_ca_pem: String,
        client_cert_chain_pem: String,
        client_private_key_pem: String,
        server_cert_chain_pem: String,
        server_private_key_pem: String,
    }

    struct FakeMtlsA2aServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        root_ca_pem: String,
        client_cert_chain_pem: String,
        client_private_key_pem: String,
        handle: thread::JoinHandle<()>,
    }

    impl FakeMtlsA2aServer {
        fn spawn_jsonrpc() -> Self {
            let materials = generate_mtls_test_materials();
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake mTLS A2A listener");
            let address = listener.local_addr().expect("listener address");
            let base_url = format!("https://localhost:{}", address.port());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);
            let server_tls_config = build_test_server_tls_config(&materials);
            let base_url_for_thread = base_url.clone();
            let (ready_tx, ready_rx) = mpsc::channel();

            let handle = thread::spawn(move || {
                ready_tx.send(()).expect("server ready");
                for _ in 0..2 {
                    let (tcp_stream, _) = listener.accept().expect("accept request");
                    tcp_stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("set read timeout");
                    let connection =
                        ureq::rustls::ServerConnection::new(Arc::clone(&server_tls_config))
                            .expect("create rustls server connection");
                    let mut stream = ureq::rustls::StreamOwned::new(connection, tcp_stream);
                    let request = read_http_request(&mut stream);
                    requests_for_thread
                        .lock()
                        .expect("lock request log")
                        .push(request.clone());
                    let first_line = request.lines().next().unwrap_or_default();
                    let response = if first_line.starts_with("GET /.well-known/agent-card.json") {
                        mtls_agent_card_payload(&base_url_for_thread)
                    } else if first_line.starts_with("POST /rpc") {
                        assert!(request.contains("\"method\":\"SendMessage\""));
                        assert!(request.contains("\"targetSkillId\":\"research\""));
                        assert!(!request.contains("Authorization: Bearer"));
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": {
                                "message": {
                                    "messageId": "msg-out",
                                    "contextId": "ctx-1",
                                    "taskId": "task-1",
                                    "role": "ROLE_AGENT",
                                    "parts": [{
                                        "text": "completed research request",
                                        "mediaType": "text/plain"
                                    }]
                                }
                            }
                        })
                    } else {
                        json!({
                            "error": format!("unexpected request: {first_line}")
                        })
                    };
                    write_http_json_response(&mut stream, 200, &response);
                    stream.flush().expect("flush response");
                }
            });

            ready_rx.recv().expect("server should start");
            Self {
                base_url,
                requests,
                root_ca_pem: materials.root_ca_pem,
                client_cert_chain_pem: materials.client_cert_chain_pem,
                client_private_key_pem: materials.client_private_key_pem,
                handle,
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn root_ca_pem(&self) -> &str {
            &self.root_ca_pem
        }

        fn client_cert_chain_pem(&self) -> &str {
            &self.client_cert_chain_pem
        }

        fn client_private_key_pem(&self) -> &str {
            &self.client_private_key_pem
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().expect("lock requests").clone()
        }

        fn join(self) {
            self.handle.join().expect("join fake mTLS A2A server");
        }
    }

    fn generate_mtls_test_materials() -> MtlsTestMaterials {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "PACT Test Root CA");
        let ca_key_pair = RcgenKeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params
            .self_signed(&ca_key_pair)
            .expect("self-sign CA certificate");

        let mut server_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
        server_params.distinguished_name = DistinguishedName::new();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key_pair = RcgenKeyPair::generate().expect("generate server key");
        let server_cert = server_params
            .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
            .expect("sign server certificate");

        let mut client_params =
            CertificateParams::new(Vec::<String>::new()).expect("client params");
        client_params.distinguished_name = DistinguishedName::new();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "PACT Test Client");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key_pair = RcgenKeyPair::generate().expect("generate client key");
        let client_cert = client_params
            .signed_by(&client_key_pair, &ca_cert, &ca_key_pair)
            .expect("sign client certificate");

        let root_ca_pem = ca_cert.pem();
        MtlsTestMaterials {
            root_ca_pem: root_ca_pem.clone(),
            client_cert_chain_pem: format!("{}{}", client_cert.pem(), root_ca_pem.clone()),
            client_private_key_pem: client_key_pair.serialize_pem(),
            server_cert_chain_pem: format!("{}{}", server_cert.pem(), root_ca_pem),
            server_private_key_pem: server_key_pair.serialize_pem(),
        }
    }

    fn build_test_server_tls_config(
        materials: &MtlsTestMaterials,
    ) -> Arc<ureq::rustls::ServerConfig> {
        let mut client_root_store = ureq::rustls::RootCertStore::empty();
        for certificate in
            parse_pem_certificates(materials.root_ca_pem.as_str(), "mTLS test root CA")
                .expect("parse test root CA")
        {
            client_root_store
                .add(certificate)
                .expect("add test root CA to verifier store");
        }
        let verifier =
            ureq::rustls::server::WebPkiClientVerifier::builder(Arc::new(client_root_store))
                .build()
                .expect("build client cert verifier");
        let server_cert_chain = parse_pem_certificates(
            materials.server_cert_chain_pem.as_str(),
            "mTLS test server certificate chain",
        )
        .expect("parse server certificate chain");
        let server_private_key = parse_pem_private_key(
            materials.server_private_key_pem.as_str(),
            "mTLS test server private key",
        )
        .expect("parse server private key");
        Arc::new(
            ureq::rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(server_cert_chain, server_private_key)
                .expect("build test mTLS server config"),
        )
    }

    fn mtls_agent_card_payload(base_url: &str) -> Value {
        json!({
            "name": "Research Agent",
            "description": "Answers research questions over A2A",
            "supportedInterfaces": [{
                "url": format!("{base_url}/rpc"),
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0"
            }],
            "version": "1.0.0",
            "capabilities": {
                "streaming": false,
                "pushNotifications": false
            },
            "defaultInputModes": ["text/plain", "application/json"],
            "defaultOutputModes": ["application/json"],
            "skills": [{
                "id": "research",
                "name": "Research",
                "description": "Search and synthesize results",
                "tags": ["search", "synthesis"],
                "examples": ["Summarize recent cardiology evidence"],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"]
            }],
            "securitySchemes": {
                "mtlsAuth": {
                    "mtlsSecurityScheme": {}
                }
            },
            "securityRequirements": [{
                "schemes": {
                    "mtlsAuth": []
                }
            }]
        })
    }

    fn read_http_request<R: Read>(stream: &mut R) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut chunk).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = find_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_content_length(&request[..end]);
                }
            }
            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn write_http_json_response<W: Write>(stream: &mut W, status: u16, body: &Value) {
        let body_text = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_text(status),
            body_text.len(),
            body_text
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    }

    fn write_http_event_stream_response<W: Write>(stream: &mut W, status: u16, body: &str) {
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_text(status),
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            400 => "Bad Request",
            _ => "Error",
        }
    }

    fn response_for_jsonrpc(request: &str, scenario: TestScenario) -> TestResponse {
        if request.contains("\"method\":\"SendMessage\"") {
            assert!(request.contains("\"targetSkillId\":\"research\""));
            match scenario {
                TestScenario::BlockingMessage | TestScenario::BearerRequired => {
                    if matches!(scenario, TestScenario::BearerRequired) {
                        assert!(request.contains("Authorization: Bearer secret-token"));
                    }
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "message": {
                                "messageId": "msg-out",
                                "contextId": "ctx-1",
                                "taskId": "task-1",
                                "role": "ROLE_AGENT",
                                "parts": [{
                                    "text": "completed research request",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    })
                    .into()
                }
                TestScenario::OAuthClientCredentialsRequired
                | TestScenario::OAuthClientCredentialsSingleInvoke => {
                    assert!(request.contains("Authorization: Bearer oauth-access-token"));
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "message": {
                                "messageId": "msg-out",
                                "contextId": "ctx-1",
                                "taskId": "task-1",
                                "role": "ROLE_AGENT",
                                "parts": [{
                                    "text": "completed research request",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    })
                    .into()
                }
                TestScenario::OpenIdClientCredentialsRequired => {
                    assert!(request.contains("Authorization: Bearer oidc-access-token"));
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "message": {
                                "messageId": "msg-out",
                                "contextId": "ctx-1",
                                "taskId": "task-1",
                                "role": "ROLE_AGENT",
                                "parts": [{
                                    "text": "completed research request",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    })
                    .into()
                }
                TestScenario::TaskFollowUp => {
                    assert!(request.contains("\"returnImmediately\":true"));
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "task": task_payload("TASK_STATE_WORKING", false)
                        }
                    })
                    .into()
                }
                TestScenario::CancelTask
                | TestScenario::PushNotificationCrud
                | TestScenario::PushNotificationCapabilityOnly => {
                    panic!("unexpected SendMessage for task-management scenario")
                }
                TestScenario::StreamingComplete
                | TestScenario::StreamingIncomplete
                | TestScenario::SubscribeComplete
                | TestScenario::SubscribeIncomplete
                | TestScenario::BasicRequired
                | TestScenario::MutualTlsRequired
                | TestScenario::ApiKeyRequired
                | TestScenario::ApiKeyQueryRequired
                | TestScenario::ApiKeyCookieRequired => {
                    panic!("unexpected SendMessage for streaming scenario")
                }
            }
        } else if request.contains("\"method\":\"SendStreamingMessage\"") {
            assert!(matches!(
                scenario,
                TestScenario::StreamingComplete | TestScenario::StreamingIncomplete
            ));
            TestResponse::EventStream(jsonrpc_stream_body(scenario))
        } else if request.contains("\"method\":\"SubscribeToTask\"") {
            assert!(matches!(
                scenario,
                TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete
            ));
            assert!(request.contains("\"id\":\"task-1\""));
            TestResponse::EventStream(jsonrpc_stream_body(scenario))
        } else if request.contains("\"method\":\"GetTask\"") {
            assert!(matches!(scenario, TestScenario::TaskFollowUp));
            assert!(request.contains("\"id\":\"task-1\""));
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": task_payload("TASK_STATE_COMPLETED", true)
            })
            .into()
        } else if request.contains("\"method\":\"CancelTask\"") {
            assert!(matches!(scenario, TestScenario::CancelTask));
            assert!(request.contains("\"id\":\"task-1\""));
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": task_payload("TASK_STATE_CANCELED", false)
            })
            .into()
        } else if request.contains("\"method\":\"CreateTaskPushNotificationConfig\"") {
            assert!(matches!(scenario, TestScenario::PushNotificationCrud));
            assert!(request.contains("\"taskId\":\"task-1\""));
            assert!(request.contains("\"url\":\"https://callbacks.example.com/pact\""));
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "result": push_notification_config_payload()
            })
            .into()
        } else if request.contains("\"method\":\"GetTaskPushNotificationConfig\"") {
            assert!(matches!(scenario, TestScenario::PushNotificationCrud));
            assert!(request.contains("\"taskId\":\"task-1\""));
            assert!(request.contains("\"id\":\"config-1\""));
            json!({
                "jsonrpc": "2.0",
                "id": 5,
                "result": push_notification_config_payload()
            })
            .into()
        } else if request.contains("\"method\":\"ListTaskPushNotificationConfigs\"") {
            assert!(matches!(scenario, TestScenario::PushNotificationCrud));
            assert!(request.contains("\"taskId\":\"task-1\""));
            assert!(request.contains("\"pageSize\":25"));
            assert!(request.contains("\"pageToken\":\"page-2\""));
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "result": {
                    "configs": [push_notification_config_payload()],
                    "nextPageToken": "next-page"
                }
            })
            .into()
        } else if request.contains("\"method\":\"DeleteTaskPushNotificationConfig\"") {
            assert!(matches!(scenario, TestScenario::PushNotificationCrud));
            assert!(request.contains("\"taskId\":\"task-1\""));
            assert!(request.contains("\"id\":\"config-1\""));
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "result": {}
            })
            .into()
        } else {
            json!({
                "jsonrpc": "2.0",
                "id": 99,
                "error": {
                    "code": -32601,
                    "message": "unexpected method"
                }
            })
            .into()
        }
    }

    fn response_for_http_send(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(request.contains("\"targetSkillId\":\"research\""));
        match scenario {
            TestScenario::BlockingMessage => json!({
                "task": task_payload("TASK_STATE_COMPLETED", true)
            }),
            TestScenario::BasicRequired => {
                assert!(request.contains("Authorization: Basic "));
                assert!(!request.contains("Authorization: Bearer"));
                json!({
                    "task": task_payload("TASK_STATE_COMPLETED", true)
                })
            }
            TestScenario::ApiKeyRequired => {
                assert!(request.contains("X-A2A-Key: secret-key"));
                assert!(!request.contains("Authorization: Bearer"));
                json!({
                    "task": task_payload("TASK_STATE_COMPLETED", true)
                })
            }
            TestScenario::ApiKeyQueryRequired => {
                assert!(request.starts_with("POST /message:send?a2a_key=secret-key "));
                assert!(!request.contains("Authorization: Bearer"));
                json!({
                    "task": task_payload("TASK_STATE_COMPLETED", true)
                })
            }
            TestScenario::ApiKeyCookieRequired => {
                assert!(request.contains("Cookie: a2a_session=secret-cookie"));
                assert!(!request.contains("Authorization: Bearer"));
                json!({
                    "task": task_payload("TASK_STATE_COMPLETED", true)
                })
            }
            TestScenario::TaskFollowUp => {
                assert!(request.contains("\"returnImmediately\":true"));
                json!({
                    "task": task_payload("TASK_STATE_WORKING", false)
                })
            }
            TestScenario::CancelTask
            | TestScenario::PushNotificationCrud
            | TestScenario::PushNotificationCapabilityOnly => {
                panic!("unexpected blocking send for task-management scenario")
            }
            TestScenario::OAuthClientCredentialsRequired
            | TestScenario::OAuthClientCredentialsSingleInvoke
            | TestScenario::OpenIdClientCredentialsRequired => {
                panic!("unexpected blocking send for OAuth/OpenID scenario")
            }
            TestScenario::StreamingComplete
            | TestScenario::StreamingIncomplete
            | TestScenario::SubscribeComplete
            | TestScenario::SubscribeIncomplete
            | TestScenario::BearerRequired
            | TestScenario::MutualTlsRequired => {
                panic!("unexpected blocking send for streaming scenario")
            }
        }
        .into()
    }

    fn response_for_http_stream(_request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(
            scenario,
            TestScenario::StreamingComplete | TestScenario::StreamingIncomplete
        ));
        TestResponse::EventStream(http_stream_body(scenario))
    }

    fn response_for_http_subscribe(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(
            scenario,
            TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete
        ));
        assert!(request.starts_with("GET /tasks/task-1:subscribe"));
        TestResponse::EventStream(http_stream_body(scenario))
    }

    fn response_for_http_get_task(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(scenario, TestScenario::TaskFollowUp));
        assert!(request.starts_with("GET /tasks/task-1"));
        json!(task_payload("TASK_STATE_COMPLETED", true)).into()
    }

    fn response_for_http_cancel_task(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(scenario, TestScenario::CancelTask));
        assert!(request.starts_with("POST /tasks/task-1:cancel"));
        assert!(request.contains("\"reason\":\"user-request\""));
        json!(task_payload("TASK_STATE_CANCELED", false)).into()
    }

    fn response_for_http_create_push_notification_config(
        request: &str,
        scenario: TestScenario,
    ) -> TestResponse {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.starts_with("POST /tasks/task-1/pushNotificationConfigs"));
        assert!(request.contains("\"url\":\"https://callbacks.example.com/pact\""));
        json!(push_notification_config_payload()).into()
    }

    fn response_for_http_get_push_notification_config(
        request: &str,
        scenario: TestScenario,
    ) -> TestResponse {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.starts_with("GET /tasks/task-1/pushNotificationConfigs/config-1"));
        json!(push_notification_config_payload()).into()
    }

    fn response_for_http_list_push_notification_configs(
        request: &str,
        scenario: TestScenario,
    ) -> TestResponse {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request
            .starts_with("GET /tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2"));
        json!({
            "configs": [push_notification_config_payload()],
            "nextPageToken": "next-page"
        })
        .into()
    }

    fn response_for_http_delete_push_notification_config(
        request: &str,
        scenario: TestScenario,
    ) -> TestResponse {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.starts_with("DELETE /tasks/task-1/pushNotificationConfigs/config-1"));
        json!({}).into()
    }

    fn response_for_openid_configuration(
        request: &str,
        scenario: TestScenario,
        base_url: &str,
    ) -> TestResponse {
        assert!(matches!(
            scenario,
            TestScenario::OpenIdClientCredentialsRequired
        ));
        assert!(request.starts_with("GET /openid/.well-known/openid-configuration"));
        json!({
            "token_endpoint": format!("{base_url}/oauth/token")
        })
        .into()
    }

    fn response_for_oauth_token(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(
            scenario,
            TestScenario::OAuthClientCredentialsRequired
                | TestScenario::OAuthClientCredentialsSingleInvoke
                | TestScenario::OpenIdClientCredentialsRequired
        ));
        assert!(request.starts_with("POST /oauth/token"));
        assert!(request.contains("grant_type=client_credentials"));
        assert!(
            request.contains("Authorization: Basic")
                || (request.contains("client_id=client-id")
                    && request.contains("client_secret=client-secret"))
        );
        match scenario {
            TestScenario::OAuthClientCredentialsRequired
            | TestScenario::OAuthClientCredentialsSingleInvoke => {
                assert!(request.contains("a2a.invoke"));
                json!({
                    "access_token": "oauth-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })
                .into()
            }
            TestScenario::OpenIdClientCredentialsRequired => {
                assert!(request.contains("openid"));
                assert!(request.contains("profile"));
                json!({
                    "access_token": "oidc-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })
                .into()
            }
            _ => unreachable!("unexpected token response scenario"),
        }
    }

    fn agent_card_security_metadata(scenario: TestScenario, base_url: &str) -> (Value, Value) {
        match scenario {
            TestScenario::BearerRequired => (
                json!({
                    "bearerAuth": {
                        "httpAuthSecurityScheme": {
                            "scheme": "bearer"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "bearerAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::BasicRequired => (
                json!({
                    "basicAuth": {
                        "httpAuthSecurityScheme": {
                            "scheme": "basic"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "basicAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::ApiKeyRequired => (
                json!({
                    "apiKeyAuth": {
                        "apiKeySecurityScheme": {
                            "name": "X-A2A-Key",
                            "location": "header"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "apiKeyAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::ApiKeyQueryRequired => (
                json!({
                    "apiKeyAuth": {
                        "apiKeySecurityScheme": {
                            "name": "a2a_key",
                            "location": "query"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "apiKeyAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::ApiKeyCookieRequired => (
                json!({
                    "apiKeyAuth": {
                        "apiKeySecurityScheme": {
                            "name": "a2a_session",
                            "location": "cookie"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "apiKeyAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::OAuthClientCredentialsRequired
            | TestScenario::OAuthClientCredentialsSingleInvoke => (
                json!({
                    "oauthAuth": {
                        "oauth2SecurityScheme": {
                            "flows": {
                                "clientCredentials": {
                                    "tokenUrl": format!("{base_url}/oauth/token")
                                }
                            }
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "oauthAuth": ["a2a.invoke"]
                        }
                    }
                ]),
            ),
            TestScenario::OpenIdClientCredentialsRequired => (
                json!({
                    "oidcAuth": {
                        "openIdConnectSecurityScheme": {
                            "openIdConnectUrl": format!("{base_url}/openid/.well-known/openid-configuration")
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "oidcAuth": ["openid", "profile"]
                        }
                    }
                ]),
            ),
            TestScenario::MutualTlsRequired => (
                json!({
                    "mtlsAuth": {
                        "mtlsSecurityScheme": {}
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "mtlsAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::BlockingMessage
            | TestScenario::TaskFollowUp
            | TestScenario::CancelTask
            | TestScenario::PushNotificationCrud
            | TestScenario::PushNotificationCapabilityOnly
            | TestScenario::StreamingComplete
            | TestScenario::StreamingIncomplete
            | TestScenario::SubscribeComplete
            | TestScenario::SubscribeIncomplete => (Value::Null, Value::Null),
        }
    }

    fn task_payload(state: &str, include_artifacts: bool) -> Value {
        let mut task = json!({
            "id": "task-1",
            "contextId": "ctx-1",
            "status": {
                "state": state
            },
            "createdAt": "2026-03-24T00:00:00.000Z",
            "lastModified": "2026-03-24T00:00:01.000Z"
        });
        if include_artifacts {
            task["artifacts"] = json!([{
                "artifactId": "artifact-1",
                "parts": [{
                    "text": "completed research request",
                    "mediaType": "text/plain"
                }]
            }]);
        }
        task
    }

    fn push_notification_config_payload() -> Value {
        json!({
            "id": "config-1",
            "taskId": "task-1",
            "url": "https://callbacks.example.com/pact",
            "token": "notify-token",
            "authentication": {
                "scheme": "bearer",
                "credentials": "callback-secret"
            }
        })
    }

    fn jsonrpc_stream_body(scenario: TestScenario) -> String {
        sse_body(match scenario {
            TestScenario::StreamingComplete | TestScenario::SubscribeComplete => vec![
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "task": task_payload("TASK_STATE_WORKING", false) }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "artifactUpdate": {
                            "taskId": "task-1",
                            "artifact": {
                                "artifactId": "artifact-1",
                                "parts": [{
                                    "text": "partial research result",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "statusUpdate": {
                            "taskId": "task-1",
                            "status": { "state": "TASK_STATE_COMPLETED" }
                        }
                    }
                }),
            ],
            TestScenario::StreamingIncomplete | TestScenario::SubscribeIncomplete => vec![
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "task": task_payload("TASK_STATE_WORKING", false) }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "artifactUpdate": {
                            "taskId": "task-1",
                            "artifact": {
                                "artifactId": "artifact-1",
                                "parts": [{
                                    "text": "partial research result",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    }
                }),
            ],
            _ => panic!("unexpected streaming scenario"),
        })
    }

    fn http_stream_body(scenario: TestScenario) -> String {
        sse_body(match scenario {
            TestScenario::StreamingComplete | TestScenario::SubscribeComplete => vec![
                json!({ "task": task_payload("TASK_STATE_WORKING", false) }),
                json!({
                    "artifactUpdate": {
                        "taskId": "task-1",
                        "artifact": {
                            "artifactId": "artifact-1",
                            "parts": [{
                                "text": "partial research result",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                }),
                json!({
                    "statusUpdate": {
                        "taskId": "task-1",
                        "status": { "state": "TASK_STATE_COMPLETED" }
                    }
                }),
            ],
            TestScenario::StreamingIncomplete | TestScenario::SubscribeIncomplete => vec![
                json!({ "task": task_payload("TASK_STATE_WORKING", false) }),
                json!({
                    "artifactUpdate": {
                        "taskId": "task-1",
                        "artifact": {
                            "artifactId": "artifact-1",
                            "parts": [{
                                "text": "partial research result",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                }),
            ],
            _ => panic!("unexpected streaming scenario"),
        })
    }

    fn sse_body(events: Vec<Value>) -> String {
        events
            .into_iter()
            .map(|event| format!("data: {}\n\n", event))
            .collect()
    }

    fn test_capability(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        capability_id: &str,
    ) -> CapabilityToken {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: capability_id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: PactScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: "research".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(5),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..PactScope::default()
                },
                issued_at: 100,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            issuer,
        )
        .expect("sign capability")
    }

    impl From<Value> for TestResponse {
        fn from(value: Value) -> Self {
            Self::Json(value)
        }
    }

    trait ToolCallOutputExt {
        fn into_value(self) -> Value;
        fn into_stream(self) -> ToolCallStream;
    }

    impl ToolCallOutputExt for pact_kernel::ToolCallOutput {
        fn into_value(self) -> Value {
            match self {
                pact_kernel::ToolCallOutput::Value(value) => value,
                pact_kernel::ToolCallOutput::Stream(_) => panic!("expected value output"),
            }
        }

        fn into_stream(self) -> ToolCallStream {
            match self {
                pact_kernel::ToolCallOutput::Value(_) => panic!("expected stream output"),
                pact_kernel::ToolCallOutput::Stream(stream) => stream,
            }
        }
    }
}
