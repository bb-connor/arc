//! Host-only issuance, durably bound to a worker's original logical invocation.
use super::*;
use chio_core_types::{canonical_json_bytes, sha256_hex, SigningBackend};
use chio_process::{
    worker::{InvocationPreparer, PreparationRequest},
    ProcessError, ProcessRuntime,
};
use chio_secret_broker::{
    capability::issue_capability,
    proof::{body_digest, issue_request_proof},
    protocol::*,
};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparationConfig {
    pub issuer_seed_file: PathBuf,
    pub credential: CredentialRef,
    pub destination: BrokerDestination,
    pub maximum_body_bytes: u64,
    pub response_limit_bytes: u64,
    pub timeout_ms: u64,
    pub lifetime_seconds: u64,
    pub payload: super::payload::PayloadConfig,
}

impl PreparationConfig {
    pub fn validate(&self) -> Result<(), CliError> {
        self.payload.validate().map_err(error)?;
        self.credential.validate().map_err(error)?;
        self.destination.validate(false).map_err(error)?;
        CallerOptions {
            timeout_ms: self.timeout_ms,
            response_limit_bytes: self.response_limit_bytes,
            streaming: false,
        }
        .validate()
        .map_err(error)?;
        if !self.issuer_seed_file.is_absolute()
            || !(1..=300).contains(&self.lifetime_seconds)
            || !(1..=131_072).contains(&self.maximum_body_bytes)
            || self.response_limit_bytes > chio_secret_broker::daemon::MAX_DAEMON_COMBINED_RESPONSE_BYTES
            || self.destination.method != "POST"
        {
            return Err(error(
                "preparation requires bounded JSON POST authority and an absolute issuer seed path",
            ));
        }
        Ok(())
    }
}

struct Route {
    quota: BrokerQuotaVerifierConfig,
    config: PreparationConfig,
    signer: Arc<Ed25519Backend>,
    binding: String,
}

pub(crate) struct Preparer {
    routes: BTreeMap<(String, String), Route>,
}

impl Preparer {
    pub fn new(config: &Config) -> Result<Self, CliError> {
        let mut routes = BTreeMap::new();
        // A change anywhere in the host's authority invalidates preparation
        // recovery, including removing a sibling route or changing its peer.
        let generation = sha256_hex(&canonical_json_bytes(config).map_err(error)?);
        for route in &config.routes {
            let Some(preparation) = &route.preparation else {
                continue;
            };
            preparation.validate()?;
            let signer =
                super::config::read_signer(&preparation.issuer_seed_file, &route.quota.issuer)?;
            routes.insert(
                (route.quota.server_id.clone(), route.quota.tool_name.clone()),
                Route {
                    quota: route.quota.clone(),
                    config: preparation.clone(),
                    signer,
                    binding: generation.clone(),
                },
            );
        }
        Ok(Self { routes })
    }
}

fn failed(error: chio_secret_broker::BrokerError) -> ProcessError {
    ProcessError::Preparation(Box::new(error))
}

impl InvocationPreparer for Preparer {
    fn prepare(
        &self,
        runtime: &ProcessRuntime,
        input: PreparationRequest<'_>,
    ) -> Result<Value, ProcessError> {
        let route = self
            .routes
            .iter()
            .find(|((server, tool), _)| server == input.server_id && tool == input.tool_name)
            .map(|(_, route)| route)
            .ok_or(ProcessError::Invalid("route has no preparation authority"))?;
        let body = canonical_json_bytes(input.arguments)?;
        if !input.arguments.is_object() || body.len() as u64 > route.config.maximum_body_bytes {
            return Err(ProcessError::Invalid(
                "broker input exceeds the installed JSON object bound",
            ));
        }
        let body = route.config.payload.body(input.arguments)?;
        if body.len() as u64 > route.config.maximum_body_bytes {
            return Err(ProcessError::Invalid(
                "mapped provider request exceeds the installed bound",
            ));
        }
        let invocation_id = runtime.request_id(input.process, input.operation_key)?;
        let binding = sha256_hex(&canonical_json_bytes(&(
            "chio.process.broker-preparation.v1",
            &route.binding,
            input.server_id,
            input.tool_name,
            &invocation_id,
            input.arguments,
        ))?);
        runtime.registry().prepare_invocation(
            input.process,
            input.operation_key,
            &binding,
            |parent, subject| route.issue(parent, subject, &binding, invocation_id, body),
        )
    }
}

impl Route {
    fn issue(
        &self,
        parent: &chio_core_types::capability::token::CapabilityToken,
        subject: &chio_core_types::Keypair,
        binding: &str,
        invocation_id: String,
        body: Vec<u8>,
    ) -> Result<Value, ProcessError> {
        use chio_core_types::capability::scope::Operation;
        let now = chio_security_types::clock::Clock::unix_millis(
            &chio_security_types::clock::SystemClock,
        )
        .map_err(|error| ProcessError::Preparation(Box::new(error)))?
        .as_secs();
        if now < parent.issued_at
            || now >= parent.expires_at
            || !parent.scope.grants.iter().any(|grant| {
                (grant.server_id == self.quota.server_id || grant.server_id == "*")
                    && (grant.tool_name == self.quota.tool_name || grant.tool_name == "*")
                    && grant.operations.contains(&Operation::Invoke)
                    && grant.max_invocations.is_some_and(|limit| limit > 0)
            })
        {
            return Err(ProcessError::Invalid(
                "live parent does not authorize broker preparation",
            ));
        }
        let expires = now
            .checked_add(self.config.lifetime_seconds)
            .ok_or(ProcessError::Invalid("preparation time overflow"))?
            .min(parent.expires_at);
        let request = BrokerRequest {
            destination: self.config.destination.clone(),
            headers: vec![
                HeaderField::normalized("content-type", b"application/json").map_err(failed)?
            ],
            body,
            approved_preview_sha256: None,
            options: CallerOptions {
                timeout_ms: self.config.timeout_ms,
                streaming: false,
                response_limit_bytes: self.config.response_limit_bytes,
            },
        };
        let owned_header = match self.quota.credential_placement {
            chio_secret_broker::daemon_runtime::ProviderPlacementConfig::BearerAuthorization => {
                "authorization"
            }
            chio_secret_broker::daemon_runtime::ProviderPlacementConfig::ApiKeyHeader => {
                "x-api-key"
            }
        };
        let capability = issue_capability(
            BrokerCapabilityBody {
                schema: BROKER_CAPABILITY_SCHEMA.into(),
                issuer: self.signer.public_key(),
                capability_id: format!("prepared-{binding}"),
                parent_capability_id: parent.id.clone(),
                subject: parent.subject.clone(),
                audience: self.quota.audience.clone(),
                issued_at_unix_seconds: now,
                not_before_unix_seconds: now,
                expires_at_unix_seconds: expires,
                credential: self.config.credential.clone(),
                provider_adapter_id: self.quota.provider_adapter_id.clone(),
                provider_adapter_version: self.quota.provider_adapter_version,
                destination: request.destination.clone(),
                constraints: RequestConstraints {
                    allowed_caller_headers: vec!["content-type".into()],
                    provider_owned_headers: vec![owned_header.into()],
                    maximum_body_bytes: self.config.maximum_body_bytes,
                    required_body_sha256: body_digest(&request.body),
                    required_preview_sha256: None,
                    redirect_policy: RedirectPolicy::Disabled,
                    maximum_response_bytes: self.config.response_limit_bytes,
                    streaming_allowed: false,
                    maximum_timeout_ms: self.config.timeout_ms,
                },
                broker_quota_key_id: format!("prepared-quota-{binding}"),
                maximum_executions: 1,
                consumption: AttemptConsumption::CaptureBeforeDispatch,
                revocation_id: format!("prepared-revocation-{binding}"),
                proof: ProofBinding {
                    mode: ProofMode::PublicKey,
                    caller_public_key: parent.subject.clone(),
                    nonce_ttl_seconds: self.config.lifetime_seconds,
                },
            },
            self.signer.as_ref(),
            true,
        )
        .map_err(failed)?;
        let proof = issue_request_proof(
            &capability,
            &request,
            uuid::Uuid::new_v4().to_string(),
            now,
            subject,
        )
        .map_err(failed)?;
        Ok(serde_json::to_value(BrokerExecuteRequest {
            schema: BROKER_EXECUTE_SCHEMA.into(),
            invocation_id,
            capability,
            proof,
            request,
        })?)
    }
}
