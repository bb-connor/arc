use super::*;
use crate::root_exchange::kinds::local_as::{CodeRedemption, RedeemedCode};

struct TokenResponseInput {
    subject: String,
    client_id: String,
    resource: String,
    scopes: Vec<String>,
    authorization_details: Option<Vec<GovernedAuthorizationDetail>>,
    transaction_context: Option<GovernedAuthorizationTransactionContext>,
    sender_constraint: Option<ChioSenderConstraintClaims>,
    grant_type: Option<String>,
    issued_at: u64,
}

struct SignedAccessTokenInput<'a> {
    subject: &'a str,
    client_id: &'a str,
    resource: &'a str,
    scopes: &'a [String],
    authorization_details: Option<&'a [GovernedAuthorizationDetail]>,
    transaction_context: Option<&'a GovernedAuthorizationTransactionContext>,
    sender_constraint: Option<&'a ChioSenderConstraintClaims>,
    issued_at: u64,
}

/// Bounds a deadline-keyed store: drops expired entries and refuses a new
/// entry once `MAX_PENDING_AUTHORIZATIONS` live entries remain.
fn reserve_capacity<T>(
    entries: &mut HashMap<String, T>,
    reading: chio_security_types::clock::ClockReading,
    deadline: impl Fn(&mut T) -> &mut AuthorityDeadline,
    exhausted: &str,
) -> Result<(), Response> {
    let mut expired = Vec::new();
    for (id, entry) in entries.iter_mut() {
        match deadline(entry).remaining(reading) {
            Err(ClockError::Expired) => expired.push(id.clone()),
            Err(error) => return Err(clock::rejection(error)),
            Ok(_) => {}
        }
    }
    for id in expired {
        entries.remove(&id);
    }
    if entries.len() >= MAX_PENDING_AUTHORIZATIONS {
        return Err(oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            OAuthError::TemporarilyUnavailable,
            exhausted,
        ));
    }
    Ok(())
}

const MAX_PENDING_AUTHORIZATIONS: usize = 4096;

fn consent_refusal(detail: &str) -> Response {
    oauth_token_error(StatusCode::BAD_REQUEST, OAuthError::InvalidRequest, detail)
}

impl LocalAuthorizationServer {
    fn issue_consent_nonce(&self, request: &AuthorizationRequest) -> Result<String, Response> {
        let entropy = Keypair::generate().public_key().to_hex();
        let nonce = format!("consent-{}", sha256_hex(entropy.as_bytes()));
        let mut consents = self
            .consents
            .lock()
            .map_err(|_| clock::rejection(ClockError::Unavailable))?;
        let reading = self.clock.read().map_err(clock::rejection)?;
        let timeout_ms = self
            .code_ttl_secs
            .checked_mul(1000)
            .ok_or_else(|| clock::rejection(ClockError::Overflow))?;
        let deadline =
            AuthorityDeadline::for_timeout_ms(reading, timeout_ms).map_err(clock::rejection)?;
        reserve_capacity(
            &mut consents,
            reading,
            |consent| &mut consent.deadline,
            "consent capacity exhausted",
        )?;
        consents.insert(
            nonce.clone(),
            PendingConsent {
                deadline,
                request: request.clone(),
            },
        );
        Ok(nonce)
    }

    fn take_pending_consent(&self, nonce: Option<&str>) -> Result<AuthorizationRequest, Response> {
        let nonce = nonce
            .filter(|nonce| !nonce.is_empty())
            .ok_or_else(|| consent_refusal("missing consent_nonce"))?;
        let mut consents = self
            .consents
            .lock()
            .map_err(|_| clock::rejection(ClockError::Unavailable))?;
        let reading = self.clock.read().map_err(clock::rejection)?;
        let pending = consents
            .get_mut(nonce)
            .ok_or_else(|| consent_refusal("unknown or answered consent_nonce"))?;
        match pending.deadline.remaining(reading) {
            Ok(_) => {}
            Err(ClockError::Expired) => {
                consents.remove(nonce);
                return Err(consent_refusal("consent_nonce expired"));
            }
            Err(error) => return Err(clock::rejection(error)),
        }
        consents
            .remove(nonce)
            .map(|pending| pending.request)
            .ok_or_else(|| consent_refusal("unknown or answered consent_nonce"))
    }

    pub(super) fn authorization_page(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<String, Response> {
        let resource = validate_authorization_request(
            &self.clock,
            request,
            &self.clients,
            &self.supported_scopes,
            &self.default_audience,
        )?;
        let scopes = resolve_requested_scopes(request.scope.as_deref(), &self.supported_scopes)?;
        let authorization_details =
            parse_request_time_authorization_details(request.authorization_details.as_deref())?;
        let transaction_context = parse_request_time_transaction_context(
            &self.clock,
            request.chio_transaction_context.as_deref(),
        )?;
        validate_request_time_transaction_context_binding(
            transaction_context.as_ref(),
            &request.client_id,
            None,
        )?;
        let sender_constraint = build_request_sender_constraint(
            request.chio_sender_dpop_public_key.as_deref(),
            request.chio_sender_mtls_thumbprint_sha256.as_deref(),
            request.chio_sender_attestation_sha256.as_deref(),
            transaction_context.as_ref(),
        )?;
        let scopes_display = scopes.join(" ");
        let details_display = authorization_details
            .as_ref()
            .map_or("none".to_string(), |details| {
                format!("{} detail(s)", details.len())
            });
        let transaction_display = transaction_context
            .as_ref()
            .map_or("none".to_string(), |ctx| {
                let continuity = ctx
                    .identity_assertion
                    .as_ref()
                    .map(|assertion| {
                        format!(" / {} / {}", assertion.subject, assertion.continuity_id)
                    })
                    .unwrap_or_default();
                format!("{} / {}{}", ctx.intent_id, ctx.intent_hash, continuity)
            });
        let sender_constraint_display = sender_constraint.as_ref().map_or_else(
            || "none".to_string(),
            |constraint| {
                let mut parts = Vec::new();
                if constraint.mtls_thumbprint_sha256.is_some() {
                    parts.push("mtls");
                }
                if constraint.chio_attestation_sha256.is_some() {
                    parts.push("attestation");
                }
                parts.join(" + ")
            },
        );
        let consent_nonce = self.issue_consent_nonce(request)?;
        Ok(format!(
            "<!doctype html><html><body><h1>Authorize MCP Access</h1><p>Client: {client}</p><p>Resource: {resource}</p><p>Subject: {subject}</p><p>Scopes: {scopes}</p><p>Chio Authorization Details: {details_display}</p><p>Chio Transaction Context: {transaction_display}</p><p>Sender Constraint: {sender_constraint_display}</p><form method=\"post\" action=\"{path}\"><input type=\"hidden\" name=\"consent_nonce\" value=\"{consent_nonce}\"><button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button><button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></body></html>",
            client = html_escape(&request.client_id),
            resource = html_escape(&resource),
            subject = html_escape(&self.subject),
            scopes = html_escape(&scopes_display),
            details_display = html_escape(&details_display),
            transaction_display = html_escape(&transaction_display),
            sender_constraint_display = html_escape(&sender_constraint_display),
            consent_nonce = html_escape(&consent_nonce),
            path = LOCAL_AUTHORIZATION_PATH,
        ))
    }

    /// Answers a rendered consent page. The nonce is consumed by the first
    /// answer, approve or deny; the approved request is the one stored when
    /// the page was rendered, never fields from the submission.
    pub(super) fn approve_authorization(
        &self,
        form: AuthorizationApprovalForm,
    ) -> Result<Redirect, Response> {
        let request = self.take_pending_consent(form.consent_nonce.as_deref())?;
        if form.decision != "approve" {
            return Err(redirect_oauth_error(
                &request.redirect_uri,
                OAuthError::AccessDenied,
                "authorization request denied",
                request.state.as_deref(),
                &self.issuer,
            ));
        }
        let resource = validate_authorization_request(
            &self.clock,
            &request,
            &self.clients,
            &self.supported_scopes,
            &self.default_audience,
        )?;
        let authorization_details =
            parse_request_time_authorization_details(request.authorization_details.as_deref())?;
        let transaction_context = parse_request_time_transaction_context(
            &self.clock,
            request.chio_transaction_context.as_deref(),
        )?;
        validate_request_time_transaction_context_binding(
            transaction_context.as_ref(),
            &request.client_id,
            None,
        )?;
        let sender_constraint = build_request_sender_constraint(
            request.chio_sender_dpop_public_key.as_deref(),
            request.chio_sender_mtls_thumbprint_sha256.as_deref(),
            request.chio_sender_attestation_sha256.as_deref(),
            transaction_context.as_ref(),
        )?;

        let scopes = resolve_requested_scopes(request.scope.as_deref(), &self.supported_scopes)?;
        let code = generate_authorization_code();
        let mut codes = self
            .codes
            .lock()
            .map_err(|_| clock::rejection(ClockError::Unavailable))?;
        let reading = self.clock.read().map_err(clock::rejection)?;
        let timeout_ms = self
            .code_ttl_secs
            .checked_mul(1000)
            .ok_or_else(|| clock::rejection(ClockError::Overflow))?;
        let deadline =
            AuthorityDeadline::for_timeout_ms(reading, timeout_ms).map_err(clock::rejection)?;
        let grant = AuthorizationCodeGrant {
            deadline,
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            resource: resource.clone(),
            scopes,
            subject: self.subject.clone(),
            code_challenge: request.code_challenge.clone().unwrap_or_default(),
            code_challenge_method: request.code_challenge_method.clone().unwrap_or_default(),
            expires_at: reading
                .unix_millis()
                .as_secs()
                .checked_add(self.code_ttl_secs)
                .ok_or_else(|| clock::rejection(ClockError::Overflow))?,
            authorization_details,
            transaction_context,
            sender_constraint,
        };
        reserve_capacity(
            &mut codes,
            reading,
            |grant| &mut grant.deadline,
            "authorization grant capacity exhausted",
        )?;
        codes.insert(code.clone(), grant);
        drop(codes);

        let mut redirect_uri = Url::parse(&request.redirect_uri).map_err(|error| {
            input::with_source(
                oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    OAuthError::InvalidRequest,
                    "invalid redirect_uri",
                ),
                error,
            )
        })?;
        {
            let mut pairs = redirect_uri.query_pairs_mut();
            pairs.append_pair("code", &code);
            if let Some(state) = request.state.as_deref() {
                pairs.append_pair("state", state);
            }
            pairs.append_pair("iss", &self.issuer);
        }
        Ok(Redirect::to(redirect_uri.as_str()))
    }

    pub(super) fn exchange_token<'a>(
        &self,
        headers: impl Into<SenderRequest<'a>>,
        form: TokenRequestForm,
    ) -> Result<Value, Response> {
        let headers = headers.into();
        match form.grant_type.as_str() {
            "authorization_code" => self.exchange_authorization_code(headers, form),
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                self.exchange_subject_token(headers, form)
            }
            _ => Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::UnsupportedGrantType,
                "unsupported grant_type",
            )),
        }
    }

    pub(super) fn exchange_authorization_code(
        &self,
        headers: SenderRequest<'_>,
        form: TokenRequestForm,
    ) -> Result<Value, Response> {
        self.redeem_authorization_code(headers, form)
            .map(|(response, _)| response)
    }

    /// Redeem an authorization code: the token response and the redeemed
    /// code it was issued from, which carries the code's sender constraint.
    pub(super) fn redeem_authorization_code(
        &self,
        headers: SenderRequest<'_>,
        form: TokenRequestForm,
    ) -> Result<(Value, RedeemedCode), Response> {
        let code = form.code.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidRequest,
                "missing code",
            )
        })?;
        let redirect_uri = form.redirect_uri.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidRequest,
                "missing redirect_uri",
            )
        })?;
        let client_id = form.client_id.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidRequest,
                "missing client_id",
            )
        })?;
        let code_verifier = form.code_verifier.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidRequest,
                "missing code_verifier",
            )
        })?;

        let mut codes = self
            .codes
            .lock()
            .map_err(|_| clock::rejection(ClockError::Unavailable))?;
        let mut grant = codes.get(code).cloned().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "unknown authorization code",
            )
        })?;

        let reading = self.clock.read().map_err(clock::rejection)?;
        let expired = match grant.deadline.remaining(reading) {
            Ok(_) => false,
            Err(ClockError::Expired) => true,
            Err(error) => return Err(clock::rejection(error)),
        };
        if reading.unix_millis().as_secs() >= grant.expires_at || expired {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "authorization code expired",
            ));
        }
        if grant.client_id != client_id || grant.redirect_uri != redirect_uri {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "client_id or redirect_uri mismatch",
            ));
        }
        if grant.code_challenge_method != "S256" {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "unsupported code_challenge_method",
            ));
        }
        if pkce_s256(code_verifier) != grant.code_challenge {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "PKCE verification failed",
            ));
        }
        let resource = form.resource.unwrap_or(grant.resource.clone());
        if resource != grant.resource {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidTarget,
                "resource parameter mismatch",
            ));
        }
        sender_constraint::validate_sender_constraint(grant.sender_constraint.as_ref(), headers)
        .map_err(|error| {
            let mut response = oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                &error.to_string(),
            );
            response.extensions_mut().insert(Arc::new(error));
            response
        })?;
        let issued_at = reading.unix_millis().as_secs();
        let token_exp = issued_at
            .checked_add(self.access_token_ttl_secs)
            .filter(|expiry| *expiry > issued_at)
            .ok_or_else(|| clock::rejection(ClockError::Overflow))?;
        let redeemed = RedeemedCode::from_redemption(CodeRedemption {
            code,
            issuer: &self.issuer,
            subject: &grant.subject,
            client_id: &grant.client_id,
            redirect_uri,
            resource: &resource,
            scopes: &grant.scopes,
            sender_constraint: grant.sender_constraint.as_ref(),
            issued_at,
            code_expires_at: grant.expires_at,
            token_exp,
        })
        .map_err(|_| {
            oauth_token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthError::ServerError,
                "authorization code redemption does not canonicalize",
            )
        })?;
        let response = self.issue_token_response(TokenResponseInput {
            subject: redeemed.subject().to_owned(),
            client_id: redeemed.client_id().to_owned(),
            resource: redeemed.resource().to_owned(),
            scopes: redeemed.scopes().to_vec(),
            authorization_details: grant.authorization_details.clone(),
            transaction_context: grant.transaction_context.clone(),
            sender_constraint: redeemed.sender_constraint().cloned(),
            grant_type: Some("authorization_code".to_string()),
            issued_at: redeemed.issued_at(),
        })?;

        codes.remove(code);
        Ok((response, redeemed))
    }

    pub(super) fn exchange_subject_token(
        &self,
        headers: SenderRequest<'_>,
        form: TokenRequestForm,
    ) -> Result<Value, Response> {
        let subject_token = form.subject_token.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidRequest,
                "missing subject_token",
            )
        })?;
        let subject_token_type = form.subject_token_type.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidRequest,
                "missing subject_token_type",
            )
        })?;
        if subject_token_type != "urn:ietf:params:oauth:token-type:access_token" {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidRequest,
                "unsupported subject_token_type",
            ));
        }
        let resource = form
            .resource
            .unwrap_or_else(|| self.default_audience.clone());
        if resource != self.default_audience {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidTarget,
                "resource parameter must match the advertised protected resource",
            ));
        }
        let (claims, _) = self.validate_subject_token(subject_token)?;
        let subject = claims.sub.clone().unwrap_or_else(|| self.subject.clone());
        let client_id = claims
            .client_id
            .clone()
            .unwrap_or_else(|| "token-exchange".to_string());
        let scopes = resolve_exchange_scopes(
            form.scope.as_deref(),
            &claims.scopes(),
            &self.supported_scopes,
        )?;
        let authorization_details = match claims.authorization_details {
            Some(value) => Some(parse_request_time_authorization_details_from_value(value)?),
            None => None,
        };
        let transaction_context = match claims.chio_transaction_context {
            Some(value) => Some(parse_request_time_transaction_context_from_value(
                &self.clock,
                value,
            )?),
            None => None,
        };
        validate_request_time_transaction_context_binding(
            transaction_context.as_ref(),
            &client_id,
            None,
        )?;

        sender_constraint::validate_sender_constraint(claims.cnf.as_ref(), headers)
        .map_err(|error| {
            let mut response = oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                &error.to_string(),
            );
            response.extensions_mut().insert(Arc::new(error));
            response
        })?;
        let response = self.issue_token_response(TokenResponseInput {
            subject,
            client_id,
            resource,
            scopes,
            authorization_details,
            transaction_context,
            sender_constraint: claims.cnf.clone(),
            grant_type: Some("urn:ietf:params:oauth:grant-type:token-exchange".to_string()),
            issued_at: self.clock.seconds().map_err(clock::rejection)?,
        })?;
        Ok(response)
    }

    fn validate_subject_token(&self, token: &str) -> Result<(JwtClaims, String), Response> {
        let (header, claims, signed_input, signature) = decode_jwt_parts(token, None)?;
        let alg = JwtSignatureAlgorithm::from_header(&header, None)?;
        if alg != JwtSignatureAlgorithm::EdDsa
            || !verify_ed25519_jwt_signature(
                &self.signing_key.public_key(),
                signed_input.as_bytes(),
                &signature,
            )
        {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "subject token signature is invalid",
            ));
        }
        if claims.iss.as_deref() != Some(self.issuer.as_str()) {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "subject token issuer mismatch",
            ));
        }
        let Some(exp) = claims.exp else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "subject token has no exp",
            ));
        };
        if self.clock.seconds().map_err(clock::rejection)? >= exp {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                "subject token expired",
            ));
        }
        if let Some(value) = claims.authorization_details.clone() {
            let _ = parse_request_time_authorization_details_from_value(value)?;
        }
        if let Some(value) = claims.chio_transaction_context.clone() {
            let context = parse_request_time_transaction_context_from_value(&self.clock, value)?;
            if context.identity_assertion.is_some() {
                let expected_client_id = claims.client_id.as_deref().ok_or_else(|| {
                    oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        OAuthError::InvalidGrant,
                        "subject token chio_transaction_context.identityAssertion requires client_id",
                    )
                })?;
                validate_request_time_transaction_context_binding(
                    Some(&context),
                    expected_client_id,
                    None,
                )?;
            }
        }
        Ok((claims, signed_input))
    }

    fn issue_token_response(&self, input: TokenResponseInput) -> Result<Value, Response> {
        let access_token = self.sign_access_token(SignedAccessTokenInput {
            subject: &input.subject,
            client_id: &input.client_id,
            resource: &input.resource,
            scopes: &input.scopes,
            authorization_details: input.authorization_details.as_deref(),
            transaction_context: input.transaction_context.as_ref(),
            sender_constraint: input.sender_constraint.as_ref(),
            issued_at: input.issued_at,
        })?;
        Ok(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.access_token_ttl_secs,
            "scope": input.scopes.join(" "),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "grant_type": input.grant_type,
        }))
    }

    fn sign_access_token(&self, input: SignedAccessTokenInput<'_>) -> Result<String, Response> {
        let now = input.issued_at;
        let expires_at = now
            .checked_add(self.access_token_ttl_secs)
            .filter(|expiry| *expiry > now)
            .ok_or_else(|| clock::rejection(ClockError::Overflow))?;
        let mut claims = json!({
            "iss": self.issuer,
            "sub": input.subject,
            "aud": input.resource,
            "scope": input.scopes.join(" "),
            "client_id": input.client_id,
            "resource": input.resource,
            "iat": now,
            "exp": expires_at,
            "jti": generate_authorization_code(),
        });
        if let Some(details) = input.authorization_details {
            claims[CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM] = json!(details);
        }
        if let Some(context) = input.transaction_context {
            claims[CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM] = json!(context);
        }
        if let Some(sender_constraint) = input
            .sender_constraint
            .filter(|sender_constraint| !sender_constraint.is_empty())
        {
            claims["cnf"] = json!(sender_constraint);
        }
        sign_jwt(&self.signing_key, &claims)
    }

    pub(super) fn jwks(&self) -> Value {
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": jwk_key_id(&self.signing_key.public_key()),
                "x": URL_SAFE_NO_PAD.encode(self.signing_key.public_key_bytes()),
            }]
        })
    }
}
