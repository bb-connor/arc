pub const ARC_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID: &str =
    "arc_agent_passport_jwt_vc_json";
pub const ARC_PASSPORT_JWT_VC_JSON_FORMAT: &str = "jwt_vc_json";
pub const ARC_PASSPORT_JWT_VC_JSON_TYPE: &str = "ArcPassportCredential";
pub const ARC_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH: &str =
    "/.well-known/arc-passport-jwt-vc-json";
const JWT_VC_TYP: &str = "vc+jwt";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcPassportJwtVcJsonTypeMetadata {
    pub types: Vec<String>,
    pub format: String,
    pub subject_binding: String,
    pub issuer_identity: String,
    #[serde(default)]
    pub portable_claim_catalog: ArcPortableClaimCatalog,
    #[serde(default)]
    pub portable_identity_binding: ArcPortableIdentityBinding,
    pub type_metadata_url: String,
    pub jwks_url: String,
    pub proof_family: String,
    pub supports_selective_disclosure: bool,
    pub status_reference_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcPassportJwtVcJsonEnvelope {
    pub compact: String,
    pub passport_id: String,
    pub subject_did: String,
    pub issuer: String,
    pub issuer_jwk: PortableEd25519Jwk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcPassportJwtVcJsonVerification {
    pub passport_id: String,
    pub subject_did: String,
    pub issuer: String,
    pub subject_thumbprint: String,
    pub holder_jwk: PortableEd25519Jwk,
    pub credential_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_status: Option<Oid4vciArcPassportStatusReference>,
}

pub fn build_arc_passport_jwt_vc_json_type_metadata(
    credential_issuer: &str,
) -> Result<ArcPassportJwtVcJsonTypeMetadata, CredentialError> {
    let credential_issuer = normalize_credential_issuer(credential_issuer)?;
    let portable_claim_catalog = jwt_vc_json_claim_catalog();
    let portable_identity_binding = jwt_vc_json_identity_binding();
    Ok(ArcPassportJwtVcJsonTypeMetadata {
        types: vec![VC_TYPE.to_string(), ARC_PASSPORT_JWT_VC_JSON_TYPE.to_string()],
        format: ARC_PASSPORT_JWT_VC_JSON_FORMAT.to_string(),
        subject_binding: portable_identity_binding.subject_binding.clone(),
        issuer_identity: portable_identity_binding.issuer_identity.clone(),
        portable_claim_catalog: portable_claim_catalog.clone(),
        portable_identity_binding: portable_identity_binding.clone(),
        type_metadata_url: format!(
            "{credential_issuer}{ARC_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH}"
        ),
        jwks_url: format!("{credential_issuer}{OID4VCI_JWKS_PATH}"),
        proof_family: JWT_VC_TYP.to_string(),
        supports_selective_disclosure: false,
        status_reference_kind: portable_claim_catalog.status_reference_kind,
    })
}

pub fn issue_arc_passport_jwt_vc_json(
    passport: &AgentPassport,
    credential_issuer: &str,
    issuer_keypair: &Keypair,
    now: u64,
    passport_status: Option<Oid4vciArcPassportStatusReference>,
) -> Result<ArcPassportJwtVcJsonEnvelope, CredentialError> {
    let credential_issuer = normalize_credential_issuer(credential_issuer)?;
    let projection = build_arc_passport_portable_projection(passport, now)?;
    let subject_did = DidArc::from_str(&projection.subject_did).map_err(CredentialError::Did)?;
    let holder_jwk = PortableEd25519Jwk::from_public_key(subject_did.public_key());
    let holder_thumbprint = holder_jwk.thumbprint()?;
    let vc = jwt_vc_json_value(&projection, passport_status.clone())?;
    let payload = json!({
        "iss": credential_issuer,
        "sub": holder_thumbprint,
        "iat": now,
        "nbf": now,
        "exp": unix_from_rfc3339(&passport.valid_until)?,
        "jti": projection.passport_id,
        "cnf": { "jwk": holder_jwk },
        "vc": vc,
    });
    let compact = sign_jwt_value(JWT_VC_TYP, &payload, issuer_keypair)?;
    Ok(ArcPassportJwtVcJsonEnvelope {
        compact,
        passport_id: projection.passport_id,
        subject_did: projection.subject_did,
        issuer: credential_issuer,
        issuer_jwk: PortableEd25519Jwk::from_public_key(&issuer_keypair.public_key()),
    })
}

pub fn verify_arc_passport_jwt_vc_json(
    compact: &str,
    issuer_public_key: &PublicKey,
    now: u64,
) -> Result<ArcPassportJwtVcJsonVerification, CredentialError> {
    let (header, payload, signing_input, signature) = decode_compact_jwt_without_signature(
        compact,
        "portable jwt vc",
        CredentialError::InvalidOid4vciCredentialResponse,
    )?;
    if header
        .get("typ")
        .and_then(Value::as_str)
        .is_some_and(|typ| typ != JWT_VC_TYP)
    {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
            "portable jwt vc header typ must be `{JWT_VC_TYP}`"
        )));
    }
    if !issuer_public_key.verify(signing_input.as_bytes(), &signature) {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc signature verification failed".to_string(),
        ));
    }
    let payload_object = payload.as_object().ok_or_else(|| {
        CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc payload must be a JSON object".to_string(),
        )
    })?;
    let issuer = payload_object
        .get("iss")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include a non-empty `iss`".to_string(),
            )
        })?;
    let issued_at = payload_object
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include `iat`".to_string(),
            )
        })?;
    let not_before = payload_object
        .get("nbf")
        .and_then(Value::as_u64)
        .unwrap_or(issued_at);
    let expires_at = payload_object
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include `exp`".to_string(),
            )
        })?;
    if issued_at > expires_at || not_before > expires_at {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc time claims are inconsistent".to_string(),
        ));
    }
    if now < not_before {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc is not yet valid".to_string(),
        ));
    }
    if now > expires_at {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc has expired".to_string(),
        ));
    }
    let subject_thumbprint = payload_object
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include a non-empty `sub`".to_string(),
            )
        })?;
    let holder_jwk_value = payload_object
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|value| value.get("jwk"))
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include `cnf.jwk`".to_string(),
            )
        })?;
    let holder_jwk: PortableEd25519Jwk =
        serde_json::from_value(holder_jwk_value.clone()).map_err(|error| {
            CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable jwt vc cnf.jwk is invalid: {error}"
            ))
        })?;
    if holder_jwk.thumbprint()? != subject_thumbprint {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc `sub` does not match cnf.jwk thumbprint".to_string(),
        ));
    }

    let vc = payload_object
        .get("vc")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include `vc`".to_string(),
            )
        })?;
    let contexts = vc
        .get("@context")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc vc.@context must be an array".to_string(),
            )
        })?;
    if !contexts.iter().any(|value| value.as_str() == Some(VC_CONTEXT_V1))
        || !contexts
            .iter()
            .any(|value| value.as_str() == Some(ARC_CREDENTIAL_CONTEXT_V1))
    {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc vc.@context did not match the supported ARC profile".to_string(),
        ));
    }
    let types = vc.get("type").and_then(Value::as_array).ok_or_else(|| {
        CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc vc.type must be an array".to_string(),
        )
    })?;
    if !types.iter().any(|value| value.as_str() == Some(VC_TYPE))
        || !types
            .iter()
            .any(|value| value.as_str() == Some(ARC_PASSPORT_JWT_VC_JSON_TYPE))
    {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc vc.type did not match the supported ARC profile".to_string(),
        ));
    }
    let subject = vc
        .get("credentialSubject")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include vc.credentialSubject".to_string(),
            )
        })?;
    let subject_did = subject
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include vc.credentialSubject.id".to_string(),
            )
        })?;
    DidArc::from_str(subject_did).map_err(CredentialError::Did)?;
    let passport_id = subject
        .get("arcPassportId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include vc.credentialSubject.arcPassportId".to_string(),
            )
        })?;
    if payload_object
        .get("jti")
        .and_then(Value::as_str)
        .is_some_and(|value| value != passport_id)
    {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable jwt vc jti must match vc.credentialSubject.arcPassportId".to_string(),
        ));
    }
    let credential_count = subject
        .get("arcCredentialCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable jwt vc must include vc.credentialSubject.arcCredentialCount"
                    .to_string(),
            )
        })?;
    json_array_claim(subject, "arcIssuerDids", "portable jwt vc")?;
    json_array_claim(subject, "arcMerkleRoots", "portable jwt vc")?;
    json_array_claim(subject, "arcEnterpriseIdentityProvenance", "portable jwt vc")?;
    let passport_status = subject
        .get("arcPassportStatus")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| {
            CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable jwt vc arcPassportStatus is invalid: {error}"
            ))
        })?;

    Ok(ArcPassportJwtVcJsonVerification {
        passport_id: passport_id.to_string(),
        subject_did: subject_did.to_string(),
        issuer: issuer.to_string(),
        subject_thumbprint: subject_thumbprint.to_string(),
        holder_jwk,
        credential_count: usize::try_from(credential_count).unwrap_or(usize::MAX),
        passport_status,
    })
}

fn jwt_vc_json_value(
    projection: &ArcPassportPortableProjection,
    passport_status: Option<Oid4vciArcPassportStatusReference>,
) -> Result<Value, CredentialError> {
    let mut credential_subject = Map::new();
    credential_subject.insert("id".to_string(), Value::String(projection.subject_did.clone()));
    credential_subject.insert(
        "arcPassportId".to_string(),
        Value::String(projection.passport_id.clone()),
    );
    credential_subject.insert(
        "arcCredentialCount".to_string(),
        Value::Number(u64::try_from(projection.credential_count).unwrap_or(u64::MAX).into()),
    );
    credential_subject.insert(
        "arcIssuerDids".to_string(),
        serde_json::to_value(&projection.issuer_dids)
            .map_err(|error| CredentialError::InvalidOid4vciCredentialResponse(error.to_string()))?,
    );
    credential_subject.insert(
        "arcMerkleRoots".to_string(),
        serde_json::to_value(&projection.merkle_roots)
            .map_err(|error| CredentialError::InvalidOid4vciCredentialResponse(error.to_string()))?,
    );
    credential_subject.insert(
        "arcEnterpriseIdentityProvenance".to_string(),
        serde_json::to_value(&projection.enterprise_identity_provenance)
            .map_err(|error| CredentialError::InvalidOid4vciCredentialResponse(error.to_string()))?,
    );
    if let Some(passport_status) = passport_status {
        credential_subject.insert(
            "arcPassportStatus".to_string(),
            serde_json::to_value(passport_status)
                .map_err(|error| CredentialError::InvalidOid4vciCredentialResponse(error.to_string()))?,
        );
    }
    Ok(json!({
        "@context": [VC_CONTEXT_V1, ARC_CREDENTIAL_CONTEXT_V1],
        "type": [VC_TYPE, ARC_PASSPORT_JWT_VC_JSON_TYPE],
        "credentialSubject": Value::Object(credential_subject),
    }))
}

fn jwt_vc_json_claim_catalog() -> ArcPortableClaimCatalog {
    let default_catalog = ArcPortableClaimCatalog::default();
    ArcPortableClaimCatalog {
        always_disclosed_claims: vec![
            "iss".to_string(),
            "sub".to_string(),
            "cnf.jwk".to_string(),
            "vc.type".to_string(),
            "vc.credentialSubject.id".to_string(),
            "vc.credentialSubject.arcPassportId".to_string(),
            "vc.credentialSubject.arcCredentialCount".to_string(),
            "vc.credentialSubject.arcIssuerDids".to_string(),
            "vc.credentialSubject.arcMerkleRoots".to_string(),
            "vc.credentialSubject.arcEnterpriseIdentityProvenance".to_string(),
        ],
        selectively_disclosable_claims: default_catalog.selectively_disclosable_claims,
        optional_claims: vec!["vc.credentialSubject.arcPassportStatus".to_string()],
        status_reference_kind: default_catalog.status_reference_kind,
        schema: default_catalog.schema,
        unsupported_claims_fail_closed: default_catalog.unsupported_claims_fail_closed,
    }
}

fn jwt_vc_json_identity_binding() -> ArcPortableIdentityBinding {
    ArcPortableIdentityBinding {
        portable_subject_claim: "sub".to_string(),
        subject_confirmation_claim: "cnf.jwk".to_string(),
        arc_subject_provenance_claim: "vc.credentialSubject.id".to_string(),
        portable_issuer_claim: "iss".to_string(),
        arc_issuer_provenance_claim: "vc.credentialSubject.arcIssuerDids".to_string(),
        enterprise_provenance_claim: "vc.credentialSubject.arcEnterpriseIdentityProvenance"
            .to_string(),
        ..ArcPortableIdentityBinding::default()
    }
}

fn json_array_claim<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    prefix: &str,
) -> Result<&'a Vec<Value>, CredentialError> {
    object.get(field).and_then(Value::as_array).ok_or_else(|| {
        CredentialError::InvalidOid4vciCredentialResponse(format!(
            "{prefix} must include vc.credentialSubject.{field}"
        ))
    })
}
