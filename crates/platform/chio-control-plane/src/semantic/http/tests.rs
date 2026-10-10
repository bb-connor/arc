use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn egress(endpoint: &str) -> TestResult<HttpEgressContract> {
    let url = reqwest::Url::parse(endpoint)?;
    Ok(HttpEgressContract {
        tenant_egress_namespace: "tests.semantic.http".to_owned(),
        allowed_schemes: std::collections::BTreeSet::from(["https".to_owned()]),
        allowed_authority_set: std::collections::BTreeSet::from([url
            .host_str()
            .ok_or("host")?
            .to_owned()]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: MAX_RECOVERY_WIRE_BYTES as u64,
    })
}
pub(super) fn request() -> TestResult<SemanticTransportRequestV1> {
    Ok(SemanticTransportRequestV1 {
        kind: SemanticOperationKindV1::IssueWrite,
        destination: SemanticDestinationV1 {
            destination: SemanticDestinationId::new("destination")?,
            provider: ProviderId::new("provider")?,
            account: ProviderAccountId::new("account")?,
            resource: ProviderResourceId::new("resource")?,
            endpoint: ProtectedText::new("https://gateway.example/issues")?,
            audience: chio_security_types::flow::InformationLabel::bottom(),
            purpose: ProtectedText::new("support")?,
            subject_mapping: CanonicalPayloadDigest::from_bytes([1; 32]),
            acl_query: CanonicalPayloadDigest::from_bytes([2; 32]),
            require_provider_precondition: true,
        },
        provider_version: ProtectedText::new("\"v1\"")?,
        operation: OperationId::new("operation")?,
        attempt: SemanticProviderAttemptId::new("attempt")?,
        payload: SemanticPayloadV1 {
            fields: NonEmptyBoundedList::new(vec![SemanticFieldV1 {
                field: SemanticFieldId::new("title")?,
                value: SemanticValueV1::Text {
                    value: ProtectedText::new("private-transport-canary")?,
                },
            }])?,
        },
    })
}
#[test]
fn http_build_binds_provider_account_resource_version_and_native_attempt() -> TestResult {
    let request = request()?;
    let transport = HttpSemanticTransport::new(
        request.destination.clone(),
        egress(request.destination.endpoint.as_str())?,
        "private-token-canary".into(),
        ProviderPreconditionGuaranteeV1::AtomicIfMatch,
    )?;
    let wire = transport.build_request(&request)?;
    assert_eq!(wire.method(), reqwest::Method::POST);
    assert_eq!(wire.url().as_str(), request.destination.endpoint.as_str());
    assert_eq!(wire.headers()["if-match"], "\"v1\"");
    assert_eq!(
        wire.headers()["x-chio-operation-id"],
        request.operation.as_str()
    );
    let body: SemanticProviderRequestV1 = decode_contract(
        wire.body()
            .and_then(reqwest::Body::as_bytes)
            .ok_or("request body")?,
    )?;
    assert_eq!(body.account, request.destination.account);
    assert_eq!(body.resource, request.destination.resource);
    assert_eq!(body.payload, request.payload);
    assert_eq!(body.attempt, request.attempt);
    assert!(!format!("{transport:?} {body:?}").contains("canary"));
    let mut read = request.clone();
    read.kind = SemanticOperationKindV1::SupportRead;
    assert_eq!(
        transport.build_request(&read)?.method(),
        reqwest::Method::GET
    );
    for mutation in 0..4 {
        let mut bad = request.clone();
        match mutation {
            0 => bad.destination.account = ProviderAccountId::new("foreign")?,
            1 => bad.destination.endpoint = ProtectedText::new("https://redirect.example/issues")?,
            2 => bad.provider_version = ProtectedText::new("\"v1\",\"v2\"")?,
            _ => bad.kind = SemanticOperationKindV1::FieldProjection,
        }
        assert!(transport.build_request(&bad).is_err());
    }
    Ok(())
}
#[test]
fn http_refuses_raw_response_foreign_account_and_unsupported_routes() -> TestResult {
    let request = request()?;
    let transport = HttpSemanticTransport::new(
        request.destination.clone(),
        egress(request.destination.endpoint.as_str())?,
        "credential".into(),
        ProviderPreconditionGuaranteeV1::AtomicIfMatch,
    )?;
    let response = SemanticProviderResponseV1 {
        provider: request.destination.provider.clone(),
        account: request.destination.account.clone(),
        resource: request.destination.resource.clone(),
        checked_provider_version: request.provider_version.clone(),
        operation: request.operation.clone(),
        attempt: request.attempt.clone(),
        payload: request.payload.clone(),
    };
    assert_eq!(
        transport.decode_response(&request, &chio_core_types::canonical_json_bytes(&response)?)?,
        request.payload
    );
    for mutation in 0..4 {
        let mut bad = response.clone();
        match mutation {
            0 => bad.account = ProviderAccountId::new("foreign")?,
            1 => bad.resource = ProviderResourceId::new("foreign")?,
            2 => bad.checked_provider_version = ProtectedText::new("\"v2\"")?,
            _ => bad.operation = OperationId::new("foreign-operation")?,
        }
        assert!(transport
            .decode_response(&request, &chio_core_types::canonical_json_bytes(&bad)?)
            .is_err());
    }
    let error = transport
        .decode_response(&request, b"{\"body\":\"private-response-canary\"}")
        .err()
        .ok_or("raw body accepted")?;
    assert!(!error.to_string().contains("private-response-canary"));
    for endpoint in [
        "http://gateway.example/issues",
        "https://user:password@gateway.example/issues",
        "https://gateway.example/issues?token=secret",
        "https://gateway.example/issues#fragment",
        "https://gateway.example/",
    ] {
        let mut destination = request.destination.clone();
        destination.endpoint = ProtectedText::new(endpoint)?;
        assert!(HttpSemanticTransport::new(
            destination,
            egress(endpoint)?,
            "credential".into(),
            ProviderPreconditionGuaranteeV1::AtomicIfMatch
        )
        .is_err());
    }
    assert!(HttpSemanticTransport::new(
        request.destination,
        egress("https://gateway.example/issues")?,
        "credential".into(),
        ProviderPreconditionGuaranteeV1::LastLocalCheckOnly
    )
    .is_err());
    Ok(())
}

#[test]
fn submission_owner_is_send_for_the_supervised_kernel_task() {
    fn requires_send<T: Send>() {}
    requires_send::<CapturedSemanticSubmissionV1>();
}
