//! Recovery destinations require declared network policy before credentials can leave the host.
use chio_control_plane::{
    recovery::PinnedSupportIssueConnector,
    semantic::{HttpSemanticTransport, ProviderPreconditionGuaranteeV1},
};
use chio_core_types::Keypair;
use chio_egress_contract::HttpEgressContract;
use chio_kernel::recovery::{RecordName, RecoveryEffectContractSchema, RecoveryEffectContractV1};
use chio_security_types::{recovery::*, semantic::*};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const RESTRICTED_ENDPOINTS: &[&str] = &[
    "https://localhost/issues",
    "https://127.0.0.1/issues",
    "https://[::1]/issues",
    "https://169.254.169.254/issues",
    "https://[fe80::1]/issues",
    "https://[fd00::1]/issues",
    "https://10.0.0.1/issues",
    "https://192.168.1.1/issues",
    "https://[::ffff:7f00:1]/issues",
    "https://[::ffff:a00:1]/issues",
];

fn network_policy(endpoint: &str) -> TestResult<HttpEgressContract> {
    let url = reqwest::Url::parse(endpoint)?;
    let host = match url.host().ok_or("host")? {
        url::Host::Domain(host) => host.to_owned(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => format!("[{address}]"),
    };
    Ok(HttpEgressContract {
        tenant_egress_namespace: "tests.recovery.network".to_owned(),
        allowed_schemes: std::collections::BTreeSet::from(["https".to_owned()]),
        allowed_authority_set: std::collections::BTreeSet::from([format!(
            "{host}:{}",
            url.port_or_known_default().ok_or("port")?
        )]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 3,
        max_response_bytes: 65536,
    })
}

fn effect_contract(endpoint: &str) -> TestResult<RecoveryEffectContractV1> {
    Ok(RecoveryEffectContractV1 {
        schema: RecoveryEffectContractSchema::V1,
        provider: RecordName::new("provider")?,
        account: RecordName::new("account")?,
        resource: ProtectedText::new(endpoint)?,
        observation_key: Keypair::from_seed(&[17; 32]).public_key(),
        max_response_bytes: SafeInteger::new(65536)?,
    })
}

fn semantic_destination(endpoint: &str) -> TestResult<SemanticDestinationV1> {
    Ok(SemanticDestinationV1 {
        destination: SemanticDestinationId::new("destination")?,
        provider: ProviderId::new("provider")?,
        account: ProviderAccountId::new("account")?,
        resource: ProviderResourceId::new("resource")?,
        endpoint: ProtectedText::new(endpoint)?,
        audience: chio_security_types::flow::InformationLabel::bottom(),
        purpose: ProtectedText::new("support")?,
        subject_mapping: CanonicalPayloadDigest::from_bytes([1; 32]),
        acl_query: CanonicalPayloadDigest::from_bytes([2; 32]),
        require_provider_precondition: true,
    })
}

#[test]
fn issue_connector_refuses_nonpublic_sinks_without_network_authorization() -> TestResult {
    let mut accepted = Vec::new();
    for endpoint in RESTRICTED_ENDPOINTS {
        if PinnedSupportIssueConnector::new(
            "issues".into(),
            "create".into(),
            effect_contract(endpoint)?,
            network_policy(endpoint)?,
            "submit-credential".into(),
            "lookup-credential".into(),
        )
        .is_ok()
        {
            accepted.push(*endpoint);
        }
    }
    assert!(
        accepted.is_empty(),
        "unauthorized nonpublic sinks accepted: {accepted:?}"
    );
    Ok(())
}

#[test]
fn semantic_transport_refuses_nonpublic_sinks_without_network_authorization() -> TestResult {
    let mut accepted = Vec::new();
    for endpoint in RESTRICTED_ENDPOINTS {
        if HttpSemanticTransport::new(
            semantic_destination(endpoint)?,
            network_policy(endpoint)?,
            "provider-credential".into(),
            ProviderPreconditionGuaranteeV1::AtomicIfMatch,
        )
        .is_ok()
        {
            accepted.push(*endpoint);
        }
    }
    assert!(
        accepted.is_empty(),
        "unauthorized nonpublic sinks accepted: {accepted:?}"
    );
    Ok(())
}

fn connectors_accept(endpoint: &str, network: &HttpEgressContract) -> TestResult<(bool, bool)> {
    Ok((
        PinnedSupportIssueConnector::new(
            "issues".into(),
            "create".into(),
            effect_contract(endpoint)?,
            network.clone(),
            "submit-credential".into(),
            "lookup-credential".into(),
        )
        .is_ok(),
        HttpSemanticTransport::new(
            semantic_destination(endpoint)?,
            network.clone(),
            "provider-credential".into(),
            ProviderPreconditionGuaranteeV1::AtomicIfMatch,
        )
        .is_ok(),
    ))
}

#[test]
fn recovery_connectors_accept_explicit_native_local_network_policy() -> TestResult {
    for endpoint in [
        "https://127.0.0.1/issues",
        "https://[::1]/issues",
        "https://localhost/issues",
    ] {
        let mut network = network_policy(endpoint)?;
        assert_eq!(connectors_accept(endpoint, &network)?, (false, false));
        network.deny_loopback = false;
        assert_eq!(connectors_accept(endpoint, &network)?, (true, true));
    }
    Ok(())
}

#[test]
fn recovery_connectors_bind_the_declared_authority_and_effective_port() -> TestResult {
    let endpoint = "https://provider.example:8443/issues";
    let mut network = network_policy(endpoint)?;
    assert_eq!(connectors_accept(endpoint, &network)?, (true, true));
    for authority in [
        "provider.example",
        "provider.example:443",
        "provider.example:9443",
        "foreign.example:8443",
    ] {
        network.allowed_authority_set = std::collections::BTreeSet::from([authority.to_owned()]);
        assert_eq!(
            connectors_accept(endpoint, &network)?,
            (false, false),
            "undeclared authority accepted: {authority}"
        );
    }
    Ok(())
}

#[test]
fn recovery_connectors_refuse_missing_or_malformed_network_policy() -> TestResult {
    let endpoint = "https://provider.example/issues";
    for mutation in 0..4 {
        let mut network = network_policy(endpoint)?;
        match mutation {
            0 => network.tenant_egress_namespace.clear(),
            1 => network.allowed_authority_set.clear(),
            2 => network.allowed_schemes.clear(),
            _ => network.max_response_bytes = 0,
        }
        assert_eq!(connectors_accept(endpoint, &network)?, (false, false));
    }
    Ok(())
}
