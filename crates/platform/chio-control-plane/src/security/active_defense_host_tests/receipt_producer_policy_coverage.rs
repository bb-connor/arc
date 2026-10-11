use super::*;
use crate::security::event_consumer::TrustedSecurityEventReceiptProducer;
use crate::security::{ProductionActiveDefenseBuildError, ProductionActiveDefenseHostError};

const DETECTOR_AND_EVENT_TABLES: [&str; 11] = [
    "security_event_ids",
    "security_verified_events",
    "security_advisory_events",
    "security_correlation_ingress",
    "security_ingress_rejections",
    "security_correlation_events",
    "security_correlation_partition_heads",
    "security_correlation_partials",
    "security_correlation_outcomes",
    "security_attested_finding_batches",
    "security_attested_finding_batch_items",
];

fn detector_and_event_rows(fixture: &HostFixture) -> Vec<(&'static str, i64)> {
    let connection = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open detector and event inspection: {error}"));
    DETECTOR_AND_EVENT_TABLES
        .iter()
        .map(|table| {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            (*table, count)
        })
        .collect()
}

fn with_receipt_producer_pinned_to(
    fixture: &HostFixture,
    policy_version: &str,
) -> ProductionActiveDefenseHostConfig {
    let mut config = fixture.config.clone();
    config.active_defense.trusted_event_receipt_producers =
        vec![TrustedSecurityEventReceiptProducer {
            tenant_id: TenantId::new("tenant-host-lifecycle")
                .unwrap_or_else(|error| panic!("tenant: {error}")),
            producer_id: ProducerId::new("host-lifecycle-receipt-producer")
                .unwrap_or_else(|error| panic!("receipt producer: {error}")),
            signer_key_id: RecordId::new("host-lifecycle-receipt-key")
                .unwrap_or_else(|error| panic!("receipt key id: {error}")),
            policy_version: RecordId::new(policy_version)
                .unwrap_or_else(|error| panic!("receipt policy: {error}")),
            signer_key: Keypair::from_seed(&[92_u8; 32]).public_key(),
        }];
    config
}

#[tokio::test]
async fn production_host_requires_a_correlated_receipt_producer_policy_pin() {
    let fixture = HostFixture::new();
    let untouched = detector_and_event_rows(&fixture);
    assert!(
        untouched.iter().all(|(_, count)| *count == 0),
        "fresh store already holds detector or event rows: {untouched:?}"
    );

    for policy_version in ["host-lifecycle-uncorrelated-policy", "*"] {
        let error = match ProductionActiveDefenseHost::start(
            Arc::clone(&fixture.registry),
            with_receipt_producer_pinned_to(&fixture, policy_version),
        )
        .await
        {
            Ok(_) => panic!("a receipt producer pinned to {policy_version} started the host"),
            Err(error) => error,
        };
        assert!(
            matches!(
                &error,
                ProductionActiveDefenseHostError::Build(ProductionActiveDefenseBuildError::Port(
                    port
                )) if port.kind() == PortErrorKind::InvalidData
                    && port.code().as_str() == "store.invalid_data"
            ),
            "{policy_version}: {error}"
        );
        assert!(
            fixture.registry.snapshot().is_none(),
            "{policy_version} published services"
        );
        assert_eq!(
            detector_and_event_rows(&fixture),
            untouched,
            "{policy_version} left detector or event state"
        );
        assert_eq!(fixture.security_event_count(), 0, "{policy_version}");
    }

    let mut host = ProductionActiveDefenseHost::start(
        Arc::clone(&fixture.registry),
        with_receipt_producer_pinned_to(&fixture, "host-lifecycle-policy"),
    )
    .await
    .unwrap_or_else(|error| panic!("receipt producer pinned to a correlated policy: {error}"));
    host.ensure_ready()
        .unwrap_or_else(|error| panic!("host with a correlated receipt pin is not ready: {error}"));
    let installed = fixture
        .registry
        .snapshot()
        .unwrap_or_else(|| panic!("published services missing"));
    let exact: Arc<dyn ActiveDefenseServices> = host.orchestrator().clone();
    assert!(Arc::ptr_eq(&installed, &exact));
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));
    assert!(fixture.registry.snapshot().is_none());
}
