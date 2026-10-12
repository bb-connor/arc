use super::*;
use crate::security::{
    ProductionActiveDefenseBuildError, ProductionActiveDefenseHostError,
    TrustedSecurityEventReceiptProducer,
};

fn extra_event_producer(tenant: &str, producer: &str) -> TrustedSecurityEventProducer {
    TrustedSecurityEventProducer {
        tenant_id: TenantId::new(tenant).unwrap_or_else(|error| panic!("tenant: {error}")),
        producer_id: ProducerId::new(producer).unwrap_or_else(|error| panic!("producer: {error}")),
        producer_key_id: RecordId::new(format!("{producer}-key"))
            .unwrap_or_else(|error| panic!("producer key id: {error}")),
        policy_version: RecordId::new("host-lifecycle-policy")
            .unwrap_or_else(|error| panic!("event policy: {error}")),
        producer_key: Keypair::from_seed(&[92_u8; 32]).public_key(),
    }
}

fn extra_receipt_producer(tenant: &str, producer: &str) -> TrustedSecurityEventReceiptProducer {
    TrustedSecurityEventReceiptProducer {
        tenant_id: TenantId::new(tenant).unwrap_or_else(|error| panic!("tenant: {error}")),
        producer_id: ProducerId::new(producer).unwrap_or_else(|error| panic!("producer: {error}")),
        signer_key_id: RecordId::new(format!("{producer}-signer"))
            .unwrap_or_else(|error| panic!("receipt signer key id: {error}")),
        policy_version: RecordId::new("host-lifecycle-policy")
            .unwrap_or_else(|error| panic!("receipt policy: {error}")),
        signer_key: Keypair::from_seed(&[93_u8; 32]).public_key(),
    }
}

async fn assert_host_refuses_producer_tenant(
    fixture: &HostFixture,
    config: ProductionActiveDefenseHostConfig,
) {
    match ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), config).await {
        Ok(_) => panic!("host started with a trusted producer outside the scheduler tenant"),
        Err(ProductionActiveDefenseHostError::Build(ProductionActiveDefenseBuildError::Port(
            error,
        ))) => assert_eq!(error.kind(), PortErrorKind::InvalidData),
        Err(error) => panic!("unexpected host start failure: {error}"),
    }
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn production_host_rejects_a_trusted_event_producer_outside_the_scheduler_tenant() {
    let fixture = HostFixture::new();
    let mut config = fixture.config.clone();
    config
        .active_defense
        .trusted_event_producers
        .push(extra_event_producer(
            "tenant-host-lifecycle-other",
            "host-lifecycle-other-producer",
        ));

    assert_host_refuses_producer_tenant(&fixture, config).await;
}

#[tokio::test]
async fn production_host_rejects_a_trusted_receipt_producer_outside_the_scheduler_tenant() {
    let fixture = HostFixture::new();
    let mut config = fixture.config.clone();
    config
        .active_defense
        .trusted_event_receipt_producers
        .push(extra_receipt_producer(
            "tenant-host-lifecycle-other",
            "host-lifecycle-other-receipt-producer",
        ));

    assert_host_refuses_producer_tenant(&fixture, config).await;
}

#[tokio::test]
async fn production_host_accepts_trusted_producers_bound_to_the_scheduler_tenant() {
    let fixture = HostFixture::new();
    let mut config = fixture.config.clone();
    config
        .active_defense
        .trusted_event_producers
        .push(extra_event_producer(
            "tenant-host-lifecycle",
            "host-lifecycle-second-producer",
        ));
    config
        .active_defense
        .trusted_event_receipt_producers
        .push(extra_receipt_producer(
            "tenant-host-lifecycle",
            "host-lifecycle-receipt-producer",
        ));

    let mut host = ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), config)
        .await
        .unwrap_or_else(|error| panic!("start host with scheduler-tenant producers: {error}"));
    assert!(fixture.registry.snapshot().is_some());
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));
    assert!(fixture.registry.snapshot().is_none());
}
