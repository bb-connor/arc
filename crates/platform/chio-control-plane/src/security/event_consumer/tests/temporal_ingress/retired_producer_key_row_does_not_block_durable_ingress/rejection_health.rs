use super::*;
use crate::security::CorrelationIngressRejectionHealth;

#[test]
fn a_rejected_ingress_row_is_counted_by_reason_and_durably_after_restart() {
    let retired = Keypair::from_seed(&[121_u8; 32]);
    let rotated = Keypair::from_seed(&[122_u8; 32]);
    let bystander = Keypair::from_seed(&[123_u8; 32]);
    let fixture = deferred_row_signed_by(&retired, &bystander);
    let producers = || {
        vec![
            trusted_detector(tenant(), "detector-key-v2", &rotated),
            trusted_detector(bystander_tenant(), "bystander-key-v1", &bystander),
        ]
    };
    fixture.clock.set(10_500);
    let after = start_runtime(&fixture.store, &fixture.clock, producers());
    let before_drain = after.drainer.rejection_health();

    let drained = after
        .drainer
        .drain_pass(16)
        .unwrap_or_else(|error| panic!("drain past the retired-key row: {error}"));
    let after_drain = after.drainer.rejection_health();
    let restarted = start_runtime(&fixture.store, &fixture.clock, producers());

    assert_eq!(before_drain, CorrelationIngressRejectionHealth::default());
    assert_eq!(drained.rejected, 1);
    assert_eq!(
        after_drain,
        CorrelationIngressRejectionHealth {
            rejected_total: 1,
            unconfigured_producer: 0,
            unconfigured_producer_key: 1,
            unconfigured_policy_version: 0,
        }
    );
    assert_eq!(
        restarted.drainer.rejection_health(),
        CorrelationIngressRejectionHealth {
            rejected_total: 1,
            ..CorrelationIngressRejectionHealth::default()
        }
    );
}
