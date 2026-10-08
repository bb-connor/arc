//! Every production recovery digest domain has a single registered meaning.
use chio_core_types::{
    canonical::CanonicalBytes,
    recovery::{RecoveryDigestDomain, RECOVERY_DIGEST_DOMAINS},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn production_digest_domains_are_complete_and_pinned_in_the_wire_inventory() -> TestResult {
    let required = [
        "chio.recovery.capability-body.v1",
        "chio.recovery.output-disposition.v1",
        "chio.recovery.deployment.v1",
        "chio.recovery.command.v1",
        "chio.recovery.source.v1",
        "chio.recovery.influence.v1",
        "chio.recovery.serving-fence.v1",
        "chio.recovery.provider-resource.v1",
        "chio.recovery.store-event.v1",
        "chio.recovery.protected-record.v1",
        "chio.recovery.semantic-policy.v1",
        "chio.recovery.authority-scope.v1",
        "chio.recovery.authority-coverage.v1",
        "chio.recovery.origin-claim.v1",
        "chio.recovery.planning-owner.v1",
        "chio.recovery.planning-reservation.v1",
        "chio.recovery.workflow-reservation.v1",
        "chio.recovery.setup.creation.v2",
        "chio.recovery.setup.source-profile.v2",
        "chio.semantic.registry.v1",
        "chio.semantic.role-key.v1",
        "chio.confined.capability.v1",
        "chio.isolation.boundary.v1",
        "chio.confined.launch.v1",
        "chio.confined.parent-control.v1",
        "chio.confined.evidence-binding.v1",
        "chio.knowledge.read-authority.v1",
        "chio.knowledge.influence.v1",
        "chio.knowledge.import-influence.v1",
        "chio.knowledge.observed-influence.v1",
        "chio.knowledge.semantic-influence.v1",
        "chio.artifact.archive.v1",
    ];
    for name in required {
        assert!(
            RECOVERY_DIGEST_DOMAINS.iter().any(|domain| {
                let prefix = domain.prefix();
                prefix.len() == name.len() + 1
                    && prefix[..name.len()] == *name.as_bytes()
                    && prefix[name.len()] == 0
            }),
            "production digest domain is missing from its central registry: {name}",
        );
    }
    let lock = include_str!("../../../../spec/wire-schemas.lock");
    let mut names = BTreeSet::new();
    let mut prefixes = BTreeSet::new();
    for domain in RECOVERY_DIGEST_DOMAINS {
        let prefix = domain.prefix();
        let name = core::str::from_utf8(&prefix[..prefix.len() - 1])?;
        assert_eq!(name, domain.name(), "domain framing and inventory diverged");
        assert!(names.insert(name), "duplicate domain name: {name}");
        assert!(prefixes.insert(prefix), "duplicate digest prefix: {name}");
        assert!(
            lock.contains(&format!("value = \"{name}\"")),
            "registered digest domain is not acknowledged by the wire inventory: {name}",
        );
    }
    Ok(())
}

#[test]
fn native_input_provenance_cannot_alias_output_or_status_provenance() -> TestResult {
    let input = RECOVERY_DIGEST_DOMAINS
        .iter()
        .find(|domain| domain.name() == "chio.semantic.native-input-origin.v1")
        .ok_or("native input provenance domain is missing")?;
    let body = CanonicalBytes::new(&serde_json::json!({"operation":"native-input"}))?;
    let actual = input.digest(&body);
    let mut expected = Sha256::new();
    expected.update(b"chio.semantic.native-input-origin.v1\0");
    expected.update(b"{\"operation\":\"native-input\"}");
    let expected: [u8; 32] = expected.finalize().into();
    assert_eq!(actual.as_bytes(), &expected);
    assert_ne!(
        actual,
        RecoveryDigestDomain::SemanticNativeOutputOrigin.digest(&body)
    );
    assert_ne!(
        actual,
        RecoveryDigestDomain::SemanticNativeStatusOrigin.digest(&body)
    );
    Ok(())
}
