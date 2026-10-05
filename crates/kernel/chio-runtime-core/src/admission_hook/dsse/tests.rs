use super::lease_matches_record;
use chio_federation::bilateral_dsse::{CapabilityLeaseRef, HashRecord};

fn lease() -> CapabilityLeaseRef {
    CapabilityLeaseRef {
        lease_id: "lease-live".into(),
        issuer: "did:chio:issuer".into(),
        expires_at_unix_ms: 100,
        scope_digest: Some(HashRecord {
            alg: "sha256".into(),
            value: "a".repeat(64),
        }),
    }
}

#[test]
fn each_reference_binding_is_checked_independently_of_store_validation() {
    let original = lease();
    assert!(lease_matches_record("lease-live", &original, &original));
    for field in 0..4 {
        let mut changed = original.clone();
        match field {
            0 => changed.lease_id = "other".into(),
            1 => changed.issuer = "did:chio:other".into(),
            2 => changed.scope_digest = None,
            _ => {
                changed.scope_digest = Some(HashRecord {
                    alg: "sha256".into(),
                    value: "b".repeat(64),
                })
            }
        }
        assert!(!lease_matches_record("lease-live", &changed, &original));
        assert!(!lease_matches_record("lease-live", &original, &changed));
    }
    assert!(!lease_matches_record("other", &original, &original));
    let mut shorter = original.clone();
    shorter.expires_at_unix_ms = 99;
    assert!(lease_matches_record("lease-live", &original, &shorter));
    assert!(!lease_matches_record("lease-live", &shorter, &original));
}

#[test]
fn agreeing_malformed_scope_is_still_rejected() {
    let mut value = lease();
    for (alg, digest) in [("sha512", "a".repeat(64)), ("sha256", "not-hex".into())] {
        value.scope_digest = Some(HashRecord {
            alg: alg.into(),
            value: digest,
        });
        assert!(!lease_matches_record("lease-live", &value, &value));
    }
    value.scope_digest = None;
    assert!(lease_matches_record("lease-live", &value, &value));
}
