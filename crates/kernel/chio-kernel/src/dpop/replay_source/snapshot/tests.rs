use super::*;
use crate::admission_operation::AdmissionIdentifier;
use crate::dpop::{replay_source::DpopReplaySourcePort, DpopNonceStore};
use std::time::Duration;

fn snapshot() -> DpopReplaySourceSnapshot {
    let store = DpopNonceStore::new_with_per_capability_capacity(8, 4, Duration::from_secs(60));
    store
        .check_and_insert_through("a-private-nonce", "cap", u64::MAX)
        .unwrap();
    store
        .check_and_insert_through("b-private-nonce", "cap", u64::MAX)
        .unwrap();
    store
        .preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: AdmissionIdentifier::try_new("authority", "authority").unwrap(),
            destination_authority_id: AdmissionIdentifier::try_new("destination", "destination")
                .unwrap(),
        })
        .unwrap()
}

#[test]
fn decoder_rejects_noncanonical_duplicate_unknown_and_oversized_data() {
    let snapshot = snapshot();
    let bytes = snapshot.canonical_bytes().unwrap();
    let mut spaced = bytes.clone();
    spaced.push(b' ');
    assert!(DpopReplaySourceSnapshot::from_canonical_bytes(&spaced).is_err());
    let text = String::from_utf8(bytes.clone()).unwrap();
    let duplicate = text.replacen(
        "\"schema\":",
        &format!("\"schema\":\"{SCHEMA}\",\"schema\":"),
        1,
    );
    assert!(DpopReplaySourceSnapshot::from_canonical_bytes(duplicate.as_bytes()).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["body"]["restored"] = true.into();
    assert!(DpopReplaySourceSnapshot::from_canonical_bytes(
        &canonical_json_bytes(&unknown).unwrap()
    )
    .is_err());
    assert!(DpopReplaySourceSnapshot::from_canonical_bytes(&[]).is_err());
    assert!(DpopReplaySourceSnapshot::from_canonical_bytes(&vec![
        b' ';
        MAX_DPOP_REPLAY_SOURCE_BYTES + 1
    ])
    .is_err());
}

#[test]
fn decoder_revalidates_digest_and_inventory_even_with_a_recomputed_digest() {
    let snapshot = snapshot();
    let mut envelope = snapshot.0.clone();
    envelope.body.inventory.markers[0].nonce = "changed-private-nonce".to_owned();
    assert!(DpopReplaySourceSnapshot::from_canonical_bytes(
        &canonical_json_bytes(&envelope).unwrap()
    )
    .is_err());
    for change in 0..10 {
        let mut envelope = snapshot.0.clone();
        let inventory = &mut envelope.body.inventory;
        match change {
            0 => inventory.revision = "01".to_owned(),
            1 => inventory.capacity = "0".to_owned(),
            2 => inventory.per_capability_capacity = "1".to_owned(),
            3 => inventory.monotonic_high_water_offset_ns = "-0".to_owned(),
            4 => inventory.markers.swap(0, 1),
            5 => inventory.markers[1] = inventory.markers[0].clone(),
            6 => inventory.pruned_through_unix_ns = Some(u128::MAX.to_string()),
            7 => inventory.created_unix_ns = u128::MAX.to_string(),
            8 => inventory.markers[0].nonce = "x".repeat(MAX_KEY_BYTES + 1),
            9 => inventory.revision = u128::MAX.to_string(),
            _ => unreachable!(),
        }
        envelope.inventory_sha256 = digest(&envelope.body).unwrap();
        assert!(
            DpopReplaySourceSnapshot::from_canonical_bytes(
                &canonical_json_bytes(&envelope).unwrap()
            )
            .is_err(),
            "mutation {change}"
        );
    }
}

#[test]
fn retention_clock_data_is_exact_and_never_collapses_local_into_signed() {
    let snapshot = snapshot();
    let mut body = snapshot.0.body;
    for retention in [
        DpopReplaySourceRetention::Local {
            monotonic_deadline_offset_ns: None,
        },
        DpopReplaySourceRetention::Local {
            monotonic_deadline_offset_ns: Some(i128::MAX.to_string()),
        },
        DpopReplaySourceRetention::Signed {
            exclusive_unix_ns: Some(u128::MAX.to_string()),
            monotonic_deadline_offset_ns: None,
        },
        DpopReplaySourceRetention::Signed {
            exclusive_unix_ns: None,
            monotonic_deadline_offset_ns: Some("-1".to_owned()),
        },
    ] {
        body.inventory.markers[0].retention = retention;
        let candidate = DpopReplaySourceSnapshot::new(body.clone()).unwrap();
        assert_eq!(
            DpopReplaySourceSnapshot::from_canonical_bytes(&candidate.canonical_bytes().unwrap())
                .unwrap(),
            candidate
        );
    }
    body.inventory.markers[0].retention = DpopReplaySourceRetention::Signed {
        exclusive_unix_ns: Some("-1".to_owned()),
        monotonic_deadline_offset_ns: None,
    };
    assert!(DpopReplaySourceSnapshot::new(body).is_err());
}

#[test]
fn domain_transition_clock_rounds_conservatively_without_changing_retention() {
    let snapshot = snapshot();
    let high = unsigned(&snapshot.0.body.inventory.wall_clock_high_water_unix_ns).unwrap();
    let ceiling_ms = u64::try_from(high.div_ceil(1_000_000)).unwrap();
    let before = snapshot.canonical_bytes().unwrap();
    assert!(snapshot.validate_transition_time(ceiling_ms - 1).is_err());
    snapshot.validate_transition_time(ceiling_ms).unwrap();
    snapshot.validate_transition_time(ceiling_ms + 1).unwrap();
    assert_eq!(snapshot.canonical_bytes().unwrap(), before);
}

#[test]
fn even_valid_reencoded_data_is_not_a_live_seal() {
    let first = snapshot();
    let mut body = first.0.body.clone();
    body.binding.destination_authority_id =
        AdmissionIdentifier::try_new("destination", "substituted").unwrap();
    let substituted = DpopReplaySourceSnapshot::new(body).unwrap();
    assert_ne!(first.inventory_sha256(), substituted.inventory_sha256());
    let fresh = DpopNonceStore::new(8, Duration::from_secs(60));
    assert!(fresh.seal_exact(&substituted).is_err());
    assert!(fresh.verify_exact(&substituted).is_err());
}
