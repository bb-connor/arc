//! Resume records verify only under the integrity envelope they name.
use super::*;

fn subscription(uri: &str) -> PersistedSubscription {
    PersistedSubscription::Standard {
        uri: uri.into(),
        capability_id: "capability-subscribe".into(),
    }
}

fn sign_v3(
    mut record: RemoteSessionResumeRecord,
    keyring: &RemoteSessionHmacKeyring,
) -> RemoteSessionResumeRecord {
    record.resume_integrity = keyring.empty_tag_for_current();
    record.resume_integrity.envelope = RemoteSessionEnvelope::V3;
    record.resume_integrity.tag = compute_resume_record_integrity_tag(&keyring.current, &record)
        .expect("sign v3 resume record");
    record
}

#[test]
fn v2_record_keeps_its_bytes_and_verifies() {
    let keyring = test_resume_hmac_keyring();
    let record = sample_resume_record_with_keyring(&keyring);
    let encoded = serde_json::to_value(&record).unwrap();
    assert!(encoded["resume_integrity"].get("envelope").is_none());
    assert!(encoded.get("subscriptions").is_none());
    let decoded: RemoteSessionResumeRecord = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.resume_integrity.envelope, RemoteSessionEnvelope::V2);
    validate_resume_record_integrity_with_keyring(&keyring, &decoded, 11).unwrap();
}

#[test]
fn v3_record_authenticates_its_subscriptions() {
    let keyring = test_resume_hmac_keyring();
    let mut record = sample_resume_record_with_keyring(&keyring);
    record.subscriptions = vec![subscription("file:///notes.txt")];
    let record = sign_v3(record, &keyring);
    assert_eq!(
        serde_json::to_value(&record).unwrap()["resume_integrity"]["envelope"],
        "v3"
    );
    validate_resume_record_integrity_with_keyring(&keyring, &record, 11).unwrap();

    let mut stripped = record.clone();
    stripped.subscriptions.clear();
    assert!(validate_resume_record_integrity_with_keyring(&keyring, &stripped, 11).is_err());

    let mut swapped = record.clone();
    swapped.subscriptions = vec![subscription("file:///other.txt")];
    assert!(validate_resume_record_integrity_with_keyring(&keyring, &swapped, 11).is_err());
}

#[test]
fn relabeled_or_v2_signed_subscriptions_are_refused() {
    let keyring = test_resume_hmac_keyring();
    let mut record = sample_resume_record_with_keyring(&keyring);
    record.subscriptions = vec![subscription("file:///notes.txt")];
    let signed = sign_v3(record.clone(), &keyring);

    let mut relabeled = signed;
    relabeled.resume_integrity.envelope = RemoteSessionEnvelope::V2;
    assert!(validate_resume_record_integrity_with_keyring(&keyring, &relabeled, 11).is_err());

    let v2_signed = sign_test_resume_record(record, &keyring);
    assert!(validate_resume_record_integrity_with_keyring(&keyring, &v2_signed, 11).is_err());
}

#[test]
fn v3_record_without_subscriptions_still_verifies_as_v3() {
    let keyring = test_resume_hmac_keyring();
    let record = sign_v3(sample_resume_record_with_keyring(&keyring), &keyring);
    validate_resume_record_integrity_with_keyring(&keyring, &record, 11).unwrap();
    let mut relabeled = record;
    relabeled.resume_integrity.envelope = RemoteSessionEnvelope::V2;
    assert!(validate_resume_record_integrity_with_keyring(&keyring, &relabeled, 11).is_err());
}

#[test]
fn envelope_selection_never_lowers() {
    let upgrade_window = ResumeEnvelopeRatchet::new(RemoteSessionEnvelope::V2);
    assert_eq!(upgrade_window.select(&[]), RemoteSessionEnvelope::V2);
    assert_eq!(
        upgrade_window.select(&[subscription("file:///notes.txt")]),
        RemoteSessionEnvelope::V3
    );
    assert_eq!(upgrade_window.select(&[]), RemoteSessionEnvelope::V3);

    let loaded_v3 = ResumeEnvelopeRatchet::new(RemoteSessionEnvelope::V2);
    loaded_v3.raise(RemoteSessionEnvelope::V3);
    assert_eq!(loaded_v3.select(&[]), RemoteSessionEnvelope::V3);
    loaded_v3.raise(RemoteSessionEnvelope::V2);
    assert_eq!(loaded_v3.select(&[]), RemoteSessionEnvelope::V3);

    let default_floor = ResumeEnvelopeRatchet::new(RemoteSessionEnvelope::V3);
    assert_eq!(default_floor.select(&[]), RemoteSessionEnvelope::V3);
}
