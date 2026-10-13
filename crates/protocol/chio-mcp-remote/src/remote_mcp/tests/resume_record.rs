//! The signed resume record authenticates every field it restores from.
use super::*;

fn subscription(uri: &str) -> PersistedSubscription {
    PersistedSubscription::Standard {
        uri: uri.into(),
        capability_id: "capability-subscribe".into(),
    }
}

fn subscribed_record(keyring: &RemoteSessionHmacKeyring) -> RemoteSessionResumeRecord {
    let mut record = sample_resume_record_with_keyring(keyring);
    record.subscriptions = vec![subscription("file:///notes.txt")];
    sign_test_resume_record(record, keyring)
}

#[test]
fn the_record_authenticates_its_subscriptions() {
    let keyring = test_resume_hmac_keyring();
    let record = subscribed_record(&keyring);
    validate_resume_record_integrity_with_keyring(&keyring, &record, 11).unwrap();

    let mut stripped = record.clone();
    stripped.subscriptions.clear();
    assert!(validate_resume_record_integrity_with_keyring(&keyring, &stripped, 11).is_err());

    let mut swapped = record;
    swapped.subscriptions = vec![subscription("file:///other.txt")];
    assert!(validate_resume_record_integrity_with_keyring(&keyring, &swapped, 11).is_err());
}

#[test]
fn a_record_without_its_subscription_set_is_refused() {
    let keyring = test_resume_hmac_keyring();
    let mut encoded = serde_json::to_value(subscribed_record(&keyring)).unwrap();
    encoded.as_object_mut().unwrap().remove("subscriptions");
    assert!(serde_json::from_value::<RemoteSessionResumeRecord>(encoded).is_err());
}
