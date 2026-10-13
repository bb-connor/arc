//! Session lifecycle tuning is read from the environment and refuses malformed values.
use super::*;

fn policy_from(vars: &[(&str, &str)]) -> Result<SessionLifecyclePolicy, CliError> {
    let vars: HashMap<String, std::ffi::OsString> = vars
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).into()))
        .collect();
    SessionLifecyclePolicy::from_lookup(|name| vars.get(name).cloned())
}

fn refusal(name: &str) -> String {
    CliError::cli_other_error(format!(
        "{name} must be a positive integer number of milliseconds"
    ))
    .to_string()
}

#[test]
fn unset_variables_take_the_defaults() {
    let policy = policy_from(&[]).expect("default policy");
    let defaults = SessionLifecyclePolicy::default();
    assert_eq!(
        policy.idle_expiry_millis,
        DEFAULT_SESSION_IDLE_EXPIRY_MILLIS
    );
    assert_eq!(policy.drain_grace_millis, defaults.drain_grace_millis);
    assert_eq!(
        policy.reaper_interval_millis,
        defaults.reaper_interval_millis
    );
    assert_eq!(
        policy.tombstone_retention_millis,
        defaults.tombstone_retention_millis
    );
    assert_eq!(
        policy.request_response_timeout_millis,
        DEFAULT_REQUEST_RESPONSE_TIMEOUT_MILLIS
    );
}

#[test]
fn set_variables_override_each_bound() {
    let policy = policy_from(&[
        (SESSION_IDLE_EXPIRY_ENV, "11"),
        (SESSION_DRAIN_GRACE_ENV, "12"),
        (SESSION_REAPER_INTERVAL_ENV, "13"),
        (SESSION_TOMBSTONE_RETENTION_ENV, "14"),
        (REQUEST_RESPONSE_TIMEOUT_ENV, "15"),
    ])
    .expect("tuned policy");
    assert_eq!(policy.idle_expiry_millis, 11);
    assert_eq!(policy.drain_grace_millis, 12);
    assert_eq!(policy.reaper_interval_millis, 13);
    assert_eq!(policy.tombstone_retention_millis, 14);
    assert_eq!(policy.request_response_timeout_millis, 15);
}

#[test]
fn malformed_values_refuse_the_policy_instead_of_taking_the_default() {
    for name in [
        SESSION_IDLE_EXPIRY_ENV,
        SESSION_DRAIN_GRACE_ENV,
        SESSION_REAPER_INTERVAL_ENV,
        SESSION_TOMBSTONE_RETENTION_ENV,
        REQUEST_RESPONSE_TIMEOUT_ENV,
    ] {
        for value in ["", "0", "-5", "1.5", "15m", " 10", "18446744073709551616"] {
            let error = policy_from(&[(name, value)])
                .err()
                .unwrap_or_else(|| panic!("{name}={value:?} must be refused"));
            assert_eq!(error.to_string(), refusal(name), "{name}={value:?}");
        }
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_value_refuses_the_policy() {
    use std::os::unix::ffi::OsStringExt;
    let error = SessionLifecyclePolicy::from_lookup(|name| {
        (name == SESSION_IDLE_EXPIRY_ENV).then(|| std::ffi::OsString::from_vec(vec![0x31, 0xff]))
    })
    .expect_err("non-UTF-8 value must be refused");
    assert_eq!(error.to_string(), refusal(SESSION_IDLE_EXPIRY_ENV));
}
