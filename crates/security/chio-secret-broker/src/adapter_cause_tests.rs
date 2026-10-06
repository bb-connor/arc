//! Native causes remain operator-owned while broker peer codes stay closed.
use crate::BrokerError;
use std::error::Error;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;
pub(crate) const PRIVATE: &str = "private-adapter-credential";

pub(crate) fn assert_public_error(error: &BrokerError, code: &str) {
    assert_eq!(error.diagnostic_code(), code);
    assert!(!format!("{error} {error:?}").contains(PRIVATE));
    let peer_code = format!("chio.broker.{}", error.diagnostic_code());
    assert!(crate::protocol::is_well_formed_broker_execute_diagnostic_code(&peer_code));
    let peer = serde_json::to_string(&serde_json::json!({"errorCode":peer_code}))
        .unwrap_or_else(|error| panic!("peer fixture encoding failed: {error}"));
    assert!(!peer.contains(PRIVATE));
}

pub(crate) fn native_cause<T: Error + 'static>(error: &BrokerError) -> TestResult<&T> {
    let mut source = error.source();
    for _ in 0..8 {
        let Some(cause) = source else { break };
        if let Some(cause) = cause.downcast_ref::<T>() {
            return Ok(cause);
        }
        source = cause.source();
    }
    Err("native adapter cause was discarded".into())
}
