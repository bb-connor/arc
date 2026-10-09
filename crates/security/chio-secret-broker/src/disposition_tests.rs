//! One disposition per broker error: request faults are contained, and only
//! faults in the broker's own state or custody are fatal.

use chio_core_types::canonical::UntrustedJsonError;
use chio_custody_store::BlobStoreError;
use chio_security_types::clock::ClockError;

use super::*;

#[test]
fn every_broker_error_has_one_disposition() {
    use BrokerFaultDisposition::{Deny, Fatal, Reject, Retry};

    let unavailable =
        |source| BrokerError::CredentialUnavailable(CredentialStoreError::for_test(source));
    let corrupt = |source| BrokerError::CredentialStorage(CredentialStoreError::for_test(source));
    let cases = [
        (
            BrokerError::UntrustedInput(UntrustedJsonError::NonCanonical),
            Reject,
        ),
        (BrokerError::InvalidRequest("malformed".into()), Reject),
        (BrokerError::AuthorizationDenied("denied".into()), Reject),
        (BrokerError::Conflict("conflict".into()), Reject),
        (unavailable(BlobStoreError::NotFound), Deny),
        (BrokerError::ResponseRejected("rejected".into()), Deny),
        (BrokerError::Clock(ClockError::Expired), Deny),
        (BrokerError::Clock(ClockError::NotYetValid), Deny),
        (BrokerError::Clock(ClockError::InvalidWindow), Deny),
        (BrokerError::Clock(ClockError::Unavailable), Retry),
        (BrokerError::Clock(ClockError::MonotonicRegression), Retry),
        (BrokerError::AuthorityUnavailable("offline".into()), Retry),
        (BrokerError::Upstream("offline".into()), Retry),
        (BrokerError::Invariant("broken".into()), Fatal),
        (BrokerError::Storage("broken".into()), Fatal),
        (corrupt(BlobStoreError::InvalidReference), Fatal),
        (corrupt(BlobStoreError::Sqlite("corrupt".into())), Fatal),
        (BrokerError::Custody("replaced".into()), Fatal),
    ];
    for (error, expected) in cases {
        assert_eq!(error.disposition(), expected, "{error:?}");
        assert_eq!(error.is_service_fault(), expected == Fatal, "{error:?}");
    }
}
