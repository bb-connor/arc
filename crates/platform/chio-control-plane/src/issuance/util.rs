pub(in crate::issuance) fn unix_now() -> Result<u64, chio_security_types::clock::ClockError> {
    use chio_security_types::clock::{Clock, SystemClock};
    SystemClock.unix_millis().map(|now| now.as_secs())
}
