std::thread_local! { static FIXTURE_COMMIT_TIME: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
pub(super) struct FixtureStatusCommitClock;
impl chio_security_types::clock::Clock for FixtureStatusCommitClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::FixedClock;
        FIXTURE_COMMIT_TIME.with(|time| FixedClock::new(time.get()).read())
    }
}
pub(super) fn fixture_commit_time(now: u64) -> u64 {
    FIXTURE_COMMIT_TIME.with(|time| time.set(now));
    now
}
