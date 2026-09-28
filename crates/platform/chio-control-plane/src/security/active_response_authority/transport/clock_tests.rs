use super::*;
use chio_security_types::clock::{ClockError, ClockReading, UnixMillis};
use std::sync::Mutex;

struct ScriptedClock(Mutex<Result<ClockReading, ClockError>>);
impl Clock for ScriptedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}

#[test]
fn ipc_deadline_refuses_bad_time_before_writing_any_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let initial = ClockReading::new(UnixMillis::new(1000), MonotonicInstant::from_nanos(0));
    for (bad, reason) in [
        (Err(ClockError::Unavailable), ClockError::Unavailable),
        (
            Ok(ClockReading::new(
                UnixMillis::new(999),
                MonotonicInstant::from_nanos(1),
            )),
            ClockError::WallClockRegression,
        ),
        (
            Ok(ClockReading::new(
                UnixMillis::new(1000),
                MonotonicInstant::from_nanos(10_000_000),
            )),
            ClockError::Expired,
        ),
        (
            Ok(ClockReading::new(
                UnixMillis::new(1010),
                MonotonicInstant::from_nanos(1),
            )),
            ClockError::Expired,
        ),
    ] {
        let clock = Arc::new(ScriptedClock(Mutex::new(Ok(initial))));
        let (stream, mut peer) = UnixStream::pair()?;
        peer.set_nonblocking(true)?;
        let mut stream =
            AbsoluteDeadlineUnixStream::new(stream, Duration::from_millis(10), clock.clone())?;
        *clock.0.lock().map_err(|_| ClockError::Unavailable)? = bad;
        let error = stream
            .write(b"effect")
            .err()
            .ok_or("expired write unexpectedly succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            error.get_ref().and_then(|e| e.downcast_ref::<ClockError>()),
            Some(&reason)
        );
        let mut bytes = [0; 6];
        assert_eq!(
            peer.read(&mut bytes).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
    }
    Ok(())
}
