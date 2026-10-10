//! Bounded observation input. One failed line aborts before capture or persistence.
use crate::runner::{Observation, RunnerError};
use chio_core::canonical::UntrustedJsonText;
use std::io::{BufRead, Read};

pub(crate) const MAX_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn next(reader: &mut impl BufRead) -> Result<Option<Observation>, RunnerError> {
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take((MAX_OBSERVATION_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(RunnerError::InputIo)?;
        if read == 0 {
            return Ok(None);
        }
        // The bound includes the line terminator and is checked before trim/parse.
        let input = UntrustedJsonText::from_wire(&line, MAX_OBSERVATION_BYTES)?;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        return input.decode_signed().map(Some).map_err(RunnerError::from);
    }
}
