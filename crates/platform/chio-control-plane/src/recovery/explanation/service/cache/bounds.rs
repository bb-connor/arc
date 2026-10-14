use super::compact::CompactGraph;
use super::flat_label::FlatLabel;
use super::*;
use chio_kernel::recovery::MAX_RECOVERY_RECORD_BYTES;
use chio_security_types::flow::{DEFAULT_LABEL_LIMITS, MAX_FLOW_IDENTIFIER_BYTES};
use std::io::{self, Write};

pub(super) const NATIVE_FACTS: usize = 4;
pub(super) const NATIVE_TEMPLATES: usize = 1;
pub(super) const METADATA_BYTES: usize = MAX_RECOVERY_WIRE_BYTES;

fn invalid() -> RecoveryRuntimeError {
    RecoveryRuntimeError::UnsupportedProfile
}

fn add(a: usize, b: usize) -> Result<usize, RecoveryRuntimeError> {
    a.checked_add(b).ok_or_else(invalid)
}

fn mul(a: usize, b: usize) -> Result<usize, RecoveryRuntimeError> {
    a.checked_mul(b).ok_or_else(invalid)
}

/// Non-control identifiers need at most two JSON bytes per UTF-8 byte.
/// Include all owner/reader/compartment delimiters and the known-label envelope.
pub(super) fn maximum_label_wire_bytes() -> Result<usize, RecoveryRuntimeError> {
    let limits = DEFAULT_LABEL_LIMITS;
    let quoted = add(mul(MAX_FLOW_IDENTIFIER_BYTES, 2)?, 2)?;
    let readers = limits.max_readers_per_owner();
    let owner = add(
        add(quoted, 3)?,
        add(mul(readers, quoted)?, readers.saturating_sub(1))?,
    )?;
    let owners = limits.max_owners();
    let compartments = limits.max_compartments();
    let mut bytes = b"{\"kind\":\"known\",\"owners\":{},\"compartments\":[]}".len();
    for amount in [
        mul(owners, owner)?,
        owners.saturating_sub(1),
        mul(compartments, quoted)?,
        compartments.saturating_sub(1),
    ] {
        bytes = add(bytes, amount)?;
    }
    Ok(bytes)
}

pub(super) fn maximum_wire_bytes() -> Result<usize, RecoveryRuntimeError> {
    add(
        add(maximum_label_wire_bytes()?, MAX_RECOVERY_RECORD_BYTES)?,
        METADATA_BYTES,
    )
}

/// Account service-owned payload rather than retaining repeated BTree labels.
/// Extra profile labels have bounded canonical size; flat spans are at most
/// three times their corresponding JSON payload. Fixed metadata accounts for
/// delimiter edges, typed headers, Arc controls and all native collections.
pub(super) fn reservation_bytes() -> Result<usize, RecoveryRuntimeError> {
    let mut bytes = FlatLabel::maximum_resident_bytes()?;
    for amount in [
        mul(MAX_RECOVERY_RECORD_BYTES, 3)?,
        METADATA_BYTES,
        core::mem::size_of::<CompactGraph>(),
        core::mem::size_of::<ProtectedRecoveryExplanationV1>(),
        mul(
            NATIVE_FACTS,
            core::mem::size_of::<RecoveryExplanationFactV1>(),
        )?,
        mul(
            NATIVE_TEMPLATES,
            core::mem::size_of::<RecoveryRemedyTemplateV1>(),
        )?,
        mul(NATIVE_FACTS, core::mem::size_of::<ObservationId>())?,
        core::mem::size_of::<ExplanationCandidateV1>(),
        mul(3, core::mem::size_of::<FlatLabel>())?,
        mul(8, core::mem::size_of::<usize>())?,
    ] {
        bytes = add(bytes, amount)?;
    }
    Ok(bytes)
}

struct Counter {
    bytes: usize,
    ceiling: usize,
}
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= self.ceiling)
            .ok_or_else(|| io::Error::other("advisory cache profile exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn measure<T: serde::Serialize>(
    value: &T,
    ceiling: usize,
) -> Result<usize, RecoveryRuntimeError> {
    let mut counter = Counter { bytes: 0, ceiling };
    serde_json::to_writer(&mut counter, value).map_err(|_| invalid())?;
    Ok(counter.bytes)
}
