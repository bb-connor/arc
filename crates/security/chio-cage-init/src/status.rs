use super::{
    is_status_socket, write_packet, BootstrapFault, CageEnforcementFailure,
    CageEnforcementFailureCode, RawFd, StatusRecord, SystemTime, STATUS_FD, STATUS_RECORD_SCHEMA,
    UNIX_EPOCH,
};

pub(super) fn write_failure_record(fault: &BootstrapFault, fallback_fd: RawFd) {
    let record = StatusRecord::Failure {
        schema: STATUS_RECORD_SCHEMA.to_string(),
        failure: CageEnforcementFailure {
            code: fault.code,
            stage: fault.stage.to_string(),
        },
    };
    if let Ok(bytes) = chio_cage_plan::canonical_json_bytes(&record) {
        if is_status_socket(fallback_fd) {
            let _ = write_packet(fallback_fd, &bytes);
        } else if is_status_socket(STATUS_FD) {
            let _ = write_packet(STATUS_FD, &bytes);
        }
    }
}

pub fn unix_time_ms() -> Result<u64, BootstrapFault> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "system_time",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        BootstrapFault::new(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "system_time",
        )
    })
}
