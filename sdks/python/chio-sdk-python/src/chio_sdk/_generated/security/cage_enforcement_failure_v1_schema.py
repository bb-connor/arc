# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 6a4145266d2febc07a862fffbc565f800ff133c6f0adb06aac524c0ff01e4f34
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, constr


class Code(Enum):
    unsupported_kernel = "unsupported_kernel"
    helper_identity_mismatch = "helper_identity_mismatch"
    invalid_plan_seals = "invalid_plan_seals"
    invalid_plan = "invalid_plan"
    descriptor_count_mismatch = "descriptor_count_mismatch"
    descriptor_identity_mismatch = "descriptor_identity_mismatch"
    privileged_executable = "privileged_executable"
    non_single_threaded_helper = "non_single_threaded_helper"
    execution_identity_invalid = "execution_identity_invalid"
    execution_identity_apply_failed = "execution_identity_apply_failed"
    execution_identity_mismatch = "execution_identity_mismatch"
    trace_handshake_failed = "trace_handshake_failed"
    landlock_unavailable = "landlock_unavailable"
    landlock_partial = "landlock_partial"
    seccomp_unavailable = "seccomp_unavailable"
    seccomp_architecture_mismatch = "seccomp_architecture_mismatch"
    seccomp_install_failed = "seccomp_install_failed"
    prepared_record_invalid = "prepared_record_invalid"
    exec_event_missing = "exec_event_missing"
    exec_identity_mismatch = "exec_identity_mismatch"
    status_protocol_violation = "status_protocol_violation"
    timeout = "timeout"
    child_exited_before_exec = "child_exited_before_exec"


class ChioCageEnforcementFailureV1(BaseModel):
    """
    Closed failure code and bounded stage identifier for a rejected, unsupported, or bootstrap-failed cage launch.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    code: Code
    stage: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=128,
    )
