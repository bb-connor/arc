//! Semantic request errors, independent of peer-controlled display text.
/// Identifier boundary rejected by the ACP edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpField {
    AgentId,
    TaskId,
    CapabilityId,
}
/// The precise identifier rule that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpFieldViolation {
    Missing,
    Type,
    Empty,
    Padded,
    Control,
}
/// Semantic request failures exposed as a stable, redacted wire code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("urn:chio:error:transport:invalid-request-shape")]
pub enum AcpRequestError {
    Field {
        field: AcpField,
        violation: AcpFieldViolation,
    },
    InvalidId,
    InvalidVersion,
    MissingMethod,
    ParamsObjectRequired,
    MixedApprovals,
    TooManyApprovals,
    ApprovalProposalRequired,
    StableRequestIdRequired,
    UnsupportedTarget,
    InvalidTaskTransition,
}

pub(crate) fn validate_field(
    field: AcpField,
    value: Option<&serde_json::Value>,
) -> Result<&str, AcpRequestError> {
    let reject = |violation| AcpRequestError::Field { field, violation };
    let value = value
        .ok_or_else(|| reject(AcpFieldViolation::Missing))?
        .as_str()
        .ok_or_else(|| reject(AcpFieldViolation::Type))?;
    validate_text(field, value)?;
    Ok(value)
}
pub(crate) fn validate_text(field: AcpField, value: &str) -> Result<(), AcpRequestError> {
    let violation = if value.trim().is_empty() {
        Some(AcpFieldViolation::Empty)
    } else if value.trim() != value {
        Some(AcpFieldViolation::Padded)
    } else if value.chars().any(char::is_control) {
        Some(AcpFieldViolation::Control)
    } else {
        None
    };
    match violation {
        Some(violation) => Err(AcpRequestError::Field { field, violation }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semantic_field_rejections_keep_precise_causes_without_peer_text() {
        for (input, violation) in [
            (serde_json::Value::Null, AcpFieldViolation::Type),
            ("".into(), AcpFieldViolation::Empty),
            (" private ".into(), AcpFieldViolation::Padded),
            ("private\0marker".into(), AcpFieldViolation::Control),
        ] {
            let result = validate_field(AcpField::TaskId, Some(&input));
            assert_eq!(
                result,
                Err(AcpRequestError::Field {
                    field: AcpField::TaskId,
                    violation
                })
            );
        }
        assert_eq!(
            validate_field(AcpField::CapabilityId, None),
            Err(AcpRequestError::Field {
                field: AcpField::CapabilityId,
                violation: AcpFieldViolation::Missing
            })
        );
    }
}
