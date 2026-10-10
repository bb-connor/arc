use super::*;
use chio_errors::_generated::error_codes::CLI_OTHER;

const TTL_ENV: &str = "CHIO_TERMINAL_RAW_PAYLOAD_TTL_SECS";
const INTERVAL_ENV: &str = "CHIO_TERMINAL_RAW_PAYLOAD_MAINTENANCE_INTERVAL_SECS";

#[derive(Debug, thiserror::Error)]
#[error("operator environment value is not Unicode")]
struct NonUnicodeOperatorValue;

impl TerminalPayloadMaintenanceConfig {
    /// These are local operator inputs, never protocol request fields. Missing
    /// both values leaves deletion disabled, and partial configuration refuses.
    pub fn from_operator_values(
        ttl: Option<&str>,
        interval: Option<&str>,
    ) -> Result<Option<Self>, CliError> {
        let (ttl, interval) = match (ttl, interval) {
            (None, None) => return Ok(None),
            (Some(ttl), Some(interval)) => (ttl, interval),
            _ => return Err(CliError::cli_other_error(
                "terminal raw payload maintenance requires both TTL and interval environment variables")),
        };
        let ttl = parse_seconds(
            ttl,
            i64::MAX.unsigned_abs() / 1_000,
            "terminal raw payload maintenance TTL must be positive bounded integer seconds",
        )?;
        let interval = parse_seconds(interval, 86_400,
            "terminal raw payload maintenance interval must be positive integer seconds at most one day")?;
        let config = Self {
            terminal_raw_payload_ttl: Duration::from_secs(ttl),
            interval: Duration::from_secs(interval),
            page_limits: ToolOutcomeCompactionLimits::default(),
        }
        .validate()
        .map_err(|source| {
            CliError::with_public_source(
                &CLI_OTHER,
                "terminal raw payload maintenance configuration is invalid",
                source,
            )
        })?;
        Ok(Some(config))
    }

    pub fn from_env() -> Result<Option<Self>, CliError> {
        let ttl = read_operator_value(TTL_ENV)?;
        let interval = read_operator_value(INTERVAL_ENV)?;
        Self::from_operator_values(ttl.as_deref(), interval.as_deref())
    }
}

fn parse_seconds(value: &str, maximum: u64, message: &'static str) -> Result<u64, CliError> {
    // ParseIntError stores the error kind, never the input value.
    let seconds = value
        .parse::<u64>()
        .map_err(|source| CliError::with_public_source(&CLI_OTHER, message, source))?;
    if seconds == 0 || seconds > maximum {
        return Err(CliError::cli_other_error(message));
    }
    Ok(seconds)
}

fn read_operator_value(name: &'static str) -> Result<Option<String>, CliError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        // VarError contains the original OsString. Retain the encoding reason
        // as a typed local cause without retaining or exposing that value.
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::with_public_source(
            &CLI_OTHER,
            "terminal raw payload maintenance environment variables must be valid Unicode",
            NonUnicodeOperatorValue,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_payload_maintenance_operator_values_are_paired_bounded_and_private(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(TerminalPayloadMaintenanceConfig::from_operator_values(None, None)?.is_none());
        for (ttl, interval) in [
            (Some("60"), None),
            (None, Some("1")),
            (Some("0"), Some("1")),
            (Some("60"), Some("0")),
            (Some("60"), Some("86401")),
            (Some("PRIVATE_ENV_VALUE_CANARY"), Some("1")),
            (Some("18446744073709551616"), Some("1")),
        ] {
            let error = TerminalPayloadMaintenanceConfig::from_operator_values(ttl, interval)
                .err()
                .ok_or("invalid operator values accepted")?;
            let report = error.report();
            assert_eq!(report.code, CLI_OTHER.urn);
            assert!(report.message.contains("terminal raw payload maintenance"));
            assert!(!format!("{error:?} {error} {report:?}").contains("PRIVATE_ENV_VALUE_CANARY"));
            if matches!(
                ttl,
                Some("PRIVATE_ENV_VALUE_CANARY" | "18446744073709551616")
            ) {
                assert!(matches!(&error, CliError::RegisteredSource(_)));
                let source = std::error::Error::source(&error)
                    .and_then(std::error::Error::source)
                    .and_then(|source| source.downcast_ref::<std::num::ParseIntError>())
                    .ok_or("integer parse cause missing")?;
                let expected = if ttl == Some("PRIVATE_ENV_VALUE_CANARY") {
                    std::num::IntErrorKind::InvalidDigit
                } else {
                    std::num::IntErrorKind::PosOverflow
                };
                assert_eq!(source.kind(), &expected);
            } else {
                assert!(matches!(&error, CliError::Chio(_)));
            }
        }
        let config = TerminalPayloadMaintenanceConfig::from_operator_values(Some("60"), Some("2"))?
            .ok_or("missing explicit configuration")?;
        assert_eq!(config.terminal_raw_payload_ttl, Duration::from_secs(60));
        assert_eq!(config.interval, Duration::from_secs(2));
        Ok(())
    }
}
