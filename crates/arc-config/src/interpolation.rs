//! Environment variable interpolation for raw YAML strings.
//!
//! Scans the input for `${VAR}` and `${VAR:-default}` patterns and replaces
//! them with the corresponding environment variable value (or the default).
//! This runs on the raw YAML text before typed deserialization so that every
//! string-typed field benefits automatically.

use regex::{Captures, Regex};
use std::env;

use crate::ConfigError;

/// Replace all `${VAR}` and `${VAR:-default}` occurrences in `input`.
///
/// Returns the interpolated string, or an error listing every variable that
/// was referenced but not set (and had no default).
pub fn interpolate(input: &str) -> Result<String, ConfigError> {
    // Pattern breakdown:
    //   \$\{            -- literal "${"
    //   ([A-Za-z_]\w*)  -- variable name (capture group 1)
    //   (?::-([^}]*))?  -- optional ":-default" (capture group 2)
    //   \}              -- literal "}"
    let re = Regex::new(r"\$\{([A-Za-z_]\w*)(?::-([^}]*))?\}")
        .map_err(|e| ConfigError::Interpolation(format!("regex compile error: {e}")))?;

    let mut missing: Vec<String> = Vec::new();

    let result = re.replace_all(input, |caps: &Captures<'_>| {
        let var_name = caps.get(1).map_or("", |m| m.as_str());
        match env::var(var_name) {
            Ok(val) => val,
            Err(_) => {
                // Check for a default value.
                if let Some(default_match) = caps.get(2) {
                    default_match.as_str().to_string()
                } else {
                    missing.push(var_name.to_string());
                    // Leave a placeholder so the rest of parsing can proceed;
                    // we will return an error after the full scan.
                    String::new()
                }
            }
        }
    });

    if missing.is_empty() {
        Ok(result.into_owned())
    } else {
        Err(ConfigError::Interpolation(format!(
            "unset environment variables with no default: {}",
            missing.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_unchanged() {
        let input = "hello world";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "hello world");
    }

    #[test]
    fn simple_var_replacement() {
        env::set_var("ARC_TEST_SIMPLE", "replaced");
        let input = "key: ${ARC_TEST_SIMPLE}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "key: replaced");
        env::remove_var("ARC_TEST_SIMPLE");
    }

    #[test]
    fn default_value_when_unset() {
        env::remove_var("ARC_TEST_UNSET_WITH_DEFAULT");
        let input = "key: ${ARC_TEST_UNSET_WITH_DEFAULT:-fallback}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "key: fallback");
    }

    #[test]
    fn default_value_overridden_when_set() {
        env::set_var("ARC_TEST_SET_OVER_DEFAULT", "actual");
        let input = "key: ${ARC_TEST_SET_OVER_DEFAULT:-fallback}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "key: actual");
        env::remove_var("ARC_TEST_SET_OVER_DEFAULT");
    }

    #[test]
    fn missing_var_no_default_is_error() {
        env::remove_var("ARC_TEST_MISSING_NO_DEFAULT");
        let input = "key: ${ARC_TEST_MISSING_NO_DEFAULT}";
        let err = interpolate(input).unwrap_err();
        match err {
            ConfigError::Interpolation(msg) => {
                assert!(
                    msg.contains("ARC_TEST_MISSING_NO_DEFAULT"),
                    "error should name the variable: {msg}"
                );
            }
            other => panic!("wrong error variant: {other}"),
        }
    }

    #[test]
    fn multiple_vars_in_one_string() {
        env::set_var("ARC_TEST_A", "alpha");
        env::set_var("ARC_TEST_B", "beta");
        let input = "${ARC_TEST_A}--${ARC_TEST_B}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "alpha--beta");
        env::remove_var("ARC_TEST_A");
        env::remove_var("ARC_TEST_B");
    }

    #[test]
    fn empty_default_is_valid() {
        env::remove_var("ARC_TEST_EMPTY_DEFAULT");
        let input = "key: ${ARC_TEST_EMPTY_DEFAULT:-}";
        let out = interpolate(input).unwrap_or_else(|e| panic!("interpolation failed: {e}"));
        assert_eq!(out, "key: ");
    }

    #[test]
    fn multiple_missing_vars_all_reported() {
        env::remove_var("ARC_TEST_X1");
        env::remove_var("ARC_TEST_X2");
        let input = "${ARC_TEST_X1} ${ARC_TEST_X2}";
        let err = interpolate(input).unwrap_err();
        match err {
            ConfigError::Interpolation(msg) => {
                assert!(msg.contains("ARC_TEST_X1"), "should contain X1: {msg}");
                assert!(msg.contains("ARC_TEST_X2"), "should contain X2: {msg}");
            }
            other => panic!("wrong error variant: {other}"),
        }
    }
}
