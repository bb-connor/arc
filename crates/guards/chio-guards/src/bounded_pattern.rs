//! Policy-load compilation of operator-supplied regex lists under fixed
//! count, length, complexity and automaton-size bounds.

use regex::{Regex, RegexBuilder};

const MAX_PATTERNS: usize = 64;
const MAX_PATTERN_LEN: usize = 512;
const MAX_PATTERN_COMPLEXITY: usize = 96;
const AUTOMATON_SIZE_LIMIT: usize = 1 << 20;

/// Case handling for [`compile_bounded_patterns`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternCase {
    Sensitive,
    Insensitive,
}

/// Reason [`compile_bounded_patterns`] refuses a pattern list. `field` is
/// the policy field the list was loaded from.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum PatternError {
    #[error("{field} allows at most {max} patterns", max = MAX_PATTERNS)]
    TooMany { field: &'static str },
    #[error("{field} cannot contain empty patterns")]
    Empty { field: &'static str },
    #[error("{field} entries must be at most {max} characters", max = MAX_PATTERN_LEN)]
    TooLong { field: &'static str },
    #[error("{field} entries must have complexity at most {max}", max = MAX_PATTERN_COMPLEXITY)]
    TooComplex { field: &'static str },
    #[error("invalid {field} entry `{pattern}`: {source}")]
    Invalid {
        field: &'static str,
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Compiles each trimmed pattern, refusing the whole list when any bound is
/// exceeded. Returns every trimmed source beside its regex.
pub fn compile_bounded_patterns(
    field: &'static str,
    patterns: &[String],
    case: PatternCase,
) -> Result<Vec<(String, Regex)>, PatternError> {
    if patterns.len() > MAX_PATTERNS {
        return Err(PatternError::TooMany { field });
    }
    patterns
        .iter()
        .map(|pattern| {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                return Err(PatternError::Empty { field });
            }
            if trimmed.len() > MAX_PATTERN_LEN {
                return Err(PatternError::TooLong { field });
            }
            if complexity(trimmed) > MAX_PATTERN_COMPLEXITY {
                return Err(PatternError::TooComplex { field });
            }
            RegexBuilder::new(trimmed)
                .case_insensitive(case == PatternCase::Insensitive)
                .size_limit(AUTOMATON_SIZE_LIMIT)
                .dfa_size_limit(AUTOMATON_SIZE_LIMIT)
                .build()
                .map(|regex| (trimmed.to_string(), regex))
                .map_err(|source| PatternError::Invalid {
                    field,
                    pattern: trimmed.to_string(),
                    source,
                })
        })
        .collect()
}

fn complexity(pattern: &str) -> usize {
    let mut score = 0usize;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '|' | '*' | '+' | '?' => score = score.saturating_add(4),
            '{' | '[' | '(' => score = score.saturating_add(2),
            _ => {}
        }
    }
    score
}
