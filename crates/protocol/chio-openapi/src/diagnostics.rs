//! Bounded and redacted detail for a trusted local operator.
use crate::OpenApiError;
use std::{error::Error as _, fmt, fmt::Write as _};

const MAX_DETAIL_BYTES: usize = 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 2048;
const MAX_CAUSES: usize = 4;

/// An explicit local diagnostic. Never use this in a peer response.
pub struct OperatorDiagnostic<'a>(&'a OpenApiError);
impl<'a> OperatorDiagnostic<'a> {
    pub(crate) const fn new(error: &'a OpenApiError) -> Self {
        Self(error)
    }
}

struct LimitedText {
    text: String,
    limit: usize,
}
impl fmt::Write for LimitedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if value.len() > self.limit.saturating_sub(self.text.len()) {
            return Err(fmt::Error);
        }
        self.text.push_str(value);
        Ok(())
    }
}

fn local_detail(value: &dyn fmt::Display) -> String {
    let mut output = LimitedText {
        text: String::new(),
        limit: MAX_DETAIL_BYTES,
    };
    if write!(&mut output, "{value}").is_err() {
        return "[detail truncated]".into();
    }
    let redacted =
        chio_log_redact::redact_text(&output.text).unwrap_or_else(|_| "[REDACTION-FAILED]".into());
    let mut escaped = LimitedText {
        text: String::new(),
        limit: MAX_DETAIL_BYTES,
    };
    for character in redacted.chars() {
        for escaped_character in character.escape_default() {
            if escaped.write_char(escaped_character).is_err() {
                return "[detail truncated]".into();
            }
        }
    }
    escaped.text
}

impl fmt::Display for OperatorDiagnostic<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (rule, detail): (&str, Option<&dyn fmt::Display>) = match self.0 {
            OpenApiError::UntrustedInput(error) => ("untrusted_input", Some(error)),
            OpenApiError::Utf8(error) => ("utf8", Some(error)),
            OpenApiError::EmptyDocument => ("empty_document", None),
            OpenApiError::MultipleDocuments => ("multiple_documents", None),
            OpenApiError::InvalidJson(error) => ("invalid_json", Some(error)),
            OpenApiError::InvalidYaml(error) => ("invalid_yaml", Some(error)),
            OpenApiError::MissingField(value) => ("missing_field", Some(value)),
            OpenApiError::UnsupportedVersion(value) => ("unsupported_version", Some(value)),
            OpenApiError::UnresolvedRef(value) => ("unresolved_ref", Some(value)),
            OpenApiError::InvalidSpec(value) => ("invalid_spec", Some(value)),
            OpenApiError::InvalidExtension { .. } => ("invalid_extension", None),
        };
        let mut output = LimitedText {
            text: String::new(),
            limit: MAX_DIAGNOSTIC_BYTES - 16,
        };
        let _ = write!(&mut output, "{} rule={rule}", self.0);
        if let OpenApiError::InvalidExtension { field, source } = self.0 {
            // Only closed producer fields and native numeric metadata enter this
            // projection. Serde's Display can contain the supplied value.
            let field = match *field {
                "x-chio-sensitivity"
                | "x-chio-side-effects"
                | "x-chio-approval-required"
                | "x-chio-publish"
                | "x-chio-flow" => *field,
                _ => "operation_extension",
            };
            let category = match source.classify() {
                serde_json::error::Category::Io => "io",
                serde_json::error::Category::Syntax => "syntax",
                serde_json::error::Category::Data => "data",
                serde_json::error::Category::Eof => "eof",
            };
            let _ = write!(
                &mut output,
                " field={field} cause=serde_json category={category}"
            );
            // Value decoding has no original byte coordinates. Include only
            // coordinates actually supplied by the native error.
            if source.line() > 0 {
                let _ = write!(
                    &mut output,
                    " line={} column={}",
                    source.line(),
                    source.column()
                );
            }
            return formatter.write_str(&output.text);
        }
        if let Some(detail) = detail {
            let _ = write!(&mut output, " detail={}", local_detail(detail));
        }
        let mut source = self.0.source();
        for _ in 0..MAX_CAUSES {
            let Some(cause) = source else {
                break;
            };
            if write!(&mut output, " cause={}", local_detail(cause)).is_err() {
                output.text.push_str(" [truncated]");
                return formatter.write_str(&output.text);
            }
            source = cause.source();
        }
        if source.is_some() {
            output.text.push_str(" [truncated]");
        }
        formatter.write_str(&output.text)
    }
}
