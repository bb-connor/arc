use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::value::RawValue;

#[derive(Deserialize)]
struct SignedMembers<'a> {
    #[serde(borrow)]
    capability: &'a RawValue,
    #[serde(default, borrow)]
    direct_root_capability: Option<&'a RawValue>,
}

pub(super) fn decode_evaluate_request<T: DeserializeOwned>(
    input: &str,
    bound: usize,
) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(input.as_bytes(), bound)?
        .decode_document::<serde::de::IgnoredAny>()?;
    let members: SignedMembers<'_> =
        serde_json::from_str(input).map_err(UntrustedJsonError::Decode)?;
    for member in [Some(members.capability), members.direct_root_capability]
        .into_iter()
        .flatten()
    {
        UntrustedJsonText::from_wire(member.get().as_bytes(), bound)?
            .decode_signed::<serde::de::IgnoredAny>()?;
    }
    serde_json::from_str(input).map_err(UntrustedJsonError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_arguments_do_not_relax_signed_member_numbers() {
        let valid = r#"{"capability":{"issued_at":1},"direct_root_capability":{"issued_at":2},"request":{"arguments":{"threshold":1e-07}}}"#;
        let decoded: serde_json::Value =
            decode_evaluate_request(valid, 1024).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            decoded["request"]["arguments"]["threshold"],
            serde_json::json!(1e-7)
        );
        for member in [r#""issued_at":1"#, r#""issued_at":2"#] {
            let altered = valid.replacen(member, &alloc_number(member), 1);
            let error = decode_evaluate_request::<serde_json::Value>(&altered, 1024)
                .err()
                .unwrap_or_else(|| panic!("noncanonical signed member accepted"));
            assert!(
                matches!(error, UntrustedJsonError::SignedInput(_)),
                "{error:?}"
            );
        }
    }

    fn alloc_number(member: &str) -> alloc::string::String {
        alloc::format!("{member}e0")
    }
}
