//! Raw JSON refusal checks for repeated object keys.

use serde::de::DeserializeOwned;

/// Assert that `document` is refused once a member of `object`, which occurs
/// exactly once in it, is repeated with the same value at the end of `object`.
/// Both are compact JSON text.
#[track_caller]
pub fn assert_repeated_member_refused<T: DeserializeOwned>(document: &str, object: &str) {
    assert_eq!(
        document.matches(object).count(),
        1,
        "document embeds the object once"
    );
    let members: serde_json::Map<String, serde_json::Value> = serde_json::from_str(object)
        .unwrap_or_else(|error| panic!("object is a JSON object: {error}"));
    let Some((key, value)) = members.iter().next() else {
        panic!("object has a member");
    };
    let close = document.find(object).unwrap_or_default() + object.len() - 1;
    let head = format!(r#"{},"{key}""#, &document[..close]);
    assert_refused::<T>(
        &format!("{head}:{value}{}", &document[close..]),
        key,
        head.len(),
    );
}

/// Assert that `raw` is refused with serde's duplicate-field error for `key`,
/// reported at `column` of line 1.
#[track_caller]
pub fn assert_refused<T: DeserializeOwned>(raw: &str, key: &str, column: usize) {
    match serde_json::from_str::<T>(raw) {
        Ok(_) => panic!("accepted a repeated `{key}`: {raw}"),
        Err(error) => assert_eq!(
            error.to_string(),
            format!("duplicate field `{key}` at line 1 column {column}"),
            "{raw}"
        ),
    }
}
