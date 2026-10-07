//! Retain declared public codecs without exposing other unreachable definitions.

use std::collections::BTreeSet;
use std::ops::Range;

use serde_json::{Map, Value};

use crate::XtaskError;

pub(super) fn prepare_public_definitions(
    source: &[u8],
    public_names: &[&str],
) -> Result<Vec<u8>, XtaskError> {
    let schema: Value = serde_json::from_slice(source)
        .map_err(|error| invalid(&format!("schema JSON: {error}")))?;
    let prepared = retain_public_definitions(&schema, public_names)?;
    let retained = prepared
        .get("$defs")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("prepared definitions are missing"))?;
    let definitions = object_member_ranges(source)?
        .into_iter()
        .find(|member| member.name == "$defs")
        .ok_or_else(|| invalid("source definitions are missing"))?;
    let definition_source = source
        .get(definitions.value.clone())
        .ok_or_else(|| invalid("definition range escaped source"))?;
    let members = object_member_ranges(definition_source)?;

    // Copy original member slices so the compiler sees authored property order
    // and exact scalar lexemes. Only the private root $defs block is rebuilt.
    let mut output = Vec::with_capacity(source.len());
    output.extend_from_slice(
        source
            .get(..definitions.value.start)
            .ok_or_else(|| invalid("definition prefix escaped source"))?,
    );
    output.push(b'{');
    let mut emitted = false;
    for member in members {
        if !retained.contains_key(&member.name) {
            continue;
        }
        if emitted {
            output.push(b',');
        }
        output.extend_from_slice(
            definition_source
                .get(member.complete)
                .ok_or_else(|| invalid("definition member escaped source"))?,
        );
        emitted = true;
    }
    output.push(b'}');
    output.extend_from_slice(
        source
            .get(definitions.value.end..)
            .ok_or_else(|| invalid("definition suffix escaped source"))?,
    );
    let reconstructed: Value = serde_json::from_slice(&output)
        .map_err(|error| invalid(&format!("prepared schema JSON: {error}")))?;
    if reconstructed != prepared {
        return Err(invalid(
            "prepared source differs from validated definitions",
        ));
    }
    Ok(output)
}

struct ObjectMember {
    name: String,
    complete: Range<usize>,
    value: Range<usize>,
}

/// Find member ranges only after the complete JSON document was validated.
/// Real serde stream offsets identify values, including nested objects and
/// escaped strings. Delimiters and every source slice remain checked.
fn object_member_ranges(source: &[u8]) -> Result<Vec<ObjectMember>, XtaskError> {
    let mut cursor = skip_whitespace(source, 0);
    cursor = consume_byte(source, cursor, b'{')?;
    cursor = skip_whitespace(source, cursor);
    let mut members = Vec::new();
    let mut names = BTreeSet::new();
    if source.get(cursor) != Some(&b'}') {
        loop {
            let start = cursor;
            let remaining = source
                .get(cursor..)
                .ok_or_else(|| invalid("member key escaped source"))?;
            let mut keys = serde_json::Deserializer::from_slice(remaining).into_iter::<String>();
            let name = keys
                .next()
                .ok_or_else(|| invalid("member key is missing"))?
                .map_err(|error| invalid(&format!("member key: {error}")))?;
            cursor = advance(source, cursor, keys.byte_offset())?;
            if !names.insert(name.clone()) {
                return Err(invalid("duplicate source object member"));
            }
            cursor = consume_byte(source, skip_whitespace(source, cursor), b':')?;
            let value_start = skip_whitespace(source, cursor);
            let remaining = source
                .get(value_start..)
                .ok_or_else(|| invalid("member value escaped source"))?;
            let mut values = serde_json::Deserializer::from_slice(remaining).into_iter::<Value>();
            values
                .next()
                .ok_or_else(|| invalid("member value is missing"))?
                .map_err(|error| invalid(&format!("member value: {error}")))?;
            let value_end = advance(source, value_start, values.byte_offset())?;
            members.push(ObjectMember {
                name,
                complete: start..value_end,
                value: value_start..value_end,
            });
            cursor = skip_whitespace(source, value_end);
            match source.get(cursor) {
                Some(b',') => {
                    cursor = skip_whitespace(source, advance(source, cursor, 1)?);
                }
                Some(b'}') => break,
                _ => return Err(invalid("source object delimiter is missing")),
            }
        }
    }
    cursor = consume_byte(source, cursor, b'}')?;
    if skip_whitespace(source, cursor) != source.len() {
        return Err(invalid("source object has trailing bytes"));
    }
    Ok(members)
}

fn consume_byte(source: &[u8], cursor: usize, expected: u8) -> Result<usize, XtaskError> {
    if source.get(cursor) != Some(&expected) {
        return Err(invalid("source object delimiter is invalid"));
    }
    advance(source, cursor, 1)
}

fn advance(source: &[u8], cursor: usize, length: usize) -> Result<usize, XtaskError> {
    cursor
        .checked_add(length)
        .filter(|end| *end <= source.len())
        .ok_or_else(|| invalid("source object range overflow"))
}

fn skip_whitespace(source: &[u8], mut cursor: usize) -> usize {
    while matches!(source.get(cursor), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        // get() proves cursor is below the slice length before advancing.
        cursor += 1;
    }
    cursor
}

/// Keep reference-reachable definitions and explicitly retained public names.
/// The caller applies this only to a private, resolved generation mirror.
pub(super) fn retain_public_definitions(
    schema: &Value,
    public_names: &[&str],
) -> Result<Value, XtaskError> {
    let definitions = schema
        .as_object()
        .and_then(|object| object.get("$defs"))
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("expected object schema and object $defs"))?;
    for definition in definitions.values() {
        require_schema(definition)?;
    }
    // Validate all local references, including definitions that will not be
    // emitted. Pruning must not conceal an invalid declaration.
    validate_references(schema)?;

    let mut retained = BTreeSet::new();
    let mut pending = vec![schema];
    for name in public_names {
        let definition = definitions
            .get(*name)
            .ok_or_else(|| invalid("retained public definition is missing"))?;
        retained.insert((*name).to_owned());
        pending.push(definition);
    }
    let mut visited = BTreeSet::new();
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(items) => pending.extend(items),
            Value::Object(object) => {
                for (key, value) in object {
                    match key.as_str() {
                        "$defs" => (),
                        "$ref" => {
                            if let Some((pointer, target)) = local_target(schema, value)? {
                                if !visited.insert(pointer.to_owned()) {
                                    continue;
                                }
                                if let Some(token) = pointer
                                    .strip_prefix("/$defs/")
                                    .and_then(|tail| tail.split('/').next())
                                {
                                    // local_target has already validated the
                                    // JSON Pointer, including its escape syntax.
                                    let name = token.replace("~1", "/").replace("~0", "~");
                                    retain_definition(
                                        definitions,
                                        &name,
                                        &mut retained,
                                        &mut pending,
                                    )?;
                                }
                                pending.push(target);
                            }
                        }
                        _ => pending.push(value),
                    }
                }
            }
            _ => (),
        }
    }
    let mut output = schema.clone();
    output
        .as_object_mut()
        .and_then(|object| object.get_mut("$defs"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("definition object changed during preparation"))?
        .retain(|name, _| retained.contains(name));
    Ok(output)
}

fn retain_definition<'a>(
    definitions: &'a Map<String, Value>,
    name: &str,
    retained: &mut BTreeSet<String>,
    pending: &mut Vec<&'a Value>,
) -> Result<(), XtaskError> {
    let definition = definitions
        .get(name)
        .ok_or_else(|| invalid("referenced definition is missing"))?;
    if retained.insert(name.to_owned()) {
        pending.push(definition);
    }
    Ok(())
}

fn validate_references(schema: &Value) -> Result<(), XtaskError> {
    let mut pending = vec![schema];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(items) => pending.extend(items),
            Value::Object(object) => {
                for (key, value) in object {
                    if key == "$ref" {
                        local_target(schema, value)?;
                    } else {
                        pending.push(value);
                    }
                }
            }
            _ => (),
        }
    }
    Ok(())
}

fn local_target<'a>(
    schema: &'a Value,
    reference: &'a Value,
) -> Result<Option<(&'a str, &'a Value)>, XtaskError> {
    let reference = reference
        .as_str()
        .filter(|reference| !reference.is_empty())
        .ok_or_else(|| invalid("expected nonempty string reference"))?;
    let Some(pointer) = reference.strip_prefix('#') else {
        // The catalog and pinned compiler own resolved sibling references.
        // Their exact reference text remains in the private mirror.
        return Ok(None);
    };
    validate_pointer(pointer)?;
    let target = schema
        .pointer(pointer)
        .ok_or_else(|| invalid("local reference does not select a schema"))?;
    require_schema(target)?;
    Ok(Some((pointer, target)))
}

fn validate_pointer(pointer: &str) -> Result<(), XtaskError> {
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return Err(invalid("local reference is not a JSON Pointer"));
    }
    let mut bytes = pointer.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return Err(invalid("local reference has an invalid pointer escape"));
        }
    }
    Ok(())
}

fn require_schema(value: &Value) -> Result<(), XtaskError> {
    if value.is_object() || value.is_boolean() {
        Ok(())
    } else {
        Err(invalid("definition or reference target is not a schema"))
    }
}

fn invalid(reason: &str) -> XtaskError {
    XtaskError::Usage(format!("typescript public definitions: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::{prepare_public_definitions, retain_public_definitions};
    use crate::XtaskError;
    use serde_json::json;

    #[test]
    fn public_codecs_and_transitive_cycles_survive_without_unused_definitions(
    ) -> Result<(), XtaskError> {
        let input = json!({
            "type": "object", "properties": {"value": {"$ref": "#/$defs/first"}},
            "$defs": {
                "first": {"type": "object", "properties": {"next": {"$ref": "#/$defs/second"}}},
                "second": {"type": "object", "properties": {"next": {"$ref": "#/$defs/first"}}},
                "safeInteger": {"type": "integer", "minimum": 0},
                "scope": {"type": "object"}
            }
        });
        let output = retain_public_definitions(&input, &["safeInteger"])?;
        assert_eq!(output["$defs"].as_object().map(|defs| defs.len()), Some(3));
        assert_eq!(output["$defs"]["first"], input["$defs"]["first"]);
        assert_eq!(output["$defs"]["second"], input["$defs"]["second"]);
        assert_eq!(
            output["$defs"]["safeInteger"],
            input["$defs"]["safeInteger"]
        );
        assert!(output["$defs"].get("scope").is_none());
        assert!(input["$defs"].get("scope").is_some());
        Ok(())
    }

    #[test]
    fn escaped_definition_names_and_sibling_reference_text_are_preserved() -> Result<(), XtaskError>
    {
        let input = json!({
            "properties": {
                "local": {"$ref": "#/$defs/a~1b~0c"},
                "sibling": {"$ref": "../other.schema.json#/$defs/value"}
            },
            "$defs": {"a/b~c": {"type": "string"}, "safeInteger": {"type": "integer"}, "unused": true}
        });
        let output = retain_public_definitions(&input, &["safeInteger"])?;
        assert_eq!(output["properties"], input["properties"]);
        assert_eq!(output["$defs"].as_object().map(|defs| defs.len()), Some(2));
        assert_eq!(output["$defs"]["a/b~c"], input["$defs"]["a/b~c"]);
        Ok(())
    }

    #[test]
    fn malformed_and_missing_definitions_refuse_before_pruning() {
        for value in [
            json!({"$defs": []}),
            json!({"$defs": {"safeInteger": {"type": "integer"}, "unused": null}}),
            json!({"$defs": {"safeInteger": {"type": "integer"}, "unused": {"$ref": "#/$defs/missing"}}}),
            json!({"$defs": {"safeInteger": {"type": "integer"}}, "$ref": 1}),
            json!({"$defs": {"safeInteger": {"type": "integer"}}, "$ref": "#/$defs/safeInteger/type"}),
            json!({"$defs": {"safeInteger": {"type": "integer"}}, "$ref": "#/$defs/bad~2escape"}),
            json!({"$defs": {"unrelated": {"type": "integer"}}}),
        ] {
            assert!(retain_public_definitions(&value, &["safeInteger"]).is_err());
        }
    }

    #[test]
    fn invalid_pointer_escape_refuses_an_existing_literal_definition() -> Result<(), XtaskError> {
        let input = json!({
            "$defs": {"safeInteger": {"type": "integer"}, "bad~2escape": {"type": "string"}},
            "$ref": "#/$defs/bad~2escape"
        });
        let mut valid = input.clone();
        valid["$ref"] = json!("#/$defs/bad~02escape");
        assert_eq!(
            retain_public_definitions(&valid, &["safeInteger"])?["$defs"]["bad~2escape"],
            input["$defs"]["bad~2escape"]
        );
        assert!(retain_public_definitions(&input, &["safeInteger"]).is_err());
        Ok(())
    }

    #[test]
    fn trailing_pointer_escape_refuses_an_existing_literal_definition() -> Result<(), XtaskError> {
        let input = json!({
            "$defs": {"safeInteger": {"type": "integer"}, "trailing~": {"type": "string"}},
            "$ref": "#/$defs/trailing~"
        });
        let mut valid = input.clone();
        valid["$ref"] = json!("#/$defs/trailing~0");
        assert_eq!(
            retain_public_definitions(&valid, &["safeInteger"])?["$defs"]["trailing~"],
            input["$defs"]["trailing~"]
        );
        assert!(retain_public_definitions(&input, &["safeInteger"]).is_err());
        Ok(())
    }

    #[test]
    fn original_property_order_survives_private_definition_retention() -> Result<(), XtaskError> {
        let source = br##"{"type":"object","properties":{"z":{"type":"integer"},"a":{"type":"string"}},"$defs":{"safeInteger":{"type":"integer"},"unused":true}}"##;
        let expected = br##"{"type":"object","properties":{"z":{"type":"integer"},"a":{"type":"string"}},"$defs":{"safeInteger":{"type":"integer"}}}"##;
        assert_eq!(
            prepare_public_definitions(source, &["safeInteger"])?,
            expected
        );
        Ok(())
    }

    #[test]
    fn private_preparation_preserves_string_and_number_lexemes() -> Result<(), XtaskError> {
        let source = br##"{"description":"\u0061","const":1e0,"$defs":{"safeInteger":{"type":"integer","minimum":0},"unused":{"type":"object"}}}"##;
        let expected = br##"{"description":"\u0061","const":1e0,"$defs":{"safeInteger":{"type":"integer","minimum":0}}}"##;
        assert_eq!(
            prepare_public_definitions(source, &["safeInteger"])?,
            expected
        );
        Ok(())
    }

    #[test]
    fn private_preparation_preserves_escaped_keys_and_nested_delimiters() -> Result<(), XtaskError>
    {
        let source = br##" {"$\u0064efs":{"safeInteger":{"type":"integer","description":"\"},:{\""},"unused":false},"examples":["}",",","{"]} "##;
        let expected = br##" {"$\u0064efs":{"safeInteger":{"type":"integer","description":"\"},:{\""}},"examples":["}",",","{"]} "##;
        assert_eq!(
            prepare_public_definitions(source, &["safeInteger"])?,
            expected
        );
        Ok(())
    }
}
