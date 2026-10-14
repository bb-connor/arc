//! Preserve recovery wire presence and scalar kinds in generated models.
//!
//! The schema permits an absent origin, but a supplied origin must be an object.
//! Keep the generated optional representation and validate only supplied values.

use std::{fs, path::Path};

use crate::{display_path, XtaskError};

const ACTION_CLASS: &str = "class RecoveryExactActionIntentV1(BaseModel):\n";
const ORIGIN_FIELD: &str = "    origin: Origin | None = Field(\n        None,\n";
const IMPORT: &str = "from pydantic import BaseModel, ";
const VALIDATOR: &str = r#"

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: Literal["allow", "ignore", "forbid"] | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        """Validate one immutable action wire before Pydantic member collapse."""
        from pydantic import ValidationError
        from ...recovery_wire import MAX_WIRE_BYTES, assert_foundation_wire

        invalid_wire = False
        try:
            if isinstance(json_data, str):
                if str.__len__(json_data) > MAX_WIRE_BYTES:
                    raise ValueError("recovery foundation byte bound")
                json_data = str.__str__(json_data)
                source = json_data
            elif isinstance(json_data, bytes):
                if bytes.__len__(json_data) > MAX_WIRE_BYTES:
                    raise ValueError("recovery foundation byte bound")
                json_data = bytes.__bytes__(json_data)
                source = json_data.decode("utf-8")
            elif isinstance(json_data, bytearray):
                # Native slicing caps allocation even if the mutable buffer grows.
                snapshot = bytearray.__getitem__(json_data, slice(0, MAX_WIRE_BYTES + 1))
                if len(snapshot) > MAX_WIRE_BYTES:
                    raise ValueError("recovery foundation byte bound")
                json_data = bytes(snapshot)
                source = json_data.decode("utf-8")
            else:
                source = None
            if source is not None:
                assert_foundation_wire(source)
        except ValueError:
            invalid_wire = True
        if invalid_wire:
            raise ValidationError.from_exception_data(
                cls.__name__,
                [{"type": "json_invalid", "loc": (), "input": None,
                  "ctx": {"error": "recovery action JSON violates its foundation profile"}}],
                input_type="json",
                hide_input=True,
            )

        validation_options: dict[str, Any] = {"strict": strict, "context": context}
        # Omit absent newer overrides for older supported Pydantic versions.
        if extra is not None:
            validation_options["extra"] = extra
        if by_alias is not None:
            validation_options["by_alias"] = by_alias
        if by_name is not None:
            validation_options["by_name"] = by_name
        return super().model_validate_json(json_data, **validation_options)

    @field_validator("origin", mode="before")
    @classmethod
    def _origin_must_not_be_null(cls, value: object) -> object:
        if value is None:
            raise ValueError("recovery origin must be omitted instead of null")
        return value

    @model_serializer(mode="wrap")
    def _omit_absent_legacy_origin(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value = handler(self)
        if self.origin is None:
            value.pop("origin", None)
        return value

"#;
const ACTION_DOC: &str = "    \"\"\"Retained v1 action data with legacy and fresh native profiles.\n\n    Legacy signed data omits origin. Fresh native authorization requires the\n    complete original denial binding; this model cannot establish freshness.\n    Explicit null is refused and an absent origin stays absent on serialization.\n    \"\"\"\n";
const WITHHELD_FIELD: &str = "    withheld_status: ";
const WITHHELD_GUARDS: &str = r#"

    @field_validator("withheld_status", mode="before")
    @classmethod
    def _withheld_status_must_not_be_null(cls, value: object) -> object:
        if value is None:
            raise ValueError("withheld status must be omitted instead of null")
        return value

    @model_serializer(mode="wrap")
    def _omit_absent_withheld_status(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value = handler(self)
        if self.withheld_status is None:
            value.pop("withheld_status", None)
        return value

"#;
const INTEGER_LITERAL_METHOD: &str = "_require_integer_literal_kind";

pub(super) fn harden(root: &Path) -> Result<(), XtaskError> {
    let path = root.join("recovery/action_intent_schema.py");
    let source =
        fs::read_to_string(&path).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    let hardened = harden_origin_source(&source).map_err(|error| {
        XtaskError::ToolFailed(format!(
            "Python recovery origin model {}: {error}",
            display_path(&path)
        ))
    })?;
    fs::write(&path, hardened).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    let path = root.join("recovery/semantic_package_schema.py");
    let source =
        fs::read_to_string(&path).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    let hardened = harden_withheld_source(&source).map_err(|error| {
        XtaskError::ToolFailed(format!(
            "Python semantic status model {}: {error}",
            display_path(&path)
        ))
    })?;
    fs::write(&path, hardened).map_err(|error| XtaskError::Io(display_path(&path), error))?;

    let directory = root.join("recovery");
    let mut paths = fs::read_dir(&directory)
        .map_err(|error| XtaskError::Io(display_path(&directory), error))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| XtaskError::Io(display_path(&directory), error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    for path in paths {
        if path.extension().is_none_or(|extension| extension != "py") {
            continue;
        }
        let source = fs::read_to_string(&path)
            .map_err(|error| XtaskError::Io(display_path(&path), error))?;
        let hardened = harden_integer_literal_source(&source).map_err(|error| {
            XtaskError::ToolFailed(format!(
                "Python recovery integer literal model {}: {error}",
                display_path(&path)
            ))
        })?;
        if hardened != source {
            fs::write(&path, hardened)
                .map_err(|error| XtaskError::Io(display_path(&path), error))?;
        }
    }
    Ok(())
}

/// Pydantic's integer Literal validation also accepts equal booleans and floats,
/// including with strict JSON validation. Preserve the wire's actual scalar kind
/// at these declared fields without traversing arbitrary receipt or result JSON.
fn harden_integer_literal_source(source: &str) -> Result<String, &'static str> {
    if source.contains(INTEGER_LITERAL_METHOD) {
        return Err("generated integer literal guards already exist");
    }
    if source.matches(VALIDATOR).count() > 1 {
        return Err("generated action validator block is duplicated");
    }
    // Presence hardening inserts this owned block verbatim before scalar guards.
    // Its typed method parameters are not schema fields. Keep all other source
    // under the existing fail-closed field parser instead of guessing scopes.
    let action_validators = source
        .find(VALIDATOR)
        .map(|start| start..start + VALIDATOR.len());
    let mut classes = Vec::new();
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        if line.starts_with("class ") {
            classes.push(offset);
        }
        offset += line.len();
    }
    classes.push(source.len());
    let mut insertions = Vec::new();
    for boundaries in classes.windows(2) {
        let body = &source[boundaries[0]..boundaries[1]];
        let mut fields = Vec::new();
        let mut line_offset = boundaries[0];
        for line in body.split_inclusive('\n') {
            let start = line_offset;
            line_offset += line.len();
            if action_validators
                .as_ref()
                .is_some_and(|range| range.contains(&start))
            {
                continue;
            }
            // Preserve str::lines handling of LF, CRLF and the final source line.
            let declaration = line.lines().next().unwrap_or_default();
            if let Some(field) = integer_literal_field(declaration)? {
                if fields.contains(&field) {
                    return Err("generated integer literal field is duplicated");
                }
                fields.push(field);
            }
        }
        if fields.is_empty() {
            continue;
        }
        let field_arguments = fields
            .iter()
            .map(|field| format!("\"{field}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let guard = format!(
            r#"

    @field_validator({field_arguments}, mode="before")
    @classmethod
    def {INTEGER_LITERAL_METHOD}(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("recovery integer literal requires an integer")
        return value
"#
        );
        let insertion = source[..boundaries[1]].trim_end_matches('\n').len();
        insertions.push((insertion, guard));
    }
    if insertions.is_empty() {
        return Ok(source.to_owned());
    }
    let mut hardened = source.to_owned();
    for (offset, guard) in insertions.into_iter().rev() {
        hardened.insert_str(offset, &guard);
    }
    // Keep __future__ imports first and compose with the earlier presence guards.
    if !source.contains("from pydantic import field_validator") {
        let insertion = hardened
            .find("from pydantic import ")
            .ok_or("generated integer literal model lacks its Pydantic import")?;
        hardened.insert_str(insertion, "from pydantic import field_validator\n");
    }
    Ok(hardened)
}

fn integer_literal_field(line: &str) -> Result<Option<&str>, &'static str> {
    let Some(declaration) = line.strip_prefix("    ") else {
        return Ok(None);
    };
    let Some((name, annotation)) = declaration.split_once(": Literal[") else {
        return Ok(None);
    };
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || name.is_empty()
        || name.as_bytes()[0].is_ascii_digit()
    {
        return Err("generated literal field name changed");
    }
    let Some((members, suffix)) = annotation.split_once(']') else {
        return Err("generated literal declaration is incomplete");
    };
    let mut has_integer = false;
    let mut has_other_kind = false;
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    let mut tokens = Vec::new();
    for (offset, character) in members.char_indices() {
        if escaped {
            escaped = false;
        } else if quote.is_some() && character == '\\' {
            escaped = true;
        } else if quote == Some(character) {
            quote = None;
        } else if quote.is_none() && matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if quote.is_none() && character == ',' {
            tokens.push(&members[start..offset]);
            start = offset + 1;
        }
    }
    if quote.is_some() || escaped {
        return Err("generated literal members are incomplete");
    }
    tokens.push(&members[start..]);
    for token in tokens {
        let token = token.trim();
        if token.parse::<i64>().is_ok() {
            has_integer = true;
        } else if matches!(token, "True" | "False" | "None") || token.starts_with(['\'', '"']) {
            has_other_kind = true;
        } else {
            return Err("generated literal member representation changed");
        }
    }
    if !has_integer {
        return Ok(None);
    }
    if has_other_kind || !(suffix.is_empty() || suffix.starts_with(" = ")) {
        return Err("generated numeric literal is not a standalone integer field");
    }
    Ok(Some(name))
}

fn harden_withheld_source(source: &str) -> Result<String, &'static str> {
    if source.matches(IMPORT).count() != 1 || source.matches(WITHHELD_FIELD).count() != 1 {
        return Err("generated semantic import or optional status inventory changed");
    }
    if source.contains("field_validator") || source.contains("model_serializer") {
        return Err("generated semantic validator inventory changed");
    }
    let field_start = source
        .find(WITHHELD_FIELD)
        .ok_or("generated semantic status field missing")?;
    let field_end = field_start
        + source[field_start..]
            .find('\n')
            .ok_or("generated semantic status field is incomplete")?;
    if !source[field_start..field_end].ends_with(" | None = None") {
        return Err("generated optional semantic status representation changed");
    }
    let class_end = source[field_start..]
        .find("\nclass ")
        .map_or(source.len(), |offset| field_start + offset);
    let insertion = source[..class_end].trim_end_matches('\n').len();
    let mut hardened = source.to_owned();
    hardened.insert_str(insertion, WITHHELD_GUARDS);
    Ok(hardened.replacen(
        IMPORT,
        "from typing import Any\nfrom pydantic import field_validator, model_serializer, SerializerFunctionWrapHandler\n\nfrom pydantic import BaseModel, ",
        1,
    ))
}

fn harden_origin_source(source: &str) -> Result<String, &'static str> {
    if source.matches(IMPORT).count() != 1 || source.matches(ACTION_CLASS).count() != 1 {
        return Err("generated recovery import or action model inventory changed");
    }
    if source.contains("field_validator") || source.contains("model_serializer") {
        return Err("generated recovery validator inventory changed");
    }
    let body_start = source
        .find(ACTION_CLASS)
        .ok_or("generated recovery action model missing")?
        + ACTION_CLASS.len();
    let body_end = source[body_start..]
        .find("\nclass ")
        .map_or(source.len(), |offset| body_start + offset);
    let body = &source[body_start..body_end];
    if body.matches(ORIGIN_FIELD).count() != 1 {
        return Err("generated optional recovery origin inventory changed");
    }
    let origin_start = body
        .find(ORIGIN_FIELD)
        .ok_or("generated optional recovery origin missing")?;
    let origin_end = origin_start
        + body[origin_start..]
            .find("\n    )\n")
            .ok_or("generated optional recovery origin field is incomplete")?
        + "\n    )\n".len();
    if !body[origin_end..].starts_with("    isolation_lineage: OpaqueId\n") {
        return Err("generated recovery origin field boundary changed");
    }
    let insertion = body_start + origin_end;
    let mut hardened = String::with_capacity(source.len() + VALIDATOR.len());
    hardened.push_str(&source[..insertion]);
    hardened.push_str(VALIDATOR);
    hardened.push_str(&source[insertion..]);
    let hardened = hardened.replacen(ACTION_CLASS, &format!("{ACTION_CLASS}{ACTION_DOC}"), 1);
    let has_literal_binding = source.lines().any(|line| {
        line.strip_prefix("from typing import ")
            .is_some_and(|members| members.split(',').any(|member| member.trim() == "Literal"))
    });
    let typing_import = if has_literal_binding {
        "from typing import Any, Self\n"
    } else {
        "from typing import Any, Literal, Self\n"
    };
    let imports = format!(
        "{typing_import}from pydantic import field_validator, model_serializer, SerializerFunctionWrapHandler\n\nfrom pydantic import BaseModel, "
    );
    Ok(hardened.replacen(IMPORT, &imports, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"from pydantic import BaseModel, ConfigDict, Field

class Origin(BaseModel):
    request_id: str

class RecoveryExactActionIntentV1(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origin: Origin | None = Field(
        None,
        description="Verified original denial. Legacy actions may omit this field.",
    )
    isolation_lineage: OpaqueId

class UnrelatedModel(BaseModel):
    origin: Origin | None = None
"#;

    #[test]
    fn recovery_origin_hardening_preserves_the_optional_field_and_unrelated_models(
    ) -> Result<(), &'static str> {
        let hardened = harden_origin_source(SOURCE)?;
        assert!(hardened.contains("    origin: Origin | None = Field(\n        None,\n"));
        assert!(hardened
            .ends_with("class UnrelatedModel(BaseModel):\n    origin: Origin | None = None\n"));
        assert_eq!(hardened.matches("@field_validator(").count(), 1);
        assert_eq!(hardened.matches("@model_serializer(").count(), 1);
        assert!(hardened.contains("value.pop(\"origin\", None)"));
        assert!(hardened.contains("this model cannot establish freshness"));
        Ok(())
    }

    #[test]
    fn recovery_origin_hardening_preserves_existing_typing_literal_bindings(
    ) -> Result<(), &'static str> {
        for import in [
            "from typing import Literal\n",
            "from typing import Annotated, Literal\n",
        ] {
            let source = format!("{import}{SOURCE}");
            let hardened = harden_origin_source(&source)?;
            assert!(hardened.starts_with(import));
            assert!(hardened.contains("from typing import Any, Self\n"));
            assert!(!hardened.contains("from typing import Any, Literal, Self\n"));
        }
        let minimal = harden_origin_source(SOURCE)?;
        assert!(minimal.contains("from typing import Any, Literal, Self\n"));
        Ok(())
    }

    #[test]
    fn recovery_origin_hardening_refuses_missing_or_ambiguous_models() {
        assert!(harden_origin_source(&SOURCE.replace(ACTION_CLASS, "")).is_err());
        assert!(harden_origin_source(&format!("{SOURCE}\n{ACTION_CLASS}    pass\n")).is_err());
        assert!(harden_origin_source(&format!("{SOURCE}\n{IMPORT}Field\n")).is_err());
        assert!(
            harden_origin_source(&SOURCE.replace(IMPORT, "from other import BaseModel, ")).is_err()
        );
    }

    #[test]
    fn recovery_origin_hardening_refuses_changed_field_presence_contracts() {
        assert!(
            harden_origin_source(&SOURCE.replace("Origin | None = Field(", "Origin = Field("))
                .is_err()
        );
        assert!(harden_origin_source(&SOURCE.replace("        None,", "        ...,")).is_err());
        assert!(
            harden_origin_source(&SOURCE.replace("    isolation_lineage: OpaqueId\n", "")).is_err()
        );
    }

    #[test]
    fn recovery_origin_hardening_refuses_double_injection() -> Result<(), &'static str> {
        assert!(harden_origin_source(&harden_origin_source(SOURCE)?).is_err());
        Ok(())
    }

    #[test]
    fn semantic_status_hardening_preserves_fields_and_declines_ambiguous_sources(
    ) -> Result<(), &'static str> {
        let source = "from pydantic import BaseModel, ConfigDict\n\nclass Operation(BaseModel):\n    withheld_status: Status | None = None\n\nclass Other(BaseModel):\n    value: str\n";
        let hardened = harden_withheld_source(source)?;
        assert!(hardened.contains("    withheld_status: Status | None = None\n"));
        assert!(hardened.contains("value.pop(\"withheld_status\", None)"));
        assert!(hardened.ends_with("class Other(BaseModel):\n    value: str\n"));
        assert!(harden_withheld_source(&hardened).is_err());
        assert!(harden_withheld_source(&source.replace(" | None = None", " = None")).is_err());
        assert!(harden_withheld_source(&source.replace(WITHHELD_FIELD, "    other: ")).is_err());
        assert!(harden_withheld_source(&format!(
            "{source}\n{WITHHELD_FIELD}Status | None = None\n"
        ))
        .is_err());
        Ok(())
    }

    #[test]
    fn numeric_literal_hardening_composes_with_generated_action_json_validation(
    ) -> Result<(), &'static str> {
        let generated = include_str!("../../tests/fixtures/recovery_action_intent.py");
        let origin_hardened = harden_origin_source(generated)?;
        let hardened = harden_integer_literal_source(&origin_hardened)?;
        for field in generated.lines().filter(|line| {
            line.starts_with("    ") && !line.starts_with("        ") && line.contains(": ")
        }) {
            assert!(hardened.contains(field), "generated field changed: {field}");
        }
        assert!(hardened.contains("    def model_validate_json("));
        assert!(hardened.contains("        extra: Literal[\"allow\", \"ignore\", \"forbid\"]"));
        assert!(hardened.contains("@field_validator(\"version\", mode=\"before\")"));
        assert_eq!(hardened.matches("@field_validator(").count(), 2);
        assert_eq!(hardened.matches("@model_serializer(").count(), 1);
        assert!(hardened.contains("if type(value) is not int:"));
        Ok(())
    }

    #[test]
    fn numeric_literal_hardening_refuses_unowned_method_literal_annotations() {
        let source = r#"from typing import Literal
from pydantic import BaseModel

class Envelope(BaseModel):
    version: Literal[1]

    def adapt(
        self,
        mode: Literal["allow", "forbid"] = "forbid",
        count: Literal[2] = 2,
    ) -> int:
        local: Literal[3] = 3
        return local

    count: Literal[4]
"#;
        assert!(harden_integer_literal_source(source).is_err());
    }

    #[test]
    fn numeric_literal_hardening_guards_fields_after_commented_class_headers(
    ) -> Result<(), &'static str> {
        let source = "from typing import Literal\nfrom pydantic import BaseModel\nclass Model(BaseModel): # comment\n    version: Literal[1]\n";
        let hardened = harden_integer_literal_source(source)?;
        assert!(hardened.contains("class Model(BaseModel): # comment"));
        assert!(hardened.contains("    version: Literal[1]"));
        assert!(hardened.contains("@field_validator(\"version\", mode=\"before\")"));
        Ok(())
    }

    #[test]
    fn numeric_literal_hardening_refuses_docstring_method_text_before_noncanonical_fields() {
        let source = r#"from typing import Literal
from pydantic import BaseModel

class Model(BaseModel):
        """
    def example():
        """
        version: Literal[1]
"#;
        assert!(harden_integer_literal_source(source).is_err());
    }

    #[test]
    fn numeric_literal_hardening_preserves_docstring_method_text_and_direct_fields(
    ) -> Result<(), &'static str> {
        let source = r#"from typing import Literal
from pydantic import BaseModel

class Model(BaseModel):
    """
    def example():
        return example
    """
    version: Literal[1]
"#;
        let hardened = harden_integer_literal_source(source)?;
        assert!(hardened.contains("    def example():\n        return example"));
        assert!(hardened.contains("    version: Literal[1]"));
        assert!(hardened.contains("@field_validator(\"version\", mode=\"before\")"));
        Ok(())
    }

    #[test]
    fn numeric_literal_hardening_refuses_overindented_class_fields() {
        for field in ["     version: Literal[1]", "        version: Literal[1]"] {
            let source =
                format!("from pydantic import BaseModel\nclass Model(BaseModel):\n{field}\n");
            assert!(harden_integer_literal_source(&source).is_err(), "{field}");
        }
    }

    #[test]
    fn numeric_literal_hardening_preserves_field_declarations_and_non_numeric_payloads(
    ) -> Result<(), &'static str> {
        let source = "from __future__ import annotations\nfrom typing import Any, Literal\nfrom pydantic import BaseModel\n\nclass Envelope(BaseModel):\n    version: Literal[1]\n    count: Literal[0, 2] = 0\n    allowed: Literal[True]\n    kind: Literal[\"constant,1\"]\n    result: Any\n\nclass Other(BaseModel):\n    value: int\n";
        let hardened = harden_integer_literal_source(source)?;
        assert!(hardened.starts_with("from __future__ import annotations\n"));
        assert!(hardened.contains("    version: Literal[1]\n"));
        assert!(hardened.contains("    count: Literal[0, 2] = 0\n"));
        assert!(hardened.contains("@field_validator(\"version\", \"count\", mode=\"before\")"));
        assert!(hardened.contains("if type(value) is not int:"));
        assert!(hardened.contains("    allowed: Literal[True]\n"));
        assert!(hardened.contains("    result: Any\n"));
        assert!(hardened.ends_with("class Other(BaseModel):\n    value: int\n"));
        assert!(harden_integer_literal_source(&hardened).is_err());
        Ok(())
    }

    #[test]
    fn numeric_literal_hardening_refuses_ambiguous_generated_declarations() {
        for field in [
            "    version: Literal[1",
            "    version: Literal[1, True]",
            "    version: Literal[1] | None",
            "    version: Literal[1.0]",
            "    version: Literal[\"unfinished]",
            "    version: Literal[1]\n    version: Literal[1]",
        ] {
            let source =
                format!("from pydantic import BaseModel\nclass Model(BaseModel):\n{field}\n");
            assert!(harden_integer_literal_source(&source).is_err(), "{field}");
        }
    }
}
