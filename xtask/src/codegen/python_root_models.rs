//! Preserve regex constraints while deferring RootModel schema construction.
//!
//! Pydantic instantiates `RootModel[constr(...)]` before the generated subclass's
//! `regex_engine` configuration exists. An unparameterized base lets Pydantic
//! apply that configuration to the unchanged `root` field declaration.

use std::fs;
use std::path::Path;

use crate::support::display_path;
use crate::XtaskError;

pub(super) fn harden(root: &Path) -> Result<(), XtaskError> {
    for (file, classes) in [
        (
            "cage_init_plan_v2_schema.py",
            &["AbsoluteCanonicalPath"][..],
        ),
        (
            "mcp_cage_launch_policy_v2_schema.py",
            &["AbsoluteCanonicalPath", "EnvironmentVariable"][..],
        ),
        (
            "tool_manifest_v2_schema.py",
            &["ReadPath", "WritePath", "EnvironmentVariable"][..],
        ),
    ] {
        let path = root.join("security").join(file);
        let mut source = fs::read_to_string(&path)
            .map_err(|error| XtaskError::Io(display_path(&path), error))?;
        for class in classes {
            source = defer_regex_root_validation(&source, class).map_err(|error| {
                XtaskError::ToolFailed(format!(
                    "Python root model {}::{class}: {error}",
                    display_path(&path)
                ))
            })?;
        }
        fs::write(&path, source).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    }
    Ok(())
}

fn defer_regex_root_validation(source: &str, class: &str) -> Result<String, &'static str> {
    let header = format!("class {class}(\n    RootModel[");
    if source.matches(&header).count() != 1 {
        return Err("expected exactly one parameterized RootModel declaration");
    }
    let start = source
        .find(&header)
        .ok_or("root model declaration missing")?;
    let end = start
        + source[start..]
            .find("\n):\n")
            .ok_or("root model header is incomplete")?
        + "\n):\n".len();
    let body_end = source[end..]
        .find("\nclass ")
        .map_or(source.len(), |offset| end + offset);
    let body = &source[end..body_end];
    if !body.contains("model_config = ConfigDict(\n        regex_engine=\"python-re\",\n    )")
        || !body.contains("    root: constr(")
    {
        return Err("expected Python regex configuration and a constrained root field");
    }
    let mut rewritten = String::with_capacity(source.len());
    rewritten.push_str(&source[..start]);
    rewritten.push_str(&format!("class {class}(RootModel):\n"));
    // The field annotation, regex and configuration remain byte-for-byte intact.
    rewritten.push_str(&source[end..]);
    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "class CanonicalPath(\n    RootModel[constr(pattern=r\"^/(?!.*//).+$\")]\n):\n    model_config = ConfigDict(\n        regex_engine=\"python-re\",\n    )\n    root: constr(pattern=r\"^/(?!.*//).+$\")\n";

    #[test]
    fn regex_root_model_keeps_the_validated_field_and_configuration() -> Result<(), &'static str> {
        let rewritten = defer_regex_root_validation(SOURCE, "CanonicalPath")?;
        let (_, body) = SOURCE.split_once("\n):\n").ok_or("fixture body missing")?;
        assert_eq!(
            rewritten,
            format!("class CanonicalPath(RootModel):\n{body}")
        );
        Ok(())
    }

    #[test]
    fn regex_root_model_refuses_changed_generator_shapes() {
        assert!(defer_regex_root_validation(SOURCE, "Missing").is_err());
        assert!(defer_regex_root_validation(
            &SOURCE.replace("python-re", "rust-regex"),
            "CanonicalPath"
        )
        .is_err());
        assert!(defer_regex_root_validation(
            &SOURCE.replace("root: constr(", "root: str #"),
            "CanonicalPath"
        )
        .is_err());
        assert!(
            defer_regex_root_validation(&format!("{SOURCE}\n{SOURCE}"), "CanonicalPath").is_err()
        );
    }
}
