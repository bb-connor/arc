//! Preserve regex constraints while deferring RootModel schema construction.
//!
//! Pydantic instantiates `RootModel[constr(...)]` before the generated subclass's
//! `regex_engine` configuration exists. An unparameterized base lets Pydantic
//! apply that configuration to the unchanged `root` field declaration.

use std::fs;
use std::path::{Path, PathBuf};

use crate::support::display_path;
use crate::XtaskError;

pub(super) fn harden(root: &Path) -> Result<(), XtaskError> {
    for path in python_files(root)? {
        let source = fs::read_to_string(&path)
            .map_err(|error| XtaskError::Io(display_path(&path), error))?;
        let mut rewritten = source.clone();
        for class in python_re_root_models(&source) {
            rewritten = defer_regex_root_validation(&rewritten, &class).map_err(|error| {
                XtaskError::ToolFailed(format!(
                    "Python root model {}::{class}: {error}",
                    display_path(&path)
                ))
            })?;
        }
        if rewritten != source {
            fs::write(&path, rewritten)
                .map_err(|error| XtaskError::Io(display_path(&path), error))?;
        }
    }
    Ok(())
}

fn python_files(dir: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    let mut files = Vec::new();
    let entries = fs::read_dir(dir).map_err(|error| XtaskError::Io(display_path(dir), error))?;
    for entry in entries {
        let path = entry
            .map_err(|error| XtaskError::Io(display_path(dir), error))?
            .path();
        if path.is_dir() {
            files.extend(python_files(&path)?);
        } else if path.extension().is_some_and(|extension| extension == "py") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// The parameterized root models whose pattern needs the Python regex engine:
/// datamodel-codegen sets `regex_engine="python-re"` on exactly the models
/// whose pattern the default Rust engine cannot compile.
fn python_re_root_models(source: &str) -> Vec<String> {
    let mut classes = Vec::new();
    let mut rest = source;
    while let Some(offset) = rest.find("\nclass ") {
        let declaration = &rest[offset + "\nclass ".len()..];
        rest = declaration;
        let Some((class, after)) = declaration.split_once("(\n    RootModel[") else {
            continue;
        };
        if class.contains(char::is_whitespace) {
            continue;
        }
        let body = after.split("\nclass ").next().unwrap_or(after);
        if body.contains("regex_engine=\"python-re\"") {
            classes.push(class.to_owned());
        }
    }
    classes
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
    fn only_python_regex_root_models_are_deferred() {
        let plain = "class Name(\n    RootModel[constr(pattern=r\"^[a-z]+$\")]\n):\n    root: constr(pattern=r\"^[a-z]+$\")\n";
        let source = format!("\n{SOURCE}\n{plain}");
        assert_eq!(python_re_root_models(&source), ["CanonicalPath"]);
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
