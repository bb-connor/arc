//! Inventory physical sources, including Rust fragments reached through `include!`.
//!
//! Each file is checked once at its physical path so moving a side effect into a
//! fragment does not inherit an exception belonging to the including file. Only
//! literal relative includes are supported; dynamic source generation must not
//! silently escape this gate. This is a source contract check, not macro expansion
//! or a semantic proof of mediation.

use super::{display_path, parse_source, test_only, SourceFacts};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};
use syn::visit::{self, Visit};

const MAX_INCLUDE_DEPTH: usize = 64;

pub(super) fn parse_repo_sources(
    root: &Path,
    sources: &[String],
) -> Result<BTreeMap<String, SourceFacts>, String> {
    let mut parsed = BTreeMap::new();
    let mut active = BTreeSet::new();
    for relative in sources {
        parse_recursive(root, relative, &mut parsed, &mut active)?;
    }
    Ok(parsed)
}

fn parse_recursive(
    root: &Path,
    relative: &str,
    parsed: &mut BTreeMap<String, SourceFacts>,
    active: &mut BTreeSet<String>,
) -> Result<(), String> {
    if active.contains(relative) {
        return Err(format!("production Rust include cycle at {relative}"));
    }
    if parsed.contains_key(relative) {
        return Ok(());
    }
    if active.len() >= MAX_INCLUDE_DEPTH {
        return Err(format!(
            "production Rust include depth exceeded at {relative}"
        ));
    }
    let path = Path::new(relative);
    validate_relative_path(path)?;
    if !path.starts_with("crates") {
        return Err(format!(
            "production Rust source is outside crates: {relative}"
        ));
    }
    // Check ancestors too. Checking only the final file would follow a symlinked
    // directory and allow an include to leave the inventoried source tree.
    let mut absolute = root.to_path_buf();
    for component in path.components() {
        absolute.push(component);
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("cannot stat {}: {error}", display_path(&absolute)))?;
        if metadata.file_type().is_symlink()
            || (absolute != root.join(path) && !metadata.is_dir())
            || (absolute == root.join(path) && !metadata.is_file())
        {
            return Err(format!(
                "production Rust source is not a regular file through regular directories: {relative}"
            ));
        }
    }
    let source = fs::read_to_string(&absolute)
        .map_err(|error| format!("cannot read {relative}: {error}"))?;
    let facts = parse_source(&source, relative)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("production Rust source has no parent: {relative}"))?;
    active.insert(relative.to_string());
    for include in &facts.includes {
        let included = parent.join(include);
        let included = included
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 include path from {relative}"))?
            .replace('\\', "/");
        parse_recursive(root, &included, parsed, active)?;
    }
    active.remove(relative);
    parsed.insert(relative.to_string(), facts);
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.to_string_lossy().contains('\\')
    {
        return Err(format!(
            "unsafe production Rust include path: {}",
            display_path(path)
        ));
    }
    Ok(())
}

pub(super) fn include_paths(syntax: &syn::File) -> Result<Vec<String>, String> {
    let mut visitor = IncludeVisitor::default();
    visitor.visit_file(syntax);
    visitor.includes.into_iter().collect()
}

#[derive(Default)]
struct IncludeVisitor {
    includes: Vec<Result<String, String>>,
}

impl<'ast> Visit<'ast> for IncludeVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if !test_only(&node.attrs) {
            visit::visit_item_impl(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !test_only(&node.attrs) {
            visit::visit_item_fn(self, node);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !test_only(&node.attrs) {
            visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if !test_only(&node.attrs) {
            visit::visit_item_macro(self, node);
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "include")
        {
            return;
        }
        self.includes.push((|| {
            let literal = syn::parse2::<syn::LitStr>(node.tokens.clone()).map_err(|_| {
                "production Rust include requires a literal relative path".to_string()
            })?;
            let value = literal.value();
            validate_relative_path(Path::new(&value))?;
            Ok(value)
        })());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter_no_bypass::validate_dangerous_calls;
    use crate::support::TempDir;

    const ENTRY: &str = "crates/protocol/chio-example-adapter/src/lib.rs";

    fn fixture(files: &[(&str, &str)]) -> Result<TempDir, Box<dyn std::error::Error>> {
        let dir = TempDir::new("adapter-include-test")?;
        let source = dir.path().join("crates/protocol/chio-example-adapter/src");
        fs::create_dir_all(&source)?;
        for (path, body) in files {
            fs::write(source.join(path), body)?;
        }
        Ok(dir)
    }

    #[test]
    fn nested_fragments_are_checked_at_their_physical_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = fixture(&[
            ("lib.rs", "include!(\"first.inc\");"),
            ("first.inc", "include!(\"second.fragment\");"),
            (
                "second.fragment",
                "fn bypass() { Command::new(\"tool\").spawn(); }",
            ),
        ])?;
        let sources = parse_repo_sources(dir.path(), &[ENTRY.to_string()])?;
        assert_eq!(sources.len(), 3);
        let error = validate_dangerous_calls(&sources, false)
            .err()
            .ok_or("bypass was accepted")?;
        assert!(error.contains("second.fragment::bypass"), "{error}");
        Ok(())
    }

    #[test]
    fn included_rs_sources_are_not_counted_twice() -> Result<(), Box<dyn std::error::Error>> {
        let dir = fixture(&[
            ("lib.rs", "include!(\"part.rs\");"),
            ("part.rs", "fn part() {}"),
        ])?;
        let part = ENTRY.replace("lib.rs", "part.rs");
        let sources = parse_repo_sources(dir.path(), &[ENTRY.to_string(), part])?;
        assert_eq!(sources.len(), 2);
        Ok(())
    }

    #[test]
    fn production_include_under_a_test_named_path_is_still_checked(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = fixture(&[
            ("lib.rs", "include!(\"tests.rs\");"),
            ("tests.rs", "fn bypass() { server.invoke(); }"),
        ])?;
        let sources = parse_repo_sources(dir.path(), &[ENTRY.to_string()])?;
        assert!(validate_dangerous_calls(&sources, false).is_err());
        Ok(())
    }

    #[test]
    fn test_only_includes_are_not_required() -> Result<(), Box<dyn std::error::Error>> {
        let dir = fixture(&[(
            "lib.rs",
            r#"
            #[cfg(test)] mod tests { include!("absent.inc"); }
            #[cfg(test)] include!("also-absent.inc");
            #[test] fn fixture() { include!("function.inc"); }
            #[cfg(test)] impl Example { fn fixture() { include!("impl.inc"); } }
        "#,
        )])?;
        assert_eq!(
            parse_repo_sources(dir.path(), &[ENTRY.to_string()])?.len(),
            1
        );
        Ok(())
    }

    #[test]
    fn missing_and_cyclic_includes_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        for (files, expected) in [
            (
                vec![("lib.rs", "include!(\"missing.inc\");")],
                "cannot stat",
            ),
            (
                vec![
                    ("lib.rs", "include!(\"cycle.inc\");"),
                    ("cycle.inc", "include!(\"lib.rs\");"),
                ],
                "include cycle",
            ),
        ] {
            let dir = fixture(&files)?;
            let error = parse_repo_sources(dir.path(), &[ENTRY.to_string()])
                .err()
                .ok_or("invalid include was accepted")?;
            assert!(error.contains(expected), "{error}");
        }
        Ok(())
    }

    #[test]
    fn include_depth_is_bounded_without_rejecting_the_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for fragments in [MAX_INCLUDE_DEPTH - 1, MAX_INCLUDE_DEPTH] {
            let mut files = vec![(
                "lib.rs".to_string(),
                "include!(\"part-0.inc\");".to_string(),
            )];
            for index in 0..fragments {
                let body = if index + 1 == fragments {
                    "fn leaf() {}".to_string()
                } else {
                    format!("include!(\"part-{}.inc\");", index + 1)
                };
                files.push((format!("part-{index}.inc"), body));
            }
            let borrowed = files
                .iter()
                .map(|(name, body)| (name.as_str(), body.as_str()))
                .collect::<Vec<_>>();
            let dir = fixture(&borrowed)?;
            let result = parse_repo_sources(dir.path(), &[ENTRY.to_string()]);
            if fragments < MAX_INCLUDE_DEPTH {
                assert_eq!(result?.len(), MAX_INCLUDE_DEPTH);
            } else {
                let error = result.err().ok_or("excessive include depth was accepted")?;
                assert!(error.contains("include depth exceeded"), "{error}");
            }
        }
        Ok(())
    }

    #[test]
    fn unsafe_or_dynamic_include_paths_fail_closed() {
        for source in [
            "include!(\"../outside.rs\");",
            "include!(\"/outside.rs\");",
            "include!(\"\");",
            "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));",
            "include!(env!(\"GENERATED_SOURCE\"));",
            "core::include!(env!(\"GENERATED_SOURCE\"));",
        ] {
            assert!(parse_source(source, "fixture.rs").is_err(), "{source}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_includes_and_ancestors_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        for target in ["linked.rs", "linked-dir/lib.rs"] {
            let dir = fixture(&[("lib.rs", &format!("include!({target:?});"))])?;
            let source = dir.path().join("crates/protocol/chio-example-adapter/src");
            std::os::unix::fs::symlink(source.join("lib.rs"), source.join("linked.rs"))?;
            std::os::unix::fs::symlink(&source, source.join("linked-dir"))?;
            let error = parse_repo_sources(dir.path(), &[ENTRY.to_string()])
                .err()
                .ok_or("symlink was accepted")?;
            assert!(error.contains("not a regular file"), "{error}");
        }
        Ok(())
    }
}
