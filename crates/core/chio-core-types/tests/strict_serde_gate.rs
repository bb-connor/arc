//! G18: a strict artifact never flattens a member of a type it deserializes,
//! because `#[serde(flatten)]` disables unknown-member rejection. Serialize-only
//! signing bodies may flatten.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

const STRICT_SOURCES: [&str; 4] = [
    "src/root_authority",
    "src/receipt",
    "src/capability/anchor.rs",
    "src/capability/token.rs",
];

/// Name of the struct or enum declared on `line`, under any visibility.
fn item_name(line: &str) -> Option<String> {
    let mut rest = line;
    if let Some(after) = rest.strip_prefix("pub(") {
        rest = after.split_once(')')?.1.trim_start();
    } else if let Some(after) = rest.strip_prefix("pub ") {
        rest = after.trim_start();
    }
    let rest = rest
        .strip_prefix("struct ")
        .or_else(|| rest.strip_prefix("enum "))?;
    let name: String = rest
        .chars()
        .take_while(|character| character.is_alphanumeric() || *character == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Types in `source` whose attributes (including `cfg_attr`) derive `Deserialize`
/// and that flatten a member.
fn flattened_deserialize_types(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut attributes = String::new();
    let mut depth = 0usize;
    let mut current: Option<String> = None;
    for line in source.lines().map(str::trim) {
        if depth > 0 || line.starts_with("#[") {
            attributes.push_str(line);
            for character in line.chars() {
                match character {
                    '[' => depth += 1,
                    ']' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            if depth == 0 && attributes.contains("serde(flatten") {
                if let Some(name) = &current {
                    if !found.contains(name) {
                        found.push(name.clone());
                    }
                }
            }
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if let Some(name) = item_name(line) {
            current = attributes.contains("Deserialize").then_some(name);
        }
        attributes.clear();
    }
    found
}

fn rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            rust_files(&entry.unwrap().path(), files);
        }
    } else if path
        .extension()
        .is_some_and(|extension| extension == "rs" || extension == "inc")
    {
        files.push(path.to_path_buf());
    }
}

#[test]
fn strict_types_never_flatten_a_deserialized_member() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for source in STRICT_SOURCES {
        rust_files(&root.join(source), &mut files);
    }
    assert!(files.len() > 10, "strict sources not found");
    let violations: Vec<String> = files
        .iter()
        .flat_map(|path| {
            let source = std::fs::read_to_string(path).unwrap();
            flattened_deserialize_types(&source)
                .into_iter()
                .map(move |name| format!("{}: {name}", path.display()))
        })
        .collect();
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn the_gate_reports_a_flattened_deserialized_type_only() {
    let source = r#"
        #[derive(Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct Padded {
            #[serde(flatten)]
            pub body: Body,
        }

        #[derive(
            Debug,
            Deserialize,
        )]
        struct Multiline {
            #[serde(flatten)]
            body: Body,
        }

        #[derive(Serialize)]
        pub struct SigningBody<'a> {
            #[serde(flatten)]
            pub body: &'a Body,
        }

        #[derive(serde::Deserialize)]
        pub(super) struct ParentVisible {
            #[serde(flatten)]
            body: Body,
        }

        #[derive(Debug)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub(in crate::receipt) enum Conditional {
            Variant {
                #[serde(flatten)]
                body: Body,
            },
        }
    "#;
    assert_eq!(
        flattened_deserialize_types(source),
        ["Padded", "Multiline", "ParentVisible", "Conditional"]
    );
}
