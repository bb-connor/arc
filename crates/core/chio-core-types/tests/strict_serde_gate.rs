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

const ITEM_KEYWORDS: [&str; 6] = [
    "pub struct ",
    "pub(crate) struct ",
    "struct ",
    "pub enum ",
    "pub(crate) enum ",
    "enum ",
];

fn item_name(line: &str) -> Option<String> {
    ITEM_KEYWORDS.iter().find_map(|keyword| {
        let rest = line.strip_prefix(keyword)?;
        let name: String = rest
            .chars()
            .take_while(|character| character.is_alphanumeric() || *character == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    })
}

/// Types in `source` that derive `Deserialize` and flatten a member.
fn flattened_deserialize_types(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut derive = String::new();
    let mut in_derive = false;
    let mut current: Option<String> = None;
    for line in source.lines().map(str::trim) {
        if line.starts_with("#[derive(") || in_derive {
            if !in_derive {
                derive.clear();
            }
            derive.push_str(line);
            in_derive = !line.contains(")]");
            continue;
        }
        if let Some(name) = item_name(line) {
            current = derive.contains("Deserialize").then_some(name);
            derive.clear();
            continue;
        }
        if line.contains("serde(flatten") {
            if let Some(name) = &current {
                if !found.contains(name) {
                    found.push(name.clone());
                }
            }
        }
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
    "#;
    assert_eq!(flattened_deserialize_types(source), ["Padded", "Multiline"]);
}
