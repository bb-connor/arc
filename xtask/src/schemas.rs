use std::fs;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::support::{
    digest_to_hex, display_path, git_inventory_paths, validate_workspace_subdirectory,
    workspace_root,
};
use crate::XtaskError;

const SCHEMAS_DIR: &str = "spec/schemas";
const SCHEMAS_MANIFEST: &str = "spec/schemas/MANIFEST.sha256";
const FIXED_MANIFEST_PATHS: [&str; 5] = [
    SCHEMAS_MANIFEST,
    "spec/schemas/VERSION",
    "spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json",
    "spec/schemas/chio-wire/v1/security/required-schema-inventory.json",
    "spec/schemas/registry.json",
];

pub(crate) fn freeze_schemas(args: Vec<String>) -> Result<(), XtaskError> {
    let mut check_only = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true,
            other => {
                return Err(XtaskError::Usage(format!(
                    "freeze-schemas: unknown flag: {other}"
                )));
            }
        }
    }

    let root = workspace_root()?;
    let schemas_root = root.join(SCHEMAS_DIR);
    let canonical_schemas_root = validate_workspace_subdirectory(&root, &schemas_root)?;
    let canonical_workspace_root =
        fs::canonicalize(&root).map_err(|error| XtaskError::Io(display_path(&root), error))?;
    let manifest_path = root.join(SCHEMAS_MANIFEST);
    let mut paths = git_inventory_paths(&root, Path::new(SCHEMAS_DIR))?
        .into_iter()
        .filter(|path| {
            path.to_str().is_some_and(|path| {
                path.ends_with(".schema.json") || FIXED_MANIFEST_PATHS.contains(&path)
            })
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    if !paths.iter().any(|path| path == Path::new(SCHEMAS_MANIFEST)) {
        return Err(XtaskError::Usage(format!(
            "freeze-schemas: inventory omitted {SCHEMAS_MANIFEST}"
        )));
    }
    for relative in &paths {
        if !check_only && relative == Path::new(SCHEMAS_MANIFEST) {
            match fs::symlink_metadata(root.join(relative)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(XtaskError::Io(display_path(&root.join(relative)), error));
                }
                Ok(_) => {}
            }
        }
        validate_inventory_file(
            &root,
            &canonical_workspace_root,
            &canonical_schemas_root,
            relative,
        )?;
    }

    let mut hashed = Vec::new();
    for relative in &paths {
        if relative == Path::new(SCHEMAS_MANIFEST) {
            continue;
        }
        let path = root.join(relative);
        let bytes = fs::read(&path).map_err(|error| XtaskError::Io(display_path(&path), error))?;
        hashed.push((relative.clone(), sha256_hex(&bytes)));
    }
    let lines_without_self = hashed
        .iter()
        .map(|(path, digest)| {
            manifest_relative_path(path).map(|path| format!("{digest}  {path}\n"))
        })
        .collect::<Result<String, XtaskError>>()?;
    let self_digest = sha256_hex(lines_without_self.as_bytes());
    let mut new_content = String::new();
    for relative in &paths {
        if relative == Path::new(SCHEMAS_MANIFEST) {
            new_content.push_str(&format!(
                "{self_digest}  {}\n",
                manifest_relative_path(relative)?
            ));
        } else {
            let rendered_path = manifest_relative_path(relative)?;
            let digest = hashed
                .iter()
                .find_map(|(path, digest)| (path == relative).then_some(digest))
                .ok_or_else(|| {
                    XtaskError::Usage(format!(
                        "freeze-schemas: missing digest for {rendered_path}"
                    ))
                })?;
            new_content.push_str(&format!("{digest}  {rendered_path}\n"));
        }
    }

    if check_only {
        let existing = fs::read_to_string(&manifest_path)
            .map_err(|error| XtaskError::Io(display_path(&manifest_path), error))?;
        if existing != new_content {
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask freeze-schemas` ({} files inspected)",
                display_path(&manifest_path),
                paths.len()
            )));
        }
        println!(
            "{} in sync with {} schema inventory files",
            display_path(&manifest_path),
            paths.len()
        );
    } else {
        write_manifest_atomically(&manifest_path, new_content.as_bytes())?;
        println!(
            "wrote {} ({} schema inventory files)",
            display_path(&manifest_path),
            paths.len()
        );
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    digest_to_hex(&hasher.finalize())
}

fn validate_inventory_file(
    workspace_root: &Path,
    canonical_workspace_root: &Path,
    canonical_schemas_root: &Path,
    relative: &Path,
) -> Result<(), XtaskError> {
    let schema_relative = relative.strip_prefix(SCHEMAS_DIR).map_err(|_| {
        XtaskError::Usage(format!(
            "freeze-schemas: inventory path is outside {SCHEMAS_DIR}: {}",
            display_path(relative)
        ))
    })?;
    let path = workspace_root.join(relative);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(XtaskError::Usage(format!(
            "freeze-schemas: inventory entry is not a real file: {}",
            display_path(&path)
        )));
    }
    let canonical =
        fs::canonicalize(&path).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    if canonical != canonical_workspace_root.join(relative)
        || canonical != canonical_schemas_root.join(schema_relative)
    {
        return Err(XtaskError::Usage(format!(
            "freeze-schemas: inventory entry contains a symlink or path alias: {}",
            display_path(&path)
        )));
    }
    Ok(())
}

fn write_manifest_atomically(path: &Path, content: &[u8]) -> Result<(), XtaskError> {
    let parent = path.parent().ok_or_else(|| {
        XtaskError::Usage(format!(
            "freeze-schemas: manifest has no parent: {}",
            display_path(path)
        ))
    })?;
    let process_id = std::process::id();
    let mut selected = None;
    for attempt in 0..100u8 {
        let candidate = parent.join(format!(".MANIFEST.sha256.tmp-{process_id}-{attempt}"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                selected = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(XtaskError::Io(display_path(&candidate), error)),
        }
    }
    let Some((temporary_path, mut file)) = selected else {
        return Err(XtaskError::Usage(
            "freeze-schemas: could not allocate a manifest staging file".to_string(),
        ));
    };
    let result = (|| {
        file.write_all(content)
            .map_err(|error| XtaskError::Io(display_path(&temporary_path), error))?;
        file.sync_all()
            .map_err(|error| XtaskError::Io(display_path(&temporary_path), error))?;
        drop(file);
        fs::rename(&temporary_path, path)
            .map_err(|error| XtaskError::Io(display_path(path), error))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn manifest_relative_path(path: &Path) -> Result<String, XtaskError> {
    let mut components = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(XtaskError::Usage(format!(
                "freeze-schemas: manifest path is not normalized: {}",
                display_path(path)
            )));
        };
        let component = component.to_str().ok_or_else(|| {
            XtaskError::Usage(format!(
                "freeze-schemas: manifest path is not valid UTF-8: {}",
                display_path(path)
            ))
        })?;
        if component.chars().any(char::is_control) {
            return Err(XtaskError::Usage(format!(
                "freeze-schemas: manifest path contains a control character: {component:?}"
            )));
        }
        components.push(component.to_string());
    }
    Ok(components.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::TempDir;
    use chio_test_support::prelude::*;

    #[test]
    fn git_inventory_paths_are_exact_and_line_safe() {
        let scope = Path::new(SCHEMAS_DIR);
        let parsed = crate::support::parse_git_inventory(
            b"spec/schemas/a.schema.json\0spec/schemas/registry.json\0",
            scope,
        )
        .test_expect("valid inventory");
        assert_eq!(parsed.len(), 2);
        assert!(crate::support::parse_git_inventory(
            b"spec/schemas/bad\nname.schema.json\0",
            scope,
        )
        .is_err());
        assert!(crate::support::parse_git_inventory(b"spec/schemas/a.schema.json", scope).is_err());
        assert!(crate::support::parse_git_inventory(
            b"spec/schemas/../escape.schema.json\0",
            scope,
        )
        .is_err());
        assert!(
            crate::support::parse_git_inventory(b"spec/schemas/\xff.schema.json\0", scope).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn inventory_validation_rejects_symlinked_files() {
        let temp = TempDir::new("freeze-schemas-symlink").test_expect("temp dir");
        let workspace = temp.path();
        let schemas = workspace.join(SCHEMAS_DIR);
        fs::create_dir_all(&schemas).test_expect("create schemas root");
        let outside = workspace.join("outside");
        fs::write(&outside, b"outside").test_expect("write outside target");
        let manifest = workspace.join(SCHEMAS_MANIFEST);
        std::os::unix::fs::symlink(&outside, &manifest).test_expect("create manifest symlink");
        let canonical_schemas = validate_workspace_subdirectory(workspace, &schemas)
            .test_expect("validate schemas root");
        let canonical_workspace = fs::canonicalize(workspace).test_expect("canonical workspace");

        assert!(validate_inventory_file(
            workspace,
            &canonical_workspace,
            &canonical_schemas,
            Path::new(SCHEMAS_MANIFEST),
        )
        .is_err());
        assert_eq!(
            fs::read(&outside).test_expect("read outside target"),
            b"outside"
        );
    }
}
