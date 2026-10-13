//! Confined npm package inputs for verified-fix seller tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{RuntimeMountSpecBuilder, MAX_RUNTIME_TREE_ENTRIES};

const MAX_NPM_METADATA_BYTES: usize = 1024 * 1024;
const SELF_CONTAINED_NPM_REQUIRED: &str =
    "npm runtime requires a self-contained package with bundled dependencies";

#[derive(Deserialize)]
struct NpmPackage {
    name: String,
    version: String,
    bin: BTreeMap<String, String>,
    dependencies: BTreeMap<String, String>,
    #[serde(rename = "bundleDependencies")]
    bundle_dependencies: Vec<String>,
}

#[derive(Deserialize)]
struct BundledPackage {
    name: String,
}

impl RuntimeMountSpecBuilder {
    pub(super) fn add_npm_runtime(&mut self, executable: &Path) -> Result<(), String> {
        let executable = fs::canonicalize(executable)
            .map_err(|_| "npm runtime executable is invalid".to_owned())?;
        let root = executable
            .parent()
            .filter(|bin| bin.file_name().is_some_and(|name| name == "bin"))
            .and_then(Path::parent)
            .filter(|root| root.parent().is_some())
            .ok_or_else(|| "npm runtime executable must resolve to bin/npm-cli.js".to_owned())?;
        if executable != root.join("bin/npm-cli.js") || !executable.is_file() {
            return Err("npm runtime executable must resolve to bin/npm-cli.js".to_owned());
        }

        let metadata: NpmPackage = read_package_metadata(&root.join("package.json"), root)?;
        if metadata.name != "npm" || metadata.version.trim().is_empty() {
            return Err("npm runtime package metadata is invalid".to_owned());
        }
        for (name, target) in [("npm", "bin/npm-cli.js"), ("npx", "bin/npx-cli.js")] {
            if metadata.bin.get(name).map(String::as_str) != Some(target) {
                return Err("npm runtime bin metadata is invalid".to_owned());
            }
            let path = root.join(target);
            if fs::canonicalize(&path).ok().as_ref() != Some(&path) || !path.is_file() {
                return Err("npm runtime bin target is invalid".to_owned());
            }
        }
        let bundled = metadata.bundle_dependencies.iter().collect::<BTreeSet<_>>();
        if bundled.is_empty()
            || bundled.len() != metadata.bundle_dependencies.len()
            || bundled != metadata.dependencies.keys().collect()
        {
            return Err(SELF_CONTAINED_NPM_REQUIRED.to_owned());
        }
        for name in bundled {
            if !valid_package_name(name) {
                return Err(SELF_CONTAINED_NPM_REQUIRED.to_owned());
            }
            let path = root.join("node_modules").join(name).join("package.json");
            let package: BundledPackage = read_package_metadata(&path, root)
                .map_err(|_| SELF_CONTAINED_NPM_REQUIRED.to_owned())?;
            if package.name != *name {
                return Err(SELF_CONTAINED_NPM_REQUIRED.to_owned());
            }
        }
        validate_package_tree(root, MAX_RUNTIME_TREE_ENTRIES)?;

        let mut selected = Self::default();
        selected.add_tree_dependencies(root)?;
        selected
            .trees
            .insert((root.to_path_buf(), PathBuf::from("/runtime/npm")));
        for name in ["npm", "npx"] {
            selected.symlinks.insert((
                Path::new("/runtime/npm/bin").join(format!("{name}-cli.js")),
                Path::new("/runtime/bin").join(name),
            ));
        }
        self.files.extend(selected.files);
        self.trees.extend(selected.trees);
        self.symlinks.extend(selected.symlinks);
        Ok(())
    }
}

fn read_package_metadata<T: serde::de::DeserializeOwned>(
    path: &Path,
    root: &Path,
) -> Result<T, String> {
    let source =
        fs::canonicalize(path).map_err(|_| "npm runtime package metadata is invalid".to_owned())?;
    if source != path || !source.starts_with(root) || !source.is_file() {
        return Err("npm runtime package metadata is invalid".to_owned());
    }
    let file =
        fs::File::open(source).map_err(|_| "npm runtime package metadata is invalid".to_owned())?;
    let mut bytes = Vec::new();
    file.take((MAX_NPM_METADATA_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "npm runtime package metadata is invalid".to_owned())?;
    if bytes.len() > MAX_NPM_METADATA_BYTES {
        return Err("npm runtime package metadata exceeds its size bound".to_owned());
    }
    chio_core::canonical::UntrustedJsonText::from_wire(&bytes, MAX_NPM_METADATA_BYTES)
        .and_then(|input| input.decode_document())
        .map_err(|_| "npm runtime package metadata is invalid".to_owned())
}

fn valid_package_name(name: &str) -> bool {
    let components = name.split('/').collect::<Vec<_>>();
    let parts = match components.as_slice() {
        [name] if !name.starts_with('@') => vec![*name],
        [scope, name] if scope.starts_with('@') => vec![&scope[1..], *name],
        _ => return false,
    };
    parts.iter().all(|part| {
        !part.is_empty()
            && *part != "."
            && *part != ".."
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    })
}

fn validate_package_tree(root: &Path, entry_limit: usize) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(directory)
            .map_err(|_| "npm runtime package tree is invalid".to_owned())?;
        for entry in entries {
            let entry = entry.map_err(|_| "npm runtime package tree is invalid".to_owned())?;
            if visited >= entry_limit {
                return Err("npm runtime package tree exceeded its entry bound".to_owned());
            }
            visited += 1;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|_| "npm runtime package tree is invalid".to_owned())?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_symlink() {
                let target = fs::read_link(&path).map_err(|_| {
                    "npm runtime package tree contains an invalid symlink".to_owned()
                })?;
                let source = fs::canonicalize(&path).map_err(|_| {
                    "npm runtime package tree contains an invalid symlink".to_owned()
                })?;
                if !relative_target_is_confined(&path, &target, root)
                    || !source.starts_with(root)
                    || (!source.is_file() && !source.is_dir())
                {
                    return Err("npm runtime package tree contains an invalid symlink".to_owned());
                }
            } else if !kind.is_file() {
                return Err("npm runtime package tree contains an unsupported entry".to_owned());
            }
        }
    }
    Ok(())
}

fn relative_target_is_confined(path: &Path, target: &Path, root: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let mut resolved = parent.to_path_buf();
    for component in target.components() {
        match component {
            std::path::Component::Normal(name) => resolved.push(name),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => resolved.push(".."),
            _ => return false,
        }
        let Ok(source) = fs::canonicalize(&resolved) else {
            return false;
        };
        if !source.starts_with(root) {
            return false;
        }
        resolved = source;
    }
    true
}

#[cfg(test)]
#[path = "verified_fix_npm_runtime_tests.rs"]
mod tests;
