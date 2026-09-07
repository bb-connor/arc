//! Explicit Rust runtime inputs for verified-fix seller tests.
//!
//! A sysroot may be `/usr`. Never bind its root, `bin`, or `lib` wholesale.
//! Only named tools, bounded rustlib contents and discovered ELF dependencies
//! enter the mount plan. This is path-based discovery, not descriptor custody.

use std::fs;
use std::path::{Path, PathBuf};

use super::{normalize_absolute_runtime_path, RuntimeMountSpecBuilder, MAX_RUNTIME_TREE_ENTRIES};

const RUST_RUNTIME: &str = "/runtime/rust";

impl RuntimeMountSpecBuilder {
    pub(super) fn add_rust_sysroot(&mut self, sysroot: &Path) -> Result<(), String> {
        let sysroot =
            fs::canonicalize(sysroot).map_err(|error| format!("invalid Rust sysroot: {error}"))?;
        if !sysroot.is_dir() || sysroot.parent().is_none() {
            return Err("Rust sysroot must be a non-root directory".to_owned());
        }

        // Stage the closure separately: a rejected component cannot publish a
        // partial Rust plan or relocate unrelated, previously selected tools.
        let mut selected = Self::default();
        for (name, required) in [
            ("cargo", true),
            ("rustc", true),
            ("rustdoc", false),
            ("cargo-clippy", false),
            ("clippy-driver", false),
            ("cargo-fmt", false),
            ("rustfmt", false),
        ] {
            let relative = Path::new("bin").join(name);
            let candidate = sysroot.join(&relative);
            match fs::symlink_metadata(&candidate) {
                Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!("Rust runtime tool {name} is unavailable: {error}"))
                }
                Ok(_) => {}
            }
            let source = confined_component(&candidate, &sysroot)?;
            if !source.is_file() {
                return Err(format!("Rust runtime tool {name} is not a regular file"));
            }
            let destination = Path::new(RUST_RUNTIME).join(relative);
            selected.add_runtime_file(source, destination.clone())?;
            selected
                .symlinks
                .insert((destination, Path::new("/runtime/bin").join(name)));
        }

        selected.add_rustlib(&sysroot)?;
        selected.relocate_rust_dependencies(&sysroot)?;
        self.files.extend(selected.files);
        self.symlinks.extend(selected.symlinks);
        Ok(())
    }

    fn add_rustlib(&mut self, sysroot: &Path) -> Result<(), String> {
        let root = sysroot.join("lib/rustlib");
        let resolved = confined_component(&root, sysroot)?;
        if resolved != root || !resolved.is_dir() {
            return Err("Rust runtime rustlib must be an unredirected directory".to_owned());
        }
        let mut pending = vec![root.clone()];
        let mut visited = 0usize;
        while let Some(directory) = pending.pop() {
            let entries = fs::read_dir(&directory)
                .map_err(|error| format!("failed to inspect Rust runtime tree: {error}"))?;
            for entry in entries {
                let entry = entry
                    .map_err(|error| format!("failed to inspect Rust runtime tree: {error}"))?;
                if visited >= MAX_RUNTIME_TREE_ENTRIES {
                    return Err("sandbox runtime tree exceeded its entry bound".to_owned());
                }
                visited += 1;
                let path = entry.path();
                let source = confined_component(&path, &root)?;
                let destination = relocated_path(&path, sysroot)?;
                let kind = entry
                    .file_type()
                    .map_err(|error| format!("invalid Rust runtime entry: {error}"))?;
                if kind.is_dir() {
                    pending.push(path);
                } else if source.is_file() {
                    // File aliases are bound to their resolved contents. No
                    // host-absolute symlink escapes into the sandbox namespace.
                    self.add_runtime_file(source, destination)?;
                } else if kind.is_symlink() && source.is_dir() {
                    // The target is inside rustlib and is enumerated through its
                    // real path. Do not recursively traverse directory aliases.
                    self.symlinks
                        .insert((relocated_path(&source, sysroot)?, destination));
                } else {
                    return Err("Rust runtime entry is not a regular file or directory".to_owned());
                }
            }
        }
        Ok(())
    }

    fn relocate_rust_dependencies(&mut self, sysroot: &Path) -> Result<(), String> {
        let mut relocated = Vec::new();
        for (source, destination) in &self.files {
            let destination = normalize_absolute_runtime_path(destination)?;
            if destination.starts_with(sysroot) {
                // Keep the host-layout binding for native dependencies too.
                // The relocated alias preserves Rust's $ORIGIN/../lib lookup.
                relocated.push((source.clone(), relocated_path(&destination, sysroot)?));
            }
        }
        self.files.extend(relocated);
        Ok(())
    }
}

fn confined_component(path: &Path, root: &Path) -> Result<PathBuf, String> {
    let source = fs::canonicalize(path)
        .map_err(|error| format!("invalid Rust runtime component: {error}"))?;
    if !source.starts_with(root) {
        return Err("Rust runtime component escapes its selected root".to_owned());
    }
    Ok(source)
}

fn relocated_path(path: &Path, sysroot: &Path) -> Result<PathBuf, String> {
    path.strip_prefix(sysroot)
        .map(|relative| Path::new(RUST_RUNTIME).join(relative))
        .map_err(|_| "Rust runtime path is outside its sysroot".to_owned())
}

#[cfg(test)]
#[path = "verified_fix_rust_runtime_tests.rs"]
mod tests;
