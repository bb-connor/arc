use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::XtaskError;

pub(crate) fn walk_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_json(&path, out)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext.eq_ignore_ascii_case("json") {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

/// Walk `dir` recursively, collecting every `*.schema.json` file. Mirrors
/// the schema discovery in `chio_spec_codegen::walk_schema_files` so the
/// Rust and TS targets see an identical input set.
pub(crate) fn walk_schema_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
    let metadata =
        fs::symlink_metadata(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(XtaskError::Usage(format!(
            "schema directory is not a real directory: {}",
            display_path(dir)
        )));
    }
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_symlink() {
            return Err(XtaskError::Usage(format!(
                "refusing symlink in schema tree: {}",
                display_path(&path)
            )));
        }
        if file_type.is_dir() {
            walk_schema_json(&path, out)?;
        } else if file_type.is_file() {
            if let Some(name) = path.file_name().and_then(OsStr::to_str) {
                if name.ends_with(".schema.json") {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn git_inventory_paths(
    workspace_root: &Path,
    scope: &Path,
) -> Result<Vec<PathBuf>, XtaskError> {
    let scope = normalized_workspace_relative_path(scope)?;
    let inventory = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
        ])
        .arg(&scope)
        .current_dir(workspace_root)
        .output()
        .map_err(|error| XtaskError::Io(format!("git ls-files {scope}"), error))?;
    if !inventory.status.success() {
        return Err(XtaskError::Process(format!(
            "git ls-files {scope} exited with code {}: {}",
            inventory.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&inventory.stderr)
        )));
    }
    parse_git_inventory(&inventory.stdout, Path::new(&scope))
}

pub(crate) fn parse_git_inventory(output: &[u8], scope: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    if !output.is_empty() && output.last() != Some(&0) {
        return Err(XtaskError::Usage(
            "git inventory is not NUL terminated".to_string(),
        ));
    }
    let mut paths = Vec::new();
    for raw_path in output
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = std::str::from_utf8(raw_path)
            .map_err(|_| XtaskError::Usage("git inventory path is not valid UTF-8".to_string()))?;
        if path.chars().any(char::is_control) {
            return Err(XtaskError::Usage(format!(
                "git inventory path contains a control character: {path:?}"
            )));
        }
        let path = PathBuf::from(path);
        if !path.starts_with(scope)
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(XtaskError::Usage(format!(
                "git inventory path is not normalized under {}: {}",
                display_path(scope),
                display_path(&path)
            )));
        }
        paths.push(path);
    }
    Ok(paths)
}

pub(crate) fn authoritative_schema_json_inventory(
    workspace_root: &Path,
    schemas_dir: &Path,
) -> Result<Vec<PathBuf>, XtaskError> {
    let canonical_schemas_dir = validate_workspace_subdirectory(workspace_root, schemas_dir)?;
    let canonical_workspace_root = fs::canonicalize(workspace_root)
        .map_err(|err| XtaskError::Io(display_path(workspace_root), err))?;
    let scope = schemas_dir.strip_prefix(workspace_root).map_err(|_| {
        XtaskError::Usage(format!(
            "schema root {} is not under workspace root {}",
            display_path(schemas_dir),
            display_path(workspace_root)
        ))
    })?;
    let mut relative_files = git_inventory_paths(workspace_root, scope)?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.ends_with(".schema.json"))
        })
        .collect::<Vec<_>>();
    relative_files.sort();
    let before_dedup = relative_files.len();
    relative_files.dedup();
    if relative_files.len() != before_dedup {
        return Err(XtaskError::Usage(
            "git schema inventory contains duplicate paths".to_string(),
        ));
    }

    let mut authoritative = Vec::with_capacity(relative_files.len());
    for relative in &relative_files {
        let schema_relative = relative.strip_prefix(scope).map_err(|_| {
            XtaskError::Usage(format!(
                "schema inventory path is outside {}: {}",
                display_path(scope),
                display_path(relative)
            ))
        })?;
        let path = workspace_root.join(relative);
        let metadata =
            fs::symlink_metadata(&path).map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(XtaskError::Usage(format!(
                "schema inventory entry is not a real file: {}",
                display_path(&path)
            )));
        }
        let canonical =
            fs::canonicalize(&path).map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if canonical != canonical_workspace_root.join(relative)
            || canonical != canonical_schemas_dir.join(schema_relative)
        {
            return Err(XtaskError::Usage(format!(
                "schema inventory entry contains a symlink or path alias: {}",
                display_path(&path)
            )));
        }
        authoritative.push(path);
    }

    let mut filesystem_files = Vec::new();
    walk_schema_json(schemas_dir, &mut filesystem_files)?;
    filesystem_files.sort();
    if filesystem_files != authoritative {
        let extra = filesystem_files
            .iter()
            .find(|path| authoritative.binary_search(path).is_err())
            .map(|path| display_path(path));
        let missing = authoritative
            .iter()
            .find(|path| filesystem_files.binary_search(path).is_err())
            .map(|path| display_path(path));
        return Err(XtaskError::Usage(format!(
            "filesystem schema tree differs from the tracked plus unignored Git inventory (extra: {}; missing: {})",
            extra.as_deref().unwrap_or("none"),
            missing.as_deref().unwrap_or("none")
        )));
    }

    Ok(authoritative)
}

fn normalized_workspace_relative_path(path: &Path) -> Result<String, XtaskError> {
    let mut segments = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(segment) = component else {
            return Err(XtaskError::Usage(format!(
                "workspace-relative path is not normalized: {}",
                display_path(path)
            )));
        };
        let segment = segment.to_str().ok_or_else(|| {
            XtaskError::Usage(format!(
                "workspace-relative path is not valid UTF-8: {}",
                display_path(path)
            ))
        })?;
        if segment.chars().any(char::is_control) {
            return Err(XtaskError::Usage(format!(
                "workspace-relative path contains a control character: {segment:?}"
            )));
        }
        segments.push(segment.to_string());
    }
    if segments.is_empty() {
        return Err(XtaskError::Usage(
            "workspace-relative path is empty".to_string(),
        ));
    }
    Ok(segments.join("/"))
}

pub(crate) fn validate_workspace_subdirectory(
    workspace_root: &Path,
    directory: &Path,
) -> Result<PathBuf, XtaskError> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|err| XtaskError::Io(display_path(directory), err))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(XtaskError::Usage(format!(
            "workspace input is not a real directory: {}",
            display_path(directory)
        )));
    }
    let relative = directory.strip_prefix(workspace_root).map_err(|_| {
        XtaskError::Usage(format!(
            "workspace input {} is not under {}",
            display_path(directory),
            display_path(workspace_root)
        ))
    })?;
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(XtaskError::Usage(format!(
                "workspace input path is not normalized: {}",
                display_path(directory)
            )));
        }
    }
    let canonical_workspace = fs::canonicalize(workspace_root)
        .map_err(|err| XtaskError::Io(display_path(workspace_root), err))?;
    let canonical_directory =
        fs::canonicalize(directory).map_err(|err| XtaskError::Io(display_path(directory), err))?;
    if canonical_directory != canonical_workspace.join(relative) {
        return Err(XtaskError::Usage(format!(
            "workspace input contains a symlink or path alias: {}",
            display_path(directory)
        )));
    }
    Ok(canonical_directory)
}

pub(crate) fn hash_schema_inventory(
    workspace_root: &Path,
    schema_files: &[PathBuf],
) -> Result<String, XtaskError> {
    let mut hasher = Sha256::new();
    let mut sorted_files = schema_files.to_vec();
    sorted_files.sort();
    for path in &sorted_files {
        let relative = path.strip_prefix(workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen schema {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let mut segments = Vec::new();
        for component in relative.components() {
            let std::path::Component::Normal(segment) = component else {
                return Err(XtaskError::Usage(format!(
                    "codegen schema path is not normalized: {}",
                    display_path(path)
                )));
            };
            segments.push(
                segment
                    .to_str()
                    .ok_or_else(|| {
                        XtaskError::Usage(format!(
                            "codegen schema path is not valid UTF-8: {}",
                            display_path(path)
                        ))
                    })?
                    .to_string(),
            );
        }
        hasher.update(segments.join("/").as_bytes());
        hasher.update([0u8]);
        let bytes = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        hasher.update(bytes);
        hasher.update([0u8]);
    }
    Ok(digest_to_hex(&hasher.finalize()))
}

pub(crate) fn digest_to_hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Lower-case hex, two chars per byte, matches `shasum -a 256` output.
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out.push(hex_nibble(hi));
        out.push(hex_nibble(lo));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

pub(crate) fn workspace_root() -> Result<PathBuf, XtaskError> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut here = PathBuf::from(manifest_dir);
    if !here.pop() {
        return Err(XtaskError::Usage(format!(
            "could not derive workspace root from CARGO_MANIFEST_DIR={manifest_dir}"
        )));
    }
    Ok(here)
}

pub(crate) fn display_path(path: &Path) -> String {
    path.display().to_string()
}

pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), XtaskError> {
    fs::create_dir_all(dst).map_err(|err| XtaskError::Io(display_path(dst), err))?;
    let entries = fs::read_dir(src).map_err(|err| XtaskError::Io(display_path(src), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(src), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let Some(name) = path.file_name() else {
            continue;
        };
        if name == "__pycache__" {
            continue;
        }
        let target = dst.join(name);
        if file_type.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "pyc" || ext == "pyo" {
                    continue;
                }
            }
            fs::copy(&path, &target).map_err(|err| XtaskError::Io(display_path(&target), err))?;
        }
    }
    Ok(())
}

pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub(crate) fn new(prefix: &str) -> std::io::Result<Self> {
        let mut base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        base.push(format!("{prefix}-{pid}-{nanos}"));
        fs::create_dir_all(&base)?;
        Ok(Self { path: base })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
