use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

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
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
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
    let cwd = env::current_dir().map_err(|err| XtaskError::Io("current directory".into(), err))?;
    workspace_root_from(&cwd)
}

/// Resolve the invocation's checkout, including when Cargo reuses a binary
/// built in another worktree. Never fall back to a compiled path or environment
/// variable: a frozen binary must also run from the intended checkout.
fn workspace_root_from(cwd: &Path) -> Result<PathBuf, XtaskError> {
    let cwd = fs::canonicalize(cwd).map_err(|err| XtaskError::Io(display_path(cwd), err))?;
    let mut package_dir = None;
    for directory in cwd.ancestors() {
        let manifest_path = directory.join("Cargo.toml");
        if let Some(manifest) = read_manifest(&manifest_path)? {
            if manifest.get("workspace").is_some() {
                validate_workspace(directory, &manifest, package_dir)?;
                return Ok(directory.to_path_buf());
            }
            if package_dir.is_none() && manifest.get("package").is_some() {
                package_dir = Some(directory);
            }
        }
        // Do not cross ordinary checkouts, worktrees, bare repositories, or
        // Git's own metadata directory to select a containing Chio checkout.
        if directory.file_name() == Some(OsStr::new(".git"))
            || path_present(&directory.join(".git"))?
            || (path_present(&directory.join("HEAD"))?
                && path_present(&directory.join("objects"))?
                && path_present(&directory.join("config"))?)
        {
            break;
        }
    }
    Err(XtaskError::Usage(format!(
        "no Chio workspace found from {}; run xtask from the intended checkout or one of its subdirectories",
        display_path(&cwd)
    )))
}

fn path_present(path: &Path) -> Result<bool, XtaskError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(XtaskError::Io(display_path(path), err)),
    }
}

fn read_manifest(path: &Path) -> Result<Option<toml::Value>, XtaskError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(XtaskError::Io(display_path(path), err)),
    };
    text.parse()
        .map(Some)
        .map_err(|err| XtaskError::Usage(format!("cannot parse {}: {err}", display_path(path))))
}

fn validate_workspace(
    root: &Path,
    manifest: &toml::Value,
    package_dir: Option<&Path>,
) -> Result<(), XtaskError> {
    let members = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array);
    let member_exists = |path: &Path| {
        members.is_some_and(|members| {
            members
                .iter()
                .filter_map(toml::Value::as_str)
                .any(|member| root.join(member) == path)
        })
    };
    // These explicit members and package names identify this repository
    // without executing Cargo, Git hooks, or any checkout-provided program.
    for (member, name) in [("xtask", "xtask"), ("crates/core/chio-core", "chio-core")] {
        let path = root.join(member);
        let package = read_manifest(&path.join("Cargo.toml"))?;
        if !member_exists(&path)
            || package
                .as_ref()
                .and_then(|manifest| manifest.get("package"))
                .and_then(|package| package.get("name"))
                .and_then(toml::Value::as_str)
                != Some(name)
        {
            return Err(XtaskError::Usage(format!(
                "{} is not a Chio workspace; run xtask from the intended checkout",
                display_path(root)
            )));
        }
    }
    if let Some(package) = package_dir {
        if !member_exists(package) {
            return Err(XtaskError::Usage(format!(
                "{} is not a member of {}; run xtask from the intended checkout",
                display_path(package),
                display_path(root)
            )));
        }
    }
    Ok(())
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
