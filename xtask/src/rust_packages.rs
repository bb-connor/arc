//! Offline preview registry. No publishing and no consumer workspace patches.

mod index;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::XtaskError;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const ROOTS: [&str; 4] = [
    "chio-kernel-core",
    "chio-kernel",
    "chio-swarm-authority",
    "chio-store-sqlite",
];
const TARGET: &str = "x86_64-unknown-linux-gnu";

pub(crate) fn run(out: &Path, allow_dirty: bool) -> std::result::Result<(), XtaskError> {
    let root = crate::workspace_root()?;
    assemble(&root, out, allow_dirty).map_err(|err| XtaskError::Process(err.to_string()))
}

fn assemble(root: &Path, out: &Path, allow_dirty: bool) -> Result<()> {
    let source_status = output(Command::new("git").current_dir(root).args([
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        ".",
        ":!output/",
        ":!.superpowers/",
    ]))?;
    let dirty = !source_status.is_empty();
    if dirty && !allow_dirty {
        return Err("Rust preview requires committed source (or explicit --allow-dirty)".into());
    }
    let parent = out.parent().ok_or("output has no parent")?.canonicalize()?;
    let out = parent.join(out.file_name().ok_or("output has no file name")?);
    if out.starts_with(root) || out.exists() {
        return Err("output must be a new directory outside the source checkout".into());
    }
    let source = String::from_utf8(output(
        Command::new("git")
            .current_dir(root)
            .args(["rev-parse", "HEAD"]),
    )?)?
    .trim()
    .to_owned();
    let lock_bytes = fs::read(root.join("Cargo.lock"))?;
    let locks: toml::Value = std::str::from_utf8(&lock_bytes)?.parse()?;
    let metadata: Value =
        serde_json::from_slice(&output(Command::new("cargo").current_dir(root).args([
            "metadata",
            "--locked",
            "--format-version",
            "1",
        ]))?)?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("missing Cargo packages")?;
    let selected = closure(&metadata)?;
    let local: Vec<_> = packages
        .iter()
        .filter(|p| {
            p["source"].is_null() && p["id"].as_str().is_some_and(|id| selected.contains(id))
        })
        .collect();
    fs::create_dir(&out)?;
    let registry = out.join("registry");
    fs::create_dir(&registry)?;
    fs::create_dir(registry.join("index"))?;
    let target = PathBuf::from(field(&metadata, "target_directory")?);
    let mut package = Command::new("cargo");
    package
        .current_dir(root)
        .args(["package", "--locked", "--no-verify", "--exclude-lockfile"]);
    if allow_dirty {
        package.arg("--allow-dirty");
    }
    for p in &local {
        if field(p, "name")?.starts_with("chio-") {
            package.args(["-p", field(p, "name")?]);
        }
    }
    checked(&mut package)?;
    let mut inventory = Vec::new();
    // Keep the complete locked upstream index available for target/optional
    // resolution. Only the chosen Chio normal/build closure is distributed.
    for p in packages {
        let name = field(p, "name")?;
        let version = field(p, "version")?;
        let archive_name = format!("{name}-{version}.crate");
        let manifest = Path::new(field(p, "manifest_path")?);
        let archive = if p["source"].is_null() {
            if !selected.contains(field(p, "id")?) {
                continue;
            }
            if !name.starts_with("chio-") {
                // A vendored registry archive already contains Cargo's reserved
                // original-manifest/VCS files. Preserve them under explicit
                // upstream names in the staging copy, leaving audited source
                // and the repository lock untouched.
                let staging = out.join(format!("source-{name}-{version}"));
                copy_tree(
                    manifest
                        .parent()
                        .ok_or("missing patched source directory")?,
                    &staging,
                )?;
                for (from, to) in [
                    ("Cargo.toml.orig", "Cargo.upstream.toml"),
                    (".cargo_vcs_info.json", "UPSTREAM_VCS.json"),
                ] {
                    if staging.join(from).exists() {
                        fs::rename(staging.join(from), staging.join(to))?;
                    }
                }
                let mut package = Command::new("cargo");
                package
                    .current_dir(root)
                    .args([
                        "package",
                        "--locked",
                        "--no-verify",
                        "--exclude-lockfile",
                        "--manifest-path",
                    ])
                    .arg(staging.join("Cargo.toml"))
                    .arg("--target-dir")
                    .arg(&target);
                if allow_dirty {
                    package.arg("--allow-dirty");
                }
                checked(&mut package)?;
            }
            target.join("package").join(&archive_name)
        } else {
            if !field(p, "source")?.starts_with("registry+") {
                return Err(format!("unsupported non-registry dependency: {name}").into());
            }
            let src_index = manifest
                .parent()
                .and_then(Path::parent)
                .ok_or("invalid Cargo cache path")?;
            let registry_root = src_index
                .parent()
                .and_then(Path::parent)
                .ok_or("invalid Cargo registry cache path")?;
            registry_root
                .join("cache")
                .join(src_index.file_name().ok_or("missing index name")?)
                .join(&archive_name)
        };
        let digest = hash(&fs::read(&archive)?);
        if !p["source"].is_null() {
            let expected = locks["package"]
                .as_array()
                .ok_or("invalid lock packages")?
                .iter()
                .find(|entry| {
                    entry["name"].as_str() == Some(name)
                        && entry["version"].as_str() == Some(version)
                        && entry.get("source").and_then(toml::Value::as_str) == p["source"].as_str()
                })
                .and_then(|entry| entry.get("checksum"))
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("missing locked checksum for {name} {version}"))?;
            if digest != expected {
                return Err(format!("locked archive checksum mismatch: {name} {version}").into());
            }
        }
        let destination = registry.join(&archive_name);
        fs::copy(&archive, &destination)?;
        index::insert(&registry, &destination, name, version, &digest)?;
        inventory.push(json!({
            "name": name, "version": version, "sha256": digest,
            "origin": p["source"],
            "distribution": if p["source"].is_null() { "staged-only" } else { "locked-upstream-archive" },
            "source_path": if p["source"].is_null() {
                Some(manifest.strip_prefix(root)?.to_string_lossy().into_owned())
            } else { None },
        }));
    }
    if fs::read(root.join("Cargo.lock"))? != lock_bytes {
        return Err("workspace lock changed during packaging".into());
    }
    let consumer = out.join("consumer");
    copy_tree(&root.join("examples/rust-runtime-consumer"), &consumer)?;
    fs::create_dir(consumer.join(".cargo"))?;
    // Reserved .invalid namespace identifies an unpublished registry. Cargo
    // replaces it exclusively with the bundled index, including patched crates.
    // It never labels changed upstream bytes as a crates.io source replacement.
    let registry_digest = hash(&serde_json::to_vec(&file_hashes(&registry)?)?);
    let registry_url = format!("https://chio.invalid/rust-preview/{source}/{registry_digest}");
    fs::write(
        consumer.join(".cargo/config.toml"),
        format!(
            "[registries.chio-preview]\nindex = {registry_url:?}\n\
         [source.chio-preview]\nregistry = {registry_url:?}\nreplace-with = \"bundled\"\n\
         [source.bundled]\nlocal-registry = \"../registry\"\n\
         [net]\noffline = true\n"
        ),
    )?;
    fs::write(
        out.join("package-manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "chio.rust-preview-package.v1", "source_commit": source,
            "source_dirty": dirty, "workspace_lock_sha256": hash(&lock_bytes),
            "target": TARGET, "roots": ROOTS, "packages": inventory,
            "registry": registry_url,
            "consumer_files": file_hashes(&consumer)?,
        }))?,
    )?;
    fs::copy(
        root.join("docs/security/rust-preview-packages.md"),
        out.join("README.md"),
    )?;
    for name in ["LICENSE", "NOTICE"] {
        fs::copy(root.join(name), out.join(name))?;
    }
    println!(
        "Rust preview assembled at {} (consumer build remains required)",
        out.display()
    );
    Ok(())
}

fn file_hashes(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                pending.push(path);
            } else if entry.file_type()?.is_file() {
                files.insert(
                    path.strip_prefix(root)?.to_string_lossy().into_owned(),
                    hash(&fs::read(path)?),
                );
            } else {
                return Err("consumer contains a non-regular entry".into());
            }
        }
    }
    Ok(files)
}

fn closure(metadata: &Value) -> Result<BTreeSet<String>> {
    let packages = metadata["packages"].as_array().ok_or("missing packages")?;
    let nodes: BTreeMap<_, _> = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("missing resolve graph")?
        .iter()
        .map(|n| Ok((field(n, "id")?, n)))
        .collect::<Result<_>>()?;
    let mut pending = Vec::new();
    for name in ROOTS {
        let p = packages
            .iter()
            .find(|p| p["name"] == name)
            .ok_or_else(|| format!("missing preview root: {name}"))?;
        pending.push(field(p, "id")?.to_owned());
    }
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let node = nodes.get(id.as_str()).ok_or("missing dependency node")?;
        for dep in node["deps"].as_array().ok_or("missing dependencies")? {
            if dep["dep_kinds"]
                .as_array()
                .ok_or("missing dependency kinds")?
                .iter()
                .any(|kind| kind["kind"] != "dev")
            {
                pending.push(field(dep, "pkg")?.to_owned());
            }
        }
    }
    Ok(seen)
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        } else if kind.is_file() {
            fs::copy(entry.path(), to.join(entry.file_name()))?;
        } else {
            return Err("consumer template contains a non-regular entry".into());
        }
    }
    Ok(())
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .ok_or_else(|| format!("missing string field: {name}").into())
}

fn hash(bytes: &[u8]) -> String {
    crate::support::digest_to_hex(&Sha256::digest(bytes))
}

fn checked(command: &mut Command) -> Result<()> {
    let status = command.status()?;
    if !status.success() {
        return Err(format!("{command:?} failed: {status}").into());
    }
    Ok(())
}

fn output(command: &mut Command) -> Result<Vec<u8>> {
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!("{command:?}: {}", String::from_utf8_lossy(&result.stderr)).into());
    }
    Ok(result.stdout)
}
