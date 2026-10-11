//! Cargo local-registry index entries derived from the actual packaged manifests.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

use serde_json::json;
use toml::Value;

use super::{output, Result};

pub(super) fn insert(
    registry: &Path,
    archive: &Path,
    name: &str,
    version: &str,
    digest: &str,
) -> Result<()> {
    let member = format!("{name}-{version}/Cargo.toml");
    let manifest: Value = std::str::from_utf8(&output(
        Command::new("tar").arg("-xOf").arg(archive).arg(member),
    )?)?
    .parse()?;
    if manifest["package"]["name"].as_str() != Some(name)
        || manifest["package"]["version"].as_str() != Some(version)
    {
        return Err(format!("archive package identity mismatch: {name} {version}").into());
    }
    let mut deps = Vec::new();
    dependencies(&manifest, None, &mut deps)?;
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (target, values) in targets {
            dependencies(values, Some(target), &mut deps)?;
        }
    }
    let entry = json!({
        "name": name, "vers": version, "cksum": digest, "deps": deps,
        "features": manifest.get("features").cloned().unwrap_or_else(|| Value::Table(Default::default())),
        "links": manifest["package"].get("links"),
        "rust_version": manifest["package"].get("rust-version"),
        "yanked": false, "v": 2,
    });
    let lower = name.to_ascii_lowercase();
    let relative = match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    };
    let path = registry.join("index").join(relative);
    fs::create_dir_all(path.parent().ok_or("index path has no parent")?)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &entry)?;
    writeln!(file)?;
    Ok(())
}

fn dependencies(
    manifest: &Value,
    target: Option<&str>,
    out: &mut Vec<serde_json::Value>,
) -> Result<()> {
    for (section, kind) in [
        ("dependencies", "normal"),
        ("build-dependencies", "build"),
        ("dev-dependencies", "dev"),
    ] {
        let Some(deps) = manifest.get(section).and_then(Value::as_table) else {
            continue;
        };
        for (name, dep) in deps {
            if ["path", "git", "workspace"]
                .iter()
                .any(|key| dep.get(key).is_some())
            {
                return Err(format!("unpackaged dependency: {name}").into());
            }
            let version = dep
                .as_str()
                .or_else(|| dep.get("version").and_then(Value::as_str))
                .ok_or_else(|| format!("dependency has no version: {name}"))?;
            out.push(json!({
                "name": name, "req": version, "kind": kind, "target": target,
                "package": dep.get("package").and_then(Value::as_str),
                "optional": dep.get("optional").and_then(Value::as_bool).unwrap_or(false),
                "default_features": dep.get("default-features").and_then(Value::as_bool).unwrap_or(true),
                "features": dep.get("features").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
                // This isolated registry supplies every dependency itself,
                // including the reviewed patched upstream artifacts.
                "registry": null,
            }));
        }
    }
    Ok(())
}
