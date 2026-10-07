//! Finite local schema resolution shared by all pinned generators.
//!
//! A schema ID identifies a catalog resource, never a network destination.
use std::collections::BTreeMap;

use super::*;

/// An immutable catalog of the schema files under one canonical root.
pub struct LocalSchemaCatalog {
    root: PathBuf,
    ids: BTreeMap<String, PathBuf>,
    resources: BTreeMap<PathBuf, SchemaResource>,
}

struct SchemaResource {
    value: serde_json::Value,
    bytes: Vec<u8>,
}

impl LocalSchemaCatalog {
    /// Load the finite local tree. Symlinks and duplicate IDs fail closed.
    pub fn load(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root).map_err(|err| CodegenError::Io(root.into(), err))?;
        let mut files = Vec::new();
        walk_schema_files(&root, &mut files)?;
        files.sort();
        let mut ids = BTreeMap::new();
        let mut resources = BTreeMap::new();
        for path in files {
            let raw = fs::read(&path).map_err(|err| CodegenError::Io(path.clone(), err))?;
            let schema: serde_json::Value = serde_json::from_slice(&raw)
                .map_err(|err| CodegenError::Json(path.clone(), err))?;
            if let Some(id) = schema.get("$id").and_then(serde_json::Value::as_str) {
                if ids.insert(id.to_owned(), path.clone()).is_some() {
                    return Err(CodegenError::SchemaRef(
                        path,
                        format!("duplicate schema ID {id}"),
                    ));
                }
            }
            resources.insert(
                path,
                SchemaResource {
                    value: schema,
                    bytes: raw,
                },
            );
        }
        Ok(Self {
            root,
            ids,
            resources,
        })
    }

    /// Mirror the catalog with known ID references rewritten to local paths.
    /// Unknown IDs or references outside this catalog are rejected before a
    /// generator process starts. The authoritative source bytes remain intact.
    pub fn mirror(&self, destination: &Path) -> Result<()> {
        for (path, resource) in &self.resources {
            let relative = path.strip_prefix(&self.root).map_err(|_| {
                CodegenError::SchemaRef(path.clone(), "schema escaped the catalog".into())
            })?;
            let target = destination.join(relative);
            let mut mirrored = resource.value.clone();
            self.rewrite_refs(&mut mirrored, path)?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|err| CodegenError::Io(parent.into(), err))?;
            }
            if mirrored == resource.value {
                // Property order can affect generated names in pinned tools.
                // Preserve unchanged source bytes, including legacy schemas.
                fs::write(&target, &resource.bytes).map_err(|err| CodegenError::Io(target, err))?;
            } else {
                let mut bytes = serde_json::to_vec_pretty(&mirrored)
                    .map_err(|err| CodegenError::Json(path.clone(), err))?;
                bytes.push(b'\n');
                fs::write(&target, bytes).map_err(|err| CodegenError::Io(target, err))?;
            }
        }
        Ok(())
    }

    pub(super) fn resource(&self, path: &Path) -> Result<serde_json::Value> {
        let canonical = fs::canonicalize(path).map_err(|err| CodegenError::Io(path.into(), err))?;
        self.resources
            .get(&canonical)
            .map(|resource| resource.value.clone())
            .ok_or_else(|| {
                CodegenError::SchemaRef(path.into(), "schema is not in the local catalog".into())
            })
    }

    pub(super) fn resolve(
        &self,
        reference: &str,
        base: &Path,
    ) -> Result<Option<(PathBuf, Option<String>)>> {
        let (path, fragment) = reference
            .split_once('#')
            .map_or((reference, None), |(path, fragment)| {
                (path, Some(fragment.to_owned()))
            });
        if path.is_empty() {
            return Ok(None);
        }
        let target = if has_uri_scheme(path) {
            self.ids.get(path).cloned().ok_or_else(|| {
                CodegenError::SchemaRef(base.into(), format!("{reference} uses an external schema reference absent from the local catalog"))
            })?
        } else {
            let parent = base.parent().ok_or_else(|| {
                CodegenError::SchemaRef(base.into(), "schema path has no parent directory".into())
            })?;
            let target = parent.join(path);
            fs::canonicalize(&target).map_err(|err| CodegenError::Io(target, err))?
        };
        if !target.starts_with(&self.root) || !self.resources.contains_key(&target) {
            return Err(CodegenError::SchemaRef(
                base.into(),
                format!("{reference} resolves outside the local schema catalog"),
            ));
        }
        Ok(Some((target, fragment)))
    }

    fn rewrite_refs(&self, value: &mut serde_json::Value, base: &Path) -> Result<()> {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::String(reference)) = map.get_mut("$ref") {
                    if let Some((target, fragment)) = self.resolve(reference, base)? {
                        if has_uri_scheme(reference.split('#').next().unwrap_or(reference)) {
                            let mut local = relative_reference(base, &target)?;
                            if let Some(fragment) = fragment {
                                local.push('#');
                                local.push_str(&fragment);
                            }
                            *reference = local;
                        }
                    }
                }
                for value in map.values_mut() {
                    self.rewrite_refs(value, base)?;
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    self.rewrite_refs(value, base)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn relative_reference(base: &Path, target: &Path) -> Result<String> {
    let parent = base.parent().ok_or_else(|| {
        CodegenError::SchemaRef(base.into(), "schema path has no parent directory".into())
    })?;
    let from: Vec<_> = parent.components().collect();
    let to: Vec<_> = target.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut parts = vec!["..".to_owned(); from.len() - common];
    for component in &to[common..] {
        parts.push(
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| {
                    CodegenError::SchemaRef(target.into(), "schema path is not UTF-8".into())
                })?
                .to_owned(),
        );
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_resolve_offline_and_mirror_locally() -> Result<()> {
        let root = crate::tests::unique_temp_dir("chio-local-schema-ids")?;
        let mirror = root.join("mirror");
        fs::create_dir_all(root.join("records"))
            .map_err(|err| CodegenError::Io(root.clone(), err))?;
        let record = root.join("records/record.schema.json");
        let response = root.join("response.schema.json");
        fs::write(&record, br#"{"$id":"https://example.invalid/immutable-record/v1","type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}"#)
            .map_err(|err| CodegenError::Io(record.clone(), err))?;
        fs::write(&response, br#"{"title":"Response","type":"object","properties":{"receipt":{"$ref":"https://example.invalid/immutable-record/v1"}},"required":["receipt"],"additionalProperties":false}"#)
            .map_err(|err| CodegenError::Io(response.clone(), err))?;
        let catalog = LocalSchemaCatalog::load(&root)?;
        assert_eq!(
            catalog.resolve(
                "https://example.invalid/immutable-record/v1#/properties/id",
                &response
            )?,
            Some((
                fs::canonicalize(&record).map_err(|err| CodegenError::Io(record, err))?,
                Some("/properties/id".into())
            ))
        );
        assert!(catalog
            .resolve("https://example.invalid/not-in-catalog/v1", &response)
            .is_err());
        let rendered = render_chio_wire_v1(&root)?;
        assert!(rendered.contains("pub receipt:"));
        catalog.mirror(&mirror)?;
        let mirrored: serde_json::Value = serde_json::from_slice(
            &fs::read(mirror.join("response.schema.json"))
                .map_err(|err| CodegenError::Io(mirror.clone(), err))?,
        )
        .map_err(|err| CodegenError::Json(mirror.clone(), err))?;
        assert_eq!(
            mirrored["properties"]["receipt"]["$ref"],
            "records/record.schema.json"
        );
        fs::remove_dir_all(&root).map_err(|err| CodegenError::Io(root, err))?;
        Ok(())
    }
}
