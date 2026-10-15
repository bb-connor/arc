//! Finite local schema resolution for the Rust generator.
//!
//! A schema ID identifies a catalog resource, never a network destination.
use std::collections::BTreeMap;

use super::*;

/// An immutable catalog of the schema files under one canonical root.
pub struct LocalSchemaCatalog {
    root: PathBuf,
    ids: BTreeMap<String, PathBuf>,
    resources: BTreeMap<PathBuf, serde_json::Value>,
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
            let schema = read_schema_file(&path)?;
            if let Some(id) = schema.get("$id").and_then(serde_json::Value::as_str) {
                if ids.insert(id.to_owned(), path.clone()).is_some() {
                    return Err(CodegenError::SchemaRef(
                        path,
                        format!("duplicate schema ID {id}"),
                    ));
                }
            }
            resources.insert(path, schema);
        }
        Ok(Self {
            root,
            ids,
            resources,
        })
    }

    pub(super) fn resource(&self, path: &Path) -> Result<serde_json::Value> {
        let canonical = fs::canonicalize(path).map_err(|err| CodegenError::Io(path.into(), err))?;
        self.resources.get(&canonical).cloned().ok_or_else(|| {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_resolve_offline_within_the_catalog() -> Result<()> {
        let root = crate::tests::unique_temp_dir("chio-local-schema-ids")?;
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
        fs::remove_dir_all(&root).map_err(|err| CodegenError::Io(root, err))?;
        Ok(())
    }
}
