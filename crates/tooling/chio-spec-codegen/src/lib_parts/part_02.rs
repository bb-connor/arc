pub(crate) fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
    }
    fs::write(path, bytes).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(prefix: &str) -> Result<PathBuf> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| CodegenError::Io(PathBuf::from(prefix), std::io::Error::other(err)))?
            .as_nanos();
        Ok(std::env::temp_dir().join(format!("{prefix}-{nanos}")))
    }

    #[test]
    fn header_is_non_empty() {
        assert!(GENERATED_HEADER.starts_with("// DO NOT EDIT"));
        assert!(GENERATED_HEADER.contains("typify =0.4.3"));
    }

    #[test]
    fn is_schema_json_recognises_canonical_extension() {
        assert!(is_schema_json(Path::new("foo/bar.schema.json")));
        assert!(!is_schema_json(Path::new("foo/bar.json")));
        assert!(!is_schema_json(Path::new("foo/bar.schema.yaml")));
    }

    #[test]
    fn missing_schemas_dir_is_error() {
        let nonexistent = Path::new("/tmp/chio-spec-codegen-does-not-exist-xyz");
        match render_chio_wire_v1(nonexistent) {
            Err(CodegenError::SchemasDirMissing(_)) => {}
            Err(other) => panic!("expected SchemasDirMissing, got {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn walk_schema_files_rejects_symlinked_schema_file() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-schemas")?;
        let outside = unique_temp_dir("chio-spec-codegen-outside")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        fs::create_dir_all(&outside).map_err(|err| CodegenError::Io(outside.clone(), err))?;
        fs::write(outside.join("escape.schema.json"), "{}")
            .map_err(|err| CodegenError::Io(outside.join("escape.schema.json"), err))?;
        let link_path = dir.join("escape.schema.json");
        std::os::unix::fs::symlink(outside.join("escape.schema.json"), &link_path)
            .map_err(|err| CodegenError::Io(link_path.clone(), err))?;

        let mut files = Vec::new();
        let result = walk_schema_files(&dir, &mut files);

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(outside);
        match result {
            Err(CodegenError::SchemaRef(path, message)) => {
                assert!(path.ends_with("escape.schema.json"));
                assert!(message.contains("symlink"));
            }
            Err(error) => panic!("expected SchemaRef symlink error, got {error}"),
            Ok(paths) => panic!("symlinked schema should fail closed: {paths:?}"),
        }
        Ok(())
    }

    #[test]
    fn render_chio_wire_v1_rejects_external_schema_ref() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-external-ref")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let schema_path = dir.join("external_ref.schema.json");
        fs::write(
            &schema_path,
            br#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://chio.world/schemas/test/v1/external-ref.schema.json",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "remote": {
      "$ref": "https://example.invalid/not-local.schema.json"
    }
  }
}"#,
        )
        .map_err(|err| CodegenError::Io(schema_path.clone(), err))?;

        let result = render_chio_wire_v1(&dir);
        let _ = fs::remove_dir_all(&dir);
        match result {
            Err(CodegenError::SchemaRef(path, message)) => {
                assert!(path.ends_with("external_ref.schema.json"));
                assert!(
                    message.contains("external schema reference"),
                    "unexpected message: {message}"
                );
            }
            Err(error) => panic!("expected SchemaRef external-ref error, got {error}"),
            Ok(rendered) => panic!("external schema ref should fail closed: {rendered}"),
        }
        Ok(())
    }

    #[test]
    fn canonical_chio_schema_uri_resolves_only_inside_the_local_tree() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-canonical-ref")?;
        let capability_dir = dir.join("capability");
        let agent_dir = dir.join("agent");
        fs::create_dir_all(&capability_dir)
            .map_err(|err| CodegenError::Io(capability_dir.clone(), err))?;
        fs::create_dir_all(&agent_dir).map_err(|err| CodegenError::Io(agent_dir.clone(), err))?;
        let target = capability_dir.join("aggregate.schema.json");
        fs::write(&target, b"{}").map_err(|err| CodegenError::Io(target.clone(), err))?;
        let base = agent_dir.join("request.schema.json");
        fs::write(&base, b"{}").map_err(|err| CodegenError::Io(base.clone(), err))?;
        let inventory = [
            fs::canonicalize(&target).map_err(|err| CodegenError::Io(target.clone(), err))?,
            fs::canonicalize(&base).map_err(|err| CodegenError::Io(base.clone(), err))?,
        ]
        .into_iter()
        .collect();

        let resolved = resolve_local_schema_ref(
            "https://chio.world/schemas/chio-wire/v1/capability/aggregate.schema.json",
            &base,
            &dir,
            &inventory,
        )?
        .ok_or_else(|| {
            CodegenError::SchemaRef(base.clone(), "canonical reference was ignored".to_string())
        })?;

        assert_eq!(
            resolved.0,
            fs::canonicalize(&target).map_err(|err| { CodegenError::Io(target.clone(), err) })?
        );
        assert_eq!(resolved.1, None);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn schema_refs_reject_external_paths_before_target_io() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-ref-boundary")?;
        let group = dir.join("group");
        fs::create_dir_all(&group).map_err(|err| CodegenError::Io(group.clone(), err))?;
        let base = group.join("source.schema.json");
        fs::write(&base, b"{}").map_err(|err| CodegenError::Io(base.clone(), err))?;
        let inventory =
            [fs::canonicalize(&base).map_err(|err| CodegenError::Io(base.clone(), err))?]
                .into_iter()
                .collect();

        for reference in [
            "/etc/passwd",
            "../../outside.schema.json",
            r"\\server\share\outside.schema.json",
            r"security\outside.schema.json",
        ] {
            match resolve_local_schema_ref(reference, &base, &dir, &inventory) {
                Err(CodegenError::SchemaRef(_, _)) => {}
                Err(error) => panic!("expected SchemaRef for {reference}, got {error}"),
                Ok(value) => panic!("external ref {reference} was accepted: {value:?}"),
            }
        }

        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn canonical_schema_uri_paths_require_exact_normal_form() {
        assert_eq!(
            exact_canonical_schema_target("security/event.schema.json"),
            Ok(PathBuf::from("security/event.schema.json"))
        );
        for path in [
            "",
            "/security/event.schema.json",
            "security//event.schema.json",
            "security/./event.schema.json",
            "security/../event.schema.json",
            r"security\event.schema.json",
        ] {
            assert!(
                exact_canonical_schema_target(path).is_err(),
                "accepted non-normalized canonical path {path}"
            );
        }
    }

    #[test]
    fn relative_schema_ref_paths_require_exact_lexical_segments() {
        assert_eq!(
            normalize_relative_schema_target(Path::new("agent"), "../capability/token.schema.json",),
            Ok(PathBuf::from("capability/token.schema.json"))
        );
        for path in [
            "./token.schema.json",
            "capability//token.schema.json",
            "capability/token.schema.json/",
        ] {
            assert!(
                normalize_relative_schema_target(Path::new("agent"), path).is_err(),
                "accepted non-normalized relative path {path}"
            );
        }
    }

    #[test]
    fn cross_file_ref_cycles_fail_closed() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-ref-cycle")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let alpha = dir.join("alpha.schema.json");
        let beta = dir.join("beta.schema.json");
        fs::write(&alpha, br#"{"$ref":"beta.schema.json"}"#)
            .map_err(|err| CodegenError::Io(alpha.clone(), err))?;
        fs::write(&beta, br#"{"$ref":"alpha.schema.json"}"#)
            .map_err(|err| CodegenError::Io(beta.clone(), err))?;
        let canonical_dir =
            fs::canonicalize(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let mut files = vec![alpha.clone(), beta];
        files.sort();
        let inventory = build_schema_inventory(&files, &dir, &canonical_dir)?;

        let result = load_schema_value(&alpha, &dir, &inventory);
        let _ = fs::remove_dir_all(dir);
        match result {
            Err(CodegenError::SchemaRef(_, message)) => {
                assert!(message.contains("cyclic schema reference"));
            }
            Err(error) => panic!("expected cyclic SchemaRef, got {error}"),
            Ok(value) => panic!("cyclic schema refs were accepted: {value}"),
        }
        Ok(())
    }

    #[test]
    fn cross_file_ref_siblings_are_preserved() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-ref-sibling")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let target = dir.join("target.schema.json");
        let source = dir.join("source.schema.json");
        fs::write(&target, br#"{"type":"string"}"#)
            .map_err(|err| CodegenError::Io(target.clone(), err))?;
        fs::write(&source, br#"{"$ref":"target.schema.json","minLength":3}"#)
            .map_err(|err| CodegenError::Io(source.clone(), err))?;
        let canonical_dir =
            fs::canonicalize(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let mut files = vec![source.clone(), target];
        files.sort();
        let inventory = build_schema_inventory(&files, &dir, &canonical_dir)?;

        let value = load_schema_value(&source, &dir, &inventory)?;
        assert_eq!(value["allOf"][0]["type"], "string");
        assert_eq!(value["minLength"], 3);
        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn cross_file_ref_siblings_keep_root_definitions_at_the_resource_root() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-ref-sibling-defs")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let target = dir.join("target.schema.json");
        let source = dir.join("source.schema.json");
        fs::write(&target, br#"{"type":"object"}"#)
            .map_err(|err| CodegenError::Io(target.clone(), err))?;
        fs::write(
            &source,
            br##"{
  "$ref": "target.schema.json",
  "$defs": {
    "local": { "type": "string" }
  },
  "properties": {
    "value": { "$ref": "#/$defs/local" }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(source.clone(), err))?;
        let canonical_dir =
            fs::canonicalize(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let mut files = vec![source.clone(), target];
        files.sort();
        let inventory = build_schema_inventory(&files, &dir, &canonical_dir)?;

        let value = load_schema_value(&source, &dir, &inventory)?;
        let _ = fs::remove_dir_all(dir);

        assert_eq!(value["allOf"][0]["type"], "object");
        assert_eq!(value["$defs"]["local"]["type"], "string");
        assert_eq!(value["properties"]["value"]["$ref"], "#/$defs/local");
        Ok(())
    }

    #[test]
    fn cross_file_fragment_rejects_non_defs_internal_pointer_capture() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-non-def-pointer-capture")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let target = dir.join("target.schema.json");
        let source = dir.join("source.schema.json");
        fs::write(
            &target,
            br##"{
  "type": "object",
  "properties": {
    "shared": { "type": "string" },
    "value": { "$ref": "#/properties/shared" }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(target.clone(), err))?;
        fs::write(
            &source,
            br##"{
  "type": "object",
  "properties": {
    "shared": { "type": "integer" },
    "imported": { "$ref": "target.schema.json#/properties/value" }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(source.clone(), err))?;
        let canonical_dir =
            fs::canonicalize(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let mut files = vec![source.clone(), target];
        files.sort();
        let inventory = build_schema_inventory(&files, &dir, &canonical_dir)?;

        let result = load_schema_value(&source, &dir, &inventory);
        let _ = fs::remove_dir_all(dir);
        match result {
            Err(CodegenError::SchemaRef(path, message)) => {
                assert!(path.ends_with("target.schema.json"));
                assert!(message.contains("cannot be safely relocated"));
                assert!(message.contains("only root $defs JSON Pointer references"));
            }
            Err(error) => panic!("expected non-$defs relocation SchemaRef, got {error}"),
            Ok(value) => panic!("non-$defs pointer capture was accepted: {value}"),
        }
        Ok(())
    }

    #[test]
    fn json_pointer_fragment_decoding_is_exact() {
        let value = serde_json::json!({
            "": { "key": 1 },
            "a/b": { "~key": 2 }
        });

        assert_eq!(
            resolve_json_pointer(&value, Some("//key")).map(serde_json::Value::as_i64),
            Ok(Some(1))
        );
        assert_eq!(
            resolve_json_pointer(&value, Some("%2Fa~1b%2F~0key")).map(serde_json::Value::as_i64),
            Ok(Some(2))
        );
        let percent_literal = serde_json::json!({ "%2F": 3 });
        assert_eq!(
            resolve_json_pointer(&percent_literal, Some("/%252F"))
                .map(serde_json::Value::as_i64),
            Ok(Some(3))
        );
        assert!(resolve_json_pointer(&value, Some("/%ZZ")).is_err());
        assert!(resolve_json_pointer(&value, Some("/a~2b")).is_err());
        assert!(resolve_json_pointer(&value, Some("/%FF")).is_err());
        assert!(resolve_json_pointer(&serde_json::json!([0, 1]), Some("/01")).is_err());
        assert!(resolve_json_pointer(&serde_json::json!([0, 1]), Some("/+1")).is_err());
    }

    #[test]
    fn schemas_with_the_same_local_definition_name_get_separate_modules() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-local-def-collision")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;

        let alpha_path = dir.join("alpha.schema.json");
        fs::write(
            &alpha_path,
            br##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AlphaEnvelope",
  "type": "object",
  "additionalProperties": false,
  "required": ["payload"],
  "properties": {
    "payload": { "$ref": "#/$defs/shared" }
  },
  "$defs": {
    "shared": {
      "title": "Shared",
      "type": "string",
      "minLength": 1
    }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(alpha_path.clone(), err))?;

        let beta_path = dir.join("beta.schema.json");
        fs::write(
            &beta_path,
            br##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "BetaEnvelope",
  "type": "object",
  "additionalProperties": false,
  "required": ["payload"],
  "properties": {
    "payload": { "$ref": "#/$defs/shared" }
  },
  "$defs": {
    "shared": {
      "title": "Shared",
      "type": "integer",
      "minimum": 1
    }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(beta_path.clone(), err))?;

        let rendered = render_chio_wire_v1(&dir);
        let rendered_again = render_chio_wire_v1(&dir);
        let _ = fs::remove_dir_all(&dir);
        let rendered = rendered?;
        assert_eq!(rendered_again?, rendered, "schema rendering must be stable");
        let parsed = syn::parse_file(&rendered).map_err(CodegenError::SynParse)?;
        let module_names: Vec<String> = parsed
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Mod(item) => Some(item.ident.to_string()),
                _ => None,
            })
            .collect();

        assert_eq!(module_names, ["alpha", "beta"]);
        assert_eq!(rendered.matches("pub struct AlphaEnvelope").count(), 1);
        assert_eq!(rendered.matches("pub struct BetaEnvelope").count(), 1);
        assert_eq!(
            rendered.matches("pub struct Shared").count(),
            2,
            "each schema must own its differently shaped local definition"
        );
        Ok(())
    }

    #[test]
    fn referenced_definition_conflicts_are_namespaced_with_nested_refs_rewritten() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-referenced-def-collision")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let alpha = dir.join("alpha.schema.json");
        let beta = dir.join("beta.schema.json");
        let root = dir.join("root.schema.json");
        fs::write(
            &alpha,
            br##"{
  "$defs": {
    "shared": { "type": "string" },
    "wrapper": {
      "type": "object",
      "properties": { "value": { "$ref": "#/$defs/shared" } }
    }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(alpha.clone(), err))?;
        fs::write(
            &beta,
            br##"{
  "$defs": {
    "shared": { "type": "integer" },
    "wrapper": {
      "type": "object",
      "properties": { "value": { "$ref": "#/$defs/shared" } }
    }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(beta.clone(), err))?;
        fs::write(
            &root,
            br##"{
  "type": "object",
  "properties": {
    "alpha": { "$ref": "alpha.schema.json#/$defs/wrapper" },
    "beta": { "$ref": "beta.schema.json#/$defs/wrapper" }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(root.clone(), err))?;
        let canonical_dir =
            fs::canonicalize(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let mut files = vec![alpha, beta.clone(), root.clone()];
        files.sort();
        let inventory = build_schema_inventory(&files, &dir, &canonical_dir)?;

        let value = load_schema_value(&root, &dir, &inventory)?;
        let value_again = load_schema_value(&root, &dir, &inventory)?;
        let namespace = schema_resource_namespace(&beta, &dir)?;
        let beta_shared = namespaced_definition_key(&namespace, "shared");
        let beta_wrapper = namespaced_definition_key(&namespace, "wrapper");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(value_again, value, "definition namespacing must be stable");
        assert_eq!(
            value["properties"]["alpha"]["properties"]["value"]["$ref"],
            "#/$defs/shared"
        );
        let expected_beta_ref = format!("#/$defs/{beta_shared}");
        assert_eq!(
            value["properties"]["beta"]["properties"]["value"]["$ref"].as_str(),
            Some(expected_beta_ref.as_str())
        );
        assert_eq!(value["$defs"]["shared"]["type"], "string");
        assert_eq!(
            value["$defs"]
                .get(&beta_shared)
                .and_then(|schema| schema["type"].as_str()),
            Some("integer")
        );
        assert_eq!(
            value["$defs"]
                .get(&beta_wrapper)
                .and_then(|schema| schema["properties"]["value"]["$ref"].as_str()),
            Some(expected_beta_ref.as_str())
        );
        assert_eq!(
            value["$defs"].as_object().map(|defs| defs.len()),
            Some(4)
        );
        Ok(())
    }

    #[test]
    fn identical_referenced_definition_closures_keep_existing_names() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-identical-referenced-defs")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let common_schema = br##"{
  "$defs": {
    "shared": { "type": "string" },
    "wrapper": {
      "type": "array",
      "items": { "$ref": "#/$defs/shared" }
    }
  }
}"##;
        let alpha = dir.join("alpha.schema.json");
        let beta = dir.join("beta.schema.json");
        let root = dir.join("root.schema.json");
        fs::write(&alpha, common_schema)
            .map_err(|err| CodegenError::Io(alpha.clone(), err))?;
        fs::write(&beta, common_schema).map_err(|err| CodegenError::Io(beta.clone(), err))?;
        fs::write(
            &root,
            br##"{
  "type": "object",
  "properties": {
    "alpha": { "$ref": "alpha.schema.json#/$defs/wrapper" },
    "beta": { "$ref": "beta.schema.json#/$defs/wrapper" }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(root.clone(), err))?;
        let canonical_dir =
            fs::canonicalize(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let mut files = vec![alpha, beta, root.clone()];
        files.sort();
        let inventory = build_schema_inventory(&files, &dir, &canonical_dir)?;

        let value = load_schema_value(&root, &dir, &inventory)?;
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(
            value["$defs"].as_object().map(|defs| defs.len()),
            Some(2),
            "identical definition closures must remain deduplicated"
        );
        assert_eq!(
            value["properties"]["alpha"]["items"]["$ref"],
            "#/$defs/shared"
        );
        assert_eq!(
            value["properties"]["beta"]["items"]["$ref"],
            "#/$defs/shared"
        );
        assert!(value["$defs"]
            .as_object()
            .is_some_and(|defs| defs.keys().all(|key| !key.starts_with("__chio_resource_"))));
        Ok(())
    }

    #[test]
    fn external_ref_inside_root_definition_does_not_remerge_stale_root_snapshot() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-root-def-external-ref")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let target = dir.join("target.schema.json");
        let root = dir.join("root.schema.json");
        fs::write(
            &target,
            br##"{
  "type": "object",
  "properties": {
    "value": { "$ref": "#/$defs/payload" }
  },
  "$defs": {
    "payload": { "type": "string" }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(target.clone(), err))?;
        fs::write(
            &root,
            br##"{
  "type": "object",
  "properties": {
    "body": { "$ref": "#/$defs/payload" }
  },
  "$defs": {
    "payload": { "$ref": "target.schema.json" }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(root.clone(), err))?;
        let canonical_dir =
            fs::canonicalize(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let mut files = vec![root.clone(), target.clone()];
        files.sort();
        let inventory = build_schema_inventory(&files, &dir, &canonical_dir)?;

        let value = load_schema_value(&root, &dir, &inventory)?;
        let value_again = load_schema_value(&root, &dir, &inventory)?;
        let namespace = schema_resource_namespace(&target, &dir)?;
        let imported_payload = namespaced_definition_key(&namespace, "payload");
        let expected_imported_ref = format!("#/$defs/{imported_payload}");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(value_again, value, "root-definition inlining must be stable");
        assert_eq!(value["properties"]["body"]["$ref"], "#/$defs/payload");
        assert_eq!(value["$defs"]["payload"]["type"], "object");
        assert_eq!(
            value["$defs"]["payload"]["properties"]["value"]["$ref"].as_str(),
            Some(expected_imported_ref.as_str())
        );
        assert_eq!(
            value["$defs"]
                .get(&imported_payload)
                .and_then(|definition| definition["type"].as_str()),
            Some("string")
        );
        assert_eq!(value["$defs"].as_object().map(|defs| defs.len()), Some(2));
        Ok(())
    }

    #[test]
    fn invalid_internal_definition_ref_fails_before_merge() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-invalid-internal-def-ref")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let target = dir.join("target.schema.json");
        let root = dir.join("root.schema.json");
        fs::write(
            &target,
            br##"{
  "$defs": {
    "wrapper": { "$ref": "#/$defs/missing" }
  }
}"##,
        )
        .map_err(|err| CodegenError::Io(target.clone(), err))?;
        fs::write(
            &root,
            br##"{ "$ref": "target.schema.json#/$defs/wrapper" }"##,
        )
        .map_err(|err| CodegenError::Io(root.clone(), err))?;
        let canonical_dir =
            fs::canonicalize(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let mut files = vec![root.clone(), target];
        files.sort();
        let inventory = build_schema_inventory(&files, &dir, &canonical_dir)?;

        let result = load_schema_value(&root, &dir, &inventory);
        let _ = fs::remove_dir_all(&dir);
        match result {
            Err(CodegenError::SchemaRef(path, message)) => {
                assert!(path.ends_with("target.schema.json"));
                assert!(message.contains("missing definition $defs/missing"));
            }
            Err(error) => panic!("expected missing-definition SchemaRef, got {error}"),
            Ok(value) => panic!("invalid internal definition ref was accepted: {value}"),
        }
        Ok(())
    }

    #[test]
    fn definition_ref_rewrite_preserves_nested_pointer_suffixes() {
        let renames = BTreeMap::from([(
            "shared/segment~value".to_string(),
            "resource_definition".to_string(),
        )]);

        assert_eq!(
            rewrite_internal_defs_ref(
                "#/$defs/shared~1segment~0value/properties/a~1b/items",
                &renames,
            ),
            Ok(Some(
                "#/$defs/resource_definition/properties/a~1b/items".to_string()
            ))
        );
        assert_eq!(
            rewrite_internal_defs_ref(
                "#/$defs/shared~1segment~0value/properties/%252F",
                &renames,
            ),
            Ok(Some(
                "#/$defs/resource_definition/properties/%252F".to_string()
            ))
        );
        assert_eq!(
            rewrite_referenced_fragment(
                Some("/$defs/shared~1segment~0value/properties/%252F"),
                &renames,
            ),
            Ok(Some(
                "/$defs/resource_definition/properties/%252F".to_string()
            ))
        );
        assert!(rewrite_internal_defs_ref("#/$defs/missing", &renames).is_err());
    }

    #[test]
    fn tool_call_response_receipt_keeps_record_type(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| std::io::Error::other("missing workspace"))?;
        let schemas_dir = workspace_root.join("spec/schemas/chio-wire/v1");

        let rendered = render_chio_wire_v1(&schemas_dir)?;

        assert!(
            rendered.contains("pub receipt: ChioReceiptRecord,"),
            "tool_call_response.receipt must use the typed receipt record"
        );
        assert!(
            !rendered.contains("External schema reference erased for Rust typify codegen"),
            "local cross-file refs must not be erased before typify"
        );
        assert_eq!(
            rendered.matches("\npub mod receipt__record {\n").count(),
            1,
            "the receipt root schema must own one deterministic module"
        );
        assert_eq!(
            rendered
                .matches("\npub mod kernel__tool_call_response {\n")
                .count(),
            1,
            "the response schema must own one deterministic module"
        );
        Ok(())
    }

    #[test]
    fn active_defense_receipt_integer_bounds_survive_rust_projection(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| std::io::Error::other("missing workspace"))?;
        let rendered = render_chio_wire_v1(&workspace_root.join("spec/schemas/chio-wire/v1"))?;
        let modules = [
            "security__correlated_finding_receipt_body_v1",
            "security__declassification_consumption_receipt_body_v1",
            "security__declassification_outcome_receipt_body_v1",
            "security__effect_transition_receipt_body_v1",
            "security__flow_denial_receipt_body_v1",
            "security__lift_rollback_completion_receipt_body_v1",
            "security__response_completion_receipt_body_v1",
            "security__response_plan_receipt_body_v1",
            "security__response_state_transition_receipt_body_v1",
            "security__scheduler_health_receipt_body_v1",
            "security__tripwire_observation_receipt_body_v1",
        ];
        for module_name in modules {
            let marker = format!("pub mod {module_name} {{");
            let start = rendered
                .find(&marker)
                .ok_or_else(|| std::io::Error::other(format!("missing {module_name}")))?;
            let search_start = start + marker.len();
            let end = rendered[search_start..]
                .find("\npub mod ")
                .map_or(rendered.len(), |relative| search_start + relative);
            let module = &rendered[start..end];
            assert!(module.contains(
                "const ACTIVE_DEFENSE_MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;"
            ));
            assert!(module.contains("pub struct Time(::std::num::NonZeroU64);"));
            assert!(!module.contains("pub struct Time(pub ::std::num::NonZeroU64);"));
            assert!(
                module.contains("impl ::std::convert::TryFrom<::std::num::NonZeroU64> for Time")
            );
            assert!(!module.contains("impl ::std::convert::From<::std::num::NonZeroU64> for Time"));
        }
        assert!(rendered.contains("pub generation: JsonSafePositiveInteger,"));
        assert!(rendered.contains("pub scheduler_fencing_token: JsonSafePositiveInteger,"));
        assert!(rendered.contains("pub attempts: ::std::num::NonZeroU32,"));
        assert!(rendered.contains("pub first_failure_at_unix_ms: Time,"));
        assert!(rendered.contains("pub plan_created_at_unix_ms: Time,"));
        Ok(())
    }

    #[test]
    fn typify_projection_strips_only_exact_approval_compatibility_exclusion() {
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {
                "approval_token": { "type": "string" },
                "approval_tokens": { "type": "array" },
                "guarded": { "type": "string" }
            },
            "not": {
                "required": ["approval_token", "approval_tokens"],
                "properties": {
                    "approval_token": true,
                    "approval_tokens": true
                }
            },
            "$defs": {
                "legacy_approval_exclusion": {
                    "type": "object",
                    "properties": {
                        "approval_token": { "type": "string" },
                        "approval_tokens": { "type": "array" }
                    },
                    "not": { "required": ["approval_token", "approval_tokens"] }
                },
                "constraint_bearing_not": {
                    "type": "object",
                    "properties": {
                        "approval_token": { "type": "string" },
                        "approval_tokens": { "type": "array" }
                    },
                    "not": {
                        "required": ["approval_token", "approval_tokens"],
                        "properties": { "approval_token": { "const": "forbidden" } }
                    }
                },
                "extra_visibility_property": {
                    "type": "object",
                    "properties": {
                        "approval_token": { "type": "string" },
                        "approval_tokens": { "type": "array" }
                    },
                    "not": {
                        "required": ["approval_token", "approval_tokens"],
                        "properties": {
                            "approval_token": true,
                            "approval_tokens": true,
                            "other": true
                        }
                    }
                },
                "false_visibility_property": {
                    "type": "object",
                    "properties": {
                        "approval_token": { "type": "string" },
                        "approval_tokens": { "type": "array" }
                    },
                    "not": {
                        "required": ["approval_token", "approval_tokens"],
                        "properties": {
                            "approval_token": false,
                            "approval_tokens": true
                        }
                    }
                },
                "unrelated_pure_exclusion": {
                    "type": "object",
                    "properties": {
                        "left": { "type": "string" },
                        "right": { "type": "string" }
                    },
                    "not": { "required": ["left", "right"] }
                },
                "single_field_not": {
                    "type": "object",
                    "properties": { "guarded": { "type": "string" } },
                    "not": { "required": ["guarded"] }
                }
            }
        });

        strip_typify_cross_field_exclusions(&mut schema);

        assert!(schema.get("not").is_none());
        assert!(schema["$defs"]["legacy_approval_exclusion"]
            .get("not")
            .is_none());
        assert!(schema["$defs"]["constraint_bearing_not"]
            .get("not")
            .is_some());
        assert!(schema["$defs"]["extra_visibility_property"]
            .get("not")
            .is_some());
        assert!(schema["$defs"]["false_visibility_property"]
            .get("not")
            .is_some());
        assert!(schema["$defs"]["unrelated_pure_exclusion"]
            .get("not")
            .is_some());
        assert!(schema["$defs"]["single_field_not"].get("not").is_some());
    }

    #[test]
    fn typify_projection_strips_only_canonical_nonzero_digest_contains() {
        let mut schema = serde_json::json!({
            "$defs": {
                "digest": {
                    "type": "array",
                    "minItems": 32,
                    "maxItems": 32,
                    "items": { "type": "integer", "minimum": 0, "maximum": 255 },
                    "contains": { "type": "integer", "minimum": 1 },
                    "minContains": 1
                },
                "other": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 32,
                    "contains": { "type": "integer", "minimum": 1 },
                    "minContains": 1
                }
            }
        });

        strip_typify_nonzero_digest_contains(&mut schema);

        assert!(schema["$defs"]["digest"].get("contains").is_none());
        assert!(schema["$defs"]["digest"].get("minContains").is_none());
        assert!(schema["$defs"]["other"].get("contains").is_some());
        assert!(schema["$defs"]["other"].get("minContains").is_some());
    }

    #[test]
    fn typify_projection_retains_nonconditional_all_of_members() {
        let mut schema = serde_json::json!({
            "allOf": [
                { "$ref": "#/$defs/shape" },
                {
                    "if": { "required": ["mode"] },
                    "then": { "required": ["detail"] }
                },
                {
                    "$ref": "#/$defs/other",
                    "if": { "required": ["kind"] },
                    "then": { "required": ["value"] }
                }
            ],
            "$defs": {
                "shape": { "type": "object" },
                "other": { "type": "object" }
            }
        });

        strip_typify_unsupported_conditionals(&mut schema);

        assert_eq!(schema["allOf"].as_array().map(Vec::len), Some(2));
        assert_eq!(schema["allOf"][0]["$ref"], "#/$defs/shape");
        assert_eq!(schema["allOf"][1]["$ref"], "#/$defs/other");
        assert!(schema["allOf"][1].get("if").is_none());
        assert!(schema["allOf"][1].get("then").is_none());
    }

    #[test]
    fn protocol_primitive_fields_survive_rust_projection(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| std::io::Error::other("missing workspace"))?;
        let rendered = render_chio_wire_v1(&workspace_root.join("spec/schemas/chio-wire/v1"))?;

        let tool_request_start = rendered
            .find("pub struct ChioAgentMessageToolCallRequest {")
            .ok_or_else(|| std::io::Error::other("missing generated tool request"))?;
        let tool_request_tail = &rendered[tool_request_start..];
        let tool_request_end = tool_request_tail
            .find("\n    }")
            .ok_or_else(|| std::io::Error::other("unterminated generated tool request"))?;
        let tool_request = &tool_request_tail[..tool_request_end];
        assert!(
            tool_request.contains("pub approval_token:"),
            "singular approval compatibility field was erased from Rust codegen"
        );
        assert!(
            tool_request.contains("pub approval_tokens:"),
            "threshold approval list was erased from Rust codegen"
        );

        let capability_start = rendered
            .find("pub struct ChioKernelMessageCapabilityListCapabilitiesItem {")
            .ok_or_else(|| std::io::Error::other("missing generated capability-list item"))?;
        let capability_tail = &rendered[capability_start..];
        let capability_end = capability_tail
            .find("\n    }")
            .ok_or_else(|| std::io::Error::other("unterminated capability-list item"))?;
        let capability = &capability_tail[..capability_end];
        assert!(
            capability.contains("pub aggregate_invocation_budget:"),
            "signed aggregate invocation restriction was erased from capability-list codegen"
        );
        Ok(())
    }
}
