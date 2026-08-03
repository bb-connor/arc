fn build_schema_inventory(
    schema_files: &[PathBuf],
    schemas_dir: &Path,
    canonical_schemas_dir: &Path,
) -> Result<BTreeSet<PathBuf>> {
    let mut inventory = BTreeSet::new();
    for path in schema_files {
        let relative = path.strip_prefix(schemas_dir).map_err(|_| {
            CodegenError::SchemaRef(
                path.clone(),
                format!("schema is outside {}", schemas_dir.display()),
            )
        })?;
        if relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(CodegenError::SchemaRef(
                path.clone(),
                "schema path is not normalized".to_string(),
            ));
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|err| CodegenError::Io(path.clone(), err))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CodegenError::SchemaRef(
                path.clone(),
                "schema inventory entry is not a real file".to_string(),
            ));
        }
        let canonical =
            fs::canonicalize(path).map_err(|err| CodegenError::Io(path.clone(), err))?;
        if canonical != canonical_schemas_dir.join(relative) {
            return Err(CodegenError::SchemaRef(
                path.clone(),
                "schema inventory entry contains a symlink or path alias".to_string(),
            ));
        }
        if !inventory.insert(canonical) {
            return Err(CodegenError::SchemaRef(
                path.clone(),
                "schema inventory contains duplicate file identity".to_string(),
            ));
        }
    }
    Ok(inventory)
}

fn walk_schema_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let metadata =
        fs::symlink_metadata(dir).map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CodegenError::SchemaRef(
            dir.to_path_buf(),
            "schema directory is not a real directory".to_string(),
        ));
    }
    let entries = fs::read_dir(dir).map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| CodegenError::Io(path.clone(), err))?;
        if file_type.is_symlink() {
            return Err(CodegenError::SchemaRef(
                path,
                "refusing symlink in schema tree".to_string(),
            ));
        }
        if file_type.is_dir() {
            walk_schema_files(&path, out)?;
        } else if file_type.is_file() && is_schema_json(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_schema_json(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    name.ends_with(".schema.json")
}

fn load_schema_value(
    path: &Path,
    schemas_dir: &Path,
    schema_inventory: &BTreeSet<PathBuf>,
) -> Result<serde_json::Value> {
    load_schema_value_inner(path, schemas_dir, schema_inventory, &mut Vec::new())
}

fn load_schema_value_inner(
    path: &Path,
    schemas_dir: &Path,
    schema_inventory: &BTreeSet<PathBuf>,
    active_paths: &mut Vec<PathBuf>,
) -> Result<serde_json::Value> {
    let canonical_path =
        fs::canonicalize(path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    if let Some(cycle_start) = active_paths
        .iter()
        .position(|active| active == &canonical_path)
    {
        let mut cycle = active_paths[cycle_start..]
            .iter()
            .map(|active| active.display().to_string())
            .collect::<Vec<_>>();
        cycle.push(canonical_path.display().to_string());
        return Err(CodegenError::SchemaRef(
            canonical_path,
            format!("cyclic schema reference: {}", cycle.join(" -> ")),
        ));
    }
    active_paths.push(canonical_path.clone());
    let result = (|| {
        let raw = fs::read_to_string(&canonical_path)
            .map_err(|err| CodegenError::Io(canonical_path.clone(), err))?;
        let mut value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|err| CodegenError::Json(canonical_path.clone(), err))?;
        let mut definition_registry = DefinitionRegistry::from_root(&value, &canonical_path)?;
        inline_local_schema_refs(
            &mut value,
            &canonical_path,
            schemas_dir,
            schema_inventory,
            active_paths,
            &mut definition_registry,
        )?;
        merge_extra_defs_into_root(
            &mut value,
            definition_registry.into_imported_defs(),
            &canonical_path,
        )?;
        let final_defs = root_schema_defs(&value, &canonical_path)?
            .keys()
            .map(|key| (key.clone(), key.clone()))
            .collect();
        rewrite_internal_defs_refs(&mut value, &final_defs, &canonical_path)?;
        strip_typify_unsupported_conditionals(&mut value);
        strip_typify_cross_field_exclusions(&mut value);
        strip_typify_nonzero_digest_contains(&mut value);
        Ok(value)
    })();
    active_paths.pop();
    result
}

fn inline_local_schema_refs(
    value: &mut serde_json::Value,
    base_path: &Path,
    schemas_dir: &Path,
    schema_inventory: &BTreeSet<PathBuf>,
    active_paths: &mut Vec<PathBuf>,
    definition_registry: &mut DefinitionRegistry,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(reference)) = map.get("$ref") {
                if let Some((target_path, fragment)) =
                    resolve_local_schema_ref(reference, base_path, schemas_dir, schema_inventory)?
                {
                    let mut target = load_schema_value_inner(
                        &target_path,
                        schemas_dir,
                        schema_inventory,
                        active_paths,
                    )?;
                    ensure_relocatable_schema_refs(&target, &target_path)?;
                    let definition_renames = merge_referenced_defs(
                        &mut target,
                        &target_path,
                        schemas_dir,
                        definition_registry,
                        base_path,
                        reference,
                    )?;
                    let resolved_fragment = rewrite_referenced_fragment(
                        fragment.as_deref(),
                        &definition_renames,
                    )
                    .map_err(|message| {
                        CodegenError::SchemaRef(
                            base_path.to_path_buf(),
                            format!("{reference}: {message}"),
                        )
                    })?;
                    let mut resolved = resolve_json_pointer(&target, resolved_fragment.as_deref())
                        .map_err(|msg| {
                            CodegenError::SchemaRef(
                                base_path.to_path_buf(),
                                format!("{reference}: {msg}"),
                            )
                        })?
                        .clone();
                    strip_inlined_resource_keywords(&mut resolved);
                    let mut siblings = map.clone();
                    siblings.remove("$ref");
                    if siblings.is_empty() {
                        *value = resolved;
                    } else {
                        let mut sibling_value = serde_json::Value::Object(siblings);
                        inline_local_schema_refs(
                            &mut sibling_value,
                            base_path,
                            schemas_dir,
                            schema_inventory,
                            active_paths,
                            definition_registry,
                        )?;
                        let sibling_map = sibling_value.as_object_mut().ok_or_else(|| {
                            CodegenError::SchemaRef(
                                base_path.to_path_buf(),
                                format!("{reference} siblings did not remain an object"),
                            )
                        })?;
                        match sibling_map.get_mut("allOf") {
                            Some(serde_json::Value::Array(items)) => {
                                items.insert(0, resolved);
                            }
                            Some(_) => {
                                return Err(CodegenError::SchemaRef(
                                    base_path.to_path_buf(),
                                    format!("{reference} has a non-array allOf sibling"),
                                ));
                            }
                            None => {
                                sibling_map.insert(
                                    "allOf".to_string(),
                                    serde_json::Value::Array(vec![resolved]),
                                );
                            }
                        }
                        *value = sibling_value;
                    }
                    return Ok(());
                }
            }
            for item in map.values_mut() {
                inline_local_schema_refs(
                    item,
                    base_path,
                    schemas_dir,
                    schema_inventory,
                    active_paths,
                    definition_registry,
                )?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                inline_local_schema_refs(
                    item,
                    base_path,
                    schemas_dir,
                    schema_inventory,
                    active_paths,
                    definition_registry,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve_local_schema_ref(
    reference: &str,
    base_path: &Path,
    schemas_dir: &Path,
    schema_inventory: &BTreeSet<PathBuf>,
) -> Result<Option<(PathBuf, Option<String>)>> {
    let (path_part, fragment) = reference
        .split_once('#')
        .map_or((reference, None), |(path, fragment)| {
            (path, Some(fragment.to_string()))
        });

    if path_part.is_empty() {
        return Ok(None);
    }
    let canonical_schemas_dir =
        fs::canonicalize(schemas_dir).map_err(|err| CodegenError::Io(schemas_dir.into(), err))?;
    let canonical_base_path =
        fs::canonicalize(base_path).map_err(|err| CodegenError::Io(base_path.into(), err))?;
    let target_relative_path = if let Some(schema_relative_path) =
        path_part.strip_prefix(CANONICAL_CHIO_WIRE_SCHEMA_PREFIX)
    {
        exact_canonical_schema_target(schema_relative_path).map_err(|message| {
            CodegenError::SchemaRef(
                base_path.to_path_buf(),
                format!("{reference} is not a normalized canonical schema reference: {message}"),
            )
        })?
    } else {
        if has_uri_scheme(path_part) || path_part.starts_with("//") || path_part.contains('\\') {
            return Err(CodegenError::SchemaRef(
                base_path.to_path_buf(),
                format!("{reference} uses an external schema reference"),
            ));
        }
        let base_dir = canonical_base_path.parent().ok_or_else(|| {
            CodegenError::SchemaRef(
                base_path.to_path_buf(),
                "schema path has no parent directory".to_string(),
            )
        })?;
        let base_relative = base_dir.strip_prefix(&canonical_schemas_dir).map_err(|_| {
            CodegenError::SchemaRef(
                base_path.to_path_buf(),
                format!("schema path is outside {}", canonical_schemas_dir.display()),
            )
        })?;
        normalize_relative_schema_target(base_relative, path_part).map_err(|message| {
            CodegenError::SchemaRef(
                base_path.to_path_buf(),
                format!("{reference} is invalid: {message}"),
            )
        })?
    };
    let target_path = canonical_schemas_dir.join(target_relative_path);
    if !schema_inventory.contains(&target_path) {
        return Err(CodegenError::SchemaRef(
            base_path.to_path_buf(),
            format!("{reference} is outside the discovered schema inventory"),
        ));
    }

    Ok(Some((target_path, fragment)))
}

fn exact_canonical_schema_target(reference_path: &str) -> std::result::Result<PathBuf, String> {
    if reference_path.contains('\\') {
        return Err("backslash separators are forbidden".to_string());
    }
    let segments = reference_path.split('/').collect::<Vec<_>>();
    if segments.is_empty()
        || segments
            .iter()
            .any(|segment| segment.is_empty() || matches!(*segment, "." | ".."))
    {
        return Err("URI path must contain only nonempty normal segments".to_string());
    }
    Ok(segments.into_iter().collect())
}

fn normalize_relative_schema_target(
    base_relative: &Path,
    reference_path: &str,
) -> std::result::Result<PathBuf, String> {
    let mut target = base_relative.to_path_buf();
    if reference_path.starts_with('/') {
        return Err("absolute reference paths are forbidden".to_string());
    }
    for segment in reference_path.split('/') {
        if segment.is_empty() || segment == "." {
            return Err("reference path is not normalized".to_string());
        }
        if segment == ".." {
            if !target.pop() {
                return Err("reference escapes the schema root".to_string());
            }
        } else {
            target.push(segment);
        }
    }
    if target.as_os_str().is_empty() {
        return Err("reference does not identify a schema file".to_string());
    }
    Ok(target)
}

fn has_uri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

fn root_schema_defs(
    value: &serde_json::Value,
    path: &Path,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let Some(root) = value.as_object() else {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "schema root is not an object".to_string(),
        ));
    };
    match root.get("$defs") {
        Some(serde_json::Value::Object(defs)) => Ok(defs.clone()),
        Some(_) => Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "root $defs is not an object".to_string(),
        )),
        None => Ok(serde_json::Map::new()),
    }
}

struct DefinitionRegistry {
    // Root definition values are mutated during inlining. Reserve their keys
    // for collision decisions, but never snapshot them into the import map.
    root_definition_keys: BTreeSet<String>,
    imported_defs: serde_json::Map<String, serde_json::Value>,
}

impl DefinitionRegistry {
    fn from_root(value: &serde_json::Value, path: &Path) -> Result<Self> {
        let root_definition_keys = root_schema_defs(value, path)?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        Ok(Self {
            root_definition_keys,
            imported_defs: serde_json::Map::new(),
        })
    }

    fn into_imported_defs(self) -> serde_json::Map<String, serde_json::Value> {
        self.imported_defs
    }
}

fn merge_referenced_defs(
    target: &mut serde_json::Value,
    target_path: &Path,
    schemas_dir: &Path,
    definition_registry: &mut DefinitionRegistry,
    base_path: &Path,
    reference: &str,
) -> Result<BTreeMap<String, String>> {
    let original_defs = root_schema_defs(target, target_path)?;
    let mut renames = original_defs
        .keys()
        .map(|key| (key.clone(), key.clone()))
        .collect::<BTreeMap<_, _>>();
    let namespace = schema_resource_namespace(target_path, schemas_dir)?;

    // A definition that is byte-identical before rewriting can still depend on
    // a differently shaped definition. Rename direct conflicts first, then
    // repeat until every dependent definition either deduplicates exactly or
    // moves into the importing resource's deterministic namespace.
    loop {
        ensure_unique_definition_targets(&renames, base_path, reference)?;
        let mut rewritten_defs = serde_json::Value::Object(original_defs.clone());
        rewrite_internal_defs_refs(&mut rewritten_defs, &renames, target_path)?;
        let rewritten_defs = rewritten_defs.as_object().ok_or_else(|| {
            CodegenError::SchemaRef(
                target_path.to_path_buf(),
                "rewritten $defs is not an object".to_string(),
            )
        })?;
        let mut changed = false;

        for (key, value) in rewritten_defs {
            let final_key = renames.get(key).ok_or_else(|| {
                CodegenError::SchemaRef(
                    target_path.to_path_buf(),
                    format!("missing deterministic rename for $defs/{key}"),
                )
            })?;
            if definition_registry.root_definition_keys.contains(final_key) {
                if final_key == key {
                    renames.insert(
                        key.clone(),
                        namespaced_definition_key(&namespace, key),
                    );
                    changed = true;
                    continue;
                }
                return Err(CodegenError::SchemaRef(
                    base_path.to_path_buf(),
                    format!(
                        "{reference} deterministic namespace $defs/{final_key} is reserved by the root schema"
                    ),
                ));
            }
            let Some(existing) = definition_registry.imported_defs.get(final_key) else {
                continue;
            };
            if existing == value {
                continue;
            }
            if final_key != key {
                return Err(CodegenError::SchemaRef(
                    base_path.to_path_buf(),
                    format!(
                        "{reference} collides with deterministic namespace $defs/{final_key}"
                    ),
                ));
            }
            renames.insert(
                key.clone(),
                namespaced_definition_key(&namespace, key),
            );
            changed = true;
        }

        if !changed {
            break;
        }
    }

    ensure_unique_definition_targets(&renames, base_path, reference)?;
    rewrite_internal_defs_refs(target, &renames, target_path)?;
    let target_root = target.as_object_mut().ok_or_else(|| {
        CodegenError::SchemaRef(
            target_path.to_path_buf(),
            "schema root is not an object".to_string(),
        )
    })?;
    let rewritten_defs = match target_root.remove("$defs") {
        Some(serde_json::Value::Object(defs)) => defs,
        Some(_) => {
            return Err(CodegenError::SchemaRef(
                target_path.to_path_buf(),
                "rewritten root $defs is not an object".to_string(),
            ))
        }
        None => serde_json::Map::new(),
    };
    let mut renamed_defs = serde_json::Map::new();
    for (key, value) in rewritten_defs {
        let final_key = renames.get(&key).ok_or_else(|| {
            CodegenError::SchemaRef(
                target_path.to_path_buf(),
                format!("missing deterministic rename for $defs/{key}"),
            )
        })?;
        merge_schema_def(
            &mut renamed_defs,
            final_key,
            value,
            base_path,
            reference,
        )?;
    }
    if !renamed_defs.is_empty() {
        target_root.insert(
            "$defs".to_string(),
            serde_json::Value::Object(renamed_defs.clone()),
        );
    }
    for (key, value) in renamed_defs {
        merge_schema_def(
            &mut definition_registry.imported_defs,
            &key,
            value,
            base_path,
            reference,
        )?;
    }

    Ok(renames)
}

fn schema_resource_namespace(target_path: &Path, schemas_dir: &Path) -> Result<String> {
    let canonical_schemas_dir =
        fs::canonicalize(schemas_dir).map_err(|err| CodegenError::Io(schemas_dir.into(), err))?;
    let canonical_target = fs::canonicalize(target_path)
        .map_err(|err| CodegenError::Io(target_path.to_path_buf(), err))?;
    let relative = canonical_target
        .strip_prefix(&canonical_schemas_dir)
        .map_err(|_| {
            CodegenError::SchemaRef(
                target_path.to_path_buf(),
                format!("schema path is outside {}", canonical_schemas_dir.display()),
            )
        })?;
    let mut resource_id = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(CodegenError::SchemaRef(
                target_path.to_path_buf(),
                "schema resource path is not normalized".to_string(),
            ));
        };
        let component = component.to_str().ok_or_else(|| {
            CodegenError::SchemaRef(
                target_path.to_path_buf(),
                "schema resource path is not valid UTF-8".to_string(),
            )
        })?;
        if !resource_id.is_empty() {
            resource_id.push('/');
        }
        resource_id.push_str(component);
    }
    if resource_id.is_empty() {
        return Err(CodegenError::SchemaRef(
            target_path.to_path_buf(),
            "schema resource path is empty".to_string(),
        ));
    }
    Ok(hex_encode(resource_id.as_bytes()))
}

fn namespaced_definition_key(namespace: &str, key: &str) -> String {
    format!(
        "__chio_resource_{namespace}_definition_{}",
        hex_encode(key.as_bytes())
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn ensure_unique_definition_targets(
    renames: &BTreeMap<String, String>,
    base_path: &Path,
    reference: &str,
) -> Result<()> {
    let mut owners = BTreeMap::<&str, &str>::new();
    for (source, target) in renames {
        if let Some(previous) = owners.insert(target, source) {
            return Err(CodegenError::SchemaRef(
                base_path.to_path_buf(),
                format!(
                    "{reference} maps both $defs/{previous} and $defs/{source} to $defs/{target}"
                ),
            ));
        }
    }
    Ok(())
}

fn ensure_relocatable_schema_refs(value: &serde_json::Value, path: &Path) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(reference_value) = map.get("$ref") {
                let serde_json::Value::String(reference) = reference_value else {
                    return Err(CodegenError::SchemaRef(
                        path.to_path_buf(),
                        "$ref is not a string".to_string(),
                    ));
                };
                let relocatable = root_defs_pointer_tokens(reference)
                    .map_err(|message| {
                        CodegenError::SchemaRef(
                            path.to_path_buf(),
                            format!("{reference}: {message}"),
                        )
                    })?
                    .is_some_and(|tokens| tokens.len() >= 2);
                if !relocatable {
                    return Err(CodegenError::SchemaRef(
                        path.to_path_buf(),
                        format!(
                            "{reference} cannot be safely relocated; only root $defs JSON Pointer references are supported"
                        ),
                    ));
                }
            }
            for item in map.values() {
                ensure_relocatable_schema_refs(item, path)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                ensure_relocatable_schema_refs(item, path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn rewrite_internal_defs_refs(
    value: &mut serde_json::Value,
    definition_renames: &BTreeMap<String, String>,
    path: &Path,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(reference_value) = map.get_mut("$ref") {
                let serde_json::Value::String(reference) = reference_value else {
                    return Err(CodegenError::SchemaRef(
                        path.to_path_buf(),
                        "$ref is not a string".to_string(),
                    ));
                };
                let original = reference.clone();
                if let Some(rewritten) = rewrite_internal_defs_ref(&original, definition_renames)
                    .map_err(|message| {
                        CodegenError::SchemaRef(
                            path.to_path_buf(),
                            format!("{original}: {message}"),
                        )
                    })?
                {
                    *reference = rewritten;
                }
            }
            for item in map.values_mut() {
                rewrite_internal_defs_refs(item, definition_renames, path)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                rewrite_internal_defs_refs(item, definition_renames, path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn rewrite_internal_defs_ref(
    reference: &str,
    definition_renames: &BTreeMap<String, String>,
) -> core::result::Result<Option<String>, String> {
    let Some(mut tokens) = root_defs_pointer_tokens(reference)? else {
        return Ok(None);
    };
    let definition = tokens
        .get(1)
        .ok_or_else(|| "internal $defs reference does not identify a definition".to_string())?;
    let renamed = definition_renames
        .get(definition)
        .ok_or_else(|| format!("missing definition $defs/{definition}"))?;
    if renamed == definition {
        return Ok(None);
    }
    tokens[1] = renamed.clone();
    let rewritten = tokens
        .iter()
        .map(|token| encode_json_pointer_token(token))
        .collect::<Vec<_>>()
        .join("/");
    let pointer = format!("/{rewritten}");
    Ok(Some(format!("#{}", percent_encode_uri_fragment(&pointer))))
}

fn root_defs_pointer_tokens(
    reference: &str,
) -> core::result::Result<Option<Vec<String>>, String> {
    let Some(fragment) = reference.strip_prefix('#') else {
        return Ok(None);
    };
    if fragment.is_empty() {
        return Ok(None);
    }
    let decoded = percent_decode_uri_fragment(fragment)?;
    let Some(pointer) = decoded.strip_prefix('/') else {
        return Ok(None);
    };
    let tokens = pointer
        .split('/')
        .map(decode_json_pointer_token)
        .collect::<core::result::Result<Vec<_>, _>>()?;
    if tokens.first().map(String::as_str) != Some("$defs") {
        return Ok(None);
    }
    Ok(Some(tokens))
}

fn rewrite_referenced_fragment(
    fragment: Option<&str>,
    definition_renames: &BTreeMap<String, String>,
) -> core::result::Result<Option<String>, String> {
    let Some(fragment) = fragment else {
        return Ok(None);
    };
    let reference = format!("#{fragment}");
    let rewritten = rewrite_internal_defs_ref(&reference, definition_renames)?;
    Ok(Some(match rewritten {
        Some(rewritten) => rewritten
            .strip_prefix('#')
            .ok_or_else(|| "rewritten fragment is missing #".to_string())?
            .to_string(),
        None => fragment.to_string(),
    }))
}

fn encode_json_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn percent_encode_uri_fragment(fragment: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(fragment.len());
    for byte in fragment.bytes() {
        if matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'?'
        ) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

fn merge_extra_defs_into_root(
    root: &mut serde_json::Value,
    extra_defs: serde_json::Map<String, serde_json::Value>,
    path: &Path,
) -> Result<()> {
    if extra_defs.is_empty() {
        return Ok(());
    }

    let Some(root_object) = root.as_object_mut() else {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "cannot merge referenced definitions into a non-object schema".to_string(),
        ));
    };

    let defs = root_object
        .entry("$defs".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(defs_object) = defs.as_object_mut() else {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "root $defs is not an object".to_string(),
        ));
    };

    for (key, value) in extra_defs {
        merge_schema_def(defs_object, &key, value, path, "$defs")?;
    }

    Ok(())
}

fn merge_schema_def(
    defs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: serde_json::Value,
    base_path: &Path,
    reference: &str,
) -> Result<()> {
    match defs.get(key) {
        Some(existing) if existing == &value => Ok(()),
        Some(_) => Err(CodegenError::SchemaRef(
            base_path.to_path_buf(),
            format!("{reference} collides with existing $defs/{key}"),
        )),
        None => {
            defs.insert(key.to_string(), value);
            Ok(())
        }
    }
}

fn resolve_json_pointer<'a>(
    value: &'a serde_json::Value,
    fragment: Option<&str>,
) -> core::result::Result<&'a serde_json::Value, String> {
    let Some(fragment) = fragment else {
        return Ok(value);
    };
    if fragment.is_empty() {
        return Ok(value);
    }
    let fragment = percent_decode_uri_fragment(fragment)?;
    let Some(pointer) = fragment.strip_prefix('/') else {
        return Err(format!("unsupported fragment #{fragment}"));
    };

    let mut current = value;
    for token in pointer.split('/') {
        let token = decode_json_pointer_token(token)?;
        current = match current {
            serde_json::Value::Object(map) => map
                .get(&token)
                .ok_or_else(|| format!("missing object key {token}"))?,
            serde_json::Value::Array(items) => {
                if token.len() > 1 && token.starts_with('0') {
                    return Err(format!("array index {token} has a leading zero"));
                }
                if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(format!("array index {token} is not numeric"));
                }
                let index = token
                    .parse::<usize>()
                    .map_err(|_| format!("array index {token} is not numeric"))?;
                items
                    .get(index)
                    .ok_or_else(|| format!("array index {index} is out of bounds"))?
            }
            _ => {
                return Err(format!(
                    "cannot descend through non-container token {token}"
                ))
            }
        };
    }

    Ok(current)
}

fn percent_decode_uri_fragment(fragment: &str) -> core::result::Result<String, String> {
    let bytes = fragment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("fragment has a truncated percent escape".to_string());
            }
            let high = decode_hex_nibble(bytes[index + 1])
                .ok_or_else(|| "fragment has an invalid percent escape".to_string())?;
            let low = decode_hex_nibble(bytes[index + 2])
                .ok_or_else(|| "fragment has an invalid percent escape".to_string())?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "fragment is not valid UTF-8".to_string())
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_json_pointer_token(token: &str) -> core::result::Result<String, String> {
    let mut decoded = String::with_capacity(token.len());
    let mut characters = token.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            Some(other) => return Err(format!("invalid JSON Pointer escape ~{other}")),
            None => return Err("truncated JSON Pointer escape".to_string()),
        }
    }
    Ok(decoded)
}

fn strip_inlined_resource_keywords(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        map.remove("$schema");
        map.remove("$id");
        map.remove("$defs");
    }
}

fn strip_typify_unsupported_conditionals(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("if");
            map.remove("then");
            map.remove("else");
            let remove_all_of = if let Some(serde_json::Value::Array(items)) = map.get_mut("allOf")
            {
                items.retain(|item| {
                    !item.as_object().is_some_and(|object| {
                        object.is_empty()
                            || object
                                .keys()
                                .all(|key| matches!(key.as_str(), "if" | "then" | "else"))
                    })
                });
                items.is_empty()
            } else {
                false
            };
            if remove_all_of {
                map.remove("allOf");
            }
            for item in map.values_mut() {
                strip_typify_unsupported_conditionals(item);
            }
            let remove_empty_all_of =
                if let Some(serde_json::Value::Array(items)) = map.get_mut("allOf") {
                    items.retain(|item| !item.as_object().is_some_and(serde_json::Map::is_empty));
                    items.is_empty()
                } else {
                    false
                };
            if remove_empty_all_of {
                map.remove("allOf");
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_typify_unsupported_conditionals(item);
            }
        }
        _ => {}
    }
}

/// Remove only the tool-request approval compatibility exclusion. Typify
/// otherwise misprojects this clause by deleting both named properties from
/// the generated Rust struct.
///
/// The authoritative schema retains the exclusion and remains the validation
/// boundary. Rust bindings must still carry every wire field so valid members
/// of the mutually exclusive set can decode and round-trip. A `properties`
/// member is accepted only when it repeats the exact pair with boolean `true`
/// schemas used solely for strictRequired visibility.
fn strip_typify_cross_field_exclusions(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let pure_cross_field_exclusion = map
                .get("not")
                .and_then(serde_json::Value::as_object)
                .filter(|not| {
                    not.keys()
                        .all(|key| matches!(key.as_str(), "required" | "properties"))
                })
                .and_then(|not| {
                    let required = not.get("required")?.as_array()?;
                    if required.len() <= 1 {
                        return None;
                    }
                    let properties = map.get("properties")?.as_object()?;
                    let fields = required
                        .iter()
                        .map(serde_json::Value::as_str)
                        .collect::<Option<Vec<_>>>()?;
                    let unique_fields = fields
                        .iter()
                        .enumerate()
                        .all(|(index, field)| !fields[..index].contains(field));
                    let exact_approval_pair = fields.len() == 2
                        && fields.contains(&"approval_token")
                        && fields.contains(&"approval_tokens");
                    let visibility_only = match not.get("properties") {
                        None => true,
                        Some(serde_json::Value::Object(visibility)) => {
                            visibility.len() == fields.len()
                                && fields.iter().all(|field| {
                                    visibility.get(*field)
                                        == Some(&serde_json::Value::Bool(true))
                                })
                        }
                        Some(_) => false,
                    };
                    (unique_fields
                        && exact_approval_pair
                        && visibility_only
                        && fields.iter().all(|field| properties.contains_key(*field)))
                    .then_some(fields)
                })
                .is_some();
            if pure_cross_field_exclusion {
                map.remove("not");
            }
            for item in map.values_mut() {
                strip_typify_cross_field_exclusions(item);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_typify_cross_field_exclusions(item);
            }
        }
        _ => {}
    }
}

fn strip_typify_nonzero_digest_contains(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let is_detector_digest = map.get("type").and_then(serde_json::Value::as_str)
                == Some("array")
                && map.get("minItems").and_then(serde_json::Value::as_u64) == Some(32)
                && map.get("maxItems").and_then(serde_json::Value::as_u64) == Some(32)
                && map.get("minContains").and_then(serde_json::Value::as_u64) == Some(1)
                && map.get("contains")
                    == Some(&serde_json::json!({"type": "integer", "minimum": 1}));
            if is_detector_digest {
                map.remove("contains");
                map.remove("minContains");
            }
            for item in map.values_mut() {
                strip_typify_nonzero_digest_contains(item);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_typify_nonzero_digest_contains(item);
            }
        }
        _ => {}
    }
}
