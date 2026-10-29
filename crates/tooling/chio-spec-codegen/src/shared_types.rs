//! Cross-module type sharing for the chio-wire/v1 Rust bindings.
//!
//! Every schema location that typify turns into a named type (an object with
//! properties, an enum, a union) has a structural key: the schema without
//! `title`, `description`, `$comment` and `examples`, with each nested schema
//! and each `#/$defs/...` reference replaced by its own key. A named location
//! whose key occurs at more than one place across all modules becomes one type
//! in the [`SHARED_MODULE`] module, and every place refers to it. A definition
//! referenced from a shared type is shared as well, so a shared type never
//! refers back into a module.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use heck::ToPascalCase;
use serde_json::{Map, Value};

/// Module that holds the shared types.
pub(crate) const SHARED_MODULE: &str = "shared";

const METADATA_KEYS: &[&str] = &["title", "description", "$comment", "examples"];
const SCHEMA_MAP_KEYS: &[&str] = &["properties", "patternProperties", "dependentSchemas"];
const SCHEMA_LIST_KEYS: &[&str] = &["prefixItems", "anyOf", "oneOf", "allOf"];
const SCHEMA_KEYS: &[&str] = &[
    "items",
    "additionalProperties",
    "unevaluatedProperties",
    "unevaluatedItems",
    "propertyNames",
    "contains",
    "not",
    "if",
    "then",
    "else",
];
const DEFS_KEYS: &[&str] = &["$defs", "definitions"];

/// The modules after sharing, plus the shared definitions.
pub(crate) struct SharedSchemas {
    /// `(module name, root schema)` in input order.
    pub(crate) modules: Vec<(String, Value)>,
    /// Shared type name to schema; references inside use `#/$defs/<name>`.
    pub(crate) shared: BTreeMap<String, Value>,
    /// Shared type names each module refers to, by module index.
    pub(crate) uses: Vec<BTreeSet<String>>,
}

#[derive(Default)]
struct Keys {
    ids: HashMap<String, usize>,
    sites: Vec<usize>,
    names: Vec<BTreeSet<String>>,
    children: Vec<Vec<usize>>,
    refs: Vec<Vec<usize>>,
}

impl Keys {
    fn intern(&mut self, canonical: String, children: Vec<usize>, refs: Vec<usize>) -> usize {
        if let Some(id) = self.ids.get(&canonical) {
            return *id;
        }
        let id = self.sites.len();
        self.ids.insert(canonical, id);
        self.sites.push(0);
        self.names.push(BTreeSet::new());
        self.children.push(children);
        self.refs.push(refs);
        id
    }
}

struct Module<'a> {
    defs: Option<&'a Map<String, Value>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    Key,
    Count,
}

struct Sharer {
    keys: Keys,
    def_ids: HashMap<(usize, String), Option<usize>>,
    in_progress: BTreeSet<(usize, String)>,
    hoisted: BTreeMap<usize, String>,
    shared: BTreeMap<String, Value>,
    used: BTreeSet<String>,
    memo: HashMap<usize, Option<usize>>,
}

fn module_defs(root: &Value) -> Option<&Map<String, Value>> {
    let object = root.as_object()?;
    DEFS_KEYS
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_object))
}

fn local_def(reference: &Value) -> Option<&str> {
    reference.as_str()?.strip_prefix("#/$defs/")
}

/// A one-branch-or-null union, which typify emits as `Option` of the branch
/// rather than as a named type.
fn is_nullable_wrapper(map: &Map<String, Value>) -> bool {
    ["oneOf", "anyOf"].iter().any(|key| {
        map.get(*key)
            .and_then(Value::as_array)
            .is_some_and(|branches| {
                branches.len() == 2
                    && branches.iter().any(|branch| {
                        branch.as_object().is_some_and(|branch| {
                            branch.len() == 1 && branch.get("type") == Some(&Value::from("null"))
                        })
                    })
            })
    })
}

/// A location typify emits as a named type.
fn is_named(map: &Map<String, Value>) -> bool {
    if is_nullable_wrapper(map) {
        return false;
    }
    ["properties", "enum", "oneOf", "anyOf", "allOf"]
        .iter()
        .any(|key| map.contains_key(*key))
        || map
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|kinds| kinds.iter().filter(|kind| *kind != "null").count() > 1)
}

fn key_token(id: usize) -> Value {
    Value::String(format!("#key/{id}"))
}

impl Sharer {
    fn def_key(&mut self, module: usize, ctx: &Module<'_>, name: &str) -> Option<usize> {
        let slot = (module, name.to_string());
        if let Some(id) = self.def_ids.get(&slot) {
            return *id;
        }
        if !self.in_progress.insert(slot.clone()) {
            return None;
        }
        let id = ctx
            .defs
            .and_then(|defs| defs.get(name))
            .and_then(|body| self.key(body, module, ctx, Pass::Key));
        self.in_progress.remove(&slot);
        if let Some(id) = id {
            self.keys.names[id].insert(name.to_string());
        }
        self.def_ids.insert(slot, id);
        id
    }

    /// Structural key of `node`; `None` when it cannot be shared (a cycle or
    /// a reference outside `#/$defs`). `Pass::Count` also counts named sites,
    /// including module definitions.
    fn key(&mut self, node: &Value, module: usize, ctx: &Module<'_>, pass: Pass) -> Option<usize> {
        let address = std::ptr::from_ref(node) as usize;
        if pass == Pass::Key {
            if let Some(id) = self.memo.get(&address) {
                return *id;
            }
        }
        let id = self.key_uncached(node, module, ctx, pass);
        self.memo.insert(address, id);
        id
    }

    fn key_uncached(
        &mut self,
        node: &Value,
        module: usize,
        ctx: &Module<'_>,
        pass: Pass,
    ) -> Option<usize> {
        let map = match node {
            Value::Bool(_) => {
                return Some(self.keys.intern(node.to_string(), Vec::new(), Vec::new()))
            }
            Value::Object(map) => map,
            _ => return None,
        };
        let mut canonical = Map::new();
        let mut children = Vec::new();
        let mut refs = Vec::new();
        let mut keyable = true;
        let child = |sharer: &mut Self, value: &Value, children: &mut Vec<usize>| {
            let id = sharer.key(value, module, ctx, pass);
            if let Some(id) = id {
                children.push(id);
            }
            id.map(key_token)
        };
        for (name, value) in map {
            if METADATA_KEYS.contains(&name.as_str()) {
                continue;
            }
            if DEFS_KEYS.contains(&name.as_str()) {
                if pass == Pass::Count {
                    if let Some(defs) = value.as_object() {
                        for body in defs.values() {
                            self.key(body, module, ctx, pass);
                        }
                    }
                }
                continue;
            }
            let rendered = if name == "$ref" {
                match local_def(value).and_then(|def| self.def_key(module, ctx, def)) {
                    Some(id) => {
                        refs.push(id);
                        Some(key_token(id))
                    }
                    None => None,
                }
            } else if SCHEMA_MAP_KEYS.contains(&name.as_str()) {
                let entries = value.as_object()?;
                let mut out = Map::new();
                let mut complete = true;
                for (entry, schema) in entries {
                    match child(self, schema, &mut children) {
                        Some(token) => {
                            out.insert(entry.clone(), token);
                        }
                        None => complete = false,
                    }
                }
                complete.then_some(Value::Object(out))
            } else if SCHEMA_LIST_KEYS.contains(&name.as_str())
                || (name == "items" && value.is_array())
            {
                let entries = value.as_array()?;
                let mut out = Vec::new();
                let mut complete = true;
                for schema in entries {
                    match child(self, schema, &mut children) {
                        Some(token) => out.push(token),
                        None => complete = false,
                    }
                }
                complete.then_some(Value::Array(out))
            } else if SCHEMA_KEYS.contains(&name.as_str()) {
                child(self, value, &mut children)
            } else {
                Some(value.clone())
            };
            match rendered {
                Some(rendered) => {
                    canonical.insert(name.clone(), rendered);
                }
                None => keyable = false,
            }
        }
        if !keyable {
            return None;
        }
        let id = self
            .keys
            .intern(Value::Object(canonical).to_string(), children, refs);
        if pass == Pass::Count && is_named(map) {
            self.keys.sites[id] += 1;
            if let Some(title) = map.get("title").and_then(Value::as_str) {
                self.keys.names[id].insert(title.to_string());
            }
        }
        Some(id)
    }

    /// Rewrite `node` for its module: shared locations become references to
    /// the shared type and their schema moves to the shared set.
    fn rewrite(&mut self, node: &Value, module: usize, ctx: &Module<'_>) -> Value {
        let Value::Object(map) = node else {
            return node.clone();
        };
        let mut out = Map::new();
        for (name, value) in map {
            let rewritten = if DEFS_KEYS.contains(&name.as_str()) {
                let Some(defs) = value.as_object() else {
                    out.insert(name.clone(), value.clone());
                    continue;
                };
                let mut kept = Map::new();
                for (def, body) in defs {
                    let shared = self
                        .def_key(module, ctx, def)
                        .is_some_and(|id| self.hoisted.contains_key(&id));
                    let body = self.rewrite_site(body, module, ctx, shared);
                    if !shared {
                        kept.insert(def.clone(), body);
                    }
                }
                Value::Object(kept)
            } else if name == "$ref" {
                match local_def(value)
                    .and_then(|def| self.def_key(module, ctx, def))
                    .and_then(|id| self.hoisted.get(&id).cloned())
                {
                    Some(shared) => {
                        self.used.insert(shared.clone());
                        Value::String(format!("#/$defs/{shared}"))
                    }
                    None => value.clone(),
                }
            } else if SCHEMA_MAP_KEYS.contains(&name.as_str()) {
                match value.as_object() {
                    Some(entries) => Value::Object(
                        entries
                            .iter()
                            .map(|(entry, schema)| {
                                (entry.clone(), self.rewrite_site(schema, module, ctx, false))
                            })
                            .collect(),
                    ),
                    None => value.clone(),
                }
            } else if SCHEMA_LIST_KEYS.contains(&name.as_str())
                || (name == "items" && value.is_array())
            {
                match value.as_array() {
                    Some(entries) => Value::Array(
                        entries
                            .iter()
                            .map(|schema| self.rewrite_site(schema, module, ctx, false))
                            .collect(),
                    ),
                    None => value.clone(),
                }
            } else if SCHEMA_KEYS.contains(&name.as_str()) {
                self.rewrite_site(value, module, ctx, false)
            } else {
                value.clone()
            };
            out.insert(name.clone(), rewritten);
        }
        Value::Object(out)
    }

    /// Rewrite a schema location, replacing it with a shared reference when
    /// its key is shared and it is a named location (or `definition` is set:
    /// a shared definition body).
    fn rewrite_site(
        &mut self,
        node: &Value,
        module: usize,
        ctx: &Module<'_>,
        definition: bool,
    ) -> Value {
        let rewritten = self.rewrite(node, module, ctx);
        let named = definition || node.as_object().is_some_and(is_named);
        let shared = named
            .then(|| self.key(node, module, ctx, Pass::Key))
            .flatten()
            .and_then(|id| self.hoisted.get(&id).cloned());
        let Some(shared) = shared else {
            return rewritten;
        };
        if !self.shared.contains_key(&shared) {
            let mut body = rewritten;
            if let Value::Object(map) = &mut body {
                map.remove("$schema");
                map.remove("$id");
                for key in DEFS_KEYS {
                    map.remove(*key);
                }
            }
            self.shared.insert(shared.clone(), body);
        }
        self.used.insert(shared.clone());
        serde_json::json!({ "$ref": format!("#/$defs/{shared}") })
    }
}

/// FNV-1a over the canonical key, spelled in lowercase letters so the name
/// survives typify's Pascal-case sanitizer unchanged.
fn hash_name(canonical: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in canonical.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut name = String::from("Shared");
    for _ in 0..13 {
        let letter = (hash % 26) as u8;
        hash /= 26;
        name.push(char::from(b'a' + letter));
    }
    name
}

/// Pascal-case form of a title or definition name, as typify spells type
/// names, or `None` unless it is an ASCII identifier starting with a letter.
fn pascal_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let name = cleaned.to_pascal_case();
    let first = name.chars().next()?;
    (first.is_ascii_alphabetic() && name.chars().all(|c| c.is_ascii_alphanumeric())).then_some(name)
}

/// Share every named location that occurs more than once across `modules`.
pub(crate) fn share_types(modules: Vec<(String, Value)>) -> SharedSchemas {
    let mut sharer = Sharer {
        keys: Keys::default(),
        def_ids: HashMap::new(),
        in_progress: BTreeSet::new(),
        hoisted: BTreeMap::new(),
        shared: BTreeMap::new(),
        used: BTreeSet::new(),
        memo: HashMap::new(),
    };
    for (index, (_, root)) in modules.iter().enumerate() {
        let ctx = Module {
            defs: module_defs(root),
        };
        sharer.memo.clear();
        sharer.key(root, index, &ctx, Pass::Count);
    }

    let mut hoisted: BTreeSet<usize> = (0..sharer.keys.sites.len())
        .filter(|id| sharer.keys.sites[*id] > 1)
        .collect();
    let mut pending: Vec<usize> = hoisted.iter().copied().collect();
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        for reference in sharer.keys.refs[id].clone() {
            if hoisted.insert(reference) {
                pending.push(reference);
            }
        }
        pending.extend(sharer.keys.children[id].iter().copied());
    }

    let canonical: HashMap<usize, String> = sharer
        .keys
        .ids
        .iter()
        .filter(|(_, id)| hoisted.contains(id))
        .map(|(key, id)| (*id, key.clone()))
        .collect();
    let mut wanted: BTreeMap<usize, Option<String>> = BTreeMap::new();
    let mut claims: BTreeMap<String, usize> = BTreeMap::new();
    for id in &hoisted {
        let candidates: BTreeSet<String> = sharer.keys.names[*id]
            .iter()
            .filter_map(|name| pascal_name(name))
            .collect();
        let name = (candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten();
        if let Some(name) = &name {
            *claims.entry(name.clone()).or_default() += 1;
        }
        wanted.insert(*id, name);
    }
    for (id, name) in wanted {
        let name = match name {
            Some(name) if claims.get(&name) == Some(&1) => name,
            _ => hash_name(canonical.get(&id).map_or("", String::as_str)),
        };
        sharer.hoisted.insert(id, name);
    }

    let mut out = Vec::with_capacity(modules.len());
    let mut uses = Vec::with_capacity(modules.len());
    for (index, (name, root)) in modules.iter().enumerate() {
        let ctx = Module {
            defs: module_defs(root),
        };
        sharer.used.clear();
        sharer.memo.clear();
        let root_id = sharer.key(root, index, &ctx, Pass::Key);
        let mut rewritten = sharer.rewrite(root, index, &ctx);
        if let Some(shared) = root_id.and_then(|id| sharer.hoisted.get(&id).cloned()) {
            if !sharer.shared.contains_key(&shared) {
                let mut body = rewritten.clone();
                if let Value::Object(map) = &mut body {
                    map.remove("$schema");
                    map.remove("$id");
                    for key in DEFS_KEYS {
                        map.remove(*key);
                    }
                }
                sharer.shared.insert(shared.clone(), body);
            }
            sharer.used.insert(shared.clone());
            let mut root = Map::new();
            if let Value::Object(map) = &rewritten {
                for key in ["$schema", "$id", "title", "description", "$defs"] {
                    if let Some(value) = map.get(key) {
                        root.insert(key.to_string(), value.clone());
                    }
                }
            }
            root.insert(
                "$ref".to_string(),
                Value::String(format!("#/$defs/{shared}")),
            );
            rewritten = Value::Object(root);
        }
        uses.push(sharer.used.clone());
        out.push((name.clone(), rewritten));
    }

    SharedSchemas {
        modules: out,
        shared: sharer.shared,
        uses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn address() -> Value {
        json!({
            "type": "object",
            "properties": { "city": { "type": "string" } },
            "required": ["city"]
        })
    }

    #[test]
    fn repeated_location_moves_to_one_shared_type() {
        let a = json!({
            "title": "A",
            "type": "object",
            "properties": { "home": address(), "work": address() }
        });
        let mut titled = address();
        titled["title"] = json!("Postal address");
        let b = json!({ "title": "B", "type": "object", "properties": { "at": titled } });
        let shared = share_types(vec![("a".into(), a), ("b".into(), b)]);
        assert_eq!(shared.shared.len(), 1);
        let name = "PostalAddress";
        assert!(shared.shared.contains_key(name));
        assert_eq!(
            shared.modules[0].1["properties"]["home"],
            json!({ "$ref": format!("#/$defs/{name}") })
        );
        assert_eq!(
            shared.modules[1].1["properties"]["at"]["$ref"],
            json!(format!("#/$defs/{name}"))
        );
        assert!(shared.uses[0].contains(name) && shared.uses[1].contains(name));
    }

    #[test]
    fn nullable_wrappers_are_not_named_types() {
        let nullable = json!({"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]});
        let union = json!({"anyOf": [{"type": "string"}, {"type": "integer"}]});
        assert!(!is_named(nullable.as_object().unwrap_or(&Map::new())));
        assert!(is_named(union.as_object().unwrap_or(&Map::new())));
    }

    #[test]
    fn single_location_stays_inline() {
        let a = json!({ "title": "A", "type": "object", "properties": { "home": address() } });
        let shared = share_types(vec![("a".into(), a.clone())]);
        assert!(shared.shared.is_empty());
        assert_eq!(shared.modules[0].1, a);
    }

    #[test]
    fn definitions_reached_from_a_shared_type_are_shared() {
        let module = |title: &str| {
            json!({
                "title": title,
                "type": "object",
                "properties": {
                    (title.to_lowercase()): { "type": "string" },
                    "record": {
                        "type": "object",
                        "properties": { "verdict": { "$ref": "#/$defs/verdict" } }
                    }
                },
                "$defs": { "verdict": { "enum": ["allow", "deny"] } }
            })
        };
        let shared = share_types(vec![("a".into(), module("A")), ("b".into(), module("B"))]);
        assert!(shared.shared.contains_key("Verdict"));
        assert_eq!(shared.modules[0].1["$defs"], json!({}));
        let record = shared.modules[0].1["properties"]["record"]["$ref"]
            .as_str()
            .and_then(|r| r.strip_prefix("#/$defs/"))
            .map(str::to_string);
        let Some(record) = record else {
            panic!("record is not shared: {}", shared.modules[0].1);
        };
        assert_eq!(
            shared.shared[&record]["properties"]["verdict"]["$ref"],
            json!("#/$defs/Verdict")
        );
    }

    #[test]
    fn title_claimed_by_two_shapes_falls_back_to_hash_names() {
        let one = json!({ "title": "Item", "type": "object", "properties": { "x": { "type": "string" } } });
        let two = json!({ "title": "Item", "type": "object", "properties": { "y": { "type": "string" } } });
        let root = json!({
            "title": "R",
            "type": "object",
            "properties": { "a": one, "b": one, "c": two, "d": two }
        });
        let shared = share_types(vec![("r".into(), root)]);
        assert_eq!(shared.shared.len(), 2);
        assert!(shared.shared.keys().all(|name| name.starts_with("Shared")));
    }
}
