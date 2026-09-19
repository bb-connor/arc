//! Exact physical-source inventory of kernel construction and factory references.
//!
//! This supplements dispatch contracts and behavior tests, not Rust type checking
//! or macro expansion. New constructor aliases and macro-hidden construction
//! require extending this checker rather than silently leaving its coverage.

use super::test_only;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use syn::visit::{self, Visit};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Site {
    pub id: String,
    pub path: String,
    pub symbol: String,
    pub target: String,
    pub references: usize,
}

const FACTORIES: &[&str] = &[
    "build_kernel",
    "build_kernel_components",
    "build_kernel_with_active_defense",
    "build_mcp_edge_kernel",
];

const DISPATCH_PREFIXES: &[&str] = &[
    "evaluate_tool_call",
    "authorize_tool_call",
    "reserve_caller_execution",
    "verdict_for_provider_invocation",
    "start_caller_execution",
    "record_caller_execution",
    "reconcile_caller_execution",
];

fn is_dispatch_entry(name: &str) -> bool {
    DISPATCH_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

pub(super) fn validate(root: &Path, sites: &[Site]) -> Result<(), String> {
    let mut expected = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for site in sites {
        if site.id.is_empty() || !ids.insert(&site.id) || site.references == 0 {
            return Err("invalid or duplicate constructor inventory identity".to_string());
        }
        if expected
            .insert(
                (site.path.clone(), site.symbol.clone(), site.target.clone()),
                site.references,
            )
            .is_some()
        {
            return Err(format!("duplicate constructor inventory site {}", site.id));
        }
    }
    if expected.is_empty() {
        return Err("constructor inventory must not be empty".to_string());
    }
    let mut observed = BTreeMap::new();
    for directory in ["crates", "examples", "integrations", "bench", "sdks"] {
        scan(root, &root.join(directory), &mut observed)?;
    }
    if observed != expected {
        let missing: Vec<_> = expected
            .iter()
            .filter(|(key, count)| observed.get(*key) != Some(*count))
            .collect();
        let unknown: Vec<_> = observed
            .iter()
            .filter(|(key, count)| expected.get(*key) != Some(*count))
            .collect();
        return Err(format!(
            "constructor inventory mismatch: stale={missing:?} unclassified={unknown:?}"
        ));
    }
    Ok(())
}

type Inventory = BTreeMap<(String, String, String), usize>;

fn scan(root: &Path, path: &Path, inventory: &mut Inventory) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if matches!(
        name,
        "tests"
            | "tests.rs"
            | "_generated"
            | "target"
            | "node_modules"
            | ".venv"
            | ".git"
            | "__pycache__"
    ) || name.ends_with("_tests.rs")
        || name.ends_with("_tests")
    {
        return Ok(());
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        // Non-Rust assets do not expand source coverage. Never follow a source
        // directory/file symlink out of the repository inventory.
        if path
            .extension()
            .is_some_and(|extension| extension == "rs" || extension == "inc")
            || path.is_dir()
        {
            return Err(format!(
                "constructor source symlink requires classification: {}",
                path.display()
            ));
        }
        return Ok(());
    }
    if metadata.is_dir() {
        for entry in
            fs::read_dir(path).map_err(|error| format!("read {}: {error}", path.display()))?
        {
            scan(
                root,
                &entry.map_err(|error| error.to_string())?.path(),
                inventory,
            )?;
        }
    } else if metadata.is_file()
        && path
            .extension()
            .is_some_and(|extension| extension == "rs" || extension == "inc")
    {
        let source = fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if !source.contains("ChioKernel")
            && !FACTORIES.iter().any(|name| source.contains(name))
            && !DISPATCH_PREFIXES.iter().any(|name| source.contains(name))
        {
            return Ok(());
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let syntax = syn::parse_file(&source)
            .map_err(|error| format!("parse constructor source {relative}: {error}"))?;
        let mut visitor = ConstructorVisitor::default();
        visitor.visit_file(&syntax);
        if let Some(error) = visitor.unsupported {
            return Err(format!("constructor source {relative}: {error}"));
        }
        for ((symbol, target), count) in visitor.references {
            inventory.insert((relative.clone(), symbol, target), count);
        }
    }
    Ok(())
}

#[derive(Default)]
struct ConstructorVisitor {
    scope: Vec<String>,
    references: BTreeMap<(String, String), usize>,
    unsupported: Option<String>,
}

impl<'ast> Visit<'ast> for ConstructorVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if test_only(&node.attrs) {
            return;
        }
        self.scope.push(node.ident.to_string());
        visit::visit_item_mod(self, node);
        self.scope.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if test_only(&node.attrs) {
            return;
        }
        let owner = super::impl_name(node);
        if let Some(owner) = &owner {
            self.scope.push(owner.clone());
        }
        visit::visit_item_impl(self, node);
        if owner.is_some() {
            self.scope.pop();
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if test_only(&node.attrs) {
            return;
        }
        self.scope.push(node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.scope.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if test_only(&node.attrs) {
            return;
        }
        self.scope.push(node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.scope.pop();
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        let names: Vec<_> = node
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if names
            .last()
            .is_some_and(|name| FACTORIES.contains(&name.as_str()) || is_dispatch_entry(name))
            || (names.iter().any(|name| name == "ChioKernel")
                && names
                    .last()
                    .is_some_and(|name| matches!(name.as_str(), "new" | "default")))
        {
            *self
                .references
                .entry((self.scope.join("::"), names.join("::")))
                .or_default() += 1;
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if is_dispatch_entry(&name) {
            *self
                .references
                .entry((self.scope.join("::"), format!(".{name}")))
                .or_default() += 1;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_use_rename(&mut self, node: &'ast syn::UseRename) {
        if node.ident == "ChioKernel"
            || FACTORIES.contains(&node.ident.to_string().as_str())
            || is_dispatch_entry(&node.ident.to_string())
        {
            self.unsupported =
                Some("constructor import alias needs explicit source-contract support".to_string());
        }
        visit::visit_use_rename(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if test_only(&node.attrs) {
            return;
        }
        if matches!(node.ty.as_ref(), syn::Type::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "ChioKernel"))
        {
            self.unsupported =
                Some("kernel type alias needs explicit source-contract support".to_string());
        }
        visit::visit_item_type(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if contains_constructor_identifier(node.tokens.clone()) {
            self.unsupported = Some(
                "macro-hidden constructor reference needs explicit source-contract support"
                    .to_string(),
            );
        }
    }
}

fn contains_constructor_identifier(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(identifier) => {
            identifier == "ChioKernel"
                || FACTORIES.contains(&identifier.to_string().as_str())
                || is_dispatch_entry(&identifier.to_string())
        }
        proc_macro2::TokenTree::Group(group) => contains_constructor_identifier(group.stream()),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(source: &str) -> Result<ConstructorVisitor, syn::Error> {
        let mut visitor = ConstructorVisitor::default();
        visitor.visit_file(&syn::parse_file(source)?);
        Ok(visitor)
    }

    #[test]
    fn constructor_inventory_retains_nested_and_function_pointer_references(
    ) -> Result<(), syn::Error> {
        let visitor = inspect("fn outer() { let factory = ChioKernel::new; fn nested() { build_kernel(); } ChioKernel::new(); }")?;
        assert_eq!(
            visitor
                .references
                .get(&("outer".to_string(), "ChioKernel::new".to_string())),
            Some(&2)
        );
        assert_eq!(
            visitor
                .references
                .get(&("outer::nested".to_string(), "build_kernel".to_string())),
            Some(&1)
        );
        Ok(())
    }

    #[test]
    fn constructor_alias_and_macro_mutations_cannot_escape_inventory() -> Result<(), syn::Error> {
        for source in [
            "use chio_kernel::ChioKernel as K;",
            "type K = ChioKernel;",
            "macro_rules! make { () => { ChioKernel::new() } }",
            "macro_rules! run { () => { kernel.evaluate_tool_call(request) } }",
            "use host::start_caller_execution as unchecked_start;",
        ] {
            assert!(inspect(source)?.unsupported.is_some());
        }
        assert!(
            inspect("#[cfg(test)] mod tests { fn fixture() { ChioKernel::new(); } }")?
                .references
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn dispatch_inventory_includes_trait_methods_and_function_references() -> Result<(), syn::Error>
    {
        let visitor = inspect("impl Service for Host { fn call(&self) { kernel.evaluate_tool_call(req); let start = ChioKernel::start_caller_execution_blocking; } }")?;
        assert_eq!(
            visitor.references.get(&(
                "<Host as Service>::call".to_string(),
                ".evaluate_tool_call".to_string()
            )),
            Some(&1)
        );
        assert_eq!(
            visitor.references.get(&(
                "<Host as Service>::call".to_string(),
                "ChioKernel::start_caller_execution_blocking".to_string()
            )),
            Some(&1)
        );
        Ok(())
    }

    #[test]
    fn new_and_removed_physical_constructor_sites_fail_the_inventory() -> Result<(), String> {
        let temporary = crate::support::TempDir::new("chio-constructor-inventory")
            .map_err(|error| error.to_string())?;
        let root = temporary.path();
        for directory in ["crates", "examples", "integrations", "bench", "sdks"] {
            fs::create_dir(root.join(directory)).map_err(|error| error.to_string())?;
        }
        let path = root.join("crates/boundary.rs");
        fs::write(&path, "fn host() { ChioKernel::new(); }").map_err(|error| error.to_string())?;
        let sites = [Site {
            id: "C01".to_string(),
            path: "crates/boundary.rs".to_string(),
            symbol: "host".to_string(),
            target: "ChioKernel::new".to_string(),
            references: 1,
        }];
        validate(root, &sites)?;
        fs::write(
            root.join("examples/new.rs"),
            "fn new_boundary() { ChioKernel::new(); }",
        )
        .map_err(|error| error.to_string())?;
        assert!(validate(root, &sites).is_err());
        fs::remove_file(root.join("examples/new.rs")).map_err(|error| error.to_string())?;
        fs::write(&path, "fn host() { unrelated(); }").map_err(|error| error.to_string())?;
        assert!(validate(root, &sites).is_err());
        Ok(())
    }
}
