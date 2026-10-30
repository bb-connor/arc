//! Identical generated type bodies across the chio-wire/v1 modules.
//!
//! Two struct-with-fields or enum items are identical when they render the
//! same after their own name and doc comments are removed and every type path
//! that names a generated type is qualified by its module. Different schemas
//! can produce identical Rust (validation-only keywords, narrowing branches),
//! so [`alias_duplicate_types`] keeps the first item of each group and turns
//! the rest into `pub type` aliases of it, dropping the alias's own impls.
//! [`duplicate_groups`] lists the groups that remain.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit_mut::VisitMut;

type Qualified = (String, String);

struct Names {
    declared: BTreeMap<String, BTreeSet<String>>,
    aliases: BTreeMap<Qualified, Qualified>,
}

impl Names {
    fn resolve(&self, module: &str, name: &str) -> Option<Qualified> {
        let mut current = (module.to_string(), name.to_string());
        if !self.declared.get(module)?.contains(name) {
            return None;
        }
        while let Some(next) = self.aliases.get(&current) {
            current = next.clone();
        }
        Some(current)
    }
}

struct Qualify<'a> {
    module: &'a str,
    names: &'a Names,
}

impl VisitMut for Qualify<'_> {
    fn visit_type_path_mut(&mut self, node: &mut syn::TypePath) {
        syn::visit_mut::visit_type_path_mut(self, node);
        if node.qself.is_some() {
            return;
        }
        let segments: Vec<String> = node
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let target = match segments.as_slice() {
            [name] => self.names.resolve(self.module, name),
            [first, module, name] if first == "super" => self.names.resolve(module, name),
            _ => None,
        };
        if let Some((module, name)) = target {
            let arguments = node
                .path
                .segments
                .last()
                .map(|segment| segment.arguments.clone())
                .unwrap_or_default();
            let Ok(mut path) = syn::parse_str::<syn::Path>(&format!("{module}::{name}")) else {
                return;
            };
            if let Some(last) = path.segments.last_mut() {
                last.arguments = arguments;
            }
            node.path = path;
        }
    }
}

fn strip_docs(attrs: &mut Vec<syn::Attribute>) {
    attrs.retain(|attr| !attr.path().is_ident("doc"));
}

fn normalized(item: &syn::Item, module: &str, names: &Names) -> Option<(String, String)> {
    let mut item = match item {
        syn::Item::Struct(item) if matches!(item.fields, syn::Fields::Named(_)) => {
            syn::Item::Struct(item.clone())
        }
        syn::Item::Enum(item) => syn::Item::Enum(item.clone()),
        _ => return None,
    };
    let name = match &mut item {
        syn::Item::Struct(item) => {
            let name = item.ident.to_string();
            item.ident = syn::Ident::new("Type", item.ident.span());
            strip_docs(&mut item.attrs);
            for field in item.fields.iter_mut() {
                strip_docs(&mut field.attrs);
            }
            name
        }
        syn::Item::Enum(item) => {
            let name = item.ident.to_string();
            item.ident = syn::Ident::new("Type", item.ident.span());
            strip_docs(&mut item.attrs);
            for variant in &mut item.variants {
                strip_docs(&mut variant.attrs);
            }
            name
        }
        _ => return None,
    };
    Qualify { module, names }.visit_item_mut(&mut item);
    let body = prettyplease::unparse(&syn::File {
        shebang: None,
        attrs: Vec::new(),
        items: vec![item],
    });
    Some((name, body))
}

fn modules(file: &syn::File) -> Vec<(String, &Vec<syn::Item>)> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) => module
                .content
                .as_ref()
                .map(|(_, items)| (module.ident.to_string(), items)),
            _ => None,
        })
        .collect()
}

fn declared(file: &syn::File) -> BTreeMap<String, BTreeSet<String>> {
    modules(file)
        .into_iter()
        .map(|(module, items)| {
            let names = items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Struct(item) => Some(item.ident.to_string()),
                    syn::Item::Enum(item) => Some(item.ident.to_string()),
                    syn::Item::Type(item) => Some(item.ident.to_string()),
                    _ => None,
                })
                .collect();
            (module, names)
        })
        .collect()
}

fn groups(file: &syn::File, names: &Names) -> Vec<Vec<Qualified>> {
    let mut bodies: BTreeMap<String, Vec<Qualified>> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for (module, items) in modules(file) {
        for item in items {
            if let Some((name, body)) = normalized(item, &module, names) {
                let entry = bodies.entry(body.clone()).or_default();
                if entry.is_empty() {
                    order.push(body);
                }
                entry.push((module.clone(), name));
            }
        }
    }
    order
        .into_iter()
        .filter_map(|body| bodies.remove(&body))
        .filter(|group| group.len() > 1)
        .collect()
}

fn names_type(ty: &syn::Type, name: &str) -> bool {
    matches!(ty, syn::Type::Path(path)
        if path.qself.is_none() && path.path.is_ident(name))
}

fn impl_mentions(item: &syn::ItemImpl, name: &str) -> bool {
    if names_type(&item.self_ty, name) {
        return true;
    }
    let Some((_, trait_path, _)) = &item.trait_ else {
        return false;
    };
    trait_path.segments.iter().any(|segment| {
        let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
            return false;
        };
        arguments.args.iter().any(|argument| match argument {
            syn::GenericArgument::Type(ty) => {
                names_type(ty, name)
                    || matches!(ty, syn::Type::Reference(reference) if names_type(&reference.elem, name))
            }
            _ => false,
        })
    })
}

/// Turns every item but the first of each identical group into an alias of
/// that first item, until no group is left.
pub(crate) fn alias_duplicate_types(file: &mut syn::File) {
    let mut names = Names {
        declared: declared(file),
        aliases: BTreeMap::new(),
    };
    loop {
        let found = groups(file, &names);
        if found.is_empty() {
            return;
        }
        let mut replace: BTreeMap<Qualified, Qualified> = BTreeMap::new();
        for group in found {
            let Some((canonical, rest)) = group.split_first() else {
                continue;
            };
            for duplicate in rest {
                replace.insert(duplicate.clone(), canonical.clone());
            }
        }
        for item in &mut file.items {
            let syn::Item::Mod(module) = item else {
                continue;
            };
            let module_name = module.ident.to_string();
            let Some((_, items)) = &mut module.content else {
                continue;
            };
            let aliased: Vec<(String, Qualified)> = replace
                .iter()
                .filter(|((module, _), _)| *module == module_name)
                .map(|((_, name), target)| (name.clone(), target.clone()))
                .collect();
            if aliased.is_empty() {
                continue;
            }
            items.retain(|item| match item {
                syn::Item::Impl(item) => !aliased.iter().any(|(name, _)| impl_mentions(item, name)),
                _ => true,
            });
            for item in items.iter_mut() {
                let ident = match item {
                    syn::Item::Struct(item) => item.ident.to_string(),
                    syn::Item::Enum(item) => item.ident.to_string(),
                    _ => continue,
                };
                let Some((_, (target_module, target_name))) =
                    aliased.iter().find(|(name, _)| *name == ident)
                else {
                    continue;
                };
                let source = if *target_module == module_name {
                    format!("pub type {ident} = {target_name};")
                } else {
                    format!("pub type {ident} = super::{target_module}::{target_name};")
                };
                if let Ok(alias) = syn::parse_str::<syn::Item>(&source) {
                    *item = alias;
                }
            }
        }
        names.aliases.extend(replace);
    }
}

/// Groups of identical items, as `module::Name` lists.
pub(crate) fn duplicate_groups(file: &syn::File) -> Vec<String> {
    let names = Names {
        declared: declared(file),
        aliases: BTreeMap::new(),
    };
    groups(file, &names)
        .into_iter()
        .map(|group| {
            group
                .into_iter()
                .map(|(module, name)| format!("{module}::{name}"))
                .collect::<Vec<_>>()
                .join(" = ")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_bodies_become_aliases_of_the_first() {
        let mut file: syn::File = syn::parse_quote! {
            pub mod shared {
                pub struct Table { pub fd: i64 }
            }
            pub mod a {
                pub struct Variant0 { pub fd: i64 }
                impl ::std::convert::From<&Variant0> for Variant0 {
                    fn from(value: &Variant0) -> Self { value.clone() }
                }
                pub struct Holder { pub value: Variant0 }
            }
            pub mod b {
                pub struct Other { pub fd: i64 }
                pub struct Holder { pub value: Other }
            }
        };
        alias_duplicate_types(&mut file);
        let rendered = prettyplease::unparse(&file);
        assert!(rendered.contains("pub type Variant0 = super::shared::Table;"));
        assert!(rendered.contains("pub type Other = super::shared::Table;"));
        assert!(rendered.contains("pub type Holder = super::a::Holder;"));
        assert!(!rendered.contains("From<&Variant0>"));
        assert!(duplicate_groups(&file).is_empty());
    }

    #[test]
    fn same_local_name_in_different_modules_is_not_a_duplicate() {
        let file: syn::File = syn::parse_quote! {
            pub mod a {
                pub struct Inner { pub x: i64 }
                pub struct Outer { pub inner: Inner }
            }
            pub mod b {
                pub struct Inner { pub y: String }
                pub struct Outer { pub inner: Inner }
            }
        };
        assert!(duplicate_groups(&file).is_empty());
    }
}
