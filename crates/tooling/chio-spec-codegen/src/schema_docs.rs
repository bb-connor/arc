//! Removes the JSON schema copy typify embeds in every generated type's docs.
//!
//! typify 0.4.3 documents each type with its description followed by a
//! `<details>` block holding the pretty-printed source schema. The schemas
//! under `spec/schemas` are the source of truth, so the copy only doubles the
//! size of the bindings. Descriptions and field docs are kept.

use syn::visit_mut::VisitMut;

const DETAILS_OPEN: &str = "<details><summary>JSON schema</summary>";
const DETAILS_CLOSE: &str = "</details>";

pub(crate) fn strip_schema_docs(file: &mut syn::File) {
    SchemaDocs.visit_file_mut(file);
}

struct SchemaDocs;

impl VisitMut for SchemaDocs {
    fn visit_item_struct_mut(&mut self, item: &mut syn::ItemStruct) {
        strip(&mut item.attrs);
        syn::visit_mut::visit_item_struct_mut(self, item);
    }

    fn visit_item_enum_mut(&mut self, item: &mut syn::ItemEnum) {
        strip(&mut item.attrs);
        syn::visit_mut::visit_item_enum_mut(self, item);
    }

    fn visit_item_type_mut(&mut self, item: &mut syn::ItemType) {
        strip(&mut item.attrs);
        syn::visit_mut::visit_item_type_mut(self, item);
    }
}

fn doc_text(attr: &syn::Attribute) -> Option<String> {
    let syn::Meta::NameValue(meta) = &attr.meta else {
        return None;
    };
    if !meta.path.is_ident("doc") {
        return None;
    }
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(text),
        ..
    }) = &meta.value
    else {
        return None;
    };
    Some(text.value())
}

fn is_doc(attr: &syn::Attribute, expected: &str) -> bool {
    doc_text(attr).is_some_and(|text| text.trim() == expected)
}

fn strip(attrs: &mut Vec<syn::Attribute>) {
    while let Some(open) = attrs.iter().position(|attr| is_doc(attr, DETAILS_OPEN)) {
        let Some(close) = attrs[open..]
            .iter()
            .position(|attr| is_doc(attr, DETAILS_CLOSE))
            .map(|offset| open + offset)
        else {
            return;
        };
        let start = if open > 0 && is_doc(&attrs[open - 1], "") {
            open - 1
        } else {
            open
        };
        attrs.drain(start..=close);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docs(item: &syn::ItemStruct) -> Vec<String> {
        item.attrs.iter().filter_map(doc_text).collect()
    }

    #[test]
    fn removes_schema_block_and_its_separator() -> syn::Result<()> {
        let mut file: syn::File = syn::parse_str(
            r#"
            #[doc = "`Thing`"]
            #[doc = ""]
            #[doc = " <details><summary>JSON schema</summary>"]
            #[doc = ""]
            #[doc = " ```json"]
            #[doc = "{"]
            #[doc = "  \"type\": \"object\""]
            #[doc = "}"]
            #[doc = " ```"]
            #[doc = " </details>"]
            #[derive(Clone)]
            pub struct Thing {
                #[doc = "Kept."]
                pub field: u8,
            }
            "#,
        )?;
        strip_schema_docs(&mut file);
        let Some(syn::Item::Struct(item)) = file.items.first() else {
            panic!("expected a struct");
        };
        assert_eq!(docs(item), vec!["`Thing`".to_owned()]);
        assert_eq!(item.attrs.len(), 2);
        let field_docs: Vec<String> = item
            .fields
            .iter()
            .flat_map(|field| field.attrs.iter().filter_map(doc_text))
            .collect();
        assert_eq!(field_docs, vec!["Kept.".to_owned()]);
        Ok(())
    }

    #[test]
    fn unterminated_block_is_left_in_place() -> syn::Result<()> {
        let mut file: syn::File = syn::parse_str(
            r#"
            #[doc = " <details><summary>JSON schema</summary>"]
            #[doc = "{"]
            pub struct Open;
            "#,
        )?;
        strip_schema_docs(&mut file);
        let Some(syn::Item::Struct(item)) = file.items.first() else {
            panic!("expected a struct");
        };
        assert_eq!(item.attrs.len(), 2);
        Ok(())
    }
}
