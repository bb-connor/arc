use std::collections::BTreeSet;

use super::*;

const NAMESPACE_DOMAIN: &str = "chio.computer.namespace.v1";
const REVISION_DOMAIN: &str = "chio.computer.revision.v1";

pub(crate) fn identifier(value: &str) -> Result<(), DescriptionError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return refuse("identifier");
    }
    Ok(())
}

pub(crate) fn hash(value: &str) -> Result<(), DescriptionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return refuse("digest_format");
    }
    Ok(())
}

pub(crate) fn generation(value: u64) -> Result<(), DescriptionError> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return refuse("generation");
    }
    Ok(())
}

pub(crate) fn namespace(value: &str) -> Result<(), DescriptionError> {
    if value.len() > 256 || !value.starts_with('/') || value == "/" {
        return refuse("namespace");
    }
    for segment in value.split('/').skip(1) {
        if segment == "." || segment == ".." || identifier(segment).is_err() {
            return refuse("namespace");
        }
    }
    Ok(())
}

pub(crate) fn content(value: &ContentRef, total: &mut u64) -> Result<(), DescriptionError> {
    identifier(&value.owner_domain)?;
    identifier(&value.artifact_id)?;
    hash(&value.sha256)?;
    *total = total
        .checked_add(value.byte_length)
        .ok_or(DescriptionError {
            code: "transfer_bytes",
        })?;
    if *total > MAX_TRANSFER_BYTES {
        return refuse("transfer_bytes");
    }
    Ok(())
}

pub(crate) fn profiles(values: &[ContentRef], total: &mut u64) -> Result<(), DescriptionError> {
    if values.len() > 64 {
        return refuse("profiles");
    }
    let mut identities = BTreeSet::new();
    for value in values {
        content(value, total)?;
        if !identities.insert((&value.owner_domain, &value.artifact_id)) {
            return refuse("duplicate_profile");
        }
    }
    Ok(())
}

pub(crate) fn shape(value: &SchemaShape, total: &mut u64) -> Result<(), DescriptionError> {
    match value {
        SchemaShape::Value { schema } => content(schema, total),
        SchemaShape::AllSuccess { schemas } => {
            if schemas.len() < 2 || schemas.len() > 16 {
                return refuse("parent_count");
            }
            for schema in schemas {
                content(schema, total)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn operations(values: &[ResourceOperation]) -> Result<(), DescriptionError> {
    if values.is_empty() || values.len() > 3 {
        return refuse("operations");
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return refuse("operations");
    }
    Ok(())
}

pub fn namespace_digest(resources: &[ResourceBinding]) -> Result<String, DescriptionError> {
    validate_resources(resources, &mut 0)?;
    digest(NAMESPACE_DOMAIN, &resources)
}

pub fn revision_digest(revision: &ComputerRevision) -> Result<String, DescriptionError> {
    validate_revision_fields(revision, &mut 0)?;
    if !revision.revision_id.is_empty() {
        hash(&revision.revision_id)?;
    }
    let mut value =
        serde_json::to_value(revision).map_err(|_| DescriptionError { code: "canonical" })?;
    if let Some(object) = value.as_object_mut() {
        object.remove("revisionId");
    }
    digest(REVISION_DOMAIN, &value)
}

fn validate_resources(
    resources: &[ResourceBinding],
    total: &mut u64,
) -> Result<(), DescriptionError> {
    if resources.len() > 256 {
        return refuse("resource_count");
    }
    let mut namespaces = BTreeSet::new();
    for resource in resources {
        namespace(&resource.namespace)?;
        if !namespaces.insert(&resource.namespace) {
            return refuse("duplicate_namespace");
        }
        identifier(&resource.resource_id)?;
        identifier(&resource.owner_domain)?;
        generation(resource.generation)?;
        content(&resource.provider, total)?;
        operations(&resource.operations)?;
        if let ResourceVersion::Pinned { content: pinned } = &resource.version {
            content(pinned, total)?;
        }
    }
    Ok(())
}

fn validate_revision_fields(
    revision: &ComputerRevision,
    total: &mut u64,
) -> Result<(), DescriptionError> {
    identifier(&revision.computer_id)?;
    identifier(&revision.owner_domain)?;
    identifier(&revision.creation_operation)?;
    hash(&revision.namespace_digest)?;
    content(&revision.boot, total)?;
    content(&revision.input, total)?;
    shape(&revision.input_schema, total)?;
    profiles(&revision.profile_refs, total)?;
    validate_resources(&revision.resources, total)
}

pub fn validate_computer(description: &ComputerDescription) -> Result<(), DescriptionError> {
    checked_transfer_size(description).map(|_| ())
}

pub(crate) fn checked_transfer_size(
    description: &ComputerDescription,
) -> Result<u64, DescriptionError> {
    if description.schema != COMPUTER_DESCRIPTION_SCHEMA {
        return refuse("description_schema");
    }
    let record = &description.record;
    let revision = &description.revision;
    let image = &description.image;
    identifier(&record.computer_id)?;
    identifier(&record.owner_domain)?;
    generation(record.lifecycle_generation)?;
    hash(&record.head_revision)?;
    if let Some(parent) = &record.parent_revision {
        hash(parent)?;
    }
    let mut total = 0;
    profiles(&record.profile_refs, &mut total)?;
    validate_revision_fields(revision, &mut total)?;
    hash(&revision.revision_id)?;
    hash(&image.revision_id)?;
    hash(&image.resource_manifest_digest)?;
    content(&image.boot, &mut total)?;
    content(&image.input, &mut total)?;
    profiles(&image.requirements, &mut total)?;
    if record.computer_id != revision.computer_id
        || record.owner_domain != revision.owner_domain
        || record.head_revision != revision.revision_id
        || record.profile_refs != revision.profile_refs
        || image.revision_id != revision.revision_id
        || image.boot != revision.boot
        || image.input != revision.input
        || image.resource_manifest_digest != revision.namespace_digest
    {
        return refuse("revision_binding");
    }
    if image
        .requirements
        .iter()
        .any(|profile| !revision.profile_refs.contains(profile))
    {
        return refuse("profile_subset");
    }
    if revision.namespace_digest != namespace_digest(&revision.resources)? {
        return refuse("namespace_digest");
    }
    if revision.revision_id != revision_digest(revision)? {
        return refuse("revision_digest");
    }
    Ok(total)
}
