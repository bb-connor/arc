use std::collections::BTreeSet;

use crate::computer::validation::{
    checked_transfer_size, content, generation, hash, identifier, namespace, operations, profiles,
    shape,
};
use crate::computer::{
    digest, refuse, wire_bound, ComputerDescription, ContentRef, DescriptionError, SchemaShape,
    MAX_DESCRIPTION_BYTES, MAX_TRANSFER_BYTES,
};

use super::*;

const PROGRAM_DOMAIN: &str = "chio.computer.program.v1";
const OCCURRENCE_DOMAIN: &str = "chio.computer.occurrence.v1";
const COMPILED_DOMAIN: &str = "chio.computer.compiled.v1";

impl LeafDescriptor {
    fn fields(&self) -> (&SchemaShape, &ContentRef, &[ResourceRequirement]) {
        match self {
            Self::Task {
                input_schema,
                output_schema,
                resources,
                ..
            }
            | Self::Program {
                input_schema,
                output_schema,
                resources,
                ..
            } => (input_schema, output_schema, resources),
        }
    }
}

pub(super) fn preflight(expression: &ProgramExpr) -> Result<u64, DescriptionError> {
    let mut pending = vec![(expression, 1_usize)];
    let mut nodes = 0;
    let mut leaves = 0;
    let mut total = 0;
    while let Some((expression, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_EXPRESSION_NODES {
            return refuse("expression_nodes");
        }
        if depth > MAX_EXPRESSION_DEPTH {
            return refuse("expression_depth");
        }
        match expression {
            ProgramExpr::Parallel { items } | ProgramExpr::Sequence { items } => {
                if items.len() < 2
                    || items.len() > MAX_EXPRESSION_NODES.saturating_sub(nodes + pending.len())
                {
                    return refuse("expression_nodes");
                }
                pending.extend(items.iter().rev().map(|item| (item, depth + 1)));
            }
            ProgramExpr::Leaf { leaf } => {
                leaves += 1;
                if leaves > MAX_PROGRAM_LEAVES {
                    return refuse("leaf_count");
                }
                validate_leaf(leaf, &mut total)?;
            }
        }
    }
    Ok(total)
}

fn validate_leaf(leaf: &LeafDescriptor, total: &mut u64) -> Result<(), DescriptionError> {
    let (input, output, resources) = leaf.fields();
    shape(input, total)?;
    content(output, total)?;
    match leaf {
        LeafDescriptor::Task {
            contract,
            acceptance,
            harness_requirements,
            ..
        } => {
            content(contract, total)?;
            content(acceptance, total)?;
            profiles(harness_requirements, total)?;
            if harness_requirements.is_empty() {
                return refuse("harness_requirements");
            }
        }
        LeafDescriptor::Program {
            bundle, entrypoint, ..
        } => {
            content(bundle, total)?;
            identifier(entrypoint)?;
        }
    }
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
        operations(&resource.operations)?;
    }
    Ok(())
}

fn normalize(expression: &ProgramExpr) -> ProgramExpr {
    match expression {
        ProgramExpr::Leaf { .. } => expression.clone(),
        ProgramExpr::Parallel { items } | ProgramExpr::Sequence { items } => {
            let parallel = matches!(expression, ProgramExpr::Parallel { .. });
            let mut normalized = Vec::new();
            for item in items {
                match normalize(item) {
                    ProgramExpr::Parallel { items } if parallel => normalized.extend(items),
                    ProgramExpr::Sequence { items } if !parallel => normalized.extend(items),
                    item => normalized.push(item),
                }
            }
            if parallel {
                ProgramExpr::Parallel { items: normalized }
            } else {
                ProgramExpr::Sequence { items: normalized }
            }
        }
    }
}

struct Compiler<'a> {
    computer: &'a ComputerDescription,
    request_id: &'a str,
    program_digest: &'a str,
    occurrences: Vec<ProgramOccurrence>,
    edges: usize,
}

impl Compiler<'_> {
    fn walk(
        &mut self,
        expression: &ProgramExpr,
        path: &[usize],
        input: &SchemaShape,
        parents: &[String],
    ) -> Result<(SchemaShape, Vec<String>), DescriptionError> {
        match expression {
            ProgramExpr::Leaf { leaf } => {
                let (required_input, output, resources) = leaf.fields();
                if input != required_input {
                    return refuse("input_schema");
                }
                if parents.len() > 16 {
                    return refuse("parent_count");
                }
                self.edges += parents.len();
                if self.edges > MAX_DEPENDENCY_EDGES {
                    return refuse("dependency_edges");
                }
                for required in resources {
                    let Some(binding) = self
                        .computer
                        .revision
                        .resources
                        .iter()
                        .find(|binding| binding.namespace == required.namespace)
                    else {
                        return refuse("resource_subset");
                    };
                    if binding.resource_id != required.resource_id
                        || binding.owner_domain != required.owner_domain
                        || binding.generation != required.generation
                        || required
                            .operations
                            .iter()
                            .any(|operation| !binding.operations.contains(operation))
                    {
                        return refuse("resource_subset");
                    }
                }
                let occurrence_id = digest(
                    OCCURRENCE_DOMAIN,
                    &serde_json::json!({
                        "requestId": self.request_id,
                        "computerId": self.computer.record.computer_id,
                        "ownerDomain": self.computer.record.owner_domain,
                        "revisionId": self.computer.revision.revision_id,
                        "programDigest": self.program_digest,
                        "path": path,
                    }),
                )?;
                self.occurrences.push(ProgramOccurrence {
                    occurrence_id: occurrence_id.clone(),
                    path: path.to_vec(),
                    parents: parents.to_vec(),
                    leaf: leaf.as_ref().clone(),
                });
                Ok((
                    SchemaShape::Value {
                        schema: output.clone(),
                    },
                    vec![occurrence_id],
                ))
            }
            ProgramExpr::Parallel { items } => {
                let mut schemas = Vec::new();
                let mut outputs = Vec::new();
                for (index, item) in items.iter().enumerate() {
                    let mut child_path = path.to_vec();
                    child_path.push(index);
                    let (shape, terminal) = self.walk(item, &child_path, input, parents)?;
                    match shape {
                        SchemaShape::Value { schema } => schemas.push(schema),
                        SchemaShape::AllSuccess { schemas: child } => schemas.extend(child),
                    }
                    outputs.extend(terminal);
                    if schemas.len() > 16 {
                        return refuse("parent_count");
                    }
                }
                Ok((SchemaShape::AllSuccess { schemas }, outputs))
            }
            ProgramExpr::Sequence { items } => {
                let mut shape = input.clone();
                let mut terminal = parents.to_vec();
                for (index, item) in items.iter().enumerate() {
                    let mut child_path = path.to_vec();
                    child_path.push(index);
                    (shape, terminal) = self.walk(item, &child_path, &shape, &terminal)?;
                }
                Ok((shape, terminal))
            }
        }
    }
}

pub fn compile_program(
    computer: &ComputerDescription,
    request_id: &str,
    expression: &ProgramExpr,
) -> Result<CheckedProgram, DescriptionError> {
    identifier(request_id)?;
    let total = preflight(expression)?;
    if checked_transfer_size(computer)?
        .checked_add(total)
        .is_none_or(|size| size > MAX_TRANSFER_BYTES)
    {
        return refuse("transfer_bytes");
    }
    wire_bound(&(computer, request_id, expression), MAX_DESCRIPTION_BYTES)?;
    let expression = normalize(expression);
    let program_digest = digest(PROGRAM_DOMAIN, &expression)?;
    let mut compiler = Compiler {
        computer,
        request_id,
        program_digest: &program_digest,
        occurrences: Vec::new(),
        edges: 0,
    };
    let (output_schema, _) =
        compiler.walk(&expression, &[], &computer.revision.input_schema, &[])?;
    let occurrences = compiler.occurrences;
    let mut description = CompiledDescription {
        schema: COMPILED_DESCRIPTION_SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
        computer_id: computer.record.computer_id.clone(),
        owner_domain: computer.record.owner_domain.clone(),
        revision_id: computer.revision.revision_id.clone(),
        lifecycle_generation: computer.record.lifecycle_generation,
        program_digest,
        expression,
        occurrences,
        output_schema,
        digest: String::new(),
    };
    let mut value =
        serde_json::to_value(&description).map_err(|_| DescriptionError { code: "canonical" })?;
    if let Some(object) = value.as_object_mut() {
        object.remove("digest");
    }
    description.digest = digest(COMPILED_DOMAIN, &value)?;
    wire_bound(&description, MAX_COMPILED_BYTES)?;
    Ok(CheckedProgram(description))
}

pub fn validate_compiled_program(
    computer: &ComputerDescription,
    request_id: &str,
    expression: &ProgramExpr,
    supplied: &CompiledDescription,
) -> Result<CheckedProgram, DescriptionError> {
    if supplied.schema != COMPILED_DESCRIPTION_SCHEMA {
        return refuse("description_schema");
    }
    identifier(&supplied.request_id)?;
    identifier(&supplied.computer_id)?;
    identifier(&supplied.owner_domain)?;
    hash(&supplied.revision_id)?;
    hash(&supplied.program_digest)?;
    hash(&supplied.digest)?;
    generation(supplied.lifecycle_generation)?;
    shape(&supplied.output_schema, &mut 0)?;
    preflight(&supplied.expression)?;
    if supplied.occurrences.len() > MAX_PROGRAM_LEAVES {
        return refuse("leaf_count");
    }
    let mut total = 0;
    for occurrence in &supplied.occurrences {
        if occurrence.parents.len() > 16
            || occurrence.path.len() > MAX_EXPRESSION_DEPTH
            || occurrence
                .path
                .iter()
                .any(|index| *index >= MAX_EXPRESSION_NODES)
        {
            return refuse("plan_bounds");
        }
        hash(&occurrence.occurrence_id)?;
        for parent in &occurrence.parents {
            hash(parent)?;
        }
        validate_leaf(&occurrence.leaf, &mut total)?;
    }
    wire_bound(supplied, MAX_COMPILED_BYTES)?;
    let checked = compile_program(computer, request_id, expression)?;
    if checked.description() != supplied {
        return refuse("compiled_mismatch");
    }
    Ok(checked)
}
