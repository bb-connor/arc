use chio_runtime_core::computer::{revision_digest, DescriptionError, SchemaShape};
use chio_runtime_core::program::{validate_compiled_program, LeafDescriptor};

use super::*;

fn replace(value: &mut Value, path: &[Value], replacement: Value) -> TestResult {
    let (last, parents) = path.split_last().ok_or("empty path")?;
    let mut current = value;
    for key in parents {
        current = if let Some(key) = key.as_str() {
            current.get_mut(key).ok_or("missing property")?
        } else {
            current
                .get_mut(usize::try_from(key.as_u64().ok_or("invalid index")?)?)
                .ok_or("missing index")?
        };
    }
    if let Some(key) = last.as_str() {
        current
            .as_object_mut()
            .ok_or("not an object")?
            .insert(key.to_owned(), replacement);
    } else {
        *current
            .get_mut(usize::try_from(last.as_u64().ok_or("invalid index")?)?)
            .ok_or("missing index")? = replacement;
    }
    Ok(())
}

#[test]
fn shared_refusals_have_exact_errors() -> TestResult {
    let fixtures = fixture()?;
    let original = fixtures.cases.first().ok_or("missing vector")?;
    let (computer, request, expression) = base()?;
    compile_program(&computer, &request, &expression)?;
    for refusal in fixtures.refusals {
        let mut computer = original.computer.clone();
        let mut expression = original.expression.clone();
        replace(
            if refusal.section == "computer" {
                &mut computer
            } else {
                &mut expression
            },
            &refusal.path,
            refusal.value,
        )?;
        let result = serde_json::from_value::<ComputerDescription>(computer)
            .map_err(|_| DescriptionError { code: "json_shape" })
            .and_then(|computer| {
                serde_json::from_value::<ProgramExpr>(expression)
                    .map_err(|_| DescriptionError { code: "json_shape" })
                    .and_then(|expression| compile_program(&computer, &request, &expression))
            });
        assert_eq!(
            result.err().map(|error| error.code),
            Some(refusal.error.as_str()),
            "{}",
            refusal.id
        );
    }
    Ok(())
}

#[test]
fn forged_plan_fields_refuse() -> TestResult {
    let (computer, request, expression) = base()?;
    let checked = compile_program(&computer, &request, &expression)?;
    for (path, replacement) in [
        (serde_json::json!(["digest"]), Value::String("0".repeat(64))),
        (
            serde_json::json!(["requestId"]),
            Value::String("other".into()),
        ),
        (
            serde_json::json!(["revisionId"]),
            Value::String("0".repeat(64)),
        ),
        (
            serde_json::json!(["ownerDomain"]),
            Value::String("other".into()),
        ),
        (serde_json::json!(["lifecycleGeneration"]), Value::from(2)),
        (
            serde_json::json!(["occurrences", 0, "occurrenceId"]),
            Value::String("0".repeat(64)),
        ),
        (
            serde_json::json!(["occurrences", 0, "path"]),
            serde_json::json!([1]),
        ),
        (
            serde_json::json!(["occurrences", 0, "parents"]),
            serde_json::json!(["0".repeat(64)]),
        ),
        (
            serde_json::json!(["occurrences", 0, "leaf", "resources", 0, "generation"]),
            Value::from(2),
        ),
    ] {
        let mut value = serde_json::to_value(checked.description())?;
        replace(
            &mut value,
            path.as_array().ok_or("invalid path")?,
            replacement,
        )?;
        let supplied = CompiledDescription::from_json(&serde_json::to_vec(&value)?)?;
        assert_eq!(
            validate_compiled_program(&computer, &request, &expression, &supplied).err(),
            Some(DescriptionError {
                code: "compiled_mismatch"
            })
        );
    }
    Ok(())
}

#[test]
fn supplied_occurrences_are_bounded_before_comparison() -> TestResult {
    let (computer, request, expression) = base()?;
    let mut supplied = compile_program(&computer, &request, &expression)?
        .description()
        .clone();
    let occurrence = supplied
        .occurrences
        .first_mut()
        .ok_or("missing occurrence")?;
    if let LeafDescriptor::Task { resources, .. } = &mut occurrence.leaf {
        *resources = vec![resources.first().ok_or("missing resource")?.clone(); 257];
    }
    assert_eq!(
        validate_compiled_program(&computer, &request, &expression, &supplied).err(),
        Some(DescriptionError {
            code: "resource_count"
        })
    );
    Ok(())
}

#[test]
fn exact_depth_nodes_leaves_and_parent_limits() -> TestResult {
    let (computer, request, leaf) = base()?;
    let mut expression = leaf.clone();
    for _ in 0..31 {
        expression = leaf.clone().pipe(expression);
    }
    assert_eq!(
        compile_program(&computer, &request, &expression)?
            .description()
            .occurrences
            .len(),
        32
    );
    assert_eq!(
        compile_program(&computer, &request, &leaf.clone().pipe(expression)).err(),
        Some(DescriptionError {
            code: "expression_depth"
        })
    );
    let mut balanced = leaf.clone();
    for _ in 0..10 {
        balanced = balanced.clone().pipe(balanced);
    }
    let maximum = compile_program(&computer, &request, &balanced)?;
    assert_eq!(maximum.description().occurrences.len(), 1024);
    assert_eq!(
        CompiledDescription::from_json(&serde_json::to_vec(maximum.description())?)?,
        *maximum.description()
    );
    assert_eq!(
        compile_program(
            &computer,
            &request,
            &ProgramExpr::Sequence {
                items: vec![leaf.clone(); 2047]
            }
        )
        .err(),
        Some(DescriptionError {
            code: "expression_nodes"
        })
    );
    assert_eq!(
        compile_program(
            &computer,
            &request,
            &ProgramExpr::Sequence {
                items: vec![leaf.clone(); 1025]
            }
        )
        .err(),
        Some(DescriptionError { code: "leaf_count" })
    );
    assert_eq!(
        compile_program(
            &computer,
            &request,
            &ProgramExpr::Parallel {
                items: vec![leaf.clone(); 16]
            }
        )?
        .description()
        .occurrences
        .len(),
        16
    );
    assert_eq!(
        compile_program(
            &computer,
            &request,
            &ProgramExpr::Parallel {
                items: vec![leaf; 17]
            }
        )
        .err(),
        Some(DescriptionError {
            code: "parent_count"
        })
    );
    Ok(())
}

fn stage(
    leaf: &ProgramExpr,
    parents: usize,
    width: usize,
) -> Result<ProgramExpr, Box<dyn std::error::Error>> {
    let mut leaf = leaf.clone();
    let ProgramExpr::Leaf { leaf: descriptor } = &mut leaf else {
        return Err("expected leaf".into());
    };
    let LeafDescriptor::Task {
        input_schema,
        output_schema,
        ..
    } = descriptor.as_mut()
    else {
        return Err("expected task".into());
    };
    *input_schema = if parents == 1 {
        SchemaShape::Value {
            schema: output_schema.clone(),
        }
    } else {
        SchemaShape::AllSuccess {
            schemas: vec![output_schema.clone(); parents],
        }
    };
    Ok(if width == 1 {
        leaf
    } else {
        ProgramExpr::Parallel {
            items: vec![leaf; width],
        }
    })
}

#[test]
fn exact_dependency_edge_limit() -> TestResult {
    let (computer, request, leaf) = base()?;
    let mut stages = vec![stage(&leaf, 1, 16)?];
    for _ in 0..15 {
        stages.push(stage(&leaf, 16, 16)?);
    }
    stages.push(stage(&leaf, 16, 15)?);
    stages.push(stage(&leaf, 15, 1)?);
    stages.push(stage(&leaf, 1, 1)?);
    let result = compile_program(
        &computer,
        &request,
        &ProgramExpr::Sequence {
            items: stages.clone(),
        },
    )?;
    assert_eq!(
        result
            .description()
            .occurrences
            .iter()
            .map(|item| item.parents.len())
            .sum::<usize>(),
        4096
    );
    stages.push(stage(&leaf, 1, 1)?);
    assert_eq!(
        compile_program(
            &computer,
            &request,
            &ProgramExpr::Sequence { items: stages }
        )
        .err(),
        Some(DescriptionError {
            code: "dependency_edges"
        })
    );
    Ok(())
}

#[test]
fn record_generation_and_namespace_identity_remain_bound() -> TestResult {
    let (mut computer, request, expression) = base()?;
    let original = compile_program(&computer, &request, &expression)?;
    computer.record.lifecycle_generation = 9_007_199_254_740_991;
    let maximum = compile_program(&computer, &request, &expression)?;
    assert_ne!(original.description().digest, maximum.description().digest);
    computer.record.lifecycle_generation += 1;
    assert_eq!(
        compile_program(&computer, &request, &expression).err(),
        Some(DescriptionError { code: "generation" })
    );
    computer.record.lifecycle_generation = 1;
    computer
        .revision
        .resources
        .first_mut()
        .ok_or("missing resource")?
        .generation = 2;
    computer.revision.revision_id = revision_digest(&computer.revision)?;
    assert_eq!(
        compile_program(&computer, &request, &expression).err(),
        Some(DescriptionError {
            code: "revision_binding"
        })
    );
    Ok(())
}

#[test]
fn revision_digest_bounds_the_excluded_placeholder() -> TestResult {
    let (computer, _, _) = base()?;
    let expected = revision_digest(&computer.revision)?;
    let mut revision = computer.revision;
    revision.revision_id.clear();
    assert_eq!(revision_digest(&revision)?, expected);
    revision.revision_id = "0".repeat(65);
    assert_eq!(
        revision_digest(&revision).err(),
        Some(DescriptionError {
            code: "digest_format"
        })
    );
    revision.revision_id = "0".repeat(8 * 1024 * 1024);
    assert_eq!(
        revision_digest(&revision).err(),
        Some(DescriptionError {
            code: "digest_format"
        })
    );
    Ok(())
}

#[test]
fn required_nullable_parent_and_nested_closed_fields() -> TestResult {
    let (computer, _, _) = base()?;
    let mut value = serde_json::to_value(&computer)?;
    ComputerDescription::from_json(&serde_json::to_vec(&value)?)?;
    value["record"]
        .as_object_mut()
        .ok_or("record")?
        .remove("parentRevision");
    assert_eq!(
        ComputerDescription::from_json(&serde_json::to_vec(&value)?).err(),
        Some(DescriptionError { code: "json_shape" })
    );
    let mut value = serde_json::to_value(&computer)?;
    value["revision"]["boot"]["extra"] = Value::Bool(true);
    assert_eq!(
        ComputerDescription::from_json(&serde_json::to_vec(&value)?).err(),
        Some(DescriptionError { code: "json_shape" })
    );
    Ok(())
}

fn pin(computer: &mut ComputerDescription) -> TestResult {
    computer.revision.namespace_digest =
        chio_runtime_core::computer::namespace_digest(&computer.revision.resources)?;
    computer.revision.revision_id = revision_digest(&computer.revision)?;
    computer
        .record
        .head_revision
        .clone_from(&computer.revision.revision_id);
    computer
        .image
        .revision_id
        .clone_from(&computer.revision.revision_id);
    computer
        .image
        .resource_manifest_digest
        .clone_from(&computer.revision.namespace_digest);
    Ok(())
}

#[test]
fn exact_resource_and_profile_limits() -> TestResult {
    let (mut computer, request, expression) = base()?;
    let original = computer
        .revision
        .resources
        .first()
        .ok_or("resource")?
        .clone();
    for index in 0..255 {
        let mut resource = original.clone();
        resource.namespace = format!("/resource-{index}");
        computer.revision.resources.push(resource);
    }
    pin(&mut computer)?;
    compile_program(&computer, &request, &expression)?;
    computer.revision.resources.push(original);
    assert_eq!(
        compile_program(&computer, &request, &expression).err(),
        Some(DescriptionError {
            code: "resource_count"
        })
    );
    let (mut computer, request, expression) = base()?;
    let original = computer
        .revision
        .profile_refs
        .first()
        .ok_or("profile")?
        .clone();
    for index in 0..63 {
        let mut profile = original.clone();
        profile.artifact_id = format!("profile-{index}");
        computer.revision.profile_refs.push(profile);
    }
    computer
        .record
        .profile_refs
        .clone_from(&computer.revision.profile_refs);
    computer
        .image
        .requirements
        .clone_from(&computer.revision.profile_refs);
    pin(&mut computer)?;
    compile_program(&computer, &request, &expression)?;
    computer.record.profile_refs.push(original);
    assert_eq!(
        compile_program(&computer, &request, &expression).err(),
        Some(DescriptionError { code: "profiles" })
    );
    Ok(())
}

#[test]
fn exact_identifier_namespace_and_transfer_limits() -> TestResult {
    let (mut computer, request, mut expression) = base()?;
    compile_program(&computer, &"a".repeat(128), &expression)?;
    for request in ["a".repeat(129), "a\n".into()] {
        assert_eq!(
            compile_program(&computer, &request, &expression).err(),
            Some(DescriptionError { code: "identifier" })
        );
    }
    let namespace = format!("/{}{}{}", "a".repeat(128), "/", "b".repeat(126));
    computer
        .revision
        .resources
        .first_mut()
        .ok_or("resource")?
        .namespace
        .clone_from(&namespace);
    let ProgramExpr::Leaf { leaf } = &mut expression else {
        return Err("expected leaf".into());
    };
    let LeafDescriptor::Task { resources, .. } = leaf.as_mut() else {
        return Err("expected task".into());
    };
    resources.first_mut().ok_or("requirement")?.namespace = namespace;
    pin(&mut computer)?;
    compile_program(&computer, &request, &expression)?;
    let ProgramExpr::Leaf { leaf } = &mut expression else {
        return Err("expected leaf".into());
    };
    let LeafDescriptor::Task { resources, .. } = leaf.as_mut() else {
        return Err("expected task".into());
    };
    resources
        .first_mut()
        .ok_or("requirement")?
        .namespace
        .push('b');
    assert_eq!(
        compile_program(&computer, &request, &expression).err(),
        Some(DescriptionError { code: "namespace" })
    );
    let (computer, request, expression) = base()?;
    let mut value = serde_json::json!([computer, expression]);
    fn zero(value: &mut Value) {
        match value {
            Value::Object(values) => {
                if values.contains_key("byteLength") {
                    values.insert("byteLength".into(), Value::from(0));
                }
                for value in values.values_mut() {
                    zero(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    zero(value);
                }
            }
            _ => {}
        }
    }
    zero(&mut value);
    let mut computer: ComputerDescription = serde_json::from_value(value[0].clone())?;
    let mut expression: ProgramExpr = serde_json::from_value(value[1].clone())?;
    pin(&mut computer)?;
    let ProgramExpr::Leaf { leaf } = &mut expression else {
        return Err("expected leaf".into());
    };
    let LeafDescriptor::Task { contract, .. } = leaf.as_mut() else {
        return Err("expected task".into());
    };
    contract.byte_length = 64 * 1024 * 1024;
    compile_program(&computer, &request, &expression)?;
    let ProgramExpr::Leaf { leaf } = &mut expression else {
        return Err("expected leaf".into());
    };
    let LeafDescriptor::Task { contract, .. } = leaf.as_mut() else {
        return Err("expected task".into());
    };
    contract.byte_length += 1;
    assert_eq!(
        compile_program(&computer, &request, &expression).err(),
        Some(DescriptionError {
            code: "transfer_bytes"
        })
    );
    Ok(())
}

#[test]
fn unsigned_integral_spellings_preserve_compiled_identity() -> TestResult {
    let (computer, request, expression) = base()?;
    let expected = compile_program(&computer, &request, &expression)?;
    let text = serde_json::to_string(&computer)?;
    for number in ["1.0", "1e0", "10e-1"] {
        let alternate = text.replace(
            "\"lifecycleGeneration\":1",
            &format!("\"lifecycleGeneration\":{number}"),
        );
        let decoded = ComputerDescription::from_json(alternate.as_bytes())?;
        assert_eq!(compile_program(&decoded, &request, &expression)?, expected);
    }
    Ok(())
}
