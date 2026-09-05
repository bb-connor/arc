use super::*;

#[test]
fn runtime_components_share_the_traversal_budget() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let first = root.path().join("bin");
    let second = root.path().join("lib");
    fs::create_dir(&first)?;
    fs::create_dir(&second)?;
    fs::write(first.join("tool"), b"tool")?;
    fs::write(second.join("library"), b"library")?;
    let mut builder = RuntimeMountSpecBuilder::default();
    // Earlier components have consumed all but one entry of the shared budget.
    let mut visited = 19_999;
    assert!(builder.add_tree_dependencies_with_count(&first, &mut visited).is_ok());
    assert!(builder.add_tree_dependencies_with_count(&second, &mut visited)
        .is_err_and(|error| error.contains("entry bound")));
    Ok(())
}
