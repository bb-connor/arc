//! Target linkage must be declared as runtime files before it is bound.

use super::*;

#[test]
fn elf_loader_alias_requires_the_exact_declared_file() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let loader = root.path().join("loader");
    let other = root.path().join("other");
    let alias = root.path().join("interpreter");
    std::fs::write(&loader, b"loader")?;
    std::fs::write(&other, b"other")?;
    std::os::unix::fs::symlink(&loader, &alias)?;
    let declared = BTreeSet::from([loader.canonicalize()?]);
    assert!(declared_runtime_interpreter(&alias, &declared)?);
    assert!(!declared_runtime_interpreter(&alias, &BTreeSet::new())?);
    std::fs::remove_file(&alias)?;
    std::os::unix::fs::symlink(&other, &alias)?;
    assert!(!declared_runtime_interpreter(&alias, &declared)?);
    std::fs::remove_file(&alias)?;
    assert!(declared_runtime_interpreter(&alias, &declared).is_err());
    Ok(())
}

fn write_canonical(path: &Path, bytes: &[u8]) -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::fs::write(path, bytes)?;
    Ok(path.canonicalize()?)
}

fn missing_objects(error: &CliError) -> Result<String, Box<dyn std::error::Error>> {
    let message = error.to_string();
    let (_, missing) = message
        .split_once("no --runtime-file provides ")
        .ok_or_else(|| format!("refusal does not name the missing objects: {message}"))?;
    Ok(missing.to_string())
}

#[test]
fn dynamic_target_must_declare_every_needed_shared_object() -> Result<(), Box<dyn std::error::Error>>
{
    use linkage::tests::synthetic_dynamic_elf;

    let root = tempfile::tempdir()?;
    let directory = root.path().canonicalize()?;
    let loader = write_canonical(&directory.join("loader"), b"loader")?;
    let loader_text = loader.to_str().ok_or("loader path is not UTF-8")?;
    let target = write_canonical(
        &directory.join("target"),
        &synthetic_dynamic_elf(
            Some(loader_text),
            &["libchio-a.so.1", "libchio-b.so.2"],
            None,
        ),
    )?;
    let unrelated = write_canonical(&directory.join("unrelated.txt"), b"unrelated")?;
    let named = write_canonical(&directory.join("libchio-a.so.1"), b"library")?;
    let versioned = write_canonical(
        &directory.join("libchio-b.so.2.4.0"),
        &synthetic_dynamic_elf(None, &[], Some("libchio-b.so.2")),
    )?;
    let other_soname = write_canonical(
        &directory.join("libchio-b.so.2.5.0"),
        &synthetic_dynamic_elf(None, &[], Some("libchio-c.so.2")),
    )?;

    let refused = require_target_linkage_declared(
        &target,
        &BTreeSet::from([loader.clone(), unrelated.clone()]),
    )
    .err()
    .ok_or("an unrelated runtime file must not satisfy DT_NEEDED")?;
    assert!(missing_objects(&refused)?.starts_with("libchio-a.so.1, libchio-b.so.2;"));

    let refused = require_target_linkage_declared(
        &target,
        &BTreeSet::from([loader.clone(), named.clone(), other_soname]),
    )
    .err()
    .ok_or("a shared object with another DT_SONAME must not satisfy DT_NEEDED")?;
    assert!(missing_objects(&refused)?.starts_with("libchio-b.so.2;"));

    let refused = require_target_linkage_declared(
        &target,
        &BTreeSet::from([named.clone(), versioned.clone()]),
    )
    .err()
    .ok_or("an undeclared interpreter must be refused")?;
    assert!(missing_objects(&refused)?.starts_with(&format!("{loader_text};")));

    require_target_linkage_declared(&target, &BTreeSet::from([loader, named, versioned]))?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn the_test_executable_needs_every_loaded_shared_object_declared(
) -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::current_exe()?.canonicalize()?;
    let linkage::ExecutableLinkage::Dynamic {
        interpreter: Some(interpreter),
        needed,
    } = linkage::inspect_executable_linkage(&std::fs::read(&target)?)?
    else {
        return Err("the test executable is not dynamically linked".into());
    };
    assert!(needed.iter().any(|name| name == "libc.so.6"), "{needed:?}");
    let interpreter = interpreter.canonicalize()?;
    let mut loaded = BTreeSet::from([interpreter.clone()]);
    for line in std::fs::read_to_string("/proc/self/maps")?.lines() {
        let Some(path) = line.split_whitespace().nth(5).map(Path::new) else {
            continue;
        };
        let shared_object = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.contains(".so"));
        if path.is_absolute() && shared_object {
            if let Ok(canonical) = path.canonicalize() {
                loaded.insert(canonical);
            }
        }
    }

    let refused = require_target_linkage_declared(&target, &BTreeSet::from([interpreter.clone()]))
        .err()
        .ok_or("the interpreter alone must not satisfy DT_NEEDED")?;
    assert!(missing_objects(&refused)?.contains("libc.so.6"));

    let without_libc = loaded
        .iter()
        .filter(|path| path.file_name() != Some(std::ffi::OsStr::new("libc.so.6")))
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(without_libc.len() + 1, loaded.len(), "{loaded:?}");
    let refused = require_target_linkage_declared(&target, &without_libc)
        .err()
        .ok_or("an undeclared libc must be refused")?;
    assert!(missing_objects(&refused)?.starts_with("libc.so.6;"));

    require_target_linkage_declared(&target, &loaded)?;
    Ok(())
}
