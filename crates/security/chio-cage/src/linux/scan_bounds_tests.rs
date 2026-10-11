use super::*;
use chio_test_support::prelude::*;
use std::os::unix::fs::symlink;

#[test]
fn read_directory_scan_refuses_excess_entries_even_when_every_child_is_skipped() {
    let tree = chio_test_support::private_tempdir().test_unwrap();
    let directory = tree.path().join("ignored-entries");
    std::fs::create_dir(&directory).test_unwrap();
    // This bounded metadata-only fixture crosses the finite scan limit by one.
    // A skipped child still costs enumeration, allocation, sorting and opening.
    for index in 0..4097 {
        symlink(
            "missing-target",
            directory.join(format!("ignored-{index:04}")),
        )
        .test_unwrap();
    }

    let result = retain_read_grants(&[directory].into_iter().collect());
    assert!(
        matches!(
            &result,
            Err(CageError::ResourceLimitExceeded("read grants"))
        ),
        "ignored entries escaped the read-directory scan budget: {result:?}"
    );
}

#[test]
fn bounded_read_directory_keeps_sorted_descendants_and_skips_symlinks() {
    let tree = chio_test_support::private_tempdir().test_unwrap();
    let directory = tree.path().join("allowed");
    let nested = directory.join("nested");
    let first = directory.join("a.data");
    let last = nested.join("z.data");
    std::fs::create_dir(&directory).test_unwrap();
    std::fs::create_dir(&nested).test_unwrap();
    std::fs::write(&first, b"first").test_unwrap();
    std::fs::write(&last, b"last").test_unwrap();
    symlink("missing-target", directory.join("ignored-link")).test_unwrap();

    let retained = retain_read_grants(&[directory.clone()].into_iter().collect()).test_unwrap();
    let paths: Vec<_> = retained
        .iter()
        .map(|resource| resource.path.clone())
        .collect();
    assert_eq!(paths, vec![directory, first, nested, last]);
}

#[test]
fn entry_budget_stops_the_name_stream_before_buffering_the_overflow_entry() {
    let pulls = std::cell::Cell::new(0);
    let source = std::iter::repeat_with(|| {
        pulls.set(pulls.get() + 1);
        b"entry".as_slice()
    });
    let mut names = Vec::new();
    let mut budget = DirectoryScanBudget::new(3, 64, "read grants");
    let failure = source.take(5).find_map(|name| {
        push_directory_name(Path::new("/fixture"), name, &mut names, &mut budget).err()
    });

    assert!(matches!(
        failure,
        Some(CageError::ResourceLimitExceeded("read grants"))
    ));
    assert_eq!(pulls.get(), 4);
    assert_eq!(names.len(), 3);
}

#[test]
fn name_byte_budget_refuses_before_copying_the_overflow_name() {
    let mut names = Vec::new();
    let mut budget = DirectoryScanBudget::new(4, 6, "read grants");
    push_directory_name(Path::new("/fixture"), b"aaaa", &mut names, &mut budget).test_unwrap();
    let result = push_directory_name(Path::new("/fixture"), b"bbbb", &mut names, &mut budget);

    assert!(matches!(
        result,
        Err(CageError::ResourceLimitExceeded("read grants"))
    ));
    assert_eq!(names, vec![std::ffi::OsString::from("aaaa")]);
}

#[test]
fn directory_collection_accepts_exact_entry_and_name_byte_bounds() {
    let tree = chio_test_support::private_tempdir().test_unwrap();
    std::fs::write(tree.path().join("aa"), b"").test_unwrap();
    std::fs::write(tree.path().join("bbb"), b"").test_unwrap();
    let directory = File::open(tree.path()).test_unwrap();
    let mut budget = DirectoryScanBudget::new(2, 5, "read grants");
    assert_eq!(
        directory_entry_names(&directory, tree.path(), &mut budget).test_unwrap(),
        vec![
            std::ffi::OsString::from("aa"),
            std::ffi::OsString::from("bbb")
        ]
    );

    let directory = File::open(tree.path()).test_unwrap();
    let mut too_few_bytes = DirectoryScanBudget::new(2, 4, "read grants");
    assert!(matches!(
        directory_entry_names(&directory, tree.path(), &mut too_few_bytes),
        Err(CageError::ResourceLimitExceeded("read grants"))
    ));
}

#[test]
fn skipped_entries_share_one_read_budget_across_declared_roots() {
    let tree = chio_test_support::private_tempdir().test_unwrap();
    let first = tree.path().join("first");
    let second = tree.path().join("second");
    for path in [&first, &second] {
        std::fs::create_dir(path).test_unwrap();
        symlink("missing", path.join("a")).test_unwrap();
        symlink("missing", path.join("b")).test_unwrap();
    }
    let root = open_root().test_unwrap();
    let mut resources = Vec::new();
    let mut visited = BTreeSet::new();
    let mut budget = DirectoryScanBudget::new(3, 32, "read grants");
    let resource = retain_existing_from_root(&root, &first, ExpectedAccess::Read).test_unwrap();
    retain_read_closure(resource, &mut resources, &mut visited, &mut budget).test_unwrap();
    let resource = retain_existing_from_root(&root, &second, ExpectedAccess::Read).test_unwrap();
    assert!(matches!(
        retain_read_closure(resource, &mut resources, &mut visited, &mut budget),
        Err(CageError::ResourceLimitExceeded("read grants"))
    ));
}

#[test]
fn vanished_entries_still_consume_the_directory_scan_budget() {
    let tree = chio_test_support::private_tempdir().test_unwrap();
    let path = tree.path().join("gone");
    std::fs::write(&path, b"").test_unwrap();
    let directory = File::open(tree.path()).test_unwrap();
    let mut budget = DirectoryScanBudget::new(1, 4, "read grants");
    let names = directory_entry_names(&directory, tree.path(), &mut budget).test_unwrap();
    std::fs::remove_file(&path).test_unwrap();
    let name = names.first().test_unwrap();
    assert!(retain_directory_entry(&directory, &path, name)
        .test_unwrap()
        .is_none());
    assert!(matches!(
        push_directory_name(tree.path(), b"next", &mut Vec::new(), &mut budget),
        Err(CageError::ResourceLimitExceeded("read grants"))
    ));
}

#[test]
fn forbidden_directory_budget_counts_skipped_entries_across_roots() {
    let tree = chio_test_support::private_tempdir().test_unwrap();
    let first = tree.path().join("first");
    let second = tree.path().join("second");
    for path in [&first, &second] {
        std::fs::create_dir(path).test_unwrap();
        symlink("missing", path.join("a")).test_unwrap();
        symlink("missing", path.join("b")).test_unwrap();
    }
    let mut scan = ForbiddenTreeScan {
        linked: &[],
        budget: DirectoryScanBudget::new(3, 32, "forbidden directory entries"),
        visited_directories: BTreeSet::new(),
    };
    scan.directory(&File::open(&first).test_unwrap(), &first, 0)
        .test_unwrap();
    assert!(matches!(
        scan.directory(&File::open(&second).test_unwrap(), &second, 0),
        Err(CageError::ResourceLimitExceeded(
            "forbidden directory entries"
        ))
    ));
}
