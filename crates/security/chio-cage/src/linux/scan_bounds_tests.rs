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
