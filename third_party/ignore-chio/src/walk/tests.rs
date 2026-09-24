use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::{DirEntry, WalkBuilder, WalkState};
use crate::tests::TempDir;

fn wfile<P: AsRef<Path>>(path: P, contents: &str) {
    let mut file = File::create(path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
}

fn wfile_size<P: AsRef<Path>>(path: P, size: u64) {
    let file = File::create(path).unwrap();
    file.set_len(size).unwrap();
}

#[cfg(unix)]
fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) {
    use std::os::unix::fs::symlink;
    symlink(src, dst).unwrap();
}

fn mkdirp<P: AsRef<Path>>(path: P) {
    fs::create_dir_all(path).unwrap();
}

fn normal_path(unix: &str) -> String {
    if cfg!(windows) { unix.replace("\\", "/") } else { unix.to_string() }
}

fn walk_collect(prefix: &Path, builder: &WalkBuilder) -> Vec<String> {
    let mut paths = vec![];
    for result in builder.build() {
        let dent = match result {
            Err(_) => continue,
            Ok(dent) => dent,
        };
        let path = dent.path().strip_prefix(prefix).unwrap();
        if path.as_os_str().is_empty() {
            continue;
        }
        paths.push(normal_path(path.to_str().unwrap()));
    }
    paths.sort();
    paths
}

fn walk_collect_parallel(
    prefix: &Path,
    builder: &WalkBuilder,
) -> Vec<String> {
    let mut paths = vec![];
    for dent in walk_collect_entries_parallel(builder) {
        let path = dent.path().strip_prefix(prefix).unwrap();
        if path.as_os_str().is_empty() {
            continue;
        }
        paths.push(normal_path(path.to_str().unwrap()));
    }
    paths.sort();
    paths
}

fn walk_collect_entries_parallel(builder: &WalkBuilder) -> Vec<DirEntry> {
    let dents = Arc::new(Mutex::new(vec![]));
    builder.build_parallel().run(|| {
        let dents = dents.clone();
        Box::new(move |result| {
            if let Ok(dent) = result {
                dents.lock().unwrap().push(dent);
            }
            WalkState::Continue
        })
    });

    let dents = dents.lock().unwrap();
    dents.to_vec()
}

fn mkpaths(paths: &[&str]) -> Vec<String> {
    let mut paths: Vec<_> = paths.iter().map(|s| s.to_string()).collect();
    paths.sort();
    paths
}

fn tmpdir() -> TempDir {
    TempDir::new().unwrap()
}

fn assert_paths(prefix: &Path, builder: &WalkBuilder, expected: &[&str]) {
    let got = walk_collect(prefix, builder);
    assert_eq!(got, mkpaths(expected), "single threaded");
    let got = walk_collect_parallel(prefix, builder);
    assert_eq!(got, mkpaths(expected), "parallel");
}

#[test]
fn no_ignores() {
    let td = tmpdir();
    mkdirp(td.path().join("a/b/c"));
    mkdirp(td.path().join("x/y"));
    wfile(td.path().join("a/b/foo"), "");
    wfile(td.path().join("x/y/foo"), "");

    assert_paths(
        td.path(),
        &WalkBuilder::new(td.path()),
        &["x", "x/y", "x/y/foo", "a", "a/b", "a/b/foo", "a/b/c"],
    );
}

#[test]
fn custom_ignore() {
    let td = tmpdir();
    let custom_ignore = ".customignore";
    mkdirp(td.path().join("a"));
    wfile(td.path().join(custom_ignore), "foo");
    wfile(td.path().join("foo"), "");
    wfile(td.path().join("a/foo"), "");
    wfile(td.path().join("bar"), "");
    wfile(td.path().join("a/bar"), "");

    let mut builder = WalkBuilder::new(td.path());
    builder.add_custom_ignore_filename(&custom_ignore);
    assert_paths(td.path(), &builder, &["bar", "a", "a/bar"]);
}

#[test]
fn custom_ignore_exclusive_use() {
    let td = tmpdir();
    let custom_ignore = ".customignore";
    mkdirp(td.path().join("a"));
    wfile(td.path().join(custom_ignore), "foo");
    wfile(td.path().join("foo"), "");
    wfile(td.path().join("a/foo"), "");
    wfile(td.path().join("bar"), "");
    wfile(td.path().join("a/bar"), "");

    let mut builder = WalkBuilder::new(td.path());
    builder.ignore(false);
    builder.git_ignore(false);
    builder.git_global(false);
    builder.git_exclude(false);
    builder.add_custom_ignore_filename(&custom_ignore);
    assert_paths(td.path(), &builder, &["bar", "a", "a/bar"]);
}

#[test]
fn gitignore() {
    let td = tmpdir();
    mkdirp(td.path().join(".git"));
    mkdirp(td.path().join("a"));
    wfile(td.path().join(".gitignore"), "foo");
    wfile(td.path().join("foo"), "");
    wfile(td.path().join("a/foo"), "");
    wfile(td.path().join("bar"), "");
    wfile(td.path().join("a/bar"), "");

    assert_paths(
        td.path(),
        &WalkBuilder::new(td.path()),
        &["bar", "a", "a/bar"],
    );
}

#[test]
fn explicit_ignore() {
    let td = tmpdir();
    let igpath = td.path().join(".not-an-ignore");
    mkdirp(td.path().join("a"));
    wfile(&igpath, "foo");
    wfile(td.path().join("foo"), "");
    wfile(td.path().join("a/foo"), "");
    wfile(td.path().join("bar"), "");
    wfile(td.path().join("a/bar"), "");

    let mut builder = WalkBuilder::new(td.path());
    assert!(builder.add_ignore(&igpath).is_none());
    assert_paths(td.path(), &builder, &["bar", "a", "a/bar"]);
}

#[test]
fn explicit_ignore_exclusive_use() {
    let td = tmpdir();
    let igpath = td.path().join(".not-an-ignore");
    mkdirp(td.path().join("a"));
    wfile(&igpath, "foo");
    wfile(td.path().join("foo"), "");
    wfile(td.path().join("a/foo"), "");
    wfile(td.path().join("bar"), "");
    wfile(td.path().join("a/bar"), "");

    let mut builder = WalkBuilder::new(td.path());
    builder.standard_filters(false);
    assert!(builder.add_ignore(&igpath).is_none());
    assert_paths(
        td.path(),
        &builder,
        &[".not-an-ignore", "bar", "a", "a/bar"],
    );
}

#[test]
fn gitignore_parent() {
    let td = tmpdir();
    mkdirp(td.path().join(".git"));
    mkdirp(td.path().join("a"));
    wfile(td.path().join(".gitignore"), "foo");
    wfile(td.path().join("a/foo"), "");
    wfile(td.path().join("a/bar"), "");

    let root = td.path().join("a");
    assert_paths(&root, &WalkBuilder::new(&root), &["bar"]);
}

#[test]
fn max_depth() {
    let td = tmpdir();
    mkdirp(td.path().join("a/b/c"));
    wfile(td.path().join("foo"), "");
    wfile(td.path().join("a/foo"), "");
    wfile(td.path().join("a/b/foo"), "");
    wfile(td.path().join("a/b/c/foo"), "");

    let mut builder = WalkBuilder::new(td.path());
    assert_paths(
        td.path(),
        &builder,
        &["a", "a/b", "a/b/c", "foo", "a/foo", "a/b/foo", "a/b/c/foo"],
    );
    assert_paths(td.path(), builder.max_depth(Some(0)), &[]);
    assert_paths(td.path(), builder.max_depth(Some(1)), &["a", "foo"]);
    assert_paths(
        td.path(),
        builder.max_depth(Some(2)),
        &["a", "a/b", "foo", "a/foo"],
    );
}

#[test]
fn max_depth_does_not_load_unreachable_ignore_files() {
    let td = tmpdir();
    let leaf = td.path().join("leaf");
    mkdirp(&leaf);
    wfile(leaf.join(".ignore"), "{invalid\n");

    let mut builder = WalkBuilder::new(td.path());
    builder.max_depth(Some(1));
    let entry = builder
        .build()
        .find_map(|result| {
            let entry = result.unwrap();
            (entry.path() == leaf).then_some(entry)
        })
        .unwrap();

    assert!(entry.error().is_none());
    assert_paths(td.path(), &builder, &["leaf"]);
}

#[test]
fn min_depth() {
    let td = tmpdir();
    mkdirp(td.path().join("a/b/c"));
    wfile(td.path().join("foo"), "");
    wfile(td.path().join("a/foo"), "");
    wfile(td.path().join("a/b/foo"), "");
    wfile(td.path().join("a/b/c/foo"), "");

    let builder = WalkBuilder::new(td.path());
    assert_paths(
        td.path(),
        &builder,
        &["a", "a/b", "a/b/c", "foo", "a/foo", "a/b/foo", "a/b/c/foo"],
    );
    let mut builder = WalkBuilder::new(td.path());
    assert_paths(
        td.path(),
        &builder.min_depth(Some(0)),
        &["a", "a/b", "a/b/c", "foo", "a/foo", "a/b/foo", "a/b/c/foo"],
    );
    assert_paths(
        td.path(),
        &builder.min_depth(Some(1)),
        &["a", "a/b", "a/b/c", "foo", "a/foo", "a/b/foo", "a/b/c/foo"],
    );
    assert_paths(
        td.path(),
        builder.min_depth(Some(2)),
        &["a/b", "a/b/c", "a/b/c/foo", "a/b/foo", "a/foo"],
    );
    assert_paths(
        td.path(),
        builder.min_depth(Some(3)),
        &["a/b/c", "a/b/c/foo", "a/b/foo"],
    );
    assert_paths(td.path(), builder.min_depth(Some(10)), &[]);

    assert_paths(
        td.path(),
        builder.min_depth(Some(2)).max_depth(Some(1)),
        &["a/b", "a/foo"],
    );
}

#[test]
fn max_filesize() {
    let td = tmpdir();
    mkdirp(td.path().join("a/b"));
    wfile_size(td.path().join("foo"), 0);
    wfile_size(td.path().join("bar"), 400);
    wfile_size(td.path().join("baz"), 600);
    wfile_size(td.path().join("a/foo"), 600);
    wfile_size(td.path().join("a/bar"), 500);
    wfile_size(td.path().join("a/baz"), 200);

    let mut builder = WalkBuilder::new(td.path());
    assert_paths(
        td.path(),
        &builder,
        &["a", "a/b", "foo", "bar", "baz", "a/foo", "a/bar", "a/baz"],
    );
    assert_paths(
        td.path(),
        builder.max_filesize(Some(0)),
        &["a", "a/b", "foo"],
    );
    assert_paths(
        td.path(),
        builder.max_filesize(Some(500)),
        &["a", "a/b", "foo", "bar", "a/bar", "a/baz"],
    );
    assert_paths(
        td.path(),
        builder.max_filesize(Some(50000)),
        &["a", "a/b", "foo", "bar", "baz", "a/foo", "a/bar", "a/baz"],
    );
}

#[cfg(unix)] // because symlinks on windows are weird
#[test]
fn symlinks() {
    let td = tmpdir();
    mkdirp(td.path().join("a/b"));
    symlink(td.path().join("a/b"), td.path().join("z"));
    wfile(td.path().join("a/b/foo"), "");

    let mut builder = WalkBuilder::new(td.path());
    assert_paths(td.path(), &builder, &["a", "a/b", "a/b/foo", "z"]);
    assert_paths(
        td.path(),
        &builder.follow_links(true),
        &["a", "a/b", "a/b/foo", "z", "z/foo"],
    );
}

#[cfg(unix)] // because symlinks on windows are weird
#[test]
fn first_path_not_symlink() {
    let td = tmpdir();
    mkdirp(td.path().join("foo"));

    let dents = WalkBuilder::new(td.path().join("foo"))
        .build()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(1, dents.len());
    assert!(!dents[0].path_is_symlink());

    let dents = walk_collect_entries_parallel(&WalkBuilder::new(
        td.path().join("foo"),
    ));
    assert_eq!(1, dents.len());
    assert!(!dents[0].path_is_symlink());
}

#[cfg(unix)] // because symlinks on windows are weird
#[test]
fn symlink_loop() {
    let td = tmpdir();
    mkdirp(td.path().join("a/b"));
    symlink(td.path().join("a"), td.path().join("a/b/c"));

    let mut builder = WalkBuilder::new(td.path());
    assert_paths(td.path(), &builder, &["a", "a/b", "a/b/c"]);
    assert_paths(td.path(), &builder.follow_links(true), &["a", "a/b"]);
}

// It's a little tricky to test the 'same_file_system' option since
// we need an environment with more than one file system. We adopt a
// heuristic where /sys is typically a distinct volume on Linux and roll
// with that.
#[test]
#[cfg(target_os = "linux")]
fn same_file_system() {
    use super::device_num;

    // If for some reason /sys doesn't exist or isn't a directory, just
    // skip this test.
    if !Path::new("/sys").is_dir() {
        return;
    }

    // If our test directory actually isn't a different volume from /sys,
    // then this test is meaningless and we shouldn't run it.
    let td = tmpdir();
    if device_num(td.path()).unwrap() == device_num("/sys").unwrap() {
        return;
    }

    mkdirp(td.path().join("same_file"));
    symlink("/sys", td.path().join("same_file").join("alink"));

    // Create a symlink to sys and enable following symlinks. If the
    // same_file_system option doesn't work, then this probably will hit a
    // permission error. Otherwise, it should just skip over the symlink
    // completely.
    let mut builder = WalkBuilder::new(td.path());
    builder.follow_links(true).same_file_system(true);
    assert_paths(td.path(), &builder, &["same_file", "same_file/alink"]);
}

#[cfg(target_os = "linux")]
#[test]
fn no_read_permissions() {
    let dir_path = Path::new("/root");

    // There's no /etc/sudoers.d, skip the test.
    if !dir_path.is_dir() {
        return;
    }
    // We're the root, so the test won't check what we want it to.
    if fs::read_dir(&dir_path).is_ok() {
        return;
    }

    // Check that we can't descend but get an entry for the parent dir.
    let builder = WalkBuilder::new(&dir_path);
    assert_paths(dir_path.parent().unwrap(), &builder, &["root"]);
}

#[test]
fn filter() {
    let td = tmpdir();
    mkdirp(td.path().join("a/b/c"));
    mkdirp(td.path().join("x/y"));
    wfile(td.path().join("a/b/foo"), "");
    wfile(td.path().join("x/y/foo"), "");

    assert_paths(
        td.path(),
        &WalkBuilder::new(td.path()),
        &["x", "x/y", "x/y/foo", "a", "a/b", "a/b/foo", "a/b/c"],
    );

    assert_paths(
        td.path(),
        &WalkBuilder::new(td.path())
            .filter_entry(|entry| entry.file_name() != OsStr::new("a")),
        &["x", "x/y", "x/y/foo"],
    );
}

#[test]
fn empty() {
    let td = tmpdir();
    assert_paths(td.path(), &WalkBuilder::empty(), &[]);

    let empty_paths: Vec<&OsStr> = Vec::new();
    assert_paths(td.path(), &WalkBuilder::from_iter(empty_paths), &[]);
}

#[test]
fn from_iter() {
    let td = tmpdir();
    mkdirp(td.path().join("a/b/c"));
    mkdirp(td.path().join("d/e/f"));
    mkdirp(td.path().join("x/y"));
    wfile(td.path().join("a/b/foo"), "");
    wfile(td.path().join("d/e/f/foo"), "");
    wfile(td.path().join("x/y/foo"), "");

    let paths = vec![
        td.path().join("a"),
        td.path().join("d"),
        td.path().join("x"),
    ];

    assert_paths(
        td.path(),
        &WalkBuilder::from_iter(paths),
        &[
            "x",
            "x/y",
            "x/y/foo",
            "d",
            "d/e",
            "d/e/f",
            "d/e/f/foo",
            "a",
            "a/b",
            "a/b/foo",
            "a/b/c",
        ],
    );
}

// This should always panic and never hang.
//
// Ref: https://github.com/BurntSushi/ripgrep/issues/3009
#[test]
#[should_panic]
fn panic_in_parallel() {
    let td = tmpdir();
    wfile(td.path().join("foo.txt"), "");

    WalkBuilder::new(td.path())
        .threads(40)
        .build_parallel()
        .run(|| Box::new(|_| panic!("oops!")));
}

// This should always panic and never hang. The first call to the visitor
// builder is used while processing the root paths. Previously, a panic on
// the third call occurred after the first worker had already been spawned,
// leaving it waiting indefinitely for workers that were never created.
#[test]
#[should_panic(expected = "builder panic")]
fn panic_in_parallel_builder() {
    let td = tmpdir();
    wfile(td.path().join("foo.txt"), "");

    let mut builds = 0;
    WalkBuilder::new(td.path()).threads(2).build_parallel().run(|| {
        builds += 1;
        if builds == 3 {
            panic!("builder panic");
        }
        Box::new(|_| WalkState::Continue)
    });
}
