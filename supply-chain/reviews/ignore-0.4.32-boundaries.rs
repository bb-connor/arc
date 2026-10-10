//! Package-review probes. Run against the exact registry release and repaired source.
use ignore::{WalkBuilder, WalkState, gitignore::GitignoreBuilder};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "chio-ignore-review-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).unwrap();
        Self(root)
    }
    fn write(&self, path: &str, text: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fn walker(&self) -> WalkBuilder {
        let mut builder = WalkBuilder::new(&self.0);
        builder
            .parents(false)
            .git_global(false)
            .git_exclude(false)
            .require_git(false)
            .threads(3);
        builder
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn serial(root: &Path, builder: &WalkBuilder) -> BTreeSet<PathBuf> {
    builder
        .build()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.error().is_none());
            entry.path().strip_prefix(root).unwrap().to_path_buf()
        })
        .collect()
}

fn parallel(root: &Path, builder: &WalkBuilder) -> BTreeSet<PathBuf> {
    let paths = Arc::new(Mutex::new(BTreeSet::new()));
    builder.build_parallel().run(|| {
        let paths = paths.clone();
        Box::new(move |entry| {
            let entry = entry.unwrap();
            assert!(entry.error().is_none());
            paths
                .lock()
                .unwrap()
                .insert(entry.path().strip_prefix(root).unwrap().to_path_buf());
            WalkState::Continue
        })
    });
    Arc::try_unwrap(paths).unwrap().into_inner().unwrap()
}

#[test]
fn malformed_rule_reports_error_and_retains_valid_rules() {
    let tree = Tree::new();
    tree.write(".gitignore", "*.secret\n[\n!public.secret\n");
    let mut builder = GitignoreBuilder::new(&tree.0);
    builder.allow_unclosed_class(false);
    assert!(builder.add(tree.0.join(".gitignore")).is_some());
    let matcher = builder.build().unwrap();
    assert!(
        matcher
            .matched(tree.0.join("private.secret"), false)
            .is_ignore()
    );
    assert!(
        matcher
            .matched(tree.0.join("public.secret"), false)
            .is_whitelist()
    );
}

#[test]
fn anchoring_directory_only_and_escaped_literals() {
    let tree = Tree::new();
    let mut builder = GitignoreBuilder::new(&tree.0);
    for line in ["/root-only", "cache/", "\\#literal", "\\!literal"] {
        builder.add_line(None, line).unwrap();
    }
    let matcher = builder.build().unwrap();
    assert!(matcher.matched(tree.0.join("root-only"), false).is_ignore());
    assert!(
        matcher
            .matched(tree.0.join("nested/root-only"), false)
            .is_none()
    );
    assert!(
        matcher
            .matched(tree.0.join("nested/cache"), true)
            .is_ignore()
    );
    assert!(
        matcher
            .matched(tree.0.join("nested/cache"), false)
            .is_none()
    );
    for name in ["#literal", "!literal"] {
        assert!(matcher.matched(tree.0.join(name), false).is_ignore());
    }
}

#[test]
fn serial_parallel_and_incremental_agree_on_pruned_parent() {
    let tree = Tree::new();
    tree.write(
        ".gitignore",
        "blocked/\n!blocked/keep.txt\n*.secret\n!public.secret\n",
    );
    for name in [
        "blocked/keep.txt",
        "private.secret",
        "public.secret",
        "nested/ok.txt",
        ".hidden",
    ] {
        tree.write(name, "x");
    }
    let builder = tree.walker();
    let paths = serial(&tree.0, &builder);
    assert_eq!(paths, parallel(&tree.0, &builder));
    assert_eq!(
        paths,
        ["", "public.secret", "nested", "nested/ok.txt"]
            .map(PathBuf::from)
            .into_iter()
            .collect()
    );
    let mut matcher = builder.build_matchers().remove(0);
    assert!(matcher.matched("blocked/keep.txt", false).is_ignore());
    assert!(matcher.matched("private.secret", false).is_ignore());
    assert!(matcher.matched("public.secret", false).is_whitelist());
}

#[test]
fn incremental_normalization_and_cached_rules_are_explicit() {
    let tree = Tree::new();
    tree.write(".gitignore", "old\n");
    let mut matcher = tree.walker().build_matchers().remove(0);
    assert_eq!(
        matcher.normalize(tree.0.join("a/../old")),
        Some(PathBuf::from("old"))
    );
    assert_eq!(matcher.normalize(tree.0.join("../outside")), None);
    assert!(matcher.matched("", true).is_none());
    assert!(matcher.matched("old", false).is_ignore());
    tree.write(".gitignore", "new\n");
    assert!(matcher.matched("old", false).is_ignore());
    let mut fresh = tree.walker().build_matchers().remove(0);
    assert!(fresh.matched("old", false).is_none());
    assert!(fresh.matched("new", false).is_ignore());
}

#[cfg(unix)]
#[test]
fn symlinks_require_explicit_descent_and_loops_report_errors() {
    let tree = Tree::new();
    let outside = Tree::new();
    outside.write("outside.txt", "x");
    std::os::unix::fs::symlink(&outside.0, tree.0.join("link")).unwrap();
    let mut builder = tree.walker();
    let paths = serial(&tree.0, &builder);
    assert_eq!(paths, parallel(&tree.0, &builder));
    assert!(paths.contains(Path::new("link")));
    assert!(!paths.contains(Path::new("link/outside.txt")));
    builder.follow_links(true);
    let paths = serial(&tree.0, &builder);
    assert_eq!(paths, parallel(&tree.0, &builder));
    assert!(paths.contains(Path::new("link/outside.txt")));
    std::os::unix::fs::symlink(&tree.0, tree.0.join("loop")).unwrap();
    assert!(builder.build().any(|entry| matches!(entry, Err(ignore::Error::WithDepth { err, .. }) if matches!(*err, ignore::Error::Loop { .. }))));
    let errors = Arc::new(AtomicUsize::new(0));
    builder.build_parallel().run(|| {
        let errors = errors.clone();
        Box::new(move |entry| {
            if entry.is_err() {
                errors.fetch_add(1, Ordering::Relaxed);
            }
            WalkState::Continue
        })
    });
    assert_eq!(errors.load(Ordering::Relaxed), 1);
}

#[test]
fn file_size_limit_keeps_custom_filter_effective() {
    let tree = Tree::new();
    tree.write("denied", "x");
    tree.write("allowed", "x");
    tree.write("large", "too large");
    let mut builder = tree.walker();
    builder
        .max_filesize(Some(2))
        .filter_entry(|entry| entry.file_name() != "denied");
    let expected = ["", "allowed"].map(PathBuf::from).into_iter().collect();
    assert_eq!(parallel(&tree.0, &builder), expected);
    assert_eq!(serial(&tree.0, &builder), expected);
}

#[cfg(unix)]
#[test]
fn hidden_names_ending_in_dots_remain_hidden() {
    let tree = Tree::new();
    for name in [".hidden.", ".hidden..", "visible.", "visible.."] {
        tree.write(name, "x");
    }
    let expected = ["", "visible.", "visible.."]
        .map(PathBuf::from)
        .into_iter()
        .collect();
    assert_eq!(serial(&tree.0, &tree.walker()), expected);
    assert_eq!(parallel(&tree.0, &tree.walker()), expected);
    let mut matcher = tree.walker().build_matchers().remove(0);
    assert!(matcher.matched(".hidden.", false).is_ignore());
    assert!(matcher.matched(".hidden..", false).is_ignore());
}
