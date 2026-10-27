//! `cargo xtask check web3-free-closure`: per-root dependency closure gate.
//!
//! Each root named in `ci-gates/web3-free-closure.toml` is resolved on its own
//! with default features (`cargo tree -p <root> -e normal,features`), so the
//! check sees the graph a `cargo build -p <root>` links rather than the
//! workspace-unified one. The closure fails if it contains a denied package or
//! enables a denied feature on any crate. Every violation names the root, the
//! denied item, the shortest inverted path from it back to the root and the
//! root's direct dependencies through which it is reached.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use crate::{display_path, workspace_root, XtaskError};

const POLICY_PATH: &str = "ci-gates/web3-free-closure.toml";
const POLICY_SCHEMA: &str = "chio.ci-gate.web3-free-closure.v1";
const TREE_FORMAT: &str = "{p} {f}";
const DEDUP_MARKER: &str = " (*)";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    schema: String,
    roots: Vec<String>,
    deny: DenyFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DenyFile {
    packages: Vec<String>,
    features: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PackagePattern {
    Exact(String),
    Prefix(String),
}

impl PackagePattern {
    fn parse(raw: &str) -> Result<Self, String> {
        let body = raw.strip_suffix('*').unwrap_or(raw);
        if body.is_empty() || body.contains('*') || !body.chars().all(is_crate_name_char) {
            return Err(format!("malformed package pattern `{raw}`"));
        }
        if raw.ends_with('*') {
            Ok(Self::Prefix(body.to_string()))
        } else {
            Ok(Self::Exact(body.to_string()))
        }
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(exact) => name == exact,
            Self::Prefix(prefix) => name.starts_with(prefix.as_str()),
        }
    }
}

fn is_crate_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

#[derive(Debug)]
pub(crate) struct Policy {
    roots: Vec<String>,
    packages: Vec<PackagePattern>,
    features: BTreeSet<String>,
}

impl Policy {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let file: PolicyFile = toml::from_str(text).map_err(|err| err.to_string())?;
        if file.schema != POLICY_SCHEMA {
            return Err(format!(
                "schema is `{}`, expected `{POLICY_SCHEMA}`",
                file.schema
            ));
        }
        let roots = unique_nonempty("roots", file.roots)?;
        for root in &roots {
            if !root.chars().all(is_crate_name_char) {
                return Err(format!("malformed root `{root}`"));
            }
        }
        let packages = unique_nonempty("deny.packages", file.deny.packages)?
            .iter()
            .map(|raw| PackagePattern::parse(raw))
            .collect::<Result<Vec<_>, _>>()?;
        let features = unique_nonempty("deny.features", file.deny.features)?;
        for feature in &features {
            if !feature.chars().all(is_crate_name_char) {
                return Err(format!("malformed feature `{feature}`"));
            }
        }
        Ok(Self {
            roots,
            packages,
            features: features.into_iter().collect(),
        })
    }

    pub(crate) fn roots(&self) -> &[String] {
        &self.roots
    }
}

fn unique_nonempty(field: &str, values: Vec<String>) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Err(format!("`{field}` is empty"));
    }
    let mut seen = BTreeSet::new();
    for value in &values {
        if value.is_empty() {
            return Err(format!("`{field}` has an empty entry"));
        }
        if !seen.insert(value.as_str()) {
            return Err(format!("`{field}` lists `{value}` twice"));
        }
    }
    Ok(values)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NodeKind {
    Package { features: Vec<String> },
    Feature { feature: String },
}

#[derive(Clone, Debug)]
struct Node {
    name: String,
    kind: NodeKind,
}

impl Node {
    fn label(&self) -> String {
        match &self.kind {
            NodeKind::Package { .. } => self.name.clone(),
            NodeKind::Feature { feature } => format!("{}/{feature}", self.name),
        }
    }
}

/// Dependency graph rebuilt from `cargo tree --prefix depth` output. Nodes are
/// packages and package features; a line elided with `(*)` adds its edge to
/// the node expanded elsewhere, so the graph is the full closure.
#[derive(Debug)]
pub(crate) struct ClosureGraph {
    nodes: Vec<Node>,
    children: Vec<Vec<usize>>,
}

impl ClosureGraph {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let mut nodes = Vec::new();
        let mut children: Vec<Vec<usize>> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut stack: Vec<usize> = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line_number = number + 1;
            if line.trim().is_empty() {
                continue;
            }
            let digits = line.chars().take_while(char::is_ascii_digit).count();
            let depth: usize = line[..digits]
                .parse()
                .map_err(|_| format!("line {line_number} has no depth prefix: `{line}`"))?;
            let body = &line[digits..];
            let body = body.strip_suffix(DEDUP_MARKER).unwrap_or(body);
            let (key, node) = parse_node(body)
                .ok_or_else(|| format!("line {line_number} is not a tree node: `{line}`"))?;
            if depth == 0 && !stack.is_empty() {
                return Err(format!("line {line_number} starts a second root: `{line}`"));
            }
            if depth > stack.len() {
                return Err(format!("line {line_number} skips a depth level: `{line}`"));
            }
            let id = match index.get(&key) {
                Some(&id) => id,
                None => {
                    let id = nodes.len();
                    nodes.push(node);
                    children.push(Vec::new());
                    index.insert(key, id);
                    id
                }
            };
            stack.truncate(depth);
            if let Some(&parent) = stack.last() {
                if !children[parent].contains(&id) {
                    children[parent].push(id);
                }
            }
            stack.push(id);
        }
        if nodes.is_empty() {
            return Err("cargo tree printed no nodes".to_string());
        }
        Ok(Self { nodes, children })
    }

    fn root_name(&self) -> &str {
        &self.nodes[0].name
    }

    fn shortest_path(&self, target: usize) -> Vec<usize> {
        let mut previous: Vec<Option<usize>> = vec![None; self.nodes.len()];
        let mut seen = vec![false; self.nodes.len()];
        let mut queue = VecDeque::from([0usize]);
        seen[0] = true;
        while let Some(current) = queue.pop_front() {
            if current == target {
                break;
            }
            for &child in &self.children[current] {
                if !seen[child] {
                    seen[child] = true;
                    previous[child] = Some(current);
                    queue.push_back(child);
                }
            }
        }
        let mut path = vec![target];
        let mut cursor = target;
        while let Some(parent) = previous[cursor] {
            path.push(parent);
            cursor = parent;
        }
        path
    }

    fn reachable_from(&self, start: usize) -> Vec<bool> {
        let mut seen = vec![false; self.nodes.len()];
        let mut queue = VecDeque::from([start]);
        seen[start] = true;
        while let Some(current) = queue.pop_front() {
            for &child in &self.children[current] {
                if !seen[child] {
                    seen[child] = true;
                    queue.push_back(child);
                }
            }
        }
        seen
    }
}

fn parse_node(body: &str) -> Option<(String, Node)> {
    if let Some((name, rest)) = body.split_once(" feature \"") {
        let feature = rest.strip_suffix('"')?;
        if name.is_empty() || name.contains(' ') || feature.is_empty() {
            return None;
        }
        let node = Node {
            name: name.to_string(),
            kind: NodeKind::Feature {
                feature: feature.to_string(),
            },
        };
        return Some((body.to_string(), node));
    }
    let mut tokens = body.split(' ');
    let name = tokens.next()?;
    let version = tokens.next()?;
    if name.is_empty() || !version.starts_with('v') {
        return None;
    }
    let mut key = format!("{name} {version}");
    let mut features = None;
    let mut open_paren = false;
    for token in tokens {
        if open_paren || token.starts_with('(') {
            key.push(' ');
            key.push_str(token);
            open_paren = !token.ends_with(')');
        } else if features.is_none() {
            features = Some(token);
        } else if !token.is_empty() {
            return None;
        }
    }
    if open_paren {
        return None;
    }
    let features = features
        .unwrap_or_default()
        .split(',')
        .filter(|feature| !feature.is_empty())
        .map(str::to_string)
        .collect();
    let node = Node {
        name: name.to_string(),
        kind: NodeKind::Package { features },
    };
    Some((key, node))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Denied {
    Package { package: String },
    Feature { package: String, feature: String },
}

impl Denied {
    fn package(&self) -> &str {
        match self {
            Self::Package { package } | Self::Feature { package, .. } => package,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) root: String,
    pub(crate) denied: Denied,
    pub(crate) inverted_path: Vec<String>,
    pub(crate) via: Vec<String>,
}

impl Violation {
    fn render(&self) -> String {
        let item = match &self.denied {
            Denied::Package { package } => format!("denied package `{package}`"),
            Denied::Feature { package, feature } => {
                format!("denied feature `{feature}` on `{package}`")
            }
        };
        format!(
            "web3-free-closure: {root}: {item}\n  path (inverted): {path}\n  via direct dependencies: {via}\n  inspect: cargo tree -p {root} -e normal,features -i {package}",
            root = self.root,
            path = self.inverted_path.join(" <- "),
            via = self.via.join(", "),
            package = self.denied.package(),
        )
    }
}

/// Evaluate one root's closure against the policy. Violations are sorted and
/// carry one entry per denied package or (package, feature) pair.
pub(crate) fn evaluate(policy: &Policy, graph: &ClosureGraph) -> Vec<Violation> {
    let mut hits: BTreeMap<Denied, usize> = BTreeMap::new();
    for (id, node) in graph.nodes.iter().enumerate() {
        match &node.kind {
            NodeKind::Package { features } => {
                if id != 0 && policy.packages.iter().any(|p| p.matches(&node.name)) {
                    hits.entry(Denied::Package {
                        package: node.name.clone(),
                    })
                    .or_insert(id);
                }
                for feature in features {
                    if policy.features.contains(feature) {
                        hits.entry(Denied::Feature {
                            package: node.name.clone(),
                            feature: feature.clone(),
                        })
                        .or_insert(id);
                    }
                }
            }
            NodeKind::Feature { feature } => {
                if policy.features.contains(feature) {
                    hits.insert(
                        Denied::Feature {
                            package: node.name.clone(),
                            feature: feature.clone(),
                        },
                        id,
                    );
                }
            }
        }
    }
    let direct: Vec<(String, Vec<bool>)> = graph.children[0]
        .iter()
        .map(|&child| (graph.nodes[child].name.clone(), graph.reachable_from(child)))
        .collect();
    hits.into_iter()
        .map(|(denied, target)| {
            let inverted_path = graph
                .shortest_path(target)
                .into_iter()
                .filter(|&id| {
                    id == target
                        || !matches!(&graph.nodes[id].kind, NodeKind::Feature { feature } if feature == "default")
                })
                .map(|id| graph.nodes[id].label())
                .collect();
            let via: BTreeSet<String> = direct
                .iter()
                .filter(|(_, reach)| reach[target])
                .map(|(name, _)| name.clone())
                .collect();
            Violation {
                root: graph.root_name().to_string(),
                denied,
                inverted_path,
                via: via.into_iter().collect(),
            }
        })
        .collect()
}

pub(crate) fn load_policy(root: &Path) -> Result<Policy, XtaskError> {
    let path = root.join(POLICY_PATH);
    let text = fs::read_to_string(&path).map_err(|err| XtaskError::Io(display_path(&path), err))?;
    Policy::parse(&text)
        .map_err(|detail| XtaskError::Web3FreeClosure(format!("{POLICY_PATH}: {detail}")))
}

fn select_roots(policy: &Policy, requested: &[String]) -> Result<Vec<String>, XtaskError> {
    if requested.is_empty() {
        return Ok(policy.roots().to_vec());
    }
    let mut selected = Vec::new();
    for root in requested {
        if !policy.roots().contains(root) {
            return Err(XtaskError::Usage(format!(
                "root `{root}` is not listed in {POLICY_PATH}"
            )));
        }
        if !selected.contains(root) {
            selected.push(root.clone());
        }
    }
    Ok(selected)
}

fn cargo_tree(workspace: &Path, root: &str) -> Result<String, XtaskError> {
    let output = Command::new("cargo")
        .current_dir(workspace)
        .args([
            "tree",
            "--locked",
            "-p",
            root,
            "-e",
            "normal,features",
            "--prefix",
            "depth",
            "--format",
            TREE_FORMAT,
        ])
        .output()
        .map_err(|err| {
            XtaskError::Process(format!("failed to spawn cargo tree -p {root}: {err}"))
        })?;
    if !output.status.success() {
        return Err(XtaskError::Process(format!(
            "cargo tree -p {root} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout).map_err(|err| {
        XtaskError::Process(format!(
            "cargo tree -p {root} printed non-UTF-8 output: {err}"
        ))
    })
}

pub(crate) fn run(requested: &[String]) -> Result<(), XtaskError> {
    let workspace = workspace_root()?;
    let policy = load_policy(&workspace)?;
    let roots = select_roots(&policy, requested)?;
    let mut failing = Vec::new();
    let mut total = 0usize;
    for root in &roots {
        let text = cargo_tree(&workspace, root)?;
        let graph = ClosureGraph::parse(&text).map_err(|detail| {
            XtaskError::Web3FreeClosure(format!("{root}: unreadable cargo tree output: {detail}"))
        })?;
        if graph.root_name() != root {
            return Err(XtaskError::Web3FreeClosure(format!(
                "{root}: cargo tree resolved root `{}`",
                graph.root_name()
            )));
        }
        let violations = evaluate(&policy, &graph);
        if violations.is_empty() {
            println!(
                "web3-free-closure: {root}: clean ({} nodes)",
                graph.nodes.len()
            );
            continue;
        }
        for violation in &violations {
            println!("{}", violation.render());
        }
        println!(
            "web3-free-closure: {root}: {} denied item(s)",
            violations.len()
        );
        total += violations.len();
        failing.push(root.clone());
    }
    if failing.is_empty() {
        println!("web3-free-closure: OK ({} roots)", roots.len());
        return Ok(());
    }
    Err(XtaskError::Web3FreeClosure(format!(
        "{total} denied item(s) in the default closure of {}",
        failing.join(", ")
    )))
}

#[cfg(test)]
mod tests;
