//! `cargo xtask check web3-free-closure`: per-root dependency closure gate.
//!
//! `ci-gates/web3-free-closure.toml` lists modes. A mode names a feature set
//! (empty for default features), the packages and features its closures must
//! not reach, and per root the packages they must reach. Each (mode, root) is
//! resolved on its own (`cargo tree -p <root> -e normal,features
//! [--features <set>]`), so the check sees the graph a `cargo build -p <root>`
//! links rather than the workspace-unified one. Every failure names the mode,
//! the root and the item; a denied item also carries the shortest inverted path
//! back to the root and the root's direct dependencies that reach it.

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
    mode: Vec<ModeFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeFile {
    name: String,
    features: Vec<String>,
    deny_packages: Vec<String>,
    deny_features: Vec<String>,
    root: Vec<RootFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFile {
    name: String,
    require: Vec<String>,
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
pub(crate) struct RootRule {
    name: String,
    require: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct Mode {
    name: String,
    features: Vec<String>,
    deny_packages: Vec<PackagePattern>,
    deny_features: BTreeSet<String>,
    roots: Vec<RootRule>,
}

impl Mode {
    fn label(&self) -> String {
        format!("[{}]", self.name)
    }

    fn tree_features(&self) -> Option<String> {
        if self.features.is_empty() {
            None
        } else {
            Some(self.features.join(","))
        }
    }
}

#[derive(Debug)]
pub(crate) struct Policy {
    modes: Vec<Mode>,
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
        if file.mode.is_empty() {
            return Err("no `[[mode]]` entries".to_string());
        }
        let mut names = BTreeSet::new();
        let mut modes = Vec::new();
        for raw in file.mode {
            let mode = parse_mode(raw)?;
            if !names.insert(mode.name.clone()) {
                return Err(format!("mode `{}` is listed twice", mode.name));
            }
            modes.push(mode);
        }
        Ok(Self { modes })
    }

    pub(crate) fn modes(&self) -> &[Mode] {
        &self.modes
    }
}

fn parse_mode(raw: ModeFile) -> Result<Mode, String> {
    let name = checked_name("mode name", raw.name)?;
    let field = |key: &str| format!("mode `{name}` {key}");
    let features = unique_names(&field("features"), raw.features)?;
    let deny_packages = unique_entries(&field("deny_packages"), raw.deny_packages)?
        .iter()
        .map(|entry| PackagePattern::parse(entry))
        .collect::<Result<Vec<_>, _>>()?;
    let deny_features = unique_names(&field("deny_features"), raw.deny_features)?;
    if raw.root.is_empty() {
        return Err(format!("mode `{name}` has no `[[mode.root]]` entries"));
    }
    let mut roots: Vec<RootRule> = Vec::new();
    for root in raw.root {
        let root_name = checked_name(&field("root"), root.name)?;
        if roots.iter().any(|seen| seen.name == root_name) {
            return Err(format!("mode `{name}` lists root `{root_name}` twice"));
        }
        let require = unique_names(&field(&format!("root `{root_name}` require")), root.require)?;
        if deny_packages.is_empty() && deny_features.is_empty() && require.is_empty() {
            return Err(format!(
                "mode `{name}` root `{root_name}` has no denied or required entry"
            ));
        }
        roots.push(RootRule {
            name: root_name,
            require,
        });
    }
    Ok(Mode {
        name,
        features,
        deny_packages,
        deny_features: deny_features.into_iter().collect(),
        roots,
    })
}

fn checked_name(field: &str, value: String) -> Result<String, String> {
    if value.is_empty() || !value.chars().all(is_crate_name_char) {
        return Err(format!("{field} `{value}` is malformed"));
    }
    Ok(value)
}

fn unique_entries(field: &str, values: Vec<String>) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    for value in &values {
        if value.is_empty() {
            return Err(format!("{field} has an empty entry"));
        }
        if !seen.insert(value.as_str()) {
            return Err(format!("{field} lists `{value}` twice"));
        }
    }
    Ok(values)
}

fn unique_names(field: &str, values: Vec<String>) -> Result<Vec<String>, String> {
    let values = unique_entries(field, values)?;
    for value in &values {
        if !value.chars().all(is_crate_name_char) {
            return Err(format!("{field} entry `{value}` is malformed"));
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
pub(crate) enum Breach {
    DeniedPackage { package: String },
    DeniedFeature { package: String, feature: String },
    MissingPackage { package: String },
}

impl Breach {
    fn package(&self) -> &str {
        match self {
            Self::DeniedPackage { package }
            | Self::DeniedFeature { package, .. }
            | Self::MissingPackage { package } => package,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) mode: String,
    pub(crate) root: String,
    pub(crate) breach: Breach,
    pub(crate) inverted_path: Vec<String>,
    pub(crate) via: Vec<String>,
}

impl Violation {
    fn render(&self, mode: &Mode) -> String {
        let features = mode
            .tree_features()
            .map(|set| format!(" --features {set}"))
            .unwrap_or_default();
        let item = match &self.breach {
            Breach::DeniedPackage { package } => format!("denied package `{package}`"),
            Breach::DeniedFeature { package, feature } => {
                format!("denied feature `{feature}` on `{package}`")
            }
            Breach::MissingPackage { package } => {
                return format!(
                    "web3-free-closure: {root} [{mode}]: required package `{package}` is not reached\n  inspect: cargo tree -p {root} -e normal,features{features}",
                    root = self.root,
                    mode = self.mode,
                );
            }
        };
        format!(
            "web3-free-closure: {root} [{mode}]: {item}\n  path (inverted): {path}\n  via direct dependencies: {via}\n  inspect: cargo tree -p {root} -e normal,features{features} -i {package}",
            root = self.root,
            mode = self.mode,
            path = self.inverted_path.join(" <- "),
            via = self.via.join(", "),
            package = self.breach.package(),
        )
    }
}

/// Evaluate one root's closure under one mode. Violations are sorted and carry
/// one entry per denied package, denied (package, feature) pair or missing
/// required package.
pub(crate) fn evaluate(mode: &Mode, rule: &RootRule, graph: &ClosureGraph) -> Vec<Violation> {
    let mut hits: BTreeMap<Breach, usize> = BTreeMap::new();
    let mut present = BTreeSet::new();
    for (id, node) in graph.nodes.iter().enumerate() {
        match &node.kind {
            NodeKind::Package { features } => {
                if id != 0 {
                    present.insert(node.name.as_str());
                    if mode.deny_packages.iter().any(|p| p.matches(&node.name)) {
                        hits.entry(Breach::DeniedPackage {
                            package: node.name.clone(),
                        })
                        .or_insert(id);
                    }
                }
                for feature in features {
                    if mode.deny_features.contains(feature) {
                        hits.entry(Breach::DeniedFeature {
                            package: node.name.clone(),
                            feature: feature.clone(),
                        })
                        .or_insert(id);
                    }
                }
            }
            NodeKind::Feature { feature } => {
                if mode.deny_features.contains(feature) {
                    hits.insert(
                        Breach::DeniedFeature {
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
    let mut violations: Vec<Violation> = hits
        .into_iter()
        .map(|(breach, target)| {
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
                mode: mode.name.clone(),
                root: graph.root_name().to_string(),
                breach,
                inverted_path,
                via: via.into_iter().collect(),
            }
        })
        .collect();
    for package in &rule.require {
        if !present.contains(package.as_str()) {
            violations.push(Violation {
                mode: mode.name.clone(),
                root: graph.root_name().to_string(),
                breach: Breach::MissingPackage {
                    package: package.clone(),
                },
                inverted_path: Vec::new(),
                via: Vec::new(),
            });
        }
    }
    violations
}

/// Outcome of one (mode, root) check. `tree` is the `cargo tree` stdout or the
/// reason it could not be produced; either failure is reported, never skipped.
pub(crate) fn check_root(
    mode: &Mode,
    rule: &RootRule,
    tree: Result<String, String>,
) -> Result<(usize, Vec<Violation>), String> {
    let text = tree?;
    let graph = ClosureGraph::parse(&text)
        .map_err(|detail| format!("unreadable cargo tree output: {detail}"))?;
    if graph.root_name() != rule.name {
        return Err(format!("cargo tree resolved root `{}`", graph.root_name()));
    }
    Ok((graph.nodes.len(), evaluate(mode, rule, &graph)))
}

pub(crate) fn load_policy(root: &Path) -> Result<Policy, XtaskError> {
    let path = root.join(POLICY_PATH);
    let text = fs::read_to_string(&path).map_err(|err| XtaskError::Io(display_path(&path), err))?;
    Policy::parse(&text)
        .map_err(|detail| XtaskError::Web3FreeClosure(format!("{POLICY_PATH}: {detail}")))
}

/// Select (mode, root) pairs. Empty filters select everything; a requested
/// mode or root the policy does not list is a usage error.
pub(crate) fn select<'p>(
    policy: &'p Policy,
    modes: &[String],
    roots: &[String],
) -> Result<Vec<(&'p Mode, &'p RootRule)>, XtaskError> {
    for mode in modes {
        if !policy.modes().iter().any(|m| &m.name == mode) {
            return Err(XtaskError::Usage(format!(
                "mode `{mode}` is not listed in {POLICY_PATH}"
            )));
        }
    }
    let selected_modes: Vec<&Mode> = policy
        .modes()
        .iter()
        .filter(|m| modes.is_empty() || modes.contains(&m.name))
        .collect();
    for root in roots {
        if !selected_modes
            .iter()
            .any(|m| m.roots.iter().any(|r| &r.name == root))
        {
            return Err(XtaskError::Usage(format!(
                "root `{root}` is not listed in {POLICY_PATH} for the selected modes"
            )));
        }
    }
    Ok(selected_modes
        .into_iter()
        .flat_map(|mode| {
            mode.roots
                .iter()
                .filter(|rule| roots.is_empty() || roots.contains(&rule.name))
                .map(move |rule| (mode, rule))
        })
        .collect())
}

fn cargo_tree(workspace: &Path, mode: &Mode, root: &str) -> Result<String, String> {
    let mut command = Command::new("cargo");
    command.current_dir(workspace).args([
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
    ]);
    if let Some(set) = mode.tree_features() {
        command.args(["--features", &set]);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to spawn cargo tree: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| format!("cargo tree printed non-UTF-8 output: {err}"))
}

pub(crate) fn run(modes: &[String], roots: &[String]) -> Result<(), XtaskError> {
    let workspace = workspace_root()?;
    let policy = load_policy(&workspace)?;
    let selected = select(&policy, modes, roots)?;
    let mut failing = Vec::new();
    let mut total = 0usize;
    for &(mode, rule) in &selected {
        let label = format!("{} {}", rule.name, mode.label());
        match check_root(mode, rule, cargo_tree(&workspace, mode, &rule.name)) {
            Err(detail) => {
                println!("web3-free-closure: {label}: {detail}");
                total += 1;
                failing.push(label);
            }
            Ok((nodes, violations)) if violations.is_empty() => {
                println!("web3-free-closure: {label}: clean ({nodes} nodes)");
            }
            Ok((_, violations)) => {
                for violation in &violations {
                    println!("{}", violation.render(mode));
                }
                println!(
                    "web3-free-closure: {label}: {} failure(s)",
                    violations.len()
                );
                total += violations.len();
                failing.push(label);
            }
        }
    }
    if failing.is_empty() {
        println!("web3-free-closure: OK ({} checks)", selected.len());
        return Ok(());
    }
    Err(XtaskError::Web3FreeClosure(format!(
        "{total} failure(s) in {}",
        failing.join(", ")
    )))
}

#[cfg(test)]
mod tests;
