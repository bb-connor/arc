//! Structural gate for the reference runtime supervision package under
//! `deploy/reference-runtime`.
//!
//! Every unit is checked against the built `chio` binary: each subcommand
//! and flag it invokes exists, credentials are declared by the manager and
//! consumed by the service, environment references are declared in the
//! template, accounts exist in sysusers, dependencies name units in this
//! package, the hardening baseline is present, and the keylog example
//! configs agree with the units that load them.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const CHIO: &str = "/usr/local/bin/chio";
const KEYLOG_BINARIES: [&str; 2] = [
    "/usr/local/bin/chio-keylog-witness",
    "/usr/local/bin/chio-keylog-audit",
];
const EXEC_KEYS: [&str; 6] = [
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];
const DEPENDENCY_KEYS: [&str; 5] = ["Requires", "Wants", "After", "BindsTo", "PartOf"];
const HARDENING_BASELINE: [(&str, &str); 24] = [
    ("Type", "notify"),
    ("NotifyAccess", "main"),
    ("Restart", "on-failure"),
    ("KillSignal", "SIGTERM"),
    ("StateDirectoryMode", "0700"),
    ("RuntimeDirectoryMode", "0700"),
    ("UMask", "0077"),
    ("LimitCORE", "0"),
    ("NoNewPrivileges", "true"),
    ("PrivateTmp", "true"),
    ("PrivateDevices", "true"),
    ("ProtectHome", "true"),
    ("ProtectSystem", "strict"),
    ("ReadOnlyPaths", "/etc/chio"),
    ("ProtectKernelTunables", "true"),
    ("ProtectKernelModules", "true"),
    ("ProtectControlGroups", "true"),
    ("RestrictNamespaces", "true"),
    ("RestrictRealtime", "true"),
    ("RestrictSUIDSGID", "true"),
    ("LockPersonality", "true"),
    ("SystemCallArchitectures", "native"),
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
];

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root")
}

fn package_root() -> PathBuf {
    repository_root().join("deploy/reference-runtime")
}

fn chio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

/// One unit file: `(section, key, value)` in file order, continuations joined.
struct Unit {
    name: String,
    entries: Vec<(String, String, String)>,
}

fn strip_continuation(value: &str) -> (String, bool) {
    match value.strip_suffix('\\') {
        Some(rest) => (rest.trim_end().to_string(), true),
        None => (value.to_string(), false),
    }
}

impl Unit {
    fn parse(path: &Path) -> Self {
        let text = std::fs::read_to_string(path).expect("read unit");
        let mut section = String::new();
        let mut entries = Vec::new();
        let mut pending: Option<(String, String)> = None;
        for raw in text.lines() {
            let line = raw.trim_end();
            if let Some((key, value)) = pending.take() {
                let (chunk, more) = strip_continuation(line.trim_start());
                let joined = format!("{value} {chunk}");
                if more {
                    pending = Some((key, joined));
                } else {
                    entries.push((section.clone(), key, joined));
                }
                continue;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            if let Some(name) = trimmed
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                section = name.to_string();
                continue;
            }
            let (key, value) = trimmed
                .split_once('=')
                .unwrap_or_else(|| panic!("{}: not key=value: {trimmed}", path.display()));
            let (chunk, more) = strip_continuation(value.trim());
            if more {
                pending = Some((key.trim().to_string(), chunk));
            } else {
                entries.push((section.clone(), key.trim().to_string(), chunk));
            }
        }
        assert!(
            pending.is_none(),
            "{}: dangling continuation",
            path.display()
        );
        Self {
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            entries,
        }
    }

    fn values(&self, section: &str, key: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(s, k, _)| s == section && k == key)
            .map(|(_, _, value)| value.as_str())
            .collect()
    }

    fn value(&self, section: &str, key: &str) -> Option<&str> {
        let values = self.values(section, key);
        assert!(
            values.len() <= 1,
            "{}: {key} is set more than once",
            self.name
        );
        values.first().copied()
    }

    fn is_template(&self) -> bool {
        self.name.contains('@')
    }

    /// Every `Exec*` entry as `(key, argv)`.
    fn exec_lines(&self) -> Vec<(&str, Vec<String>)> {
        EXEC_KEYS
            .iter()
            .flat_map(|key| {
                self.values("Service", key)
                    .into_iter()
                    .map(move |value| (*key, argv(value)))
            })
            .collect()
    }
}

/// Split a command line the way the manager does for the units here:
/// whitespace separates words and double quotes group them.
fn argv(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut has_token = false;
    for c in value.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                has_token = true;
            }
            c if c.is_whitespace() && !quoted => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    assert!(!quoted, "unbalanced quote in {value}");
    if has_token {
        tokens.push(current);
    }
    tokens
}

/// The subcommands and flags one `chio ...` level accepts, from its help.
struct Surface {
    subcommands: BTreeSet<String>,
    flags: BTreeMap<String, bool>,
}

fn surface(path: &[String]) -> Surface {
    let output = Command::new(chio())
        .args(path)
        .arg("--help")
        .output()
        .expect("run chio --help");
    assert!(
        output.status.success(),
        "chio {} --help failed: {}",
        path.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_help(&String::from_utf8_lossy(&output.stdout))
}

fn parse_help(help: &str) -> Surface {
    let mut section = "";
    let mut subcommands = BTreeSet::new();
    let mut flags = BTreeMap::new();
    for line in help.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            section = match line.trim_end() {
                "Commands:" => "commands",
                "Options:" => "options",
                _ => "",
            };
            continue;
        }
        match section {
            "commands" if line.starts_with("  ") && !line.starts_with("   ") => {
                if let Some(name) = line.split_whitespace().next() {
                    subcommands.insert(name.to_string());
                }
            }
            "options" if line.trim_start().starts_with('-') => {
                let text = line.trim_start();
                let Some(start) = text.find("--") else {
                    continue;
                };
                let name: String = text[start + 2..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                let rest = &text[start + 2 + name.len()..];
                let takes_value = rest.trim_start().starts_with('<') || rest.starts_with("=<");
                flags.insert(name, takes_value);
            }
            _ => {}
        }
    }
    Surface { subcommands, flags }
}

/// Validate one `chio` invocation (arguments after the program) against the
/// binary's help at every level, returning the wrapped command after `--`.
fn walk_chio(args: &[String], context: &str) -> Option<Vec<String>> {
    let mut path: Vec<String> = Vec::new();
    let mut current = surface(&path);
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if token == "--" {
            return Some(args[index + 1..].to_vec());
        }
        if let Some(flag) = token.strip_prefix("--") {
            let (name, inline_value) = match flag.split_once('=') {
                Some((name, _)) => (name, true),
                None => (flag, false),
            };
            let takes_value = *current.flags.get(name).unwrap_or_else(|| {
                panic!("{context}: chio {} has no flag --{name}", path.join(" "))
            });
            if takes_value && !inline_value {
                index += 1;
                assert!(
                    index < args.len(),
                    "{context}: --{name} is missing its value"
                );
            }
            index += 1;
            continue;
        }
        assert!(
            current.subcommands.contains(token),
            "{context}: chio {} has no subcommand {token}",
            path.join(" ")
        );
        path.push(token.clone());
        current = surface(&path);
        index += 1;
    }
    None
}

/// The values given to `flag` anywhere in `args`.
fn flag_values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
        .collect()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|token| token == flag)
}

/// The subcommand path of a `chio` invocation: the non-flag tokens before `--`.
fn subcommand_path(args: &[String]) -> Vec<String> {
    let mut path = Vec::new();
    let mut skip_value = false;
    for token in args {
        if token == "--" {
            break;
        }
        if skip_value {
            skip_value = false;
            continue;
        }
        if token.starts_with("--") {
            skip_value = !token.contains('=')
                && !matches!(
                    token.as_str(),
                    "--exec" | "--require-enforcement" | "--json" | "--discover-tools"
                );
            continue;
        }
        path.push(token.clone());
    }
    path
}

fn environment_reference(token: &str) -> Option<&str> {
    if let Some(name) = token
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return Some(name);
    }
    token.strip_prefix('$')
}

/// Everything one unit invokes, gathered while validating it.
#[derive(Default)]
struct Usage {
    environment_references: BTreeSet<String>,
    credentials_consumed: BTreeSet<String>,
    etc_paths: BTreeSet<String>,
}

fn validate_command(unit: &Unit, key: &str, args: &[String], usage: &mut Usage) -> Vec<String> {
    let context = format!("{}: {key}", unit.name);
    let (program, rest) = args
        .split_first()
        .unwrap_or_else(|| panic!("{context}: empty command"));
    assert!(
        !program.starts_with(['-', '+', '!', '@', ':']),
        "{context}: no execution prefix is allowed on {program}"
    );
    for token in rest {
        if let Some(name) = environment_reference(token) {
            usage.environment_references.insert(name.to_string());
        } else {
            assert!(
                !token.contains('$'),
                "{context}: {token} mixes an environment reference into a word"
            );
        }
        if let Some(name) = token.strip_prefix("%d/") {
            usage.credentials_consumed.insert(name.to_string());
        }
        if token.starts_with("/etc/chio/") {
            usage.etc_paths.insert(token.clone());
        }
    }
    if program == CHIO {
        for binding in flag_values(rest, "--credential-env") {
            let (_, name) = binding
                .split_once('=')
                .unwrap_or_else(|| panic!("{context}: malformed credential binding {binding}"));
            usage.credentials_consumed.insert(name.to_string());
        }
        let Some(wrapped) = walk_chio(rest, &context) else {
            return Vec::new();
        };
        let wrapped_program = wrapped
            .first()
            .unwrap_or_else(|| panic!("{context}: nothing after --"));
        if wrapped_program == CHIO || KEYLOG_BINARIES.contains(&wrapped_program.as_str()) {
            let inner = validate_command(unit, key, &wrapped, usage);
            return if inner.is_empty() { wrapped } else { inner };
        }
        if let Some(name) = environment_reference(wrapped_program) {
            usage.environment_references.insert(name.to_string());
            assert_eq!(
                wrapped.len(),
                1,
                "{context}: the wrapped command must be one environment reference"
            );
            return wrapped;
        }
        panic!("{context}: the wrapped command {wrapped_program} is not a chio binary or an environment reference");
    }
    if KEYLOG_BINARIES.contains(&program.as_str()) {
        let binary = Path::new(program)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            repository_root()
                .join("crates/security/chio-keyring/src/bin")
                .join(format!("{binary}.rs"))
                .is_file(),
            "{context}: {binary} is not a chio-keyring binary"
        );
        assert_eq!(
            rest.len(),
            2,
            "{context}: {binary} takes exactly --config PATH"
        );
        assert_eq!(
            rest[0], "--config",
            "{context}: {binary} takes exactly --config PATH"
        );
        assert!(
            rest[1].starts_with("/etc/chio/keylog/"),
            "{context}: the keylog config must live under /etc/chio/keylog"
        );
        return Vec::new();
    }
    panic!("{context}: {program} is not a binary this package installs");
}

fn parse_env_example(path: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, _) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("{}: not NAME=value: {line}", path.display()));
            name.to_string()
        })
        .collect()
}

fn sysusers_accounts() -> BTreeSet<String> {
    std::fs::read_to_string(package_root().join("sysusers.d/chio.conf"))
        .expect("sysusers")
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("u")).then(|| words.next().expect("account name").to_string())
        })
        .collect()
}

/// `path -> (mode, user, group)` from tmpfiles `d` lines.
fn tmpfiles_directories() -> BTreeMap<String, (String, String, String)> {
    std::fs::read_to_string(package_root().join("tmpfiles.d/chio.conf"))
        .expect("tmpfiles")
        .lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            (words.first() == Some(&"d")).then(|| {
                (
                    words[1].to_string(),
                    (
                        words[2].to_string(),
                        words[3].to_string(),
                        words[4].to_string(),
                    ),
                )
            })
        })
        .collect()
}

fn package_units() -> Vec<Unit> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(package_root().join("systemd"))
        .expect("systemd directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "service")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no units in the package");
    paths.iter().map(|path| Unit::parse(path)).collect()
}

fn seconds(value: &str) -> u64 {
    value
        .strip_suffix('s')
        .unwrap_or(value)
        .parse()
        .unwrap_or_else(|_| panic!("not a duration in seconds: {value}"))
}

fn instance(unit: &Unit) -> &'static str {
    if unit.is_template() {
        "a"
    } else {
        ""
    }
}

fn expand(unit: &Unit, value: &str) -> String {
    value.replace("%i", instance(unit))
}

/// The unit name of the example instance: `name@.service` becomes `name@a.service`.
fn instance_unit_name(unit: &Unit) -> String {
    unit.name
        .replacen("@.", &format!("@{}.", instance(unit)), 1)
}

fn keylog_example(
    unit: &Unit,
    config_path: &str,
) -> (PathBuf, serde_json::Map<String, serde_json::Value>) {
    let file = Path::new(config_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let example = package_root()
        .join("keylog")
        .join(format!("{}.example", expand(unit, &file)));
    let text = std::fs::read_to_string(&example)
        .unwrap_or_else(|error| panic!("{}: {error}", example.display()));
    let value: serde_json::Value = serde_json::from_str(&text).expect("keylog example JSON");
    (
        example,
        value.as_object().expect("keylog example object").clone(),
    )
}

#[test]
fn every_unit_invokes_commands_the_binary_accepts_and_declares_what_it_consumes() {
    let units = package_units();
    let unit_names: BTreeSet<String> = units.iter().map(|unit| unit.name.clone()).collect();
    let accounts = sysusers_accounts();
    let directories = tmpfiles_directories();
    assert_eq!(
        directories.get("/etc/chio/credentials"),
        Some(&("0700".to_string(), "root".to_string(), "root".to_string())),
        "credential sources must be root-only"
    );

    for unit in &units {
        let name = &unit.name;
        let mut usage = Usage::default();
        let mut wrapped_by_key: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let mut args_by_key: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for (key, args) in unit.exec_lines() {
            let wrapped = validate_command(unit, key, &args, &mut usage);
            wrapped_by_key.insert(key, wrapped);
            args_by_key.insert(key, args);
        }

        // Hardening baseline and stop timing.
        for (key, expected) in HARDENING_BASELINE {
            assert_eq!(
                unit.value("Service", key),
                Some(expected),
                "{name}: {key} must be {expected:?}"
            );
        }
        for key in [
            "RestrictAddressFamilies",
            "MemoryHigh",
            "MemoryMax",
            "LimitNOFILE",
            "StateDirectory",
            "RuntimeDirectory",
            "WorkingDirectory",
        ] {
            assert!(
                unit.value("Service", key).is_some(),
                "{name}: {key} must be set"
            );
        }
        assert_eq!(
            unit.value("Install", "WantedBy"),
            Some("multi-user.target"),
            "{name}: WantedBy"
        );

        // Accounts.
        let user = unit
            .value("Service", "User")
            .unwrap_or_else(|| panic!("{name}: User"));
        assert!(
            accounts.contains(user),
            "{name}: {user} is not declared in sysusers.d"
        );
        assert_eq!(
            unit.value("Service", "Group"),
            Some(user),
            "{name}: Group must equal User"
        );

        // The main process is the supervisor with a readiness gate; checks use --exec.
        let start = &args_by_key["ExecStart"];
        assert_eq!(start[0], CHIO, "{name}: ExecStart must run chio");
        assert_eq!(
            subcommand_path(&start[1..]),
            ["security", "supervise"],
            "{name}: ExecStart must run chio security supervise"
        );
        assert!(
            has_flag(start, "--ready-http") || has_flag(start, "--ready-unix-socket"),
            "{name}: a notify unit needs a readiness probe"
        );
        assert!(
            !has_flag(start, "--exec"),
            "{name}: ExecStart must supervise, not exec"
        );
        let stop_grace: u64 = flag_values(start, "--stop-grace")
            .first()
            .unwrap_or_else(|| panic!("{name}: --stop-grace"))
            .parse()
            .expect("stop grace seconds");
        let ready_timeout: u64 = flag_values(start, "--ready-timeout")
            .first()
            .unwrap_or_else(|| panic!("{name}: --ready-timeout"))
            .parse()
            .expect("ready timeout seconds");
        assert!(
            seconds(unit.value("Service", "TimeoutStopSec").unwrap()) >= stop_grace + 5,
            "{name}: TimeoutStopSec must leave the supervisor its stop grace plus a margin"
        );
        assert!(
            seconds(unit.value("Service", "TimeoutStartSec").unwrap()) > ready_timeout,
            "{name}: TimeoutStartSec must exceed the readiness timeout"
        );
        for (key, args) in &args_by_key {
            if *key != "ExecStart" && subcommand_path(&args[1..]) == ["security", "supervise"] {
                assert!(
                    has_flag(args, "--exec"),
                    "{name}: {key} must use supervise --exec"
                );
            }
        }

        // Credentials: declared by the manager, consumed by the service, sourced from the root-only directory.
        let mut declared = BTreeSet::new();
        for entry in unit.values("Service", "LoadCredential") {
            let (credential, source) = entry
                .split_once(':')
                .unwrap_or_else(|| panic!("{name}: LoadCredential {entry}"));
            declared.insert(credential.to_string());
            assert!(
                Path::new(source).parent() == Some(Path::new("/etc/chio/credentials")),
                "{name}: credential {credential} must be sourced from /etc/chio/credentials"
            );
            if unit.is_template() {
                assert!(
                    source.contains("%i"),
                    "{name}: template credential sources must vary by instance"
                );
            }
        }
        assert!(
            !declared.is_empty(),
            "{name}: every unit delivers at least one credential"
        );
        let mut consumed = usage.credentials_consumed.clone();

        // Keylog templates consume their seed through the service config.
        for key in args_by_key.keys() {
            let program = wrapped_by_key[key].first().cloned().unwrap_or_default();
            if !KEYLOG_BINARIES.contains(&program.as_str()) {
                continue;
            }
            let config_path = &wrapped_by_key[key][2];
            let (example, config) = keylog_example(unit, config_path);
            let label = example.display().to_string();
            let seed = config["seed_file_path"].as_str().expect("seed_file_path");
            let expected_seed_directory = format!("/run/credentials/{}", instance_unit_name(unit));
            let seed_path = Path::new(seed);
            assert_eq!(
                seed_path
                    .parent()
                    .map(|p| p.display().to_string())
                    .as_deref(),
                Some(expected_seed_directory.as_str()),
                "{label}: seed_file_path must be the credentials directory of {name}"
            );
            consumed.insert(
                seed_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
            assert_eq!(
                config["socket_path"].as_str(),
                flag_values(start, "--ready-unix-socket")
                    .first()
                    .map(|value| expand(unit, value))
                    .as_deref(),
                "{label}: socket_path must be the unit's readiness socket"
            );
            let state = format!(
                "/var/lib/{}/",
                expand(unit, unit.value("Service", "StateDirectory").unwrap())
            );
            let runtime = format!(
                "/run/{}/",
                expand(unit, unit.value("Service", "RuntimeDirectory").unwrap())
            );
            assert!(
                config["socket_path"]
                    .as_str()
                    .unwrap()
                    .starts_with(&runtime),
                "{label}: socket_path must live in the runtime directory"
            );
            for key in ["database_path", "operator_database_path"] {
                if let Some(path) = config.get(key) {
                    assert!(
                        path.as_str().unwrap().starts_with(&state),
                        "{label}: {key} must live in the state directory"
                    );
                }
            }
            assert!(
                config["policy_path"]
                    .as_str()
                    .unwrap()
                    .starts_with("/etc/chio/keylog/"),
                "{label}: policy_path"
            );
            assert_eq!(
                config["provision"],
                serde_json::Value::Bool(true),
                "{label}: provision opens or creates the store"
            );
            let expected_keys: BTreeSet<&str> = if program.ends_with("witness") {
                assert_eq!(
                    config["schema"], "chio.key-log.witness-service-config.v1",
                    "{label}: schema"
                );
                assert_eq!(config["witness_id"], instance(unit), "{label}: witness_id");
                [
                    "schema",
                    "policy_path",
                    "database_path",
                    "socket_path",
                    "witness_id",
                    "seed_file_path",
                    "provision",
                ]
                .into_iter()
                .collect()
            } else {
                assert_eq!(
                    config["schema"], "chio.key-log.audit-service-config.v1",
                    "{label}: schema"
                );
                assert_eq!(config["monitor_id"], instance(unit), "{label}: monitor_id");
                let witnesses = config["witness_sockets"]
                    .as_object()
                    .expect("witness_sockets");
                let wanted: BTreeSet<String> = unit
                    .values("Unit", "Wants")
                    .iter()
                    .flat_map(|value| value.split_whitespace())
                    .filter_map(|dependency| {
                        dependency
                            .strip_prefix("chio-keylog-witness@")
                            .and_then(|rest| rest.strip_suffix(".service"))
                    })
                    .map(str::to_string)
                    .collect();
                assert_eq!(
                    witnesses.keys().cloned().collect::<BTreeSet<_>>(),
                    wanted,
                    "{label}: witness_sockets must name the witnesses the unit wants"
                );
                for (witness, socket) in witnesses {
                    assert_eq!(
                        socket.as_str(),
                        Some(format!("/run/chio-keylog/witness-{witness}/witness.sock").as_str()),
                        "{label}: witness {witness} socket"
                    );
                }
                assert!(
                    config["poll_interval_millis"]
                        .as_u64()
                        .is_some_and(|millis| millis >= 1000),
                    "{label}: poll_interval_millis"
                );
                [
                    "schema",
                    "policy_path",
                    "database_path",
                    "operator_database_path",
                    "socket_path",
                    "monitor_id",
                    "seed_file_path",
                    "witness_sockets",
                    "poll_interval_millis",
                    "provision",
                ]
                .into_iter()
                .collect()
            };
            assert_eq!(
                config.keys().map(String::as_str).collect::<BTreeSet<_>>(),
                expected_keys,
                "{label}: exact config keys"
            );
        }
        assert_eq!(
            declared, consumed,
            "{name}: LoadCredential names and the credentials the service consumes must match"
        );

        // Environment references are declared in the example, and nothing else is.
        match unit.value("Service", "EnvironmentFile") {
            Some(environment_file) => {
                let base = name.strip_suffix(".service").unwrap();
                assert_eq!(
                    Path::new(environment_file)
                        .file_name()
                        .unwrap()
                        .to_string_lossy(),
                    format!("{base}.env"),
                    "{name}: EnvironmentFile must be named after the unit"
                );
                usage.etc_paths.insert(environment_file.to_string());
                let example = package_root()
                    .join("env")
                    .join(format!("{base}.env.example"));
                let declared = parse_env_example(&example);
                assert_eq!(
                    declared,
                    usage.environment_references,
                    "{name}: environment references and {} must match",
                    example.display()
                );
            }
            None => assert!(
                usage.environment_references.is_empty(),
                "{name}: environment references without an EnvironmentFile"
            ),
        }

        // Every configuration path under /etc/chio has a declared parent the service can read.
        for path in &usage.etc_paths {
            let parent = Path::new(path).parent().unwrap().display().to_string();
            let (mode, owner, group) = directories
                .get(&parent)
                .unwrap_or_else(|| panic!("{name}: {parent} is not declared in tmpfiles.d"));
            assert_eq!(owner, "root", "{name}: {parent} must be root-owned");
            if parent == "/etc/chio/credentials" {
                assert_eq!(mode, "0700");
            } else {
                assert_eq!(
                    (mode.as_str(), group.as_str()),
                    ("0750", user),
                    "{name}: {parent} must be readable by {user} only"
                );
            }
        }
        for source in unit.values("Service", "LoadCredential") {
            let (_, path) = source.split_once(':').unwrap();
            assert!(path.starts_with("/etc/chio/credentials/"), "{name}: {path}");
        }

        // Dependencies name units in this package.
        for key in DEPENDENCY_KEYS {
            for dependency in unit
                .values("Unit", key)
                .iter()
                .flat_map(|value| value.split_whitespace())
            {
                if !dependency.starts_with("chio-") {
                    continue;
                }
                let template = match dependency.split_once('@') {
                    Some((base, _)) => format!("{base}@.service"),
                    None => dependency.to_string(),
                };
                assert!(
                    unit_names.contains(&template),
                    "{name}: {key} names {dependency}, which is not in the package"
                );
            }
        }

        // Templates vary by instance; plain units never use specifiers.
        if unit.is_template() {
            assert!(
                start.iter().any(|token| token.contains("%i")),
                "{name}: ExecStart must use %i"
            );
        } else {
            assert!(
                unit.entries
                    .iter()
                    .all(|(_, _, value)| !value.contains("%i") && !value.contains("%I")),
                "{name}: %i in a non-template unit"
            );
        }
    }
}

/// The `chio ...` invocation a `supervise --exec` line wraps, without its program.
fn pre_inner(args: &[String]) -> Vec<String> {
    let separator = args
        .iter()
        .position(|token| token == "--")
        .expect("wrapped command");
    args[separator + 2..].to_vec()
}

#[test]
fn the_edge_preflight_gates_exactly_the_launch_it_supervises() {
    let unit = Unit::parse(&package_root().join("systemd/chio-mcp-edge.service"));
    let mut usage = Usage::default();
    let lines = unit.exec_lines();
    let (pre_key, pre) = lines
        .iter()
        .find(|(key, _)| *key == "ExecStartPre")
        .expect("ExecStartPre");
    let (start_key, start) = lines
        .iter()
        .find(|(key, _)| *key == "ExecStart")
        .expect("ExecStart");
    let pre_wrapped = validate_command(&unit, pre_key, pre, &mut usage);
    let start_wrapped = validate_command(&unit, start_key, start, &mut usage);
    assert_eq!(
        pre_wrapped, start_wrapped,
        "the preflight must check the command the edge launches"
    );
    assert!(
        has_flag(pre, "--require-enforcement"),
        "the edge preflight must require enforcement"
    );
    assert_eq!(
        subcommand_path(&pre_inner(pre)),
        ["security", "preflight"],
        "the check must be the preflight"
    );
    for flag in [
        "--signed-manifest",
        "--manifest-public-key",
        "--cage-policy",
        "--cage-policy-signer",
        "--server-id",
        "--session-db",
    ] {
        assert_eq!(
            flag_values(pre, flag),
            flag_values(start, flag)
                .into_iter()
                .take(1)
                .collect::<Vec<_>>(),
            "{flag} must agree between the preflight and the launch"
        );
    }
    assert_eq!(
        unit.value("Service", "KillMode"),
        Some("mixed"),
        "the wrapped server must outlive the edge's drain"
    );
    assert_eq!(
        flag_values(start, "--ready-http-bearer-env"),
        ["CHIO_ADMIN_TOKEN"],
        "the admin health route takes the admin bearer"
    );
    assert!(unit
        .value("Unit", "Requires")
        .is_some_and(|value| value.contains("chio-trust-control.service")));
    assert!(unit
        .value("Unit", "After")
        .is_some_and(|value| value.contains("chio-trust-control.service")));
}

#[test]
fn the_trust_preflight_names_the_stores_the_service_opens() {
    let unit = Unit::parse(&package_root().join("systemd/chio-trust-control.service"));
    let lines = unit.exec_lines();
    let (_, pre) = lines
        .iter()
        .find(|(key, _)| *key == "ExecStartPre")
        .expect("ExecStartPre");
    let (_, start) = lines
        .iter()
        .find(|(key, _)| *key == "ExecStart")
        .expect("ExecStart");
    assert!(pre.iter().any(|token| token == "preflight"));
    assert!(
        !has_flag(pre, "--require-enforcement"),
        "trust-control does not confine a wrapped server"
    );
    for flag in ["--receipt-db", "--authority-db", "--session-db"] {
        let store = flag_values(pre, flag);
        assert_eq!(store.len(), 1, "{flag} in the preflight");
        assert_eq!(
            store,
            flag_values(start, flag),
            "{flag} must agree between the preflight and the service"
        );
        assert!(
            store[0].starts_with("/var/lib/chio-trust-control/"),
            "{flag} lives in the state directory"
        );
    }
    assert!(
        !has_flag(start, "--authority-seed-file"),
        "the authority key lives in the authority database"
    );
}

#[test]
fn the_help_parser_reads_clap_output() {
    let surface = parse_help(
        "Usage: chio security supervise [OPTIONS] -- <COMMAND>...\n\nArguments:\n  [COMMAND]...\n\nOptions:\n      --credentials-dir <PATH>\n          Directory holding the credential files\n\n          [env: CREDENTIALS_DIRECTORY=]\n\n      --exec\n          Deliver the credentials\n\n  -h, --help\n          Print help\n",
    );
    assert_eq!(surface.flags.get("credentials-dir"), Some(&true));
    assert_eq!(surface.flags.get("exec"), Some(&false));
    assert_eq!(surface.flags.get("help"), Some(&false));
    let surface = parse_help("Usage: chio security <COMMAND>\n\nCommands:\n  preflight   Prove the host\n  supervise   Run one service\n  help        Print this message\n\nOptions:\n      --json\n          Short alias\n");
    assert_eq!(
        surface.subcommands.iter().cloned().collect::<Vec<_>>(),
        ["help", "preflight", "supervise"]
    );
    assert_eq!(argv(r#"a "b c" d\"#), ["a", "b c", "d\\"]);
}
