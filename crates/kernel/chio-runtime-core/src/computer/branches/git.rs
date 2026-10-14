use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use super::BranchError;

/// Configuration forced on every invocation. Hooks, fsmonitor, attribute
/// files, alternate ref commands, transports and automatic maintenance never
/// run against the private object store.
const OVERRIDES: &[&str] = &[
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "core.alternateRefsCommand=",
    "-c",
    "core.logAllRefUpdates=false",
    "-c",
    "protocol.allow=never",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
];

pub(super) const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// The only configuration a store may carry: the keys `git init --bare`
/// writes for a SHA-1 store with the files ref backend.
const STORE_CONFIG: &[&str] = &[
    "core.repositoryformatversion=0",
    "core.filemode=true",
    "core.bare=true",
];

/// Accepts exactly a 40-character lowercase hexadecimal object id.
pub(super) fn check_oid(value: &str) -> Result<(), BranchError> {
    if value.len() == ZERO_OID.len()
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(BranchError::InvalidObjectId)
    }
}

/// A git CLI bound to one private bare object store. The child process never
/// inherits the caller's environment, system or global configuration.
pub(super) struct Git {
    binary: PathBuf,
    git_dir: PathBuf,
}

impl Git {
    pub(super) fn open(binary: &Path, git_dir: &Path) -> Result<Self, BranchError> {
        if !binary.is_absolute() || !git_dir.is_absolute() {
            return Err(BranchError::PathNotAbsolute);
        }
        let git = Self {
            binary: binary.to_path_buf(),
            git_dir: git_dir.to_path_buf(),
        };
        if !git_dir.join("HEAD").is_file() {
            std::fs::create_dir_all(git_dir)?;
            git.run(
                "init",
                &["init", "--bare", "--quiet", "--template="],
                None,
                None,
            )?;
        }
        git.check_store()?;
        let config = git.git_dir.join("config");
        let config = config.to_str().ok_or(BranchError::PathNotAbsolute)?;
        let listed = git.run_line(
            "config",
            &["config", "--file", config, "--no-includes", "--list"],
            None,
            None,
        )?;
        let mut keys: Vec<&str> = listed.lines().collect();
        keys.sort_unstable();
        let mut expected = STORE_CONFIG.to_vec();
        expected.sort_unstable();
        if let Some(extra) = keys.iter().find(|key| !expected.contains(key)) {
            return Err(BranchError::UnsupportedStoreConfig((*extra).to_owned()));
        }
        Ok(git)
    }

    fn check_store(&self) -> Result<(), BranchError> {
        for name in ["alternates", "http-alternates"] {
            if self.git_dir.join("objects/info").join(name).exists() {
                return Err(BranchError::AlternatesPresent);
            }
        }
        Ok(())
    }

    pub(super) fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    fn command(&self, args: &[&str], index: Option<&Path>) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .env("GIT_DIR", &self.git_dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("HOME", &self.git_dir)
            .env("LC_ALL", "C")
            .args(OVERRIDES)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(index) = index {
            command.env("GIT_INDEX_FILE", index);
        }
        command
    }

    /// Runs one command and returns its raw output whatever the exit status.
    pub(super) fn output(
        &self,
        op: &'static str,
        args: &[&str],
        stdin: Option<&[u8]>,
        index: Option<&Path>,
    ) -> Result<Output, BranchError> {
        self.check_store()?;
        let mut child = self
            .command(args, index)
            .spawn()
            .map_err(|_| BranchError::Git(op))?;
        if let Some(mut pipe) = child.stdin.take() {
            if let Some(bytes) = stdin {
                pipe.write_all(bytes).map_err(|_| BranchError::Git(op))?;
            }
        }
        child.wait_with_output().map_err(|_| BranchError::Git(op))
    }

    /// Runs one command and refuses any non-zero exit.
    pub(super) fn run(
        &self,
        op: &'static str,
        args: &[&str],
        stdin: Option<&[u8]>,
        index: Option<&Path>,
    ) -> Result<Vec<u8>, BranchError> {
        let output = self.output(op, args, stdin, index)?;
        if !output.status.success() {
            return Err(BranchError::Git(op));
        }
        Ok(output.stdout)
    }

    pub(super) fn run_line(
        &self,
        op: &'static str,
        args: &[&str],
        stdin: Option<&[u8]>,
        index: Option<&Path>,
    ) -> Result<String, BranchError> {
        let stdout = self.run(op, args, stdin, index)?;
        let text = String::from_utf8(stdout).map_err(|_| BranchError::Git(op))?;
        Ok(text.trim_end_matches('\n').to_owned())
    }

    /// The object a ref names, or `None` when the ref is absent.
    pub(super) fn resolve(&self, reference: &str) -> Result<Option<String>, BranchError> {
        let output = self.output(
            "rev-parse",
            &["rev-parse", "--verify", "--quiet", reference],
            None,
            None,
        )?;
        if !output.status.success() {
            return Ok(None);
        }
        let text = String::from_utf8(output.stdout).map_err(|_| BranchError::Git("rev-parse"))?;
        let oid = text.trim_end_matches('\n');
        check_oid(oid)?;
        Ok(Some(oid.to_owned()))
    }

    pub(super) fn write_blob(&self, bytes: &[u8]) -> Result<String, BranchError> {
        let oid = self.run_line(
            "hash-object",
            &["hash-object", "-w", "--no-filters", "--stdin"],
            Some(bytes),
            None,
        )?;
        check_oid(&oid)?;
        Ok(oid)
    }

    pub(super) fn read_blob(&self, oid: &str) -> Result<Vec<u8>, BranchError> {
        self.run("cat-file", &["cat-file", "blob", oid], None, None)
    }

    /// Applies ref updates as one atomic transaction. Each line is a
    /// `verify`, `create` or `update` instruction with its expected old value.
    /// Returns `false` when any expected value no longer holds.
    pub(super) fn transaction(&self, instructions: &[String]) -> Result<bool, BranchError> {
        let mut script = String::from("start\n");
        for line in instructions {
            if line.contains(['\n', '\r', '\0']) {
                return Err(BranchError::Git("update-ref"));
            }
            script.push_str(line);
            script.push('\n');
        }
        script.push_str("prepare\ncommit\n");
        let output = self.output(
            "update-ref",
            &["update-ref", "--stdin"],
            Some(script.as_bytes()),
            None,
        )?;
        Ok(output.status.success())
    }
}
