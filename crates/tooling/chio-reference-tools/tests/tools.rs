//! The three tools driven over their stdio protocol.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

struct Tool {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Tool {
    fn spawn(binary: &str, arguments: &[&str]) -> Self {
        let mut child = Command::new(binary)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn tool");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut tool = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        let initialized = tool.request(
            "initialize",
            json!({ "protocolVersion": "2025-11-25", "capabilities": {} }),
        );
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        tool.notify("notifications/initialized");
        tool
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.stdin, "{message}").expect("write request");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        let response: Value = serde_json::from_str(&line).expect("JSON response");
        assert_eq!(response["id"], id);
        response
    }

    fn notify(&mut self, method: &str) {
        let message = json!({ "jsonrpc": "2.0", "method": method });
        writeln!(self.stdin, "{message}").expect("write notification");
        self.stdin.flush().expect("flush");
    }

    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }

    fn tool_names(&mut self) -> Vec<String> {
        self.request("tools/list", json!({}))["result"]["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .map(|tool| tool["name"].as_str().expect("name").to_string())
            .collect()
    }

    fn finish(mut self) -> std::process::ExitStatus {
        drop(self.stdin);
        self.child.wait().expect("wait")
    }
}

fn reader(root: &Path) -> Tool {
    Tool::spawn(
        env!("CARGO_BIN_EXE_chio-tool-repo-reader"),
        &["--root", root.to_str().unwrap()],
    )
}

fn text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content")
}

fn structured(response: &Value) -> &Value {
    &response["result"]["structuredContent"]
}

#[test]
fn the_reader_lists_reads_and_stats_inside_its_root() {
    let root = tempfile::tempdir().expect("root");
    std::fs::create_dir(root.path().join("src")).unwrap();
    std::fs::write(
        root.path().join("src/lib.rs"),
        "pub fn answer() -> u8 { 42 }\n",
    )
    .unwrap();
    std::fs::write(root.path().join("README.md"), "# reference\n").unwrap();
    let mut tool = reader(root.path());
    assert_eq!(tool.tool_names(), ["list_directory", "read_file", "stat"]);
    let listing = tool.call("list_directory", json!({}));
    let names: Vec<&str> = structured(&listing)["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["README.md", "src"]);
    let read = tool.call("read_file", json!({ "path": "src/lib.rs" }));
    assert_eq!(read["result"]["isError"], false);
    assert_eq!(
        structured(&read)["content"],
        "pub fn answer() -> u8 { 42 }\n"
    );
    assert_eq!(structured(&read)["truncated"], false);
    let capped = tool.call("read_file", json!({ "path": "src/lib.rs", "max_bytes": 6 }));
    assert_eq!(structured(&capped)["content"], "pub fn");
    assert_eq!(structured(&capped)["truncated"], true);
    let stat = tool.call("stat", json!({ "path": "src" }));
    assert_eq!(structured(&stat)["kind"], "directory");
    assert!(tool.finish().success());
}

#[test]
fn the_reader_refuses_every_way_out_of_its_root() {
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("secret"), "no").unwrap();
    let root = tempfile::tempdir().expect("root");
    std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("link")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("linked-dir")).unwrap();
    let mut tool = reader(root.path());
    for path in [
        "../secret",
        "/etc/passwd",
        "link",
        "linked-dir/secret",
        "src/../../secret",
    ] {
        let response = tool.call("read_file", json!({ "path": path }));
        assert_eq!(response["result"]["isError"], true, "{path}: {response}");
        assert!(text(&response).contains("refused"), "{path}: {response}");
    }
    let missing = tool.call("read_file", json!({ "path": "absent" }));
    assert_eq!(missing["result"]["isError"], true);
    assert!(text(&missing).contains("does not exist"));
    let invalid = tool.call("read_file", json!({ "path": 7 }));
    assert_eq!(invalid["error"]["code"], -32602);
    assert!(tool.finish().success());
}

#[test]
fn the_reader_stops_at_its_session_budget() {
    let root = tempfile::tempdir().expect("root");
    for index in 0..65 {
        std::fs::write(root.path().join(format!("f{index}")), "x").unwrap();
    }
    let mut tool = reader(root.path());
    for index in 0..64 {
        let response = tool.call("read_file", json!({ "path": format!("f{index}") }));
        assert_eq!(response["result"]["isError"], false, "{response}");
    }
    let again = tool.call("read_file", json!({ "path": "f0" }));
    assert_eq!(
        again["result"]["isError"], false,
        "a file already read costs no new grant"
    );
    let overflow = tool.call("read_file", json!({ "path": "f64" }));
    assert_eq!(overflow["result"]["isError"], true);
    assert!(text(&overflow).contains("64 distinct files"));
    assert!(tool.finish().success());
}

#[test]
fn the_writer_replaces_one_pre_created_file_in_place() {
    let directory = tempfile::tempdir().expect("directory");
    let artifact = directory.path().join("report.json");
    std::fs::write(&artifact, "").unwrap();
    let mut tool = Tool::spawn(
        env!("CARGO_BIN_EXE_chio-tool-artifact-writer"),
        &["--artifact", artifact.to_str().unwrap()],
    );
    let path = artifact.to_str().unwrap();
    assert_eq!(tool.tool_names(), ["write_file", "read_file", "stat"]);
    let written = tool.call(
        "write_file",
        json!({ "path": path, "content": "{\"ok\":true}" }),
    );
    assert_eq!(written["result"]["isError"], false, "{written}");
    assert_eq!(structured(&written)["bytes_written"], 11);
    assert_eq!(std::fs::read_to_string(&artifact).unwrap(), "{\"ok\":true}");
    let shorter = tool.call("write_file", json!({ "path": path, "content": "{}" }));
    assert_eq!(structured(&shorter)["bytes_written"], 2);
    assert_eq!(
        std::fs::read_to_string(&artifact).unwrap(),
        "{}",
        "a shorter write truncates"
    );
    let read = tool.call("read_file", json!({ "path": path }));
    assert_eq!(structured(&read)["content"], "{}");
    let status = tool.call("stat", json!({ "path": path }));
    assert_eq!(structured(&status)["size"], 2);
    assert_eq!(
        structured(&status)["sha256"],
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
    let oversized = tool.call(
        "write_file",
        json!({ "path": path, "content": "x".repeat(1024 * 1024 + 1) }),
    );
    assert_eq!(oversized["result"]["isError"], true);
    assert_eq!(
        std::fs::read_to_string(&artifact).unwrap(),
        "{}",
        "a refused write leaves the artifact alone"
    );
    let other = directory.path().join("other");
    let elsewhere = tool.call(
        "write_file",
        json!({ "path": other.to_str().unwrap(), "content": "no" }),
    );
    assert_eq!(elsewhere["result"]["isError"], true);
    assert!(text(&elsewhere).contains("not the artifact"), "{elsewhere}");
    assert!(!other.exists());
    assert!(tool.finish().success());
    assert_eq!(
        std::fs::read_dir(directory.path()).unwrap().count(),
        1,
        "nothing else was created"
    );
}

#[test]
fn the_writer_needs_its_artifact_before_it_starts() {
    let directory = tempfile::tempdir().expect("directory");
    let status = Command::new(env!("CARGO_BIN_EXE_chio-tool-artifact-writer"))
        .args([
            "--artifact",
            directory.path().join("missing").to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run writer");
    assert!(!status.success());
    assert!(!directory.path().join("missing").exists());
}

#[test]
fn the_digest_tool_computes_without_any_grant() {
    let mut tool = Tool::spawn(env!("CARGO_BIN_EXE_chio-tool-digest"), &[]);
    assert_eq!(tool.tool_names(), ["sha256", "canonical_json"]);
    let digest = tool.call("sha256", json!({ "text": "abc" }));
    assert_eq!(
        structured(&digest)["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let canonical = tool.call(
        "canonical_json",
        json!({ "value": { "z": [1, 2], "a": { "y": null, "b": "x" } } }),
    );
    assert_eq!(
        structured(&canonical)["canonical"],
        "{\"a\":{\"b\":\"x\",\"y\":null},\"z\":[1,2]}"
    );
    let unknown = tool.request("resources/list", json!({}));
    assert_eq!(unknown["error"]["code"], -32601);
    assert!(tool.finish().success());
    let with_arguments = Command::new(env!("CARGO_BIN_EXE_chio-tool-digest"))
        .arg("--anything")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run digest");
    assert!(!with_arguments.success());
}
