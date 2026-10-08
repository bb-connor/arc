#!/usr/bin/env python3
"""Compile and run the bounded architecture models; retain source-bound evidence."""

import hashlib
import json
import argparse
import os
from pathlib import Path
import stat
import subprocess
import time
import types

ROOT = Path(__file__).resolve().parent
TOOLCHAIN = "+1.94.1"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, output_root, name, commands, cwd=ROOT):
    started = time.monotonic()
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    log = output_root / (name + ".log")
    log.write_text(result.stdout + result.stderr)
    commands.append({"name":name,"command":command,"cwd":str(cwd),"exit_code":result.returncode,
                     "seconds":round(time.monotonic()-started, 6),"log":log.name,"log_sha256":sha256(log)})
    if result.returncode != 0:
        raise SystemExit(f"Failed: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def capture_inputs(paths, destination):
    """Hash and compile the same captured bytes, independently of later live edits."""
    destination.mkdir(mode=0o700)
    rows = []
    parent = os.open(ROOT,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for path in paths:
            descriptor = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("model input is not a regular file")
                with os.fdopen(os.dup(descriptor),"rb") as stream:
                    data = stream.read()
                after = os.fstat(descriptor)
                located = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                identity = lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
                if identity(before) != identity(after) or identity(after) != identity(located):
                    raise ValueError("model input changed during capture")
            finally:
                os.close(descriptor)
            captured = destination / path.name
            with captured.open("xb") as output:
                output.write(data)
            captured.chmod(0o444)
            rows.append({"path":path.name,"sha256":hashlib.sha256(data).hexdigest()})
    finally:
        os.close(parent)
    destination.chmod(0o500)
    return rows


def optional_compiler_capture(repository, output, configuration, expected_sha, dimension="formal"):
    """Execute only the explicitly pinned helper's original no-follow bytes."""
    if configuration is None:
        if expected_sha is not None:raise ValueError("compiler.capture_configuration_required")
        return None,None
    repository,configuration = Path(repository),Path(configuration)
    def public_path(path):
        secrets = {"credentials","credentials.json","credentials.toml",".netrc",".git-credentials",
            ".npmrc",".pypirc",".aws",".ssh",".gnupg",".secrets",".auth",".password-store",
            "id_rsa","id_ed25519","id_ecdsa","id_dsa"}
        if (not path.is_absolute() or ".." in path.parts or str(path).startswith("//")
                or path.suffix.casefold() in {".pem",".key",".p12",".pfx",".keystore"}
                or any(part.casefold() in secrets for part in path.parts)):
            raise ValueError("compiler.capture_input_policy")
    public_path(configuration)
    if (type(expected_sha) is not str or len(expected_sha) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha)
            or not configuration.is_relative_to(repository/"target")):
        raise ValueError("compiler.capture_configuration_pin_required")
    def read(path,readonly=False):
        public_path(path)
        descriptors,locations = [],[]
        identity = lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_size,item.st_mtime_ns,item.st_ctime_ns,item.st_nlink)
        try:
            parent = os.open("/",os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW);descriptors.append(parent)
            for part in path.parts[1:-1]:
                child = os.open(part,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent);descriptors.append(child)
                value = identity(os.fstat(child))[:3]
                if value != identity(os.stat(part,dir_fd=parent,follow_symlinks=False))[:3]:raise ValueError("compiler.capture_parent_changed")
                locations.append((parent,part,child,value));parent = child
            descriptor = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent);descriptors.append(descriptor)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024*1024 or before.st_nlink != 1 or readonly and before.st_mode & 0o222:
                raise ValueError("compiler.capture_input")
            body = bytearray()
            for chunk in iter(lambda:os.read(descriptor,1024*1024),b""):body.extend(chunk)
            if identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)):
                raise ValueError("compiler.capture_input_changed")
            for ancestor,name,child,value in locations:
                if identity(os.fstat(child))[:3] != value or identity(os.stat(name,dir_fd=ancestor,follow_symlinks=False))[:3] != value:
                    raise ValueError("compiler.capture_parent_changed")
            return bytes(body)
        finally:
            for descriptor in reversed(descriptors):os.close(descriptor)
    raw = read(configuration,readonly=True)
    if hashlib.sha256(raw).hexdigest() != expected_sha:raise ValueError("compiler.capture_configuration_pin")
    def pairs(rows):
        result = {}
        for name,value in rows:
            if name in result:raise ValueError("compiler.capture_duplicate_field")
            result[name] = value
        return result
    options = json.loads(raw,object_pairs_hook=pairs)
    image = repository/"scripts/compiled-dimension-profiles.py"
    body = read(image)
    if options["tools"]["helper"] != {"path":str(image),"sha256":hashlib.sha256(body).hexdigest(),"size":len(body)}:
        raise ValueError("compiler.capture_helper_pin")
    module = types.ModuleType("owned_dimension_compiler_capture");module.__file__ = str(image)
    exec(compile(body,str(image),"exec"),module.__dict__)
    return module,module.open_capture(repository,output/"compiled-capture",configuration,expected_sha,dimension)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True, help="fresh directory below the candidate's target directory")
    parser.add_argument("--compiled-capture-config",type=Path,help="explicit readonly version-two compiler capture options")
    parser.add_argument("--compiled-capture-sha256",help="exact reviewed capture configuration byte digest")
    args = parser.parse_args()
    repository = ROOT.parents[3].resolve(strict=True)
    output_root = args.output.absolute()
    if output_root.exists() or output_root.is_symlink():
        parser.error("output already exists; retained evidence must not be overwritten")
    if ".." in output_root.parts:
        parser.error("output contains parent traversal")
    if not output_root.is_relative_to(repository / "target") or output_root == repository / "target":
        parser.error("output must be a fresh directory below the candidate's target directory")
    if (repository / "target").is_symlink():
        parser.error("output target directory is symbolic")
    existing = output_root.parent
    while not existing.exists():
        existing = existing.parent
    located = existing.resolve(strict=True)
    if located != repository and not located.is_relative_to(repository / "target"):
        parser.error("output parent escapes the candidate")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    output_root = output_root.parent.resolve(strict=True) / output_root.name
    if not output_root.is_relative_to(repository / "target") or output_root == repository / "target":
        parser.error("output must be a fresh directory below the candidate's target directory")
    output_root.mkdir(mode=0o700)
    commands = []
    sources = sorted(ROOT.glob("*.rs"))
    captured = output_root / "inputs"
    source_rows = capture_inputs([*sources, ROOT / "run.py"],captured)
    support,capture = optional_compiler_capture(repository,output_root,args.compiled_capture_config,args.compiled_capture_sha256)
    try:
        if capture is not None:
            if set(capture.options["actions"]) != {"ownership","review","third"} or any(
                    not Path(action["target"]).is_relative_to(output_root) for action in capture.options["actions"].values()):
                raise ValueError("model.capture_action_inventory")
        projections = []
        if capture is not None:
            for row in source_rows:
                original,snapshot = ROOT/row["path"],captured/row["path"]
                image = {"path":str(original),"sha256":row["sha256"],"size":original.stat().st_size}
                projections.append(support.capture_source_projection(image,{**image,"path":str(snapshot)}))
        run(["rustfmt", TOOLCHAIN, "--edition", "2021", "--check", *[path.name for path in sources]],
            output_root, "format", commands, cwd=captured)
        compiler = run(["rustc", TOOLCHAIN, "-Vv"], output_root, "compiler", commands)
        outputs = []
        for name, entry, output in [
            ("ownership", "recovery.rs", "results.txt"),
            ("review", "review.rs", "review-results.txt"),
            ("third", "third.rs", "third-results.txt"),
        ]:
            if capture is None:
                binary = output_root / name
                run(["rustc", TOOLCHAIN, "--edition", "2021", "-D", "warnings", entry, "-o", str(binary)],
                    output_root, "compile-"+name, commands, cwd=captured)
            else:
                target = Path(capture.options["actions"][name]["target"])
                produced = capture.produce(name,3600,captured_inputs=captured,output_root=target)
                binary = target/name
                producer = produced["producer"]
                commands.append({"name":"compile-"+name,"command":producer["contract"]["command"],"cwd":str(captured),
                    "exit_code":producer["actual_exit"],"seconds":producer["duration_seconds"],
                    "log":str((repository/producer["log"]["path"]).relative_to(output_root)),"log_sha256":producer["log"]["sha256"],
                    "compiled_capture":produced["reference"]})
            binary.chmod(0o500)
            executable_sha256 = sha256(binary)
            result = run([str(binary)], output_root, "execute-"+name, commands)
            if sha256(binary) != executable_sha256:
                raise SystemExit("model executable changed during execution")
            outputs.append((name, entry, output, result, executable_sha256))
            if capture is not None:
                image = {"path":str(binary),"sha256":executable_sha256,"size":binary.stat().st_size}
                unit,receipt = capture.produced_output(name,image)
                subject = "dimension/formal/"+name
                capture.observe(name,{subject:[unit]},{subject:[image]},[receipt] if receipt is not None else [],source_projections=projections)
        # Publish evidence only after every binary completes successfully.
        for _, _, output, result, _ in outputs:
            (output_root / output).write_text(result)
        by_compile = {row["name"]:row for row in commands}
        evidence = {
            "schema": "chio.recovery-architecture-model-evidence.v2" if capture is not None else "chio.recovery-architecture-model-evidence.v1",
            "scope": "Bounded abstract protocols only; no production qualification",
            "compiler": compiler,
            "toolchain": TOOLCHAIN,
            "edition": "2021",
            "warnings_denied": True,
            "formatting_checked": True,
            "commands":commands,
            "sources": source_rows,
            "input_snapshot":"inputs",
            "runs": [{"name": name, "entry": entry, "output": output,
                      "output_sha256": sha256(output_root / output), "exit_code": 0,
                      "executable":str(Path(by_compile["compile-"+name]["command"][-1]).relative_to(output_root)),"executable_sha256":executable_sha256,
                      **({"executable_size":Path(by_compile["compile-"+name]["command"][-1]).stat().st_size} if capture is not None else {})}
                     for name, entry, output, _, executable_sha256 in outputs],
        }
        current_rows = [{"path":path.name, "sha256":sha256(path)} for path in [*sources, ROOT / "run.py"]]
        if current_rows != source_rows or sorted(ROOT.glob("*.rs")) != sources:
            raise SystemExit("model source changed during execution")
        (output_root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        if capture is not None:
            index = capture.finish()
            (output_root/"compiled-capture-index.json").write_text(json.dumps({"capture_index":index,
                "qualified":False,"compiled_closure_status":"not-established"},indent=2)+"\n")
            capture.close()
        for name, _, _, output, _ in outputs:
            print(f"{name}: compiled and completed")
            for line in output.splitlines():
                if "BASELINE PASS" in line or "MUTATION REJECTED" in line or "CONTRACT PASS" in line:
                    print(line)
    finally:
        if capture is not None:capture.close()


if __name__ == "__main__":
    main()
