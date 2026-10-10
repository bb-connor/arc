#!/usr/bin/env python3
"""Join owned dimension compilation actions to their actual produced subjects.

These contracts are consumed by the recorder, dimension callers, and independent
qualification verifier. Decoded joins alone never establish compiler execution,
native enforcement, original image custody, or a qualified feature.
"""
from pathlib import Path, PurePosixPath
from contextlib import ExitStack, contextmanager
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import time
import types
import argparse


LINUX_CASE_PREFIX = "recovery::tests::knowledge::confinement::linux::"
CANARY_MODES = ("error","log","progress","stream","file","callback","wrong-predicate","overflow","hang")
CAGE_PHASES = ("strict-static-normal","strict-native-all-targets","strict-static-mutants","strict-native-mutants")
FORMAL_ENTRIES = {"ownership":"recovery.rs","review":"review.rs","third":"third.rs"}
CALLER_SOURCES = {
    "linux":"scripts/run-confined-return-linux-acceptance.py",
    "formal":"docs/architecture/recoverable-agent-runtime/model/run.py",
    "live_provider":"fixtures/recovery-product/campaign_main.py",
}
LIVE_NATIVE_COMMAND = ["cargo","test","--offline","--locked","-p","chio-control-plane","--lib",
                       "live_comparative_native_host","--","--ignored","--test-threads=1"]
MAX_UNIT_ROWS = 100000
SECRET_NAMES = frozenset({"credentials","credentials.json","credentials.toml",".netrc",".git-credentials",
    ".npmrc",".pypirc","id_rsa","id_ed25519","id_ecdsa","id_dsa",".aws",".ssh",".gnupg",
    ".secrets",".auth",".password-store"})
SECRET_SUFFIXES = frozenset({".pem",".key",".p12",".pfx",".keystore"})


def require(condition, reason):
    if not condition:
        raise ValueError("qualification.compiled_dimension_"+reason)


def absolute_path(value):
    require(type(value) is str and value.startswith("/") and not value.startswith("//")
            and "\x00" not in value and ".." not in PurePosixPath(value).parts
            and all(ord(character) >= 32 and ord(character) != 127 for character in value)
            and PurePosixPath(value).as_posix() == value,"path")
    return Path(value)


def image_key(value):
    require(type(value) is dict and {"path","sha256","size"} <= set(value)
            and type(value["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}",value["sha256"])
            and type(value["size"]) is int and 0 <= value["size"] <= 512*1024**2,"image")
    return str(absolute_path(value["path"])),value["sha256"],value["size"]


def compilation_contract(dimension, label, repository, *, captured_inputs=None, output_root=None):
    """Finite owning commands, never a borrowed Cargo gate or arbitrary argv."""
    require(type(dimension) is str and dimension in CALLER_SOURCES and type(label) is str,"producer")
    repository = absolute_path(str(repository))
    if dimension == "linux":
        build = ["cargo","build","--offline","--locked","--target","x86_64-unknown-linux-musl","-p","chio-cage"]
        test = ["cargo","test","--offline","--locked","-p","chio-cage"]
        commands = {
            "strict-static-normal":[*build,"--bin","chio-cage-init","--features","real-linux-enforcement"],
            "strict-native-all-targets":[*test,"--all-targets","--features","real-linux-enforcement","--no-run"],
            "strict-static-mutants":[*build,"--bin","chio-cage-init","--features","real-linux-enforcement,enforcement-mutants"],
            "strict-native-mutants":[*test,"--test","linux_enforcement","--features","real-linux-enforcement,enforcement-mutants","--no-run"],
            "static-tools":[*build,"--bin","chio-cage-init","--bin","chio-confined-reader"],
            "control-plane-library":["cargo","test","--offline","--locked","-p","chio-control-plane","--lib",LINUX_CASE_PREFIX,"--no-run"],
            "store-library":["cargo","test","--offline","--locked","-p","chio-store-sqlite","--lib","--no-run"],
            **{"canary-"+mode:[*build,"--example","confined-return-canary"] for mode in CANARY_MODES},
        }
        require(label in commands,"producer")
        environment = {"CHIO_CONFINED_CANARY_MODE":label.removeprefix("canary-")} if label.startswith("canary-") else {}
        return {"command":commands[label],"cwd":str(repository),"environment":environment,
                "caller_source":CALLER_SOURCES[dimension]}
    if dimension == "live_provider":
        require(label == "native-host-library","producer")
        # Compilation is separate from the unchanged live execution command.
        # The provider process and its credentials never enter a compiler scope.
        command = LIVE_NATIVE_COMMAND[:LIVE_NATIVE_COMMAND.index("--")]+["--no-run"]
        return {"command":command,"cwd":str(repository),"environment":{},"caller_source":CALLER_SOURCES[dimension]}
    require(label in FORMAL_ENTRIES and captured_inputs is not None and output_root is not None,"producer")
    captured = absolute_path(str(captured_inputs))
    output = absolute_path(str(output_root))
    require(captured.is_relative_to(repository/"target") and output.is_relative_to(repository/"target")
            and captured != output and not captured.is_relative_to(output),"projection")
    return {"command":["rustc","+1.94.1","--edition","2021","-D","warnings",FORMAL_ENTRIES[label],
                       "--emit","dep-info,link","-o",str(output/label)],
            "cwd":str(captured),"environment":{},"caller_source":CALLER_SOURCES[dimension],
            "entry_source":"docs/architecture/recoverable-agent-runtime/model/"+FORMAL_ENTRIES[label]}


def checked_dimension_binding(value, expected_dimension_reference):
    """Bind the profile to the actual owning record retained by the caller."""
    require(type(value) is dict and set(value) == {"schema","dimension","label","record"}
            and value["schema"] == "chio.compiled-dimension-production-binding.v2"
            and type(value["dimension"]) is str and value["dimension"] in CALLER_SOURCES
            and type(value["label"]) is str and type(value["record"]) is dict
            and set(value["record"]) == {"path","sha256"}
            and type(value["record"]["path"]) is str
            and type(value["record"]["sha256"]) is str
            and re.fullmatch(r"[a-f0-9]{64}",value["record"]["sha256"]),"binding")
    require(value["record"] == expected_dimension_reference,"binding")
    labels = {"linux": {"strict-static-normal","strict-native-all-targets","strict-static-mutants",
        "strict-native-mutants","static-tools","control-plane-library","store-library",
        *{"canary-"+mode for mode in CANARY_MODES}}, "formal": set(FORMAL_ENTRIES),
        "live_provider": {"native-host-library"}}
    require(value["label"] in labels[value["dimension"]],"producer")
    return value["dimension"],value["label"]


def produced_subject_roots(rows, subjects):
    """Every root comes from one successful actual unit, with no skipped rows."""
    require(type(rows) is list and 0 < len(rows) <= MAX_UNIT_ROWS
            and type(subjects) is dict and bool(subjects),"rows")
    units, outputs = {}, {}
    for row in rows:
        require(type(row) is dict and type(row.get("invocation_id")) is str
                and re.fullmatch(r"[a-f0-9]{32}",row["invocation_id"])
                and type(row.get("kind")) is str and row["kind"] in {"probe","compilation"}
                and row.get("status") == "success" and type(row.get("compiler_exit")) is int
                and row["compiler_exit"] == 0 and row["invocation_id"] not in units,"rows")
        units[row["invocation_id"]] = row
        require(type(row.get("outputs")) is list,"rows")
        if row["kind"] == "probe":
            require(not row["outputs"],"rows")
            continue
        for image in row["outputs"]:
            key = image_key(image)
            require(type(image.get("role")) is str and image["role"] in {"unit","depfile"},"rows")
            if image["role"] == "depfile":
                continue
            require(key not in outputs,"root_producer")
            outputs[key] = row["invocation_id"]
    matched = {}
    for name, images in subjects.items():
        require(type(name) is str and name.startswith("dimension/") and type(images) is list
                and bool(images),"subjects")
        keys = [image_key(image) for image in images]
        require(len(keys) == len(set(keys)) and all(key in outputs for key in keys),"root_producer")
        matched[name] = [{"image":{"path":key[0],"sha256":key[1],"size":key[2]},
                          "invocation_id":outputs[key]} for key in keys]
    return matched


def checked_subject_copies(value, produced, executed):
    """Require owned output-to-executed-copy receipts and exact byte identities."""
    require(type(value) is list and len(value) <= 100000,"copies")
    roots = {image_key(image) for image in produced}
    targets = {image_key(image) for image in executed}
    covered, seen = set(), set()
    for receipt in value:
        require(type(receipt) is dict and set(receipt) == {"schema","source","destination","source_identity",
            "destination_identity","source_before_sha256","source_after_sha256","destination_sha256"}
            and receipt["schema"] == "chio.compiled-subject-copy-custody.v1","copies")
        source, destination = image_key(receipt["source"]),image_key(receipt["destination"])
        require(source in roots and destination in targets and source[1:] == destination[1:]
                and destination not in seen and all(receipt[key] == source[1] for key in
                    ["source_before_sha256","source_after_sha256","destination_sha256"]),"copies")
        for field in ["source_identity","destination_identity"]:
            identity = receipt[field]
            require(type(identity) is list and len(identity) == 7
                    and all(type(item) is int and item >= 0 for item in identity)
                    and stat.S_ISREG(identity[2]) and identity[3] == source[2] and identity[-1] == 1,"copies")
        covered.add(destination);seen.add(destination)
    require(all(image in roots or image in covered for image in targets),"executed_subject")
    return covered


def metadata_identity(value):
    return [value.st_dev,value.st_ino,value.st_mode,value.st_size,
            value.st_mtime_ns,value.st_ctime_ns,value.st_nlink]


@contextmanager
def held_directory(path):
    """Hold every original no-follow ancestor until its caller completes."""
    path = absolute_path(str(path))
    descriptors, locations = [], []
    try:
        parent = os.open("/",os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        for name in path.parts[1:]:
            before = os.stat(name,dir_fd=parent,follow_symlinks=False)
            child = os.open(name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
            descriptors.append(child)
            identity = metadata_identity(os.fstat(child))[:3]
            require(identity == metadata_identity(before)[:3],"copy_directory")
            locations.append((parent,name,child,identity))
            parent = child
        yield parent
        for ancestor,name,child,identity in locations:
            require(metadata_identity(os.fstat(child))[:3] == identity ==
                    metadata_identity(os.stat(name,dir_fd=ancestor,follow_symlinks=False))[:3],"copy_directory")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def capture_subject_copy(source, destination):
    """Copy a measured produced executable once, retaining original FD identity."""
    source_key = image_key(source)
    source_path, destination = Path(source_key[0]),absolute_path(str(destination))
    require(source_path != destination,"copy_destination")
    require(not any(part.casefold() in SECRET_NAMES for path in [source_path,destination] for part in path.parts)
            and source_path.suffix.casefold() not in SECRET_SUFFIXES
            and destination.suffix.casefold() not in SECRET_SUFFIXES,"copy_policy")
    created = None
    with ExitStack() as stack:
        original_parent = stack.enter_context(held_directory(source_path.parent))
        target_parent = stack.enter_context(held_directory(destination.parent))
        original_fd = os.open(source_path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=original_parent)
        stack.callback(os.close,original_fd)
        before = os.fstat(original_fd)
        identity = metadata_identity(before)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_mode & 0o111
                and not before.st_mode & 0o022 and before.st_size == source_key[2]
                and identity == metadata_identity(os.stat(source_path.name,dir_fd=original_parent,follow_symlinks=False)),
                "copy_source")
        target_fd = os.open(destination.name,os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o500,dir_fd=target_parent)
        stack.callback(os.close,target_fd)
        created = metadata_identity(os.fstat(target_fd))[:3]
        complete = False
        try:
            digest = hashlib.sha256()
            count = 0
            for chunk in iter(lambda:os.read(original_fd,1024*1024),b""):
                count += len(chunk)
                require(count <= source_key[2],"copy_source")
                digest.update(chunk)
                offset = 0
                while offset < len(chunk):
                    written = os.write(target_fd,chunk[offset:])
                    require(written > 0,"copy_destination")
                    offset += written
            require(count == source_key[2] and digest.hexdigest() == source_key[1],"copy_source")
            os.fsync(target_fd)
            os.fchmod(target_fd,0o500)
            os.lseek(target_fd,0,os.SEEK_SET)
            destination_digest = hashlib.sha256()
            destination_count = 0
            for chunk in iter(lambda:os.read(target_fd,1024*1024),b""):
                destination_count += len(chunk)
                require(destination_count <= count,"copy_destination")
                destination_digest.update(chunk)
            require(destination_count == count and destination_digest.hexdigest() == source_key[1],"copy_destination")
            os.lseek(original_fd,0,os.SEEK_SET)
            source_after_digest = hashlib.sha256()
            for chunk in iter(lambda:os.read(original_fd,1024*1024),b""):
                source_after_digest.update(chunk)
            require(source_after_digest.hexdigest() == source_key[1],"copy_source")
            after = metadata_identity(os.fstat(original_fd))
            require(after == identity == metadata_identity(os.stat(source_path.name,
                    dir_fd=original_parent,follow_symlinks=False)),"copy_source")
            copied = metadata_identity(os.fstat(target_fd))
            require(copied == metadata_identity(os.stat(destination.name,dir_fd=target_parent,follow_symlinks=False))
                    and copied[3] == count and copied[-1] == 1,"copy_destination")
            os.fsync(target_parent)
            complete = True
            receipt = {"schema":"chio.compiled-subject-copy-custody.v1",
                "source":{"path":source_key[0],"sha256":source_key[1],"size":source_key[2]},
                "destination":{"path":str(destination),"sha256":source_key[1],"size":source_key[2]},
                "source_identity":identity,"destination_identity":copied,
                "source_before_sha256":digest.hexdigest(),"source_after_sha256":source_after_digest.hexdigest(),
                "destination_sha256":destination_digest.hexdigest()}
        finally:
            if not complete:
                try:
                    current = metadata_identity(os.stat(destination.name,dir_fd=target_parent,follow_symlinks=False))[:3]
                    # Remove only this newly created original inode. A replacement
                    # remains untouched and the operation fails closed.
                    if current[:2] == created[:2]:os.unlink(destination.name,dir_fd=target_parent)
                except FileNotFoundError:
                    pass
    return receipt


def capture_source_projection(source, captured):
    """Observe the exact original and captured readonly compiler input bytes."""
    source_key, captured_key = image_key(source),image_key(captured)
    require(source_key[0] != captured_key[0] and source_key[1:] == captured_key[1:],"projection")
    paths = [Path(source_key[0]),Path(captured_key[0])]
    require(not any(part.casefold() in SECRET_NAMES for path in paths for part in path.parts)
            and not any(path.suffix.casefold() in SECRET_SUFFIXES for path in paths),"projection_policy")
    identities, digests = [], []
    with ExitStack() as stack:
        originals = []
        for path,key in zip(paths,[source_key,captured_key]):
            parent = stack.enter_context(held_directory(path.parent))
            descriptor = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
            stack.callback(os.close,descriptor)
            identity = metadata_identity(os.fstat(descriptor))
            require(stat.S_ISREG(identity[2]) and identity[-1] == 1 and identity[3] == key[2]
                    and identity == metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),"projection")
            identities.append(identity)
            originals.append((path,parent,descriptor,identity,key))
            digest,count = hashlib.sha256(),0
            for chunk in iter(lambda:os.read(descriptor,1024*1024),b""):
                count += len(chunk)
                require(count <= key[2],"projection")
                digest.update(chunk)
            require(count == key[2] and digest.hexdigest() == key[1],"projection")
            digests.append(digest.hexdigest())
        require(not identities[1][2] & 0o222,"projection_readonly")
        after = hashlib.sha256()
        os.lseek(originals[0][2],0,os.SEEK_SET)
        for chunk in iter(lambda:os.read(originals[0][2],1024*1024),b""):
            after.update(chunk)
        require(after.hexdigest() == source_key[1],"projection")
        for path,parent,descriptor,identity,_ in originals:
            require(metadata_identity(os.fstat(descriptor)) == identity
                    == metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),"projection")
    return {"schema":"chio.compiled-source-projection-custody.v1",
        "source":{"path":source_key[0],"sha256":source_key[1],"size":source_key[2]},
        "captured":{"path":captured_key[0],"sha256":captured_key[1],"size":captured_key[2]},
        "source_identity":identities[0],"captured_identity":identities[1],
        "source_before_sha256":digests[0],"source_after_sha256":after.hexdigest(),"captured_sha256":digests[1]}


def replace_owned_output_alias(unit, alias, target):
    """Replace only a new private target's Cargo alias with an observed copy.

    Cargo can create a second hard link after the wrapper records its unit. The
    trusted outside copier proves both original names, removes only that owned
    alias, then creates a fresh single-link executed copy from the producing
    unit. Original compiler records and retained images are never modified.
    """
    source,public = image_key(unit),image_key(alias)
    target = absolute_path(str(target))
    require(source[0] != public[0] and source[1:] == public[1:]
            and all(Path(key[0]).is_relative_to(target) for key in [source,public]),"output_alias")
    require(not any(part.casefold() in SECRET_NAMES for key in [source,public] for part in Path(key[0]).parts)
            and not any(Path(key[0]).suffix.casefold() in SECRET_SUFFIXES for key in [source,public]),"input_policy")
    with ExitStack() as stack:
        originals = []
        for key in [source,public]:
            path = Path(key[0]);parent = stack.enter_context(held_directory(path.parent))
            descriptor = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
            stack.callback(os.close,descriptor)
            identity = metadata_identity(os.fstat(descriptor))
            require(stat.S_ISREG(identity[2]) and identity[3] == key[2] and identity[2] & 0o111
                    and not identity[2] & 0o022 and identity[-1] in {1,2}
                    and identity == metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),"output_alias")
            digest = hashlib.sha256()
            for chunk in iter(lambda:os.read(descriptor,1024*1024),b""):digest.update(chunk)
            require(digest.hexdigest() == key[1],"output_alias")
            originals.append((path,parent,descriptor,identity))
        same_inode = originals[0][3][:2] == originals[1][3][:2]
        require(originals[0][3][-1] == originals[1][3][-1] == (2 if same_inode else 1),"output_alias")
        for path,parent,descriptor,identity in originals:
            require(metadata_identity(os.fstat(descriptor)) == identity
                    == metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),"output_alias")
        path,parent,_,_ = originals[1]
        os.unlink(path.name,dir_fd=parent);os.fsync(parent)
        require(os.fstat(originals[0][2]).st_nlink == 1,"output_alias")
        receipt = capture_subject_copy(unit,path)
    return receipt


def checked_source_projections(value, sources, repository, captured_inputs):
    """A model snapshot can only project the current explicitly inventoried files."""
    require(type(value) is list and 0 < len(value) <= 100000 and type(sources) is list,"projection")
    repository,captured_inputs = absolute_path(str(repository)),absolute_path(str(captured_inputs))
    require(captured_inputs.is_relative_to(repository/"target"),"projection")
    prefix = "docs/architecture/recoverable-agent-runtime/model/"
    expected = {str(repository/row["path"]):row["sha256"] for row in sources
        if type(row) is dict and type(row.get("path")) is str and row["path"].startswith(prefix)
        and "/" not in row["path"][len(prefix):] and (row["path"].endswith(".rs") or row["path"] == prefix+"run.py")
        and type(row.get("sha256")) is str}
    require(bool(expected),"projection")
    seen,targets = set(),set()
    for receipt in value:
        require(type(receipt) is dict and set(receipt) == {"schema","source","captured","source_identity",
            "captured_identity","source_before_sha256","source_after_sha256","captured_sha256"}
            and receipt["schema"] == "chio.compiled-source-projection-custody.v1","projection")
        source,captured = image_key(receipt["source"]),image_key(receipt["captured"])
        require(source[0] in expected and source[0] not in seen and captured[0] not in targets
                and source[1] == expected[source[0]] and source[1:] == captured[1:]
                and Path(captured[0]) == captured_inputs/Path(source[0]).name
                and all(receipt[key] == source[1] for key in
                    ["source_before_sha256","source_after_sha256","captured_sha256"]),"projection")
        for name in ["source_identity","captured_identity"]:
            identity = receipt[name]
            require(type(identity) is list and len(identity) == 7
                    and all(type(item) is int and item >= 0 for item in identity)
                    and stat.S_ISREG(identity[2]) and identity[3] == source[2] and identity[-1] == 1,"projection")
        require(not receipt["captured_identity"][2] & 0o222,"projection_readonly")
        seen.add(source[0]);targets.add(captured[0])
    require(seen == set(expected),"projection")
    return [{**receipt["captured"],"role":"campaign-produced"} for receipt in value]


def export_dimension_bindings(binding, expected_record, rows, produced, executed, copies):
    """Export only matched actual producer rows and owning executed subjects."""
    dimension,label = checked_dimension_binding(binding,expected_record)
    roots = produced_subject_roots(rows,produced)
    prefix = "dimension/"+dimension+"/"
    require(type(executed) is dict and set(roots) == set(executed)
            and all(name.startswith(prefix) for name in roots)
            and all(type(images) is list and bool(images) for images in executed.values()),"subjects")
    require(type(copies) is list,"copies")
    checked_subject_copies(copies,[row["image"] for images in roots.values() for row in images],
                           [image for images in executed.values() for image in images])
    for name, images in executed.items():
        require(type(images) is list and bool(images),"executed_subject")
        source_images = [row["image"] for row in roots[name]]
        expected = {image_key(image) for image in images}
        relevant = [receipt for receipt in copies if type(receipt) is dict
                    and type(receipt.get("destination")) is dict
                    and image_key(receipt["destination"]) in expected]
        checked_subject_copies(relevant,source_images,images)
    return {"schema":"chio.compiled-dimension-subject-export.v2","dimension_binding":binding,
            "produced_subjects":roots,"executed_subjects":executed,"copy_custody":copies,
            "compiled_closure_status":"not-established","qualified":False}


def checked_subject_observation(value, rows):
    """Validate the original observed roots without a future record hash cycle."""
    fields = {"schema","dimension","label","produced_subjects","executed_subjects","copy_custody"}
    require(type(value) is dict and set(value) == fields
            and value["schema"] == "chio.compiled-dimension-subject-custody.v2","subjects")
    temporary = {"schema":"chio.compiled-dimension-production-binding.v2","dimension":value["dimension"],
        "label":value["label"],"record":{"path":"original-subject-observation","sha256":"0"*64}}
    return export_dimension_bindings(temporary,temporary["record"],rows,value["produced_subjects"],
                                    value["executed_subjects"],value["copy_custody"])


def checked_producer_record(producer, runtime, repository, options, version_stdout):
    """Recompute one actual dimension action, including the exact launch argv."""
    fields = {"schema","dimension","label","contract","command","environment","namespace","source_binding",
        "runtime_inventory_before","runtime_inventory_after","toolchain_probe","tools","options",
        "launch_configuration","source_origin","actual_exit","duration_seconds","completed","log",
        "qualified","compiled_closure_status"}
    require(type(producer) is dict and set(producer) == fields
            and producer["schema"] == "chio.compiled-dimension-command-production.v2"
            and type(producer["actual_exit"]) is int and producer["actual_exit"] == 0
            and producer["completed"] is True and producer["qualified"] is False
            and producer["compiled_closure_status"] == "not-established"
            and type(producer["duration_seconds"]) in {int,float}
            and math.isfinite(producer["duration_seconds"]) and 0 <= producer["duration_seconds"] <= 3610,"producer")
    options = checked_capture_options(options,repository,producer["dimension"],runtime["source_binding"])
    label = producer["label"]
    require(type(label) is str and label in options["actions"] and producer["tools"] == options["tools"]
            and producer["source_origin"] == options["source_origin"]
            and producer["source_binding"] == runtime["source_binding"],"producer")
    action,tools = options["actions"][label],options["tools"]
    require(producer["namespace"] == action["namespace"] and producer["launch_configuration"] == action["launch_configuration"],"producer")
    contract = producer["contract"]
    require(type(contract) is dict and type(contract.get("command")) is list,"producer")
    captured = contract.get("cwd") if producer["dimension"] == "formal" else None
    output = action["target"] if producer["dimension"] == "formal" else None
    expected = compilation_contract(producer["dimension"],label,repository,captured_inputs=captured,output_root=output)
    require(contract == expected,"producer")
    inner = [tools["cargo"]["path"],*contract["command"][1:]] if producer["dimension"] != "formal" \
        else [tools["rustc"]["path"],*contract["command"][2:]]
    environment = {**options["environment"],**contract["environment"],"CARGO_TARGET_DIR":action["target"]}
    if options["mode"] == "linux-enforced":
        # A direct Rust action is an explicit, delegated compiler probe. The
        # client submits it to the same outside supervisor as Cargo's wrapper.
        if producer["dimension"] == "formal":inner = [tools["python"]["path"],"-B",tools["recorder"]["path"],*inner]
        command = [tools["python"]["path"],"-B",tools["recorder"]["path"],"--launch-scope",action["launch_configuration"]["path"],
            *( ["--probe"] if producer["dimension"] == "formal" else []),"--",*inner]
        outer_environment = {"PATH":"/usr/bin:/bin","HOME":"/nonexistent","LC_ALL":"C",
            "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null"}
    else:
        command = inner if producer["dimension"] != "formal" else [tools["python"]["path"],"-B",tools["recorder"]["path"],*inner]
        outer_environment = {**environment,"RUSTC":tools["rustc"]["path"],"RUSTC_WRAPPER":tools["recorder"]["path"],
            "CHIO_COMPILATION_RECORDS":action["namespace"],"CHIO_COMPILATION_SOURCE_ROOT":str(repository),
            "CHIO_COMPILATION_SOURCE_BINDING":runtime["source_binding"]}
    require(producer["command"] == command and producer["environment"] == outer_environment,"producer")
    probe = producer["toolchain_probe"]
    require(type(probe) is dict and set(probe) == {"command","actual_exit","stdout","compiler"}
            and probe["command"] == [tools["rustc"]["path"],"-Vv"] and type(probe["actual_exit"]) is int
            and probe["actual_exit"] == 0 and probe["compiler"] == tools["rustc"]
            and type(version_stdout) is str and len(version_stdout) <= 4096,"toolchain")
    expected_release = "1.94.1" if producer["dimension"] == "formal" else "1.95.0"
    require("release: "+expected_release in version_stdout.splitlines(),"toolchain")
    for name in ["runtime_inventory_before","runtime_inventory_after","log"]:
        reference = producer[name]
        require(type(reference) is dict and set(reference) == {"path","sha256","size"}
                and type(reference["path"]) is str
                and not reference["path"].startswith("/"),"producer")
        image_key({**reference,"path":str(Path(repository)/reference["path"])})
    return {"contract":expected,"inner_command":inner,"environment":environment,"mode":options["mode"]}


@contextmanager
def held_regular_image(image):
    """Pin bytes, the original regular inode, and all no-follow ancestors."""
    path,digest,size = image_key(image)
    path = Path(path)
    require(not any(part.casefold() in SECRET_NAMES for part in path.parts)
            and path.suffix.casefold() not in SECRET_SUFFIXES,"input_policy")
    with ExitStack() as stack:
        parent = stack.enter_context(held_directory(path.parent))
        descriptor = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
        stack.callback(os.close,descriptor)
        identity = metadata_identity(os.fstat(descriptor))
        require(stat.S_ISREG(identity[2]) and identity[3] == size and identity[-1] == 1
                and identity == metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),"input")
        observed,count = hashlib.sha256(),0
        for chunk in iter(lambda:os.read(descriptor,1024*1024),b""):
            count += len(chunk)
            require(count <= size,"input")
            observed.update(chunk)
        require(count == size and observed.hexdigest() == digest,"input")
        os.lseek(descriptor,0,os.SEEK_SET)
        yield descriptor,identity
        require(metadata_identity(os.fstat(descriptor)) == identity
                == metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),"input")
        os.lseek(descriptor,0,os.SEEK_SET)
        after = hashlib.sha256()
        for chunk in iter(lambda:os.read(descriptor,1024*1024),b""):
            after.update(chunk)
        require(after.hexdigest() == digest,"input")


def closed_pairs(pairs):
    value = {}
    for key,item in pairs:
        require(key not in value,"duplicate_field")
        value[key] = item
    return value


def checked_capture_options(value, repository, dimension, source_binding):
    """Explicit fixed tools/actions; inherited compiler selectors grant nothing."""
    fields = {"schema","dimension","source_binding","mode","tools","environment","actions",
              "source_origin","primary_probes"}
    require(type(value) is dict and set(value) == fields
            and value["schema"] == "chio.compiled-dimension-capture-options.v2"
            and type(dimension) is str and dimension in CALLER_SOURCES and value["dimension"] == dimension
            and value["source_binding"] == source_binding and type(source_binding) is str
            and re.fullmatch(r"[a-f0-9]{64}",source_binding)
            and type(value["mode"]) is str and value["mode"] in {"host-trusted-fresh","linux-enforced"},"options")
    repository = absolute_path(str(repository))
    tools = value["tools"]
    require(type(tools) is dict and set(tools) == {"helper","inspector","recorder","python","cargo","rustc"},"tools")
    own = {"helper":"scripts/compiled-dimension-profiles.py","inspector":"scripts/verify-recovery-qualification.py",
           "recorder":"scripts/record-rust-compilation.py"}
    for name,image in tools.items():
        require(type(image) is dict and set(image) == {"path","sha256","size"},"tools")
        path,_,_ = image_key(image)
        if name in own:require(path == str(repository/own[name]),"tools")
    allowed = {"PATH","HOME","CARGO_HOME","RUSTUP_HOME","RUSTUP_TOOLCHAIN","LANG","LC_ALL","TMPDIR",
               "CARGO_INCREMENTAL","CARGO_BUILD_JOBS","CARGO_NET_OFFLINE","CARGO_TERM_COLOR",
               "CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG"}
    environment = value["environment"]
    require(type(environment) is dict and set(environment) <= allowed
            and all(type(item) is str and "\x00" not in item for item in environment.values())
            and environment.get("CARGO_INCREMENTAL") == "0" and environment.get("CARGO_NET_OFFLINE") == "true"
            and environment.get("CARGO_TERM_COLOR") == "never" and environment.get("CARGO_BUILD_JOBS") == "2"
            and environment.get("LC_ALL") == "C","environment")
    entries = environment.get("PATH","").split(":")
    require(0 < len(entries) <= 128 and all(entries),"environment")
    for path in entries:absolute_path(path)
    for name in ["HOME","CARGO_HOME","TMPDIR"]:
        require(name in environment,"environment");absolute_path(environment[name])
    require(type(value["actions"]) is dict and 0 < len(value["actions"]) <= 32,"actions")
    namespaces,targets = set(),set()
    for label,action in value["actions"].items():
        # Formal paths are checked against the actual captured snapshot at run.
        compilation_contract(dimension,label,repository,captured_inputs=repository/"target/contract-inputs",
                             output_root=repository/"target/contract-outputs")
        require(type(action) is dict and set(action) == {"namespace","target","launch_configuration"},"actions")
        namespace,target = absolute_path(action["namespace"]),absolute_path(action["target"])
        require(not any(part.casefold() in SECRET_NAMES for path in [namespace,target] for part in path.parts),"actions")
        require(namespace.is_relative_to(repository/"target") and target.is_relative_to(repository/"target")
                and namespace != repository/"target" and target != repository/"target"
                and not namespace.is_relative_to(target) and not target.is_relative_to(namespace)
                and namespace not in namespaces and target not in targets,"actions")
        namespaces.add(namespace);targets.add(target)
        if value["mode"] == "host-trusted-fresh":require(action["launch_configuration"] is None,"actions")
        else:
            require(type(action["launch_configuration"]) is dict
                    and set(action["launch_configuration"]) == {"path","sha256","size"},"actions")
            path,_,_ = image_key(action["launch_configuration"])
            require(Path(path).is_relative_to(repository/"target/metadata"),"actions")
    for name in ["source_origin","primary_probes"]:
        reference = value[name]
        if reference is not None:
            require(type(reference) is dict and set(reference) == {"path","sha256","size"},"options")
            image_key(reference)
    paths = list(namespaces | targets)
    require(len(paths) == len(namespaces)+len(targets)
            and all(not left.is_relative_to(right) and not right.is_relative_to(left)
                    for index,left in enumerate(paths) for right in paths[index+1:]),"actions")
    require(value["mode"] != "linux-enforced" or value["source_origin"] is not None
            and value["primary_probes"] is not None,"options")
    return value


@contextmanager
def fresh_owned_directory(path, boundary):
    """Create only bounded owned directories through original no-follow FDs."""
    path,boundary = absolute_path(str(path)),absolute_path(str(boundary))
    require(path != boundary and path.is_relative_to(boundary),"output")
    with ExitStack() as held:
        parent = held.enter_context(held_directory(boundary))
        locations = []
        parts = path.relative_to(boundary).parts
        for name in parts[:-1]:
            try:os.mkdir(name,0o700,dir_fd=parent)
            except FileExistsError:pass
            child = os.open(name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
            held.callback(os.close,child)
            actual = os.fstat(child)
            require(actual.st_uid == os.getuid() and not actual.st_mode & 0o022,"output")
            identity = metadata_identity(actual)[:3]
            require(identity == metadata_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))[:3],"output")
            locations.append((parent,name,child,identity))
            parent = child
        os.mkdir(parts[-1],0o700,dir_fd=parent)
        os.fsync(parent)
        actual = os.open(parts[-1],os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
        held.callback(os.close,actual)
        leaf_identity = metadata_identity(os.fstat(actual))[:3]
        require(os.fstat(actual).st_uid == os.getuid() and stat.S_IMODE(leaf_identity[2]) == 0o700,"output")
        yield path
        for original,name,child,identity in locations:
            require(metadata_identity(os.fstat(child))[:3] == identity
                    == metadata_identity(os.stat(name,dir_fd=original,follow_symlinks=False))[:3],"output")
        require(metadata_identity(os.fstat(actual))[:3] == leaf_identity
                == metadata_identity(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False))[:3],"output")


class DimensionCompilerCapture:
    """Opt-in original compiler production; no qualification or ambient wrapper.

    Each configured action starts with its own fresh target and publication
    namespace. This refuses existing compiled caches whose producing units were
    not captured. The caller keeps its original runtime/provider commands.
    """
    def __init__(self, repository, output, configuration, expected_sha, dimension, auditor):
        self.repository,self.output = absolute_path(str(repository)),absolute_path(str(output))
        require(self.output.is_relative_to(self.repository/"target") and self.output != self.repository/"target","output")
        require(type(expected_sha) is str and re.fullmatch(r"[a-f0-9]{64}",expected_sha),"options")
        self.auditor,self.dimension,self.stack = auditor,dimension,ExitStack()
        self.actions = {}
        try:
            configuration = absolute_path(str(configuration))
            require(configuration.is_relative_to(self.repository/"target")
                    and not any(part.casefold() in SECRET_NAMES for part in configuration.parts)
                    and configuration.suffix.casefold() not in SECRET_SUFFIXES,"options")
            with self.auditor.regular_input(configuration) as stream:
                before = metadata_identity(os.fstat(stream.fileno()))
                require(0 < before[3] <= 1024*1024 and not before[2] & 0o222,"options")
                raw = stream.read(1024*1024+1)
                require(hashlib.sha256(raw).hexdigest() == expected_sha,"options")
                options = json.loads(raw,object_pairs_hook=closed_pairs,
                    parse_constant=lambda _:require(False,"nonfinite_number"))
            self.inventory = self.runtime_inventory()
            self.options = checked_capture_options(options,self.repository,dimension,self.inventory["source_binding"])
            self.configuration = {"path":str(configuration),"sha256":expected_sha,"size":len(raw)}
            self.stack.enter_context(held_regular_image(self.configuration))
            host = self.auditor.platform.system(),self.auditor.platform.machine()
            require(self.options["mode"] == "host-trusted-fresh" and host[0] != "Linux"
                    or self.options["mode"] == "linux-enforced" and host == ("Linux","x86_64"),"mode")
            selectors = {"RUSTC","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC",
                "CARGO_BUILD_RUSTC_WRAPPER","CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS"}
            require(not any(os.environ.get(name) for name in selectors),"ambient_selector")
            current = {str(self.repository/row["path"]):row.get("sha256") for row in self.inventory["sources"]}
            for name,image in self.options["tools"].items():
                self.stack.enter_context(held_regular_image(image))
                if name in {"helper","inspector","recorder"}:require(current.get(image["path"]) == image["sha256"],"tools")
            for name in ["source_origin","primary_probes"]:
                if self.options[name] is not None:self.stack.enter_context(held_regular_image(self.options[name]))
            self.stack.enter_context(fresh_owned_directory(self.output,self.repository/"target"))
        except BaseException:
            self.stack.close()
            raise

    def runtime_inventory(self):
        actual = subprocess.run(["git","-C",str(self.repository),"rev-parse","--verify","HEAD"],
            env={"PATH":"/usr/bin:/bin","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null"},
            capture_output=True,check=False,timeout=10)
        require(actual.returncode in {0,128},"source")
        base = actual.stdout.decode("ascii").strip() if actual.returncode == 0 else None
        sources = self.auditor.current_source_inventory(self.repository)
        return {"source_inventory_version":self.auditor.INVENTORY_VERSION,"base_commit":base,
            "sources":sources,"source_binding":self.auditor.binding(sources,base)}

    def publish(self, relative, body):
        relative = self.auditor.relative_path(relative)
        path = self.output/relative
        require(path.parent == self.output,"output")
        with held_directory(self.output) as parent:
            descriptor = os.open(path.name,os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600,dir_fd=parent)
            try:
                offset = 0
                while offset < len(body):
                    written = os.write(descriptor,body[offset:]);require(written > 0,"publication");offset += written
                os.fsync(descriptor);os.fchmod(descriptor,0o444);os.fsync(descriptor)
                before = metadata_identity(os.fstat(descriptor))
                os.lseek(descriptor,0,os.SEEK_SET)
                readback = bytearray()
                for chunk in iter(lambda:os.read(descriptor,1024*1024),b""):readback.extend(chunk)
                require(bytes(readback) == body and before == metadata_identity(os.fstat(descriptor))
                        == metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),"publication")
                os.fsync(parent)
            finally:os.close(descriptor)
        return {"path":str(path.relative_to(self.repository)),"sha256":hashlib.sha256(body).hexdigest(),"size":len(body)}

    def publish_json(self, name, value):
        return self.publish(name,(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode())

    def produce(self, label, timeout, *, captured_inputs=None, output_root=None):
        require(type(timeout) is int and 0 < timeout <= 3600 and label not in self.actions
                and label in self.options["actions"],"action")
        action = self.options["actions"][label]
        namespace,target = Path(action["namespace"]),Path(action["target"])
        require(not namespace.exists() and not namespace.is_symlink()
                and not target.exists() and not target.is_symlink(),"fresh_compilation")
        contract = compilation_contract(self.dimension,label,self.repository,
            captured_inputs=captured_inputs,output_root=output_root)
        require(self.dimension != "formal" or target == Path(output_root),"projection")
        environment = {**self.options["environment"],**contract["environment"],"CARGO_TARGET_DIR":str(target)}
        tools = self.options["tools"]
        compiler_command = [tools["cargo"]["path"],*contract["command"][1:]] if self.dimension != "formal" \
            else [tools["rustc"]["path"],*contract["command"][2:]]
        launch = action["launch_configuration"]
        if self.options["mode"] == "linux-enforced":
            self.stack.enter_context(held_regular_image(launch))
            config = self.auditor.read_json(Path(launch["path"]))
            require(config.get("candidate") == str(self.repository) and config.get("records") == str(namespace)
                    and config.get("source_binding") == self.inventory["source_binding"]
                    and config.get("environment") == environment
                    and all(config.get("images",{}).get(name) == {key:tools[name][key] for key in ["path","sha256"]}
                        for name in ["cargo","rustc","python","recorder"]),"launch")
            if self.dimension == "formal":compiler_command = [tools["python"]["path"],"-B",tools["recorder"]["path"],*compiler_command]
            command = [tools["python"]["path"],"-B",tools["recorder"]["path"],"--launch-scope",launch["path"],
                *( ["--probe"] if self.dimension == "formal" else []),"--",*compiler_command]
            outer_environment = {"PATH":"/usr/bin:/bin","HOME":"/nonexistent","LC_ALL":"C",
                "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null"}
        else:
            outer_environment = {**environment,"RUSTC":tools["rustc"]["path"],"RUSTC_WRAPPER":tools["recorder"]["path"],
                "CHIO_COMPILATION_RECORDS":str(namespace),"CHIO_COMPILATION_SOURCE_ROOT":str(self.repository),
                "CHIO_COMPILATION_SOURCE_BINDING":self.inventory["source_binding"]}
            command = compiler_command if self.dimension != "formal" else \
                [tools["python"]["path"],"-B",tools["recorder"]["path"],*compiler_command]
        self.stack.enter_context(fresh_owned_directory(target,self.repository/"target"))
        before = self.runtime_inventory();require(before == self.inventory,"source")
        version = subprocess.run([tools["rustc"]["path"],"-Vv"],env=self.options["environment"],
            capture_output=True,check=False,timeout=30)
        require(version.returncode == 0 and len(version.stdout) <= 4096 and not version.stderr,"toolchain")
        release = "1.94.1" if self.dimension == "formal" else "1.95.0"
        require("release: "+release in version.stdout.decode("ascii").splitlines(),"toolchain")
        probe = {"command":[tools["rustc"]["path"],"-Vv"],"actual_exit":version.returncode,
            "stdout":self.publish(label+".compiler-version.log",version.stdout),"compiler":tools["rustc"]}
        log_path = self.output/(label+".compiler.log")
        started,exit_code,completed = time.monotonic(),None,False
        with held_directory(self.output) as parent:
            descriptor = os.open(log_path.name,os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600,dir_fd=parent)
            try:
                try:
                    process = subprocess.Popen(command,cwd=contract["cwd"],env=outer_environment,stdin=subprocess.DEVNULL,
                        stdout=descriptor,stderr=subprocess.STDOUT,close_fds=True,start_new_session=True)
                    try:
                        exit_code = process.wait(timeout=timeout)
                        completed = True
                    finally:
                        # An unreaped direct child cannot have its PID reused.
                        # Signal only its originally created session/group.
                        if process.poll() is None:
                            try:os.killpg(process.pid,15)
                            except ProcessLookupError:pass
                            try:process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                try:os.killpg(process.pid,9)
                                except ProcessLookupError:pass
                                process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    completed = False
                os.fsync(descriptor);os.fchmod(descriptor,0o444);os.fsync(descriptor)
                identity = metadata_identity(os.fstat(descriptor));require(identity[3] <= 64*1024**2,"log_budget")
                os.lseek(descriptor,0,os.SEEK_SET);digest = hashlib.sha256()
                for chunk in iter(lambda:os.read(descriptor,1024*1024),b""):digest.update(chunk)
                require(identity == metadata_identity(os.fstat(descriptor))
                        == metadata_identity(os.stat(log_path.name,dir_fd=parent,follow_symlinks=False)),"log")
                log = {"path":str(log_path.relative_to(self.repository)),"sha256":digest.hexdigest(),"size":identity[3]}
                os.fsync(parent)
            finally:os.close(descriptor)
        after = self.runtime_inventory()
        duration = time.monotonic()-started
        before_ref,after_ref = self.publish_json(label+".source-before.json",before),self.publish_json(label+".source-after.json",after)
        producer = {"schema":"chio.compiled-dimension-command-production.v2","dimension":self.dimension,"label":label,
            "contract":contract,"command":command,"environment":outer_environment,"namespace":str(namespace),
            "source_binding":before["source_binding"],"runtime_inventory_before":before_ref,"runtime_inventory_after":after_ref,
            "toolchain_probe":probe,"tools":tools,"options":self.configuration,"launch_configuration":launch,
            "source_origin":self.options["source_origin"],"actual_exit":exit_code,"duration_seconds":duration,
            "completed":completed,"log":log,"qualified":False,"compiled_closure_status":"not-established"}
        reference = self.publish_json(label+".producer.json",producer)
        require(completed and type(exit_code) is int and exit_code == 0 and before == after,"production_failed")
        self.actions[label] = {"producer":producer,"reference":reference,"namespace":namespace,"target":target}
        return self.actions[label]

    def observe(self, label, produced, executed, copies, *, source_projections=None):
        """Run the pinned original inspector before outputs can be overwritten."""
        require(label in self.actions and "observation" not in self.actions[label],"action")
        action = self.actions[label]
        namespace = action["namespace"]
        publication = self.auditor.audit_compiler_publications(namespace,self.inventory["source_binding"])
        rows = [self.auditor.read_json(namespace/"records"/(row["invocation_id"]+".json"))
                for row in publication["records"]]
        subject = {"schema":"chio.compiled-dimension-subject-custody.v2","dimension":self.dimension,"label":label,
            "produced_subjects":produced,"executed_subjects":executed,"copy_custody":copies}
        checked_subject_observation(subject,rows)
        projections = [] if source_projections is None else source_projections
        projection_inputs = checked_source_projections(projections,self.inventory["sources"],self.repository,
            action["producer"]["contract"]["cwd"]) if self.dimension == "formal" else []
        require(self.dimension == "formal" or projections == [],"projection")
        current = {str(self.repository/row["path"]):row.get("sha256") for row in self.inventory["sources"]}
        declared = {image_key(image):image for image in projection_inputs}
        readonly,linux,scope_data = {},None,None
        if self.options["mode"] == "linux-enforced":
            config = self.auditor.read_json(Path(action["producer"]["launch_configuration"]["path"]))
            scopes = sorted(Path(config["evidence"]).glob("*/scope.json"))
            require(len(scopes) == 1,"linux_scope")
            scope_path = scopes[0]
            scope = self.auditor.read_json(scope_path)
            declaration = self.auditor.read_json(scope_path.with_name("declaration.json"))
            retained = lambda reference:self.auditor.read_json(namespace/reference["artifact"])
            inventories = [retained(row["inventory"]) for row in declaration["scopes"]]
            for inventory in inventories:
                for member in inventory["members"]:
                    if member.get("kind") == "regular":
                        path = str(Path(inventory["root"])/member["path"])
                        readonly[path] = {**member,"path":path,"role":inventory["role"]}
            command = action["producer"]["command"]
            inner = command[command.index("--")+1:]
            command_ref = self.publish_json(label+".inner-command.json",inner)
            command_absolute = str(self.repository/command_ref["path"])
            with self.auditor.compiler_namespace_directory(self.repository) as descriptor:
                metadata = os.fstat(descriptor)
                location = {"schema":"chio.source-location.v1","repository":str(self.repository),
                    "host":{"system":self.auditor.platform.system(),"machine":self.auditor.platform.machine(),
                            "node":self.auditor.platform.node()},
                    "root":{"device":metadata.st_dev,"inode":metadata.st_ino,"uid":metadata.st_uid,
                            "mode":stat.S_IMODE(metadata.st_mode)}}
            linux = {"schema":"chio.linux-compiler-custody-request.v1","source_location":location,
                "scopes":[{"scope":{"path":str(scope_path),"sha256":self.auditor.sha(scope_path)},
                           "command":{"path":command_absolute,"sha256":command_ref["sha256"]}}]}
            events = retained(scope["execution"]["supervisor_events"])
            scope_data = {"schema":"chio.original-linux-compilation-data.v1","scope_path":str(scope_path),
                "scope_sha256":self.auditor.sha(scope_path),"configuration":config,"declaration":declaration,
                "scope":scope,"inventories":inventories,"command":inner,"events":events,
                "runtime_inventory":retained(declaration["runtime_inventory"]),
                "source_origin":retained(declaration["source_origin"]),"rows":rows}
        for row in rows:
            for image in row["inputs"]:
                key = image_key(image)
                if key in declared:continue
                if current.get(key[0]) == key[1]:role = "candidate"
                elif key[0] in readonly:role = readonly[key[0]]["role"]
                elif Path(key[0]).is_relative_to(self.repository/"target"):role = "campaign-produced"
                else:
                    require(self.options["mode"] == "host-trusted-fresh","input_role")
                    role = "toolchain" if image.get("role") == "toolchain" else "vendor"
                declared[key] = {"path":key[0],"sha256":key[1],"size":key[2],"role":role}
        roots = [image for images in produced.values() for image in images]
        roots = list({image_key(image):image for image in roots}.values())
        inputs = sorted(declared.values(),key=lambda image:(image["path"],image["sha256"]))
        producer_absolute = {**action["reference"],"path":str(self.repository/action["reference"]["path"])}
        runtime_ref = action["producer"]["runtime_inventory_before"]
        request = {"schema":"chio.compiler-profile-custody-request.v2","namespace":str(namespace),
            "repository":str(self.repository),"runtime_inventory":{"path":str(self.repository/runtime_ref["path"]),
                "sha256":runtime_ref["sha256"]},"source_binding":self.inventory["source_binding"],"roots":roots,
            "additional_inputs":[image for image in inputs if image["role"] != "candidate"],
            "selected_invocation_ids":[row["invocation_id"] for row in rows],"mode":self.options["mode"],"linux":linux,
            "producer":producer_absolute,"subject_observation":subject,"source_projections":projections}
        request_ref = self.publish_json(label+".custody-request.json",request)
        tools = self.options["tools"]
        command = [tools["python"]["path"],"-I","-B",tools["inspector"]["path"],"--compiler-profile-request",
                   str(self.repository/request_ref["path"])]
        before = self.runtime_inventory()
        result = subprocess.run(command,cwd=self.repository,
            env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent","LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1",
                 "GIT_CONFIG_GLOBAL":"/dev/null"},capture_output=True,check=False,timeout=120)
        after = self.runtime_inventory()
        stdout_ref = self.publish(label+".custody.stdout.log",result.stdout)
        stderr_ref = self.publish(label+".custody.stderr.log",result.stderr)
        execution = {"schema":"chio.compiled-dimension-inspector-execution.v2","command":command,
            "cwd":str(self.repository),"actual_exit":result.returncode,"stdout":stdout_ref,"stderr":stderr_ref,
            "runtime_inventory_before":self.publish_json(label+".inspector-source-before.json",before),
            "runtime_inventory_after":self.publish_json(label+".inspector-source-after.json",after),
            "tool":tools["inspector"],"request":request_ref,"qualified":False}
        execution_ref = self.publish_json(label+".custody-execution.json",execution)
        require(result.returncode == 0 and before == after == self.inventory,"custody")
        prefix = b"COMPILER_PROFILE_CUSTODY "
        observations = [json.loads(line[len(prefix):],object_pairs_hook=closed_pairs)
                        for line in result.stdout.splitlines() if line.startswith(prefix)]
        require(len(observations) == 1 and observations[0].get("qualified") is False,"custody")
        report_ref = self.publish_json(label+".custody-report.json",observations[0])
        rows_ref = self.publish_json(label+".rows.json",rows)
        action["observation"] = {"request":request_ref,"report":report_ref,"execution":execution_ref,
            "rows":rows_ref,"rows_value":rows,"inputs":inputs,"roots":roots,"subject":subject,
            "source_projections":projections,"scope_data":scope_data}
        return {key:value for key,value in action["observation"].items() if key in {"request","report","execution","rows"}}

    def produced_output(self, label, public_image):
        """Join a caller's finite output path to its actual recorded unit image."""
        require(label in self.actions,"action")
        action = self.actions[label]
        key = image_key(public_image)
        target = action["target"]
        path = Path(key[0])
        if self.dimension == "formal":
            require(path == target/label,"output_alias")
        elif label == "static-tools":
            require(path.parent == target/"x86_64-unknown-linux-musl/debug"
                    and path.name in {"chio-cage-init","chio-confined-reader"},"output_alias")
        elif label.startswith("canary-"):
            require(path == target/"x86_64-unknown-linux-musl/debug/examples/confined-return-canary","output_alias")
        elif label in {"control-plane-library","native-host-library"}:
            require(path.parent == target/"debug/deps" and path.name.startswith("chio_control_plane-"),"output_alias")
        elif label in {"strict-static-normal","strict-static-mutants"}:
            require(path == target/"x86_64-unknown-linux-musl/debug/chio-cage-init","output_alias")
        elif label in {"strict-native-all-targets","strict-native-mutants"}:
            require(path.parent in {target/"debug/deps",target/"debug/examples"},"output_alias")
        else:require(False,"unsupported_subject")
        publication = self.auditor.audit_compiler_publications(action["namespace"],self.inventory["source_binding"])
        rows = [self.auditor.read_json(action["namespace"]/"records"/(row["invocation_id"]+".json"))
                for row in publication["records"]]
        candidates = []
        for row in rows:
            require(row.get("status") == "success" and type(row.get("compiler_exit")) is int
                    and row["compiler_exit"] == 0,"rows")
            for output in row["outputs"]:
                if output.get("role") == "unit" and image_key(output)[1:] == key[1:]:candidates.append(output)
        require(len(candidates) == 1,"root_producer")
        unit = {name:candidates[0][name] for name in ["path","sha256","size"]}
        if image_key(unit) == key:
            self.stack.enter_context(held_regular_image(unit))
            return unit,None
        receipt = replace_owned_output_alias(unit,public_image,target)
        self.stack.enter_context(held_regular_image(unit))
        self.stack.enter_context(held_regular_image(public_image))
        return unit,receipt

    def measure_output(self, path):
        """Measure an original owned output before normalization or execution."""
        path = absolute_path(str(path))
        require(path.is_relative_to(self.repository/"target"),"output")
        with held_directory(path.parent) as parent:
            descriptor = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
            try:
                identity = metadata_identity(os.fstat(descriptor))
                require(stat.S_ISREG(identity[2]) and identity[2] & 0o111 and not identity[2] & 0o022
                        and identity[-1] in {1,2} and 0 < identity[3] <= 512*1024**2,"output")
                digest = hashlib.sha256()
                for block in iter(lambda:os.read(descriptor,1024*1024),b""):digest.update(block)
                require(identity == metadata_identity(os.fstat(descriptor))
                        == metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),"output")
                return {"path":str(path),"sha256":digest.hexdigest(),"size":identity[3]}
            finally:os.close(descriptor)

    def compiled_library(self, label):
        require(label in {"native-host-library","control-plane-library"} and label in self.actions,"action")
        text = self.auditor.checked_log(self.repository,self.actions[label]["producer"]["log"])
        paths = re.findall(r"^\s*Executable unittests src/lib\.rs \((.+)\)$",text,re.MULTILINE)
        require(len(paths) == 1,"output")
        logical = Path(paths[0]);logical = logical if logical.is_absolute() else self.repository/logical
        target = self.actions[label]["target"]
        require(logical.parent == target/"debug/deps" and logical.name.startswith("chio_control_plane-"),"output")
        image = self.measure_output(logical)
        unit,copy = self.produced_output(label,image)
        return image,unit,copy

    def runtime_environment(self, label, original):
        """Keep runtime authority settings, while using the measured fresh target."""
        require(label in self.actions and type(original) is dict,"action")
        selectors = {"RUSTC","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER","CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","CARGO_BUILD_TARGET"}
        require(not any(original.get(name) for name in selectors),"ambient_selector")
        for name in ["CARGO_INCREMENTAL","CARGO_BUILD_JOBS","CARGO_NET_OFFLINE",
                     "CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG"]:
            require(original.get(name) == self.options["environment"].get(name),"runtime_profile")
        return {**original,"CARGO_TARGET_DIR":str(self.actions[label]["target"])}

    def prepare_cage_targets(self):
        """Measure all four actual cage producers before the unchanged runtime."""
        require(self.dimension == "linux" and all(label in self.actions for label in CAGE_PHASES),"cage_phases")
        probe = self.output/"cage-probes"
        self.stack.enter_context(fresh_owned_directory(probe,self.repository/"target"))
        phases,units = {},{}
        for label in CAGE_PHASES:
            action = self.actions[label]
            if label.startswith("strict-static"):
                paths = [action["target"]/"x86_64-unknown-linux-musl/debug/chio-cage-init"]
            else:
                text = self.auditor.checked_log(self.repository,action["producer"]["log"])
                emitted = re.findall(r"^\s*Executable .+ \((.+)\)$",text,re.MULTILINE)
                require(bool(emitted) and len(emitted) <= 128 and len(set(emitted)) == len(emitted),"cage_images")
                paths = [Path(path) if Path(path).is_absolute() else self.repository/path for path in emitted]
            images,produced,copies = [],[],[]
            for path in paths:
                image = self.measure_output(path)
                unit,copy = self.produced_output(label,image)
                images.append(image);produced.append(unit)
                if copy is not None:copies.append(copy)
            phases[label] = {"producer":action["reference"],"target":str(action["target"]),"images":images}
            units[label] = {"images":images,"produced":produced,"copies":copies}
        receipt = self.publish_json("cage-preparation.json",{
            "schema":"chio.prepared-cage-compilation.v2","source_binding":self.inventory["source_binding"],
            "runtime_inventory":self.publish_json("cage-preparation-source.json",self.inventory),
            "tools":self.options["tools"],"phases":phases,"probe_root":str(probe),
            "qualified":False,"compiled_closure_status":"not-established"})
        return receipt,units

    def export(self, label, dimension_record=None):
        """Retain proofs, then bind them only when the actual owner is finalized."""
        require(label in self.actions and "observation" in self.actions[label],"custody")
        action = self.actions[label]
        observation,producer = action["observation"],action["producer"]
        if dimension_record is not None:
            require(type(dimension_record) is dict and set(dimension_record) == {"path","sha256"},"binding")
            self.auditor.artifact_json(self.repository,dimension_record)
        bound = {"schema":"chio.compiled-dimension-production-binding.v2","dimension":self.dimension,
                 "label":label,"record":dimension_record}
        subject = observation["subject"]
        subject_export = None if dimension_record is None else export_dimension_bindings(bound,dimension_record,observation["rows_value"],
            subject["produced_subjects"],subject["executed_subjects"],subject["copy_custody"])
        images = {}
        def retain(image, projected_original=False):
            key = image_key(image)
            identity = key[1],key[2]
            if identity in images:return
            path = action["namespace"]/"artifacts"/key[1]
            if not path.exists():
                require(projected_original and any(image_key(receipt["captured"]) == key
                        for receipt in observation["source_projections"]),"missing_artifact")
                path = Path(key[0])
            with held_regular_image({"path":str(path),"sha256":key[1],"size":key[2]}) as (descriptor,_):
                body = bytearray()
                for block in iter(lambda:os.read(descriptor,1024*1024),b""):body.extend(block)
            images[identity] = self.publish(label+".image-"+key[1],bytes(body))
        for row in observation["rows_value"]:
            for image in [*row["inputs"],*row["outputs"],row["compiler"]]:retain(image)
        for image in observation["inputs"]:retain(image,projected_original=True)
        linux = None
        if observation["scope_data"] is not None:
            data = observation["scope_data"]
            # Scope bodies refer to exact CAS originals. Export every original
            # image named by the scope, including inventory and provenance JSON.
            pending = [data]
            while pending:
                value = pending.pop()
                if type(value) is dict:
                    if {"sha256","size","artifact"} <= set(value) and value["artifact"] == "artifacts/"+str(value["sha256"]):
                        retain({"path":str(action["namespace"]/value["artifact"]),"sha256":value["sha256"],"size":value["size"]})
                    pending.extend(value.values())
                elif type(value) is list:pending.extend(value)
            scope_ref = self.publish_json(label+".scope-data.json",data)
            linux = {"schema":"chio.linux-compiled-profile-evidence.v1","scopes":[scope_ref],
                     "primary_probes":{**self.options["primary_probes"],"path":str(Path(self.options["primary_probes"]["path"]).relative_to(self.repository))}}
        def tool_bytes(name):
            with held_regular_image(self.options["tools"][name]) as (descriptor,_):
                body = bytearray()
                for block in iter(lambda:os.read(descriptor,1024*1024),b""):body.extend(block)
                return bytes(body)
        tool_ref = self.publish(label+".inspector-tool.py",tool_bytes("inspector"))
        helper_ref = self.publish(label+".producer-tool.py",tool_bytes("helper"))
        qualified_binding = self.inventory["source_binding"]
        if self.options["source_origin"] is not None:
            origin = self.auditor.read_json(Path(self.options["source_origin"]["path"]))
            qualified_binding = origin["source_binding"]
        profile = {"schema":"chio.compiled-profile-evidence.v2" if dimension_record is not None else "chio.unbound-compiled-profile-evidence.v2",
            "source_binding":qualified_binding,
            "mode":self.options["mode"],"subjects":subject["produced_subjects"],"producer":action["reference"],
            "runtime_inventory":producer["runtime_inventory_before"],"custody_request":observation["request"],
            "custody_report":observation["report"],"custody_execution":observation["execution"],"custody_tool":tool_ref,
            "rows":observation["rows"],"inputs":observation["inputs"],"roots":observation["roots"],
            "images":list(images.values()),"linux":linux,"dimension_binding":bound,"subject_export":subject_export,
            "source_projections":observation["source_projections"],"producer_tool":helper_ref}
        return self.publish_json(label+".profile.json",profile)

    def finish(self):
        """Publish an unbound index; it cannot satisfy a qualification record."""
        require(bool(self.actions) and all("observation" in action for action in self.actions.values()),"custody")
        templates = [self.export(label) for label in sorted(self.actions)]
        return self.publish_json("capture-index.json",{
            "schema":"chio.compiled-dimension-capture-index.v2","dimension":self.dimension,
            "templates":templates,"producer_tool":self.options["tools"]["helper"],
            "qualified":False,"compiled_closure_status":"not-established"})

    def close(self):
        self.stack.close()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def open_capture(repository, output, configuration, expected_sha, dimension):
    """Load the same pinned inspector bytes that the caller explicitly selected."""
    configuration = absolute_path(str(configuration))
    require(configuration.is_relative_to(Path(repository)/"target")
            and not any(part.casefold() in SECRET_NAMES for part in configuration.parts)
            and configuration.suffix.casefold() not in SECRET_SUFFIXES,"options")
    metadata = os.stat(configuration,follow_symlinks=False)
    image = {"path":str(configuration),"sha256":expected_sha,"size":metadata.st_size}
    with held_regular_image(image) as (descriptor,_):
        require(0 < metadata.st_size <= 1024*1024,"options")
        raw = os.read(descriptor,1024*1024+1)
        options = json.loads(raw,object_pairs_hook=closed_pairs,
            parse_constant=lambda _:require(False,"nonfinite_number"))
        require(type(options) is dict and type(options.get("tools")) is dict
                and type(options["tools"].get("inspector")) is dict,"tools")
        tool = options["tools"]["inspector"]
        require(tool.get("path") == str(Path(repository)/"scripts/verify-recovery-qualification.py"),"tools")
        with held_regular_image(tool) as (inspector_descriptor,_):
            require(tool["size"] <= 1024*1024,"tools")
            body = bytearray()
            for chunk in iter(lambda:os.read(inspector_descriptor,1024*1024),b""):body.extend(chunk)
            inspector = types.ModuleType("owned_compiler_dimension_inspector")
            inspector.__file__ = tool["path"]
            exec(compile(bytes(body),tool["path"],"exec"),inspector.__dict__)
            return DimensionCompilerCapture(repository,output,configuration,expected_sha,dimension,inspector)


def bind_profile_to_owner(auditor, repository, template, owner_reference):
    """Create a successor profile with one real owner; never rewrite a template."""
    fields = {"schema","source_binding","mode","subjects","producer","runtime_inventory","custody_request",
        "custody_report","custody_execution","custody_tool","rows","inputs","roots","images","linux",
        "dimension_binding","subject_export","source_projections","producer_tool"}
    require(type(template) is dict and set(template) == fields
            and template["schema"] == "chio.unbound-compiled-profile-evidence.v2"
            and template["subject_export"] is None,"unbound_profile")
    owner = template["dimension_binding"]
    require(type(owner) is dict and set(owner) == {"schema","dimension","label","record"}
            and owner["record"] is None,"binding")
    bound = {**owner,"record":owner_reference}
    dimension,label = checked_dimension_binding(bound,owner_reference)
    evidence = auditor.artifact_json(repository,owner_reference)
    expected_schema = {"linux":"chio.recovery-linux-evidence.v1","formal":"chio.recovery-formal-evidence.v1",
                       "live_provider":"chio.recovery-live-provider-evidence.v1"}[dimension]
    require(type(evidence) is dict and evidence.get("schema") == expected_schema,"owner_record")
    request = auditor.artifact_json(repository,template["custody_request"])
    rows = auditor.artifact_json(repository,template["rows"])
    observed = request["subject_observation"]
    require(observed["dimension"] == dimension and observed["label"] == label
            and observed["produced_subjects"] == template["subjects"],"subjects")
    exported = export_dimension_bindings(bound,owner_reference,rows,template["subjects"],
        observed["executed_subjects"],observed["copy_custody"])
    expected = auditor.compiled_subjects(repository,{"dimension_records":{dimension:owner_reference}})
    producer = auditor.artifact_json(repository,template["producer"])
    original_repository = absolute_path(str(Path(producer["tools"]["helper"]["path"]).parents[1]))
    for name,images in observed["executed_subjects"].items():
        require(name in expected,"executed_subject")
        actual = {image_key(image) for image in images}
        for image in expected[name]:
            path = image.get("original_path")
            if path is None and "original_relative_path" in image:
                path = str(original_repository/auditor.relative_path(image["original_relative_path"]))
            require(type(path) is str and (path,image.get("sha256"),image.get("size")) in actual,"executed_subject")
    return {**template,"schema":"chio.compiled-profile-evidence.v2","dimension_binding":bound,"subject_export":exported}


@contextmanager
def checked_cage_preparation(repository, reference):
    """Rejoin the original four producer records, images and source bracket."""
    repository = absolute_path(str(repository))
    with ExitStack() as held:
        def read_image(image):
            descriptor,_ = held.enter_context(held_regular_image(image))
            require(image["size"] <= 16*1024**2,"cage_preparation")
            raw = bytearray()
            for block in iter(lambda:os.read(descriptor,1024*1024),b""):raw.extend(block)
            return bytes(raw)
        def read_reference(value):
            path = repository/Path(value["path"])
            return json.loads(read_image({**value,"path":str(path),"size":path.stat(follow_symlinks=False).st_size}),
                object_pairs_hook=closed_pairs,parse_constant=lambda _:require(False,"nonfinite_number"))
        data = json.loads(read_image(reference),object_pairs_hook=closed_pairs,
            parse_constant=lambda _:require(False,"nonfinite_number"))
        require(type(data) is dict and set(data) == {"schema","source_binding","runtime_inventory","tools","phases",
            "probe_root","qualified","compiled_closure_status"} and data["schema"] == "chio.prepared-cage-compilation.v2"
            and data["qualified"] is False and data["compiled_closure_status"] == "not-established"
            and type(data["phases"]) is dict and set(data["phases"]) == set(CAGE_PHASES),"cage_preparation")
        runtime = read_reference(data["runtime_inventory"])
        tools = data["tools"]
        require(type(tools) is dict and set(tools) == {"helper","inspector","recorder","cargo","rustc","python"},"tools")
        helper = tools["helper"]
        require(helper["path"] == str(repository/"scripts/compiled-dimension-profiles.py")
                and helper["sha256"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"tools")
        read_image(helper)
        inspector = tools["inspector"]
        require(inspector["path"] == str(repository/"scripts/verify-recovery-qualification.py"),"tools")
        body = read_image(inspector)
        auditor = types.ModuleType("owned_cage_preparation_inspector");auditor.__file__ = inspector["path"]
        exec(compile(body,inspector["path"],"exec"),auditor.__dict__)
        shim = DimensionCompilerCapture.__new__(DimensionCompilerCapture)
        shim.repository,shim.auditor = repository,auditor
        require(runtime == shim.runtime_inventory() and data["source_binding"] == runtime["source_binding"],"source")
        indexed = {str(repository/row["path"]):row.get("sha256") for row in runtime["sources"]}
        for name in ["helper","inspector","recorder"]:
            require(indexed.get(tools[name]["path"]) == tools[name]["sha256"],"tools")
        probe = absolute_path(data["probe_root"])
        require(probe.is_relative_to(Path(reference["path"]).parent) and probe.name == "cage-probes","cage_preparation")
        held.enter_context(held_directory(probe))
        outputs = {}
        for label in CAGE_PHASES:
            phase = data["phases"][label]
            require(type(phase) is dict and set(phase) == {"producer","target","images"}
                    and type(phase["images"]) is list and 0 < len(phase["images"]) <= 128,"cage_preparation")
            producer = read_reference(phase["producer"])
            options = json.loads(read_image(producer["options"]),object_pairs_hook=closed_pairs)
            version = read_image({**producer["toolchain_probe"]["stdout"],
                "path":str(repository/producer["toolchain_probe"]["stdout"]["path"])}).decode("ascii")
            context = checked_producer_record(producer,runtime,repository,options,version)
            require(producer["dimension"] == "linux" and producer["label"] == label and producer["tools"] == tools
                    and options["actions"][label]["target"] == phase["target"]
                    and read_reference(producer["runtime_inventory_before"]) == runtime
                    and read_reference(producer["runtime_inventory_after"]) == runtime,"cage_preparation")
            publication = auditor.audit_compiler_publications(producer["namespace"],runtime["source_binding"])
            auditor.audit_current_compiled_publication(repository,publication,runtime,producer)
            rows = [auditor.read_json(Path(producer["namespace"])/"records"/(row["invocation_id"]+".json")) for row in publication["records"]]
            produced_subject_roots(rows,{"dimension/linux/check-all-producers":[image for row in rows
                if row["kind"] == "compilation" for image in row["outputs"] if image["role"] == "unit"]})
            units = []
            seen = set()
            for image in phase["images"]:
                path,_,_ = image_key(image);require(path not in seen,"cage_preparation");seen.add(path)
                target = absolute_path(phase["target"])
                require(Path(path).is_relative_to(target),"cage_preparation")
                if label.startswith("strict-static"):
                    require(len(phase["images"]) == 1 and Path(path) == target/"x86_64-unknown-linux-musl/debug/chio-cage-init","cage_preparation")
                else:require(Path(path).parent in {target/"debug/deps",target/"debug/examples"},"cage_preparation")
                matches = [output for row in rows for output in row["outputs"]
                    if output.get("role") == "unit" and image_key(output)[1:] == image_key(image)[1:]]
                require(len(matches) == 1,"root_producer")
                unit = {name:matches[0][name] for name in ["path","sha256","size"]}
                held.enter_context(held_regular_image(image));held.enter_context(held_regular_image(unit));units.append(unit)
            outputs[label] = {"target":phase["target"],"images":phase["images"],"units":units,"runtime_context":context}
        yield data,outputs


def cage_preparation_main(argv):
    parser = argparse.ArgumentParser(description="Read original finite cage compiler preparation")
    parser.add_argument("--repository",type=Path,required=True)
    parser.add_argument("--cage-preparation",type=Path,required=True)
    parser.add_argument("--cage-preparation-sha256",required=True)
    parser.add_argument("--copy-phase",choices=["strict-static-normal","strict-static-mutants"])
    parser.add_argument("--destination",type=Path)
    args = parser.parse_args(argv)
    path = absolute_path(str(args.cage_preparation))
    reference = {"path":str(path),"sha256":args.cage_preparation_sha256,"size":path.stat(follow_symlinks=False).st_size}
    with checked_cage_preparation(args.repository,reference) as (data,phases):
        if args.copy_phase is None:
            require(args.destination is None,"cage_preparation")
            print(data["probe_root"])
            for label in CAGE_PHASES:print(phases[label]["target"])
        else:
            suffix = "normal" if args.copy_phase == "strict-static-normal" else "mutants"
            require(args.destination == Path(data["probe_root"])/("cage-init-"+suffix),"copy_destination")
            receipt = capture_subject_copy(phases[args.copy_phase]["units"][0],args.destination)
            print(json.dumps(receipt,sort_keys=True,allow_nan=False))


def main():
    import sys
    if "--cage-preparation" in sys.argv[1:]:
        cage_preparation_main(sys.argv[1:]);return
    parser = argparse.ArgumentParser(description="Bind an immutable compiler capture index to its finalized dimension record")
    parser.add_argument("--repository",type=Path,required=True)
    parser.add_argument("--capture-index",type=Path,required=True)
    parser.add_argument("--capture-index-sha256",required=True)
    parser.add_argument("--dimension-record",type=Path,required=True)
    parser.add_argument("--dimension-record-sha256",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    repository = absolute_path(str(args.repository))
    for path in [args.capture_index,args.dimension_record,args.output]:
        require(absolute_path(str(path)).is_relative_to(repository/"target") and path != repository/"target","output")
    def read_reference(path,digest):
        with held_regular_image({"path":str(path),"sha256":digest,"size":path.stat(follow_symlinks=False).st_size}) as (descriptor,_):
            body = bytearray()
            for block in iter(lambda:os.read(descriptor,1024*1024),b""):body.extend(block)
            require(0 < len(body) <= 16*1024**2,"index")
            return json.loads(body,object_pairs_hook=closed_pairs,parse_constant=lambda _:require(False,"nonfinite_number"))
    index = read_reference(args.capture_index,args.capture_index_sha256)
    require(type(index) is dict and set(index) == {"schema","dimension","templates","producer_tool","qualified","compiled_closure_status"}
            and index["schema"] == "chio.compiled-dimension-capture-index.v2" and index["qualified"] is False
            and index["compiled_closure_status"] == "not-established"
            and index["producer_tool"]["path"] == str(repository/"scripts/compiled-dimension-profiles.py"),"index")
    with held_regular_image(index["producer_tool"]):pass
    require(index["producer_tool"]["sha256"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"tools")
    require(type(index["templates"]) is list and 0 < len(index["templates"]) <= 32,"index")
    first = read_reference(repository/index["templates"][0]["path"],index["templates"][0]["sha256"])
    producer = read_reference(repository/first["producer"]["path"],first["producer"]["sha256"])
    inspector = producer["tools"]["inspector"]
    require(inspector["path"] == str(repository/"scripts/verify-recovery-qualification.py"),"tools")
    with held_regular_image(inspector) as (descriptor,_):
        body = bytearray()
        for block in iter(lambda:os.read(descriptor,1024*1024),b""):body.extend(block)
        require(len(body) <= 1024*1024,"tools")
        auditor = types.ModuleType("owned_dimension_export_inspector");auditor.__file__ = inspector["path"]
        exec(compile(bytes(body),inspector["path"],"exec"),auditor.__dict__)
    owner = {"path":str(args.dimension_record.relative_to(repository)),"sha256":args.dimension_record_sha256}
    read_reference(args.dimension_record,args.dimension_record_sha256)
    with fresh_owned_directory(args.output,repository/"target"):
        references = []
        seen = set()
        for reference in index["templates"]:
            template = read_reference(repository/auditor.relative_path(reference["path"]),reference["sha256"])
            require(template["dimension_binding"]["dimension"] == index["dimension"],"binding")
            profile = bind_profile_to_owner(auditor,repository,template,owner)
            label = profile["dimension_binding"]["label"];require(label not in seen,"binding");seen.add(label)
            with auditor.compiled_image_custody(repository) as held:
                runtime = auditor.artifact_json(repository,profile["runtime_inventory"])
                auditor.audit_compiled_profile(repository,profile,profile["source_binding"],runtime["sources"],runtime["base_commit"],held,{index["dimension"]:owner})
            data = (json.dumps(profile,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
            path = args.output/(label+".json")
            with path.open("xb") as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            path.chmod(0o444)
            references.append({"path":str(path.relative_to(repository)),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)})
        result = {"compiled_profiles":references,"qualified":False,"compiled_closure_status":"not-established"}
        (args.output/"index.json").write_text(json.dumps(result,sort_keys=True,allow_nan=False)+"\n")
        print("COMPILED_DIMENSION_EXPORT "+json.dumps(result,sort_keys=True,allow_nan=False))


if __name__ == "__main__":main()
