"""Deterministic source inventory worker; no model or network credentials."""

import json
import sys

from chio_process import ProcessClient

config = json.load(sys.stdin)
client = ProcessClient(config["socket_path"], config["credential"])
read = client.invoke("read-snapshot", "tools", "read", {})
if read["verdict"] != "allow":
    raise RuntimeError("source snapshot denied")
files = read["output"]["value"]["files"]
report = {
    "worker": "python",
    "files": len(files),
    "nonempty_lines": sum(
        bool(line.strip()) for file in files for line in file["content"].split("\n")
    ),
    "paths": sorted(file["path"] for file in files),
}
published = client.invoke("publish-inventory", "tools", "append", report)
if published["verdict"] != "allow":
    raise RuntimeError("inventory publication denied")
snapshot = client.inspect()
if snapshot["checkpoint"]["revision"] == "0":
    blob = client.put_blob(bytes(range(256)) * 4096)
    client.checkpoint("0", {"published": True, "blob": blob})
reference = client.inspect()["checkpoint"]["value"]["blob"]
if client.read_blob(reference["sha256"]) != bytes(range(256)) * 4096:
    raise RuntimeError("persisted blob differs")
print(json.dumps({"read": read, "published": published, "snapshot": client.inspect()}))
