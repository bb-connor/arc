#!/usr/bin/env python3
import argparse, datetime, json, pathlib, subprocess, sys, time
p = argparse.ArgumentParser()
p.add_argument("label")
p.add_argument("--cwd", default="/tmp/chio-paper-erc8183")
p.add_argument("command", nargs=argparse.REMAINDER)
a = p.parse_args()
cmd = a.command[1:] if a.command and a.command[0] == "--" else a.command
base = pathlib.Path(__file__).resolve().parent
start = datetime.datetime.now(datetime.timezone.utc).isoformat()
t0 = time.monotonic()
try:
    r = subprocess.run(cmd, cwd=a.cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
except OSError as e:
    r = subprocess.CompletedProcess(cmd, 126, stdout=(str(e)+"\n").encode())
(base / "logs" / (a.label + ".log")).write_bytes(r.stdout)
meta = {"argv": cmd, "cwd": a.cwd, "started_at": start, "elapsed_seconds": time.monotonic()-t0, "exit_status": r.returncode, "log": "logs/"+a.label+".log"}
(base / "logs" / (a.label + ".command.json")).write_text(json.dumps(meta, indent=2)+"\n")
sys.stdout.buffer.write(r.stdout)
print(json.dumps(meta))
sys.exit(r.returncode)
