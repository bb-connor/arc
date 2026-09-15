"""Untrusted candidate invocation shim. Its output is data, never a verdict.

The host checker runs Git separately and inspects the resulting repository.
Candidate imports can alter this process, so nothing asserted here authorizes
publication by itself. This process has no receiver keys or checker state.
"""

import asyncio
import importlib.util
import json
import pathlib
import sys
import types


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sys.modules["chio_adapter_base"] = types.ModuleType("chio_adapter_base")
security = load("chio_adapter_base.security", "/security.py")
executors = load("repair_executors", "/executors.py")


def capture(argv, **kwargs):
    return {"argv": argv}


executors._run_subprocess_impl = capture
requests = json.loads(pathlib.Path("/requests.json").read_text())
responses = []
for request in requests:
    if request["entrypoint"] == "helper":
        argv = security.harden_git_argv(request["argv"])
    elif request["entrypoint"] == "commit":
        argv = asyncio.run(executors.git_commit_executor(
            message=request["message"], cwd=pathlib.Path("/work"))) ["argv"]
    else:
        argv = asyncio.run(executors.git_run_executor(
            command=request["command"], cwd=pathlib.Path("/work"))) ["argv"]
    responses.append(argv)
print(json.dumps(responses))
