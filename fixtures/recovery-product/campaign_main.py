"""Execute a sealed finite corpus. Never repair, retry or replace a trial."""
from __future__ import annotations
import argparse
import asyncio
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import ExitStack
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time
import types

from qualification_runtime import installed_module, native_environment, require, wait_endpoint
from owned_native_process import NativeProcessCleanupError, owned_native_process

# Validate the wheel origin before SDK imports can load its transport module.
installed_module("httpx", "httpx")

from campaign_baseline import SupervisorSession
from campaign_runner import ModelBudget, crew_trial, graph_trial, public_task
from campaign_report import summarize
from chio_sdk.recovery_host import RecoveryHostSession
from chio_sdk.recovery_host import RecoveryHostOutcome
from manifest_builder import PROVIDER_ENDPOINT, SOURCE_INVENTORY_VERSION, source_binding, source_inventory


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


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def observed_native_executable(root, log_text):
    images = re.findall(r"^\s*Running unittests src/lib\.rs \((.+)\)$",log_text,re.MULTILINE)
    require(len(images) == 1,"native_executable")
    root = Path(root).resolve(strict=True)
    logical = Path(images[0])
    logical = logical if logical.is_absolute() else root/logical
    require(logical.is_relative_to(root) and ".." not in logical.parts
            and logical.parent.name == "deps" and logical.name.startswith("chio_control_plane-"),
            "native_executable")
    relative = logical.relative_to(root)
    digest = hashlib.sha256()
    descriptors = []
    parents = []
    identity = lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
    try:
        parent = os.open(root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        parents.append((root,parent))
        directory = root
        for component in relative.parts[:-1]:
            parent = os.open(component,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
            descriptors.append(parent)
            directory /= component
            parents.append((directory,parent))
        descriptor = os.open(relative.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode),"native_executable")
        for data in iter(lambda:os.read(descriptor,1024*1024),b""):
            digest.update(data)
        after = os.fstat(descriptor)
        located = os.stat(relative.name,dir_fd=parent,follow_symlinks=False)
        require(identity(before) == identity(after) == identity(located),"native_executable_changed")
        for path, held in parents:
            current, observed = path.stat(follow_symlinks=False),os.fstat(held)
            require((current.st_dev,current.st_ino,current.st_mode)
                    == (observed.st_dev,observed.st_ino,observed.st_mode),"native_executable_changed")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return {"path":str(relative),"sha256":digest.hexdigest(),"size":before.st_size}


class DeadlineSession:
    def __init__(self, owner, deadline):
        self._owner = owner
        self._deadline = deadline
    @property
    def attempts(self): return self._owner.attempts
    async def execute(self, choice):
        if time.monotonic() >= self._deadline:
            return RecoveryHostOutcome("budget_exhausted")
        return await self._owner.execute(choice)


class CampaignAdmissionStopped(RuntimeError):
    """An unstarted slot is not a native trial or a replacement result."""


class CampaignNativeCleanupError(RuntimeError):
    """Carry the already-retained row across the aggregate journal boundary."""

    def __init__(self, row, interruption=None):
        super().__init__("campaign.native_cleanup_failed")
        self.row = row
        self.interruption = interruption


class CampaignTrialInterrupted(RuntimeError):
    """Journal the attempted trial before propagating its original interruption."""

    def __init__(self, row, interruption):
        super().__init__("campaign.interrupted")
        self.row = row
        self.interruption = interruption


class CampaignAdmission:
    """Serialize launch admission with closing the campaign after cleanup trouble."""

    def __init__(self):
        self.lock = threading.Lock()
        self.stopped = threading.Event()

    def stop(self):
        with self.lock:
            self.stopped.set()


def trial_run(root, evidence, manifest, trial, compiler_capture=None, admission=None):
    admission = admission if admission is not None else CampaignAdmission()
    exchange = evidence / trial["id"]
    started = time.monotonic()
    preparation_finished = None
    host_started = None
    host_finished = None
    body_finished = None
    shutdown_started = None
    owner = None
    attempted = False
    cleanup_failed = False
    body_interruption = None
    cleanup_interruption = None
    model = None
    session = None
    row = {**trial, "requested_model":manifest["model"], "authority_policy":manifest["authority_policy"],
           "provider_endpoint":manifest["provider_endpoint"], "base_commit":manifest["base_commit"],
           "source_inventory_version":manifest["source_inventory_version"],
           "source_binding":manifest["source_binding"], "model_attempts":[], "tool_actions":0,
           "hidden_retries":0, "outcome":"native_error", "native":None,
           "native_observation":"unknown", "native_exit_code":None, "elapsed_seconds":0}
    try:
        with ExitStack() as scope:
            with admission.lock:
                if admission.stopped.is_set():
                    raise CampaignAdmissionStopped("campaign.admission_stopped")
                attempted = True
                exchange.mkdir(mode=0o700, parents=True, exist_ok=False)
                (exchange/"configuration.json").write_text(json.dumps({key:trial[key] for key in ["workflow", "case"]}))
                environment = native_environment("CHIO_RECOVERY_CAMPAIGN_EXCHANGE", exchange)
                if compiler_capture is not None:
                    environment = compiler_capture.runtime_environment("native-host-library", environment)
                try:
                    owner = scope.enter_context(owned_native_process(
                        ["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib",
                         "live_comparative_native_host", "--", "--ignored", "--test-threads=1"],
                        cwd=root, env=environment, log_path=exchange/"native.log", finish_path=exchange/"finish",
                        grace_seconds=manifest["budgets"]["native_shutdown_seconds"],
                        terminate_seconds=5, kill_seconds=5))
                except OSError:
                    raise RuntimeError("campaign.native_launch_failed") from None
            try:
                endpoint = wait_endpoint(exchange/"ready", owner.process, manifest["budgets"]["native_preparation_seconds"])
                preparation_finished = time.monotonic()
                row["authority_policy"] = sha(exchange/"authority-contract.json")
                if row["authority_policy"] != manifest["authority_policy"]:
                    raise RuntimeError("campaign.authority_mismatch")
                capability = (exchange/"capability.json").read_text()
                wire = (exchange/"command.json").read_bytes()
                if trial["arm"] == "product":
                    session = RecoveryHostSession(endpoint, capability, {"resume":wire}, max_tool_actions=8, timeout_seconds=120)
                else:
                    session = SupervisorSession(endpoint, capability, wire)
                deadline_at = time.monotonic() + manifest["budgets"]["host_start_deadline_seconds"]
                session = DeadlineSession(session, deadline_at)
                openai_module, provider_origin = installed_module("openai", "openai")
                http_module, http_origin = installed_module("httpx", "httpx")
                row["provider_modules"] = [provider_origin,http_origin]
                timeout = manifest["budgets"]["provider_seconds"]
                with openai_module.OpenAI(base_url=manifest["provider_endpoint"], api_key=os.environ["OPENAI_API_KEY"],
                            max_retries=0, timeout=timeout,
                            http_client=http_module.Client(trust_env=False, follow_redirects=False, timeout=timeout)) as provider:
                    model = ModelBudget(manifest["model"], provider.chat.completions,
                        max_calls=manifest["budgets"]["model_calls"], prompt_bytes=manifest["budgets"]["prompt_bytes"],
                        output_tokens=manifest["budgets"]["output_tokens"], deadline_at=deadline_at,
                        provider_endpoint=manifest["provider_endpoint"])
                    host_started = time.monotonic()
                    if trial["host"] == "langgraph":
                        output = asyncio.run(graph_trial(session, model, public_task(trial)))
                    else:
                        output = crew_trial(session, model, public_task(trial))
                    host_finished = time.monotonic()
                row["outcome"] = output.get("category", "parser_error") if output else "skipped_tool"
                row["host_output"] = output
            except Exception as error:
                category = "campaign.provider_module_origin" if isinstance(error, ValueError) and str(error) == "qualification.provider_module_origin" else \
                    str(error) if isinstance(error, (RuntimeError, TimeoutError)) and str(error).startswith("campaign.") else "campaign.framework_error"
                row["error_category"] = category
                row["outcome"] = "provider_error" if category == "campaign.provider_unavailable" else \
                                 "budget_exhausted" if category in ["campaign.model_budget_exhausted", "campaign.prompt_budget_exhausted", "campaign.response_budget_exhausted"] else \
                                 "parser_error" if category in ["campaign.response_invalid", "campaign.parser_error"] else \
                                 "native_error" if category in ["campaign.native_launch_failed", "campaign.native_preparation_failed", "campaign.authority_mismatch"] else "framework_error"
            except BaseException as error:
                # Preserve the primary interruption while still observing the
                # owner's single finish result before retaining either journal.
                admission.stop()
                body_interruption = error
                row["error_category"] = "campaign.interrupted"
                row["outcome"] = "native_error" if preparation_finished is None else "framework_error"
            finally:
                body_finished = time.monotonic()
                shutdown_started = body_finished
            try:
                owner.finish()
            except BaseException as error:
                # Stop admission before log/evidence processing or durable writes.
                admission.stop()
                cleanup_failed = True
                if not isinstance(error, Exception):
                    cleanup_interruption = error
                raise
    except CampaignAdmissionStopped:
        raise
    except NativeProcessCleanupError:
        admission.stop()
        cleanup_failed = True
    except Exception as error:
        if not cleanup_failed:
            category = "campaign.native_launch_failed" if isinstance(error, RuntimeError) and str(error) == "campaign.native_launch_failed" else "campaign.framework_error"
            row["error_category"] = category
            row["outcome"] = "native_error" if category == "campaign.native_launch_failed" else "framework_error"
    except BaseException as error:
        admission.stop()
        if not attempted:
            raise
        if not cleanup_failed:
            body_interruption = error
            row["error_category"] = "campaign.interrupted"
            row["outcome"] = "native_error" if preparation_finished is None else "framework_error"
    finally:
        if attempted:
            finished = time.monotonic()
            body_finished = body_finished if body_finished is not None else finished
            row["native_preparation_seconds"] = round((preparation_finished or body_finished)-started, 6)
            row["host_model_native_seconds"] = None if host_started is None else round((host_finished or body_finished)-host_started, 6)
            row["native_shutdown_seconds"] = 0 if shutdown_started is None else round(finished-shutdown_started, 6)
            if model is not None:
                row["model_attempts"] = model.attempts
            if session is not None:
                row["tool_actions"] = session.attempts
            row["native_exit_code"] = None if owner is None else owner.process.returncode
            if body_interruption is not None or cleanup_interruption is not None:
                row["interrupted"] = True
            if cleanup_failed:
                row["body_outcome"] = row["outcome"]
                row["outcome"] = "native_error"
                row["native_shutdown_error"] = True
                row["native_cleanup_error"] = "campaign.native_cleanup_failed"
                row["native_execution_error"] = True
            try:
                native = json.loads((exchange/"native-evidence.json").read_bytes())
                require(isinstance(native, dict), "native_evidence_object")
                row["native"] = native
                row["native_observation"] = "observed"
            except FileNotFoundError:
                pass
            except (ValueError, OSError):
                row["native_evidence_error"] = True
            native_log = ""
            try:
                native_log = (exchange/"native.log").read_text()
            except (ValueError, OSError):
                row["native_log_error"] = True
            # A log from a forced or unresolved shutdown cannot prove execution.
            if not cleanup_failed:
                try:
                    row["native_executable"] = observed_native_executable(root,native_log)
                except (ValueError,OSError):
                    row["native_executable_error"] = True
            if row["native_exit_code"] != 0 or "1 passed; 0 failed; 0 ignored" not in native_log:
                row["native_execution_error"] = True
            row["elapsed_seconds"] = round(time.monotonic()-started, 6)
            (exchange/"result.json").write_text(json.dumps(row, indent=2, allow_nan=False)+"\n")
    if body_interruption is not None:
        if cleanup_failed:
            body_interruption.add_note("campaign.native_cleanup_failed")
        raise CampaignTrialInterrupted(row, body_interruption) from body_interruption
    if cleanup_failed:
        raise CampaignNativeCleanupError(row, cleanup_interruption) from cleanup_interruption
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--compiled-capture-config",type=Path)
    parser.add_argument("--compiled-capture-sha256")
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.manifest.with_suffix(".sha256").read_text().strip(),
            "manifest_hash")
    manifest = json.loads(raw)
    require(manifest.get("schema") == "chio.recovery-live-corpus.v2", "manifest_version")
    require(manifest.get("source_inventory_version") == SOURCE_INVENTORY_VERSION, "source_inventory_version")
    require(manifest.get("provider_endpoint") == PROVIDER_ENDPOINT, "provider_endpoint")
    require(len(manifest["trials"]) == 96, "campaign_denominator")
    for distribution, version in manifest["hosts"].items():
        require(importlib.metadata.version(distribution) == version, "host_version")
    current_commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], cwd=args.checkout).decode().strip()
    require(current_commit == manifest["base_commit"], "base_commit")
    sources = source_inventory(args.checkout)
    require(sources == manifest["sources"], "campaign_source_inventory")
    require(source_binding(sources, current_commit) == manifest["source_binding"], "campaign_source_binding")
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    support,capture = optional_compiler_capture(args.checkout,args.evidence,args.compiled_capture_config,args.compiled_capture_sha256,"live_provider")
    try:
        compiled = None
        if capture is not None:
            require(set(capture.options["actions"]) == {"native-host-library"},"capture_action_inventory")
            capture.produce("native-host-library",3600)
            compiled = capture.compiled_library("native-host-library")
        lock = threading.Lock()
        admission = CampaignAdmission()
        rows = []
        def execute(trial):
            failure = None
            try:
                row = trial_run(args.checkout, args.evidence, manifest, trial, capture, admission)
            except CampaignAdmissionStopped:
                return
            except (CampaignNativeCleanupError, CampaignTrialInterrupted) as error:
                row, failure = error.row, error
            with lock:
                rows.append(row)
                with (args.evidence/"results.jsonl").open("a") as output:
                    output.write(json.dumps(row, separators=(",", ":"), allow_nan=False)+"\n")
                print(f"Retained {len(rows)}/96 {row['id']} {row['outcome']}", flush=True)
            if failure is not None:
                raise failure
        trials = iter(manifest["trials"])
        failure = None
        interruption = None
        limit = manifest["budgets"]["concurrent_trials"]
        with ThreadPoolExecutor(max_workers=limit) as executor:
            pending = set()
            def admit():
                while len(pending) < limit and not admission.stopped.is_set():
                    trial = next(trials, None)
                    if trial is None:
                        break
                    pending.add(executor.submit(execute, trial))
            def record_failure(error):
                nonlocal failure, interruption
                admission.stop()
                if failure is None:
                    failure = error
                primary = error.interruption if isinstance(error, (CampaignNativeCleanupError, CampaignTrialInterrupted)) else \
                          error if not isinstance(error, Exception) else None
                if interruption is None and primary is not None:
                    interruption = primary
            def collect(future):
                if future.cancelled():
                    return
                while True:
                    try:
                        future.result()
                        return
                    except BaseException as error:
                        record_failure(error)
                        if future.done():
                            return
                        # A scheduler interruption during result() must not drop
                        # an active owner. Its body keeps its existing bounds.
            try:
                admit()
                while pending:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        collect(future)
                        pending.discard(future)
                    if admission.stopped.is_set():
                        break
                    admit()
            except BaseException as error:
                record_failure(error)
            finally:
                if admission.stopped.is_set():
                    for future in pending:
                        future.cancel()
                    for future in pending:
                        collect(future)
        if admission.stopped.is_set():
            diagnostic = "campaign.interrupted" if interruption is not None else \
                         "campaign.native_cleanup_failed" if isinstance(failure, CampaignNativeCleanupError) else "campaign.execution_failed"
            (args.evidence/"campaign-abort.json").write_text(json.dumps({
                "error_category":diagnostic, "planned_trials":len(manifest["trials"]),
                "retained_trials":len(rows), "completed":False}, indent=2)+"\n")
            if interruption is not None:
                raise interruption
            if failure is not None:
                raise failure
            raise RuntimeError(diagnostic)
        report = summarize(manifest, rows)
        (args.evidence/"summary.json").write_text(json.dumps(report, indent=2, allow_nan=False)+"\n")
        require(report["unauthorized_effects"] == report["duplicate_effects"] == 0, "campaign_safety")
        require(report["native_evidence_unknown_trials"] == 0, "campaign_native_evidence")
        require(all(row["native"]["source_label_retained"] is True for row in rows), "campaign_labels")
        require(all(not row.get("native_execution_error") and not row.get("native_shutdown_error")
                    and not row.get("native_executable_error")
                    and row["elapsed_seconds"] <= manifest["budgets"]["trial_seconds"] for row in rows),
                "campaign_native_execution")
        after_commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], cwd=args.checkout).decode().strip()
        require(after_commit == current_commit and source_inventory(args.checkout) == sources, "campaign_source_changed")
        # All declared positive strata must demonstrate useful execution. Failures
        # remain in their exact three-trial denominator; no replacement is allowed.
        require(all(stratum["completion"]["numerator"] >= 1 for stratum in report["strata"] if stratum["case"] in ["authorized", "lost_ack_restart"]),
                "campaign_utility")
        if capture is not None:
            image,unit,copy = compiled
            expected = {"path":str(Path(image["path"]).relative_to(args.checkout)),"sha256":image["sha256"],"size":image["size"]}
            require(all(row.get("native_executable") == expected for row in rows),"capture_executed_subject")
            name = "dimension/live_provider/native-host-library"
            capture.observe("native-host-library",{name:[unit]},{name:[image]},[copy] if copy is not None else [])
            index = capture.finish()
            (args.evidence/"compiled-capture-index.json").write_text(json.dumps({"capture_index":index,
                "qualified":False,"compiled_closure_status":"not-established"},indent=2)+"\n")
        print("Completed source-bound 96-trial live campaign", flush=True)
    finally:
        if capture is not None:capture.close()


if __name__ == "__main__": main()
