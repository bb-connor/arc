"""Model-free actual framework/native corpus preflight, outside live denominators."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from campaign_baseline import SupervisorSession
from campaign_runner import graph_trial, crew_trial, public_task
from chio_sdk.recovery_host import RecoveryHostSession
from qualification_runtime import model_free_network_guard, native_environment, require, wait_endpoint


class ExplicitAction:
    model = "model-free-corpus-preflight"
    def __init__(self):
        self.calls = 0
        self.attempts = []
    def call(self, messages):
        self.calls += 1
        if self.calls > 1: raise RuntimeError("preflight model-free action bound")
        content = 'Thought: Check the owned command.\nAction: recovery\nAction Input: {"choice":"resume"}'
        self.attempts.append({"mode":"model-free", "provider_requests":0, "completion":content})
        return content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = []
    policy = None
    for host in ["langgraph", "crewai"]:
        for workflow in ["support", "artifact"]:
            for arm in ["baseline", "product"]:
                trial = {"host":host,"workflow":workflow,"arm":arm,"case":"authorized"}
                directory = args.evidence/f"{host}-{workflow}-{arm}"
                directory.mkdir(mode=0o700)
                (directory/"configuration.json").write_text(json.dumps({"workflow":workflow,"case":"authorized"}))
                log = (directory/"native.log").open("wb")
                env = native_environment("CHIO_RECOVERY_CAMPAIGN_EXCHANGE", directory)
                try:
                    process = subprocess.Popen(["cargo","test","--offline","--locked","-p","chio-control-plane","--lib",
                        "live_comparative_native_host","--","--ignored","--test-threads=1"],cwd=args.checkout,
                        env=env,stdout=log,stderr=subprocess.STDOUT)
                except BaseException:
                    log.close()
                    raise
                try:
                    endpoint = wait_endpoint(directory/"ready", process, 240)
                    descriptor = (directory/"authority-contract.json").read_bytes()
                    digest = hashlib.sha256(descriptor).hexdigest()
                    if policy is None:
                        policy = digest
                        (args.evidence/"authority-contract.json").write_bytes(descriptor)
                    require(policy == digest, "preflight_authority")
                    capability = (directory/"capability.json").read_text()
                    wire = (directory/"command.json").read_bytes()
                    session = RecoveryHostSession(endpoint,capability,{"resume":wire},timeout_seconds=120) if arm == "product" else SupervisorSession(endpoint,capability,wire)
                    model = ExplicitAction()
                    with model_free_network_guard() as network_attempts:
                        output = asyncio.run(graph_trial(session,model,public_task(trial))) if host == "langgraph" else crew_trial(session,model,public_task(trial))
                    require(output["category"] == "complete" and session.attempts == model.calls == 1,
                            "preflight_model_free_completion")
                    require(not network_attempts, "preflight_provider_requests")
                    (directory/"finish").touch()
                    status = process.wait(timeout=120)
                    require(status == 0, "preflight_native_execution")
                    facts = json.loads((directory/"native-evidence.json").read_bytes())
                    require(facts["useful_completion"] is True and facts["source_label_retained"] is True,
                            "preflight_native_completion")
                    require(facts["unauthorized_effects"] == facts["duplicate_effects"] == 0,
                            "preflight_native_safety")
                    results.append({**trial,"native":facts,"outcome":output,"model_free_actions":model.calls,
                        "provider_requests":len(network_attempts), "network_attempts":network_attempts,
                        "scripted_external_input":True,"model_frames":model.attempts,
                        "authority_policy":digest})
                    print("Actual model-free preflight passed",host,workflow,arm,flush=True)
                finally:
                    (directory/"finish").touch()
                    if process.poll() is None: process.wait(timeout=120)
                    log.close()
    require(len(results) == 8, "preflight_denominator")
    (args.evidence/"result.json").write_text(json.dumps({"cases":results,"passed":True,
        "mode":"model-free-native-preflight",
        "provider_requests":sum(row["provider_requests"] for row in results)},indent=2)+"\n")


if __name__ == "__main__": main()
