#!/usr/bin/env python3
"""Exhaust the finite response model and require named mutation counterexamples."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def validate_runtime_trace(trace):
    """Check ordering and acknowledgement claims in committed Rust mutations.

    These records are state-machine evidence, not signatures or an independent
    external effect journal. The model checks that latter abstraction separately.
    """
    if trace.get("mode") != "live":
        raise ValueError("runtime work is not live")
    state, states, effects = "planned", ["planned"], {}
    mutations = trace["mutations"]
    if not mutations or trace["generation"] != len(mutations) - 1:
        raise ValueError("runtime mutation generation is incomplete")
    for generation, mutation in enumerate(mutations):
        kind, record = mutation["record_type"], mutation["record"]
        if record["generation"] != generation:
            raise ValueError("runtime mutations are out of order")
        if generation == 0:
            if kind != "requested":
                raise ValueError("runtime trace lacks its initial request")
            continue
        if state in {"lifted", "expired", "failed", "cancelled"}:
            raise ValueError("runtime trace mutates terminal state")
        effect = record.get("effect_id")
        if kind == "effect_requested":
            if state != "applying":
                raise ValueError("effect requested outside applying")
            effects[effect] = "requested"
        elif kind == "effect_applied":
            if effects.get(effect) != "requested":
                raise ValueError("effect acknowledged without request")
            effects[effect] = "applied"
        elif kind == "effect_failed":
            if effects.get(effect) != "requested":
                raise ValueError("effect failure without request")
            effects[effect] = "apply_failed"
        elif kind == "rollback":
            outcome = record["outcome"]["outcome"]
            prior = effects.get(effect)
            if state != "rolling_back" or (
                prior not in {"applied", "rollback_failed"} if outcome == "requested"
                else prior != "rollback_requested"
            ):
                raise ValueError("rollback acknowledgement has no matching request")
            effects[effect] = {"requested": "rollback_requested", "restored": "restored",
                               "failed": "rollback_failed"}[outcome]
        elif kind in {"transition", "failed", "final"}:
            if record["from_state"] != state:
                raise ValueError("runtime transition source is discontinuous")
            state = record.get("to_state", record.get("final_state"))
            states.append(state)
        else:
            raise ValueError("unexpected runtime mutation")
        if state == "active" and (not effects or any(p != "applied" for p in effects.values())):
            raise ValueError("active before every effect is acknowledged")
        if state == "lifted" and any(p not in {"restored", "apply_failed"} for p in effects.values()):
            raise ValueError("clean lift before restoration")
        if state == "rollback_partial" and "rollback_failed" not in effects.values():
            raise ValueError("partial rollback lacks failed restoration evidence")
    if states != trace["states"]:
        raise ValueError("runtime state list differs from committed mutation order")
    return set(states)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", default=os.environ.get("TLA2TOOLS_JAR"), required=False)
    parser.add_argument("--java", default="java")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-traces", type=Path)
    parser.add_argument("--durable-traces", type=Path, required=True)
    args = parser.parse_args()
    if not args.jar or not Path(args.jar).is_file():
        parser.error("--jar or TLA2TOOLS_JAR must name a TLC or Apalache jar containing tlc2.TLC")
    from formal.durable_lifecycle import validate_durable_trace
    try:
        durable_results = validate_durable_trace(json.loads(args.durable_traces.read_text()), validate_runtime_trace)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"invalid durable lifecycle evidence: {error}") from error
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    linkage = tomllib.loads((ROOT / "formal/response-lifecycle.toml").read_text())
    if linkage["schema"] != "chio.response-lifecycle-linkage.v1":
        raise SystemExit("unsupported lifecycle linkage schema")
    hooks = []
    for hook in linkage["hook"]:
        source = (ROOT / hook["path"]).read_bytes()
        if not re.search(r"\bfn\s+" + re.escape(hook["symbol"]) + r"\s*\(", source.decode()):
            raise SystemExit(f"missing production hook: {hook}")
        hooks.append(dict(hook, sha256=hashlib.sha256(source).hexdigest()))
    model = ROOT / linkage["model"]
    configs = [ROOT / linkage["config"]] + [ROOT / entry["config"] for entry in linkage["negative"]]
    actual = set((ROOT / "formal/apalache/_negative_tests").glob("MCResponseLifecycle*.cfg"))
    if set(configs[1:]) != actual:
        raise SystemExit("lifecycle registry does not cover the exact negative inventory")
    if len(configs) != 9:
        raise SystemExit("expected one positive model and eight calibrated counterexamples")
    expected = {entry["config"]: entry["falsifies"] for entry in linkage["negative"]}
    for config in configs[1:]:
        invariants = re.findall(r"INVARIANT\s+(\w+)", config.read_text())
        if invariants != [expected[str(config.relative_to(ROOT))]]:
            raise SystemExit(f"negative invariant differs from registered claim: {config}")
    results = []
    # Put modules together for portable EXTENDS resolution, retaining exact bytes.
    with tempfile.TemporaryDirectory(prefix="chio-response-model-") as temp:
        work = Path(temp)
        (work / model.name).write_bytes(model.read_bytes())
        for config in configs:
            negative = config.parent.name == "_negative_tests"
            module = config.with_name(config.name[2:]).with_suffix(".tla")
            (work / module.name).write_bytes(module.read_bytes())
            (work / config.name).write_bytes(config.read_bytes())
            command = [args.java, "-XX:+UseParallelGC", "-Xmx2048m", "-cp",
                       str(Path(args.jar).resolve()), "tlc2.TLC", "-workers", "2",
                       "-deadlock", "-metadir", str(work / config.stem),
                       "-config", config.name, module.name]
            with (output / (config.stem + ".log")).open("w") as log:
                try:
                    run = subprocess.run(command, cwd=work, stdout=log,
                                         stderr=subprocess.STDOUT, timeout=60, check=False)
                except subprocess.TimeoutExpired:
                    raise SystemExit(f"{config.stem}: timed out; no passing evidence")
            text = (output / (config.stem + ".log")).read_text()
            invariant = re.search(r"INVARIANT\s+(\w+)", config.read_text()).group(1)
            passed = (run.returncode == 12 and f"Invariant {invariant} is violated" in text
                      if negative else run.returncode == 0 and
                      "Model checking completed. No error has been found." in text)
            results.append({"config": str(config.relative_to(ROOT)), "passed": passed,
                            "expected_counterexample": invariant if negative else None,
                            "exit_code": run.returncode})
            print(f"{config.stem}: {'PASS' if passed else 'FAIL'}", flush=True)
            if not passed:
                break
    report = {"model_sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
              "scope": "finite abstraction; runtime correspondence is tested separately",
              "production_hooks": hooks, "results": results,
              "durable_trace_sha256": hashlib.sha256(args.durable_traces.read_bytes()).hexdigest(),
              "durable_scenarios": durable_results}
    if args.runtime_traces:
        traces = json.loads(args.runtime_traces.read_text())
        if traces.get("schema") != linkage["runtime_trace"] or traces.get("owner") != "ResponseStateMachine":
            raise SystemExit("unexpected runtime trace owner or schema")
        required = {"happy": {"applying", "active", "rolling_back", "lifted"},
                    "partial": {"rollback_partial", "lifted"},
                    "expiry": {"expiring", "lifted"}, "unstarted": {"expired"},
                    "unresolved": {"applying"}}
        for name, states in required.items():
            try:
                observed = validate_runtime_trace(traces[name])
            except (KeyError, TypeError, ValueError) as error:
                raise SystemExit(f"invalid {name} runtime trace: {error}") from error
            if not states.issubset(observed):
                raise SystemExit(f"runtime trace did not exercise required {name} states")
        report["runtime_trace_sha256"] = hashlib.sha256(args.runtime_traces.read_bytes()).hexdigest()
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    if len(results) != 9 or not all(result["passed"] for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
