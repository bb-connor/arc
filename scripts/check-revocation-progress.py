#!/usr/bin/env python3
"""Check source-pinned revocation progress obligations with bounded solver time."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import tomllib
import z3
from formal.revocation_progress import obligations, witness

ROOT = Path(__file__).resolve().parent.parent


def check(pre, post, negative, timeout_ms=10000, query_path=None):
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    solver.add(pre)
    feasible = solver.check()
    if feasible != z3.sat:
        return {"passed": False, "feasible": str(feasible), "reason": "vacuous or unknown premise"}, None
    solver.add(z3.Not(post))
    if query_path is not None:
        query_path.write_text(solver.to_smt2())
    verdict = solver.check()
    return {"passed": verdict == (z3.sat if negative else z3.unsat),
            "feasible": str(feasible), "verdict": str(verdict),
            "reason": solver.reason_unknown() if verdict == z3.unknown else None}, solver.model() if verdict == z3.sat else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    linkage = tomllib.loads((ROOT / "formal/revocation-progress.toml").read_text())
    if z3.get_version_string() != linkage["solver_version"]:
        raise SystemExit("unexpected Z3 version")
    for path, expected in linkage["source_sha256"].items():
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != expected:
            raise SystemExit(f"projection requires review after source drift: {path}")
    implementation = [ROOT / "scripts/formal/revocation_progress.py", Path(__file__).resolve()]
    report = {"implementation_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in implementation}, "scope": linkage["scope"], "source_sha256": linkage["source_sha256"],
              "solver_version": z3.get_version_string(), "authorities": 4, "capabilities": 8,
              "epochs": "unbounded integers", "fairness": "WF_vars(PropagateAny), manual well-founded argument",
              "historical_query": "length 24 SMT query remains timed out; replaced operational gate, not a passing old query",
              "results": []}
    for name, pre, post, negative, state in obligations():
        start = time.monotonic()
        result, model = check(pre, post, negative, query_path=args.output / f"{name}.smt2")
        result.update(name=name, negative=negative, seconds=round(time.monotonic()-start, 3))
        if model is not None:
            result["counterexample"] = witness(model, state)
        report["results"].append(result)
        (args.output / "summary.json").write_text(json.dumps(report, indent=2)+"\n")
        print(f"{name}: {'PASS' if result['passed'] else 'FAIL'} ({result.get('verdict', result.get('reason'))})", flush=True)
        if not result["passed"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
