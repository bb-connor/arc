"""An audit must reject fabricated or stale current-phase gate evidence."""
from copy import deepcopy
import hashlib
import json
import tempfile
from pathlib import Path
import unittest
from package_audit import audit_gate, audit_model_attempt
import package_audit


class GateAuditTest(unittest.TestCase):
    def test_framework_stop_frame_is_exact_and_cannot_synthesize_an_action(self):
        action = 'Thought: Use the owner.\nAction: recovery\nAction Input: {"choice":"resume"}'
        row = {"error":None, "completion":action+'\nObservation: invented\nFinal Answer: invented',
               "framework_stop_sequences":["\nObservation:"], "framework_completion":action}
        package_audit.audit_framework_frame(row, "crewai")
        for mutation in ["injected", "missing", "stops", "foreign"]:
            changed = deepcopy(row)
            if mutation == "injected": changed["framework_completion"] += '\nAction: recovery'
            elif mutation == "missing": changed.pop("framework_completion")
            elif mutation == "stops": changed["framework_stop_sequences"] = []
            with self.assertRaises(ValueError, msg=mutation):
                package_audit.audit_framework_frame(changed, "langgraph" if mutation == "foreign" else "crewai")
        final = 'Final Answer: {"category":"complete"}'
        declined = {**row,"completion":final,"framework_completion":final}
        package_audit.audit_framework_frame(declined, "crewai")
        declined["framework_completion"] = action
        with self.assertRaises(ValueError):
            package_audit.audit_framework_frame(declined, "crewai")

    def test_changed_prompt_output_latency_and_missing_request_refuse(self):
        messages = [{"role": "user", "content": "Public synthetic task"}]
        encoded = json.dumps(messages, ensure_ascii=False, separators=(",", ":")).encode()
        row = {"messages": messages, "prompt_bytes": len(encoded),
               "prompt_sha256": hashlib.sha256(encoded).hexdigest(), "output_tokens": 12,
               "seconds": 1, "completion": "Action: recovery", "error": None,
               "request_id": "public-request-id"}
        budgets = {"prompt_bytes": 16384, "output_tokens": 512,
                   "output_bytes": 8192, "provider_seconds": 45}
        audit_model_attempt(row, budgets)
        for mutation in ["prompt", "tokens", "bytes", "latency", "request"]:
            changed = deepcopy(row)
            if mutation == "prompt": changed["messages"][0]["content"] = "changed"
            elif mutation == "tokens": changed["output_tokens"] = 513
            elif mutation == "bytes": changed["completion"] = "x" * 8193
            elif mutation == "latency": changed["seconds"] = 46
            else: changed["request_id"] = None
            with self.assertRaises(ValueError, msg=mutation): audit_model_attempt(changed, budgets)

    def test_failed_stale_zero_test_wrong_command_and_changed_log_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'gate.log'
            log.write_text('test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured\n')
            expected={'command':['cargo','test','--lib'],'cwd':'.'}
            row={'gate':'native','command':expected['command'],'cwd':'.','exit_code':0,
                 'source_stable':True,'source_binding':'current','log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
            audit_gate(row,expected,log,'current',requires_tests=True)
            for mutation in ['failed','source','stable','command','zero','log']:
                altered=deepcopy(row)
                if mutation=='failed':altered['exit_code']=1
                elif mutation=='source':altered['source_binding']='historic'
                elif mutation=='stable':altered['source_stable']=False
                elif mutation=='command':altered['command']=['true']
                elif mutation=='zero':
                    log.write_text('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured\n')
                    altered['log_sha256']=hashlib.sha256(log.read_bytes()).hexdigest()
                else:log.write_text('fabricated passing summary')
                with self.assertRaises(ValueError,msg=mutation):audit_gate(altered,expected,log,'current',requires_tests=True)
                log.write_text('test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured\n')


if __name__ == '__main__':unittest.main()
