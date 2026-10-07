"""Failed launch and shutdown observations retain their declared trial slots."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import campaign_main


class CampaignRetentionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.evidence = Path(self.temporary.name)
        self.manifest = {"model":"fixed-model", "authority_policy":hashlib.sha256(b"{}").hexdigest(),
            "source_binding":"test-candidate", "base_commit":"1"*40,
            "source_inventory_version":campaign_main.SOURCE_INVENTORY_VERSION,
            "provider_endpoint":"https://api.openai.com/v1",
            "budgets":{"native_preparation_seconds":1, "native_shutdown_seconds":1,
                "host_start_deadline_seconds":1, "provider_seconds":1,
                "model_calls":1, "prompt_bytes":512, "output_tokens":128}}
        self.trial = {"id":"retained-trial", "host":"langgraph", "workflow":"support", "arm":"product",
                      "case":"authorized", "repetition":1}

    def launch(self, command, **options):
        exchange = Path(options["stdout"].name).parent
        for name, data in [("authority-contract.json", b"{}"), ("capability.json", b"synthetic"),
                           ("command.json", b"{}")]:
            (exchange / name).write_bytes(data)
        options["stdout"].write(b"test result: ok. 1 passed; 0 failed; 0 ignored\n")
        options["stdout"].flush()
        return SimpleNamespace(wait=lambda **kwargs:0, terminate=lambda:None, kill=lambda:None)

    def retained(self, row):
        stored = json.loads((self.evidence / self.trial["id"] / "result.json").read_bytes())
        self.assertEqual(stored, row)
        self.assertGreaterEqual(row["elapsed_seconds"], 0)
        self.assertGreaterEqual(row["native_preparation_seconds"], 0)

    def test_native_launch_failure_is_retained_with_unknown_facts(self):
        with patch.object(campaign_main.subprocess, "Popen", side_effect=FileNotFoundError("synthetic")):
            row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
        self.retained(row)
        self.assertEqual(row["outcome"], "native_error")
        self.assertEqual(row["error_category"], "campaign.native_launch_failed")
        self.assertEqual(row["native_observation"], "unknown")
        self.assertIsNone(row["native"])

    def test_ready_timeout_is_native_error_and_retains_preparation_duration(self):
        with patch.object(campaign_main.subprocess, "Popen", self.launch), \
             patch.object(campaign_main, "wait_endpoint", side_effect=TimeoutError("campaign.native_preparation_failed")):
            row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
        self.retained(row)
        self.assertEqual(row["outcome"], "native_error")
        self.assertEqual(row["error_category"], "campaign.native_preparation_failed")

    def test_host_failure_retains_host_duration(self):
        import openai
        class Provider:
            def __init__(self, **options):
                self.chat = SimpleNamespace(completions=SimpleNamespace())
                self.http = options["http_client"]
            def __enter__(self): return self
            def __exit__(self, *arguments): self.http.close()
        async def failure(*arguments):
            raise RuntimeError("campaign.provider_unavailable")
        with patch.object(campaign_main.subprocess, "Popen", self.launch), \
             patch.object(campaign_main, "wait_endpoint", return_value="http://127.0.0.1:20096"), \
             patch.object(campaign_main, "graph_trial", failure), patch.object(openai, "OpenAI", Provider), \
             patch.dict(os.environ, {"OPENAI_API_KEY":"synthetic"}):
            row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
        self.retained(row)
        self.assertEqual(row["outcome"], "provider_error")
        self.assertGreaterEqual(row["host_model_native_seconds"], 0)

    def test_failed_shutdown_and_malformed_native_evidence_still_retain_row(self):
        def launch(command, **options):
            process = self.launch(command, **options)
            (Path(options["stdout"].name).parent / "native-evidence.json").write_text("malformed")
            process.wait = lambda **kwargs:(_ for _ in ()).throw(subprocess.TimeoutExpired("native", 1))
            return process
        with patch.object(campaign_main.subprocess, "Popen", launch), \
             patch.object(campaign_main, "wait_endpoint", side_effect=TimeoutError("campaign.native_preparation_failed")):
            row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
        self.retained(row)
        self.assertIsNone(row["native"])
        self.assertTrue(row["native_shutdown_error"])
        self.assertTrue(row["native_evidence_error"])

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(signal, "SIGALRM"), "POSIX FIFO")
    def test_native_image_rejects_fifo_without_blocking(self):
        image = self.evidence / "target/debug/deps/chio_control_plane-synthetic"
        image.parent.mkdir(parents=True)
        os.mkfifo(image)
        previous = signal.getsignal(signal.SIGALRM)
        def expired(*arguments):
            raise TimeoutError("native image reader blocked")
        signal.signal(signal.SIGALRM, expired)
        signal.alarm(1)
        try:
            with self.assertRaisesRegex(ValueError, "^qualification.native_executable$"):
                campaign_main.observed_native_executable(self.evidence,
                    "Running unittests src/lib.rs (target/debug/deps/chio_control_plane-synthetic)\n")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def test_native_image_cannot_follow_a_replaced_parent_directory(self):
        image = self.evidence / "target/debug/deps/chio_control_plane-synthetic"
        image.parent.mkdir(parents=True)
        image.write_bytes(b"synthetic executable observation")
        actual = self.evidence / "alternate/debug/deps"
        actual.parent.mkdir(parents=True)
        image.parent.rename(actual)
        image.parent.symlink_to(actual, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            campaign_main.observed_native_executable(self.evidence,
                "Running unittests src/lib.rs (target/debug/deps/chio_control_plane-synthetic)\n")

    def test_provider_origin_is_checked_before_a_shadow_module_can_execute(self):
        root = Path(__file__).resolve().parents[2]
        marker = self.evidence / "shadow-executed"
        (self.evidence / "httpx.py").write_text(
            "from pathlib import Path\nPath("+repr(str(marker))+").touch()\n"
            "raise RuntimeError('shadow executed')\n")
        code = "import sys;from pathlib import Path;root=Path(sys.argv[1]);" \
               "sys.path[:0]=[sys.argv[2],str(root/'fixtures/recovery-product')," \
               "str(root/'sdks/python/chio-sdk-python/src'),str(root/'sdks/python/chio-adapter-base/src')];" \
               "\ntry: import campaign_main\n" \
               "except ValueError as error:\n" \
               " if str(error)!='qualification.provider_module_origin':raise\n" \
               "else: raise SystemExit('shadow module was not refused')\n"
        result = subprocess.run([sys.executable,"-I","-B","-c",code,str(root),str(self.evidence)],
                                cwd=root,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        self.assertFalse(marker.exists(),"provider shadow executed before origin validation")


if __name__ == "__main__":
    unittest.main()
