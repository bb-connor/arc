#!/usr/bin/env python3
"""Exercise the actual grep gate on isolated positive and negative sources."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class LogRedactionCalibration(unittest.TestCase):
    def test_qualified_macro_and_raw_field_boundaries(self):
        cases = [
            ('reason = %redacted!(&reason)', True),
            ('reason = %chio_log_redact::redacted!(&reason)', True),
            ('error = %chio_log_redact::redacted!(&error)', True),
            ('reason = %redact_for_operator_log(&reason)', True),
            ('reason = %reason', False),
            ('reason = %other::redacted!(&reason)', False),
            ('reason = %chio_log_redact::raw(&reason)', False),
            ('reason = %chio_log_redact::redacted_value(&reason)', False),
            ('%reason', False),
            ('body = %body', False),
            ('payload = %payload', False),
            ('prompt = format!("{}", prompt)', False),
            ('reason = %chio_log_redact::redacted!(&reason), error = %error', False),
        ]
        with tempfile.TemporaryDirectory(prefix="chio-log-redaction-calibration-") as directory:
            root = Path(directory)
            script = root / "scripts/check-log-redaction.sh"
            script.parent.mkdir()
            shutil.copyfile(ROOT / "scripts/check-log-redaction.sh", script)
            for scope in ["crates/kernel/chio-kernel/src", "crates/observability/chio-siem/src"]:
                source = root / scope / "fixture.rs"
                source.parent.mkdir(parents=True)
                source.write_text("", encoding="utf-8")
            for scope in ["crates/kernel/chio-kernel/src", "crates/observability/chio-siem/src"]:
                source = root / scope / "fixture.rs"
                for fields, accepted in cases:
                    with self.subTest(scope=scope, fields=fields):
                        source.write_text(f'tracing::warn!({fields}, "event");\n', encoding="utf-8")
                        result = subprocess.run(
                            ["bash", str(script)], capture_output=True, text=True, check=False,
                        )
                        self.assertEqual(result.returncode, 0 if accepted else 1, result.stdout + result.stderr)
                        if accepted:
                            self.assertIn("log redaction grep gate passed", result.stdout)
                        else:
                            self.assertIn("sensitive", result.stderr)
                source.write_text("", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
