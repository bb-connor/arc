"""Process recovery observers see complete worker JSON publications."""

import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "process_runner_fixture", Path(__file__).with_name("runner.py")
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class FixturePublication(unittest.TestCase):
    def test_new_publication_stays_absent_until_json_is_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "send-1.json"
            self.assert_during_write(path, None)
            self.assertEqual(json.loads(path.read_text()), {"published": True})

    def test_replacement_preserves_previous_complete_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "send-1.json"
            path.write_text('{"published":false}')
            self.assert_during_write(path, {"published": False})
            self.assertEqual(json.loads(path.read_text()), {"published": True})

    def assert_during_write(self, path, previous):
        serializing = threading.Event()
        resume = threading.Event()
        failures = []

        class PausedPublication(dict):
            def items(self):
                serializing.set()
                if not resume.wait(5):
                    raise AssertionError("publication serialization was not released")
                return super().items()

        def publish():
            try:
                runner.write(path, PausedPublication(published=True))
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=publish)
        thread.start()
        try:
            self.assertTrue(serializing.wait(5), "publisher never serialized the record")
            if previous is None:
                self.assertFalse(path.exists(), "observer saw an unfinished publication")
            else:
                self.assertEqual(path.read_text(), '{"published":false}')
        finally:
            resume.set()
            thread.join(5)
        self.assertFalse(thread.is_alive(), "publisher did not finish")
        if failures:
            raise failures[0]


if __name__ == "__main__":
    unittest.main()
