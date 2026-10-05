"""The isolation probe must name real host material, with a positive control."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import client


class SandboxProbeTests(unittest.TestCase):
    def test_external_canary_is_readable_without_filesystem_confinement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'worker'
            state.mkdir(mode=0o700)
            client.init(state)
            canary = root / 'actual-host-canary'
            canary.write_bytes(b'host probe')
            with patch.object(client.socket, 'create_connection', side_effect=OSError('no route')):
                result = client.main(['probe-sandbox', str(state), 'https://localhost:8443', str(canary)])
                self.assertTrue(result['parentFilesystemReadable'])
                canary.unlink()
                result = client.main(['probe-sandbox', str(state), 'https://localhost:8443', str(canary)])
                self.assertFalse(result['parentFilesystemReadable'])


if __name__ == '__main__':
    unittest.main()
