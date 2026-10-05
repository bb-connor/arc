"""Host-side custody controls; native confinement is qualified separately."""

import os
import unittest
from unittest.mock import patch

import host
from chio_process import WorkerError


class HostCustodyTests(unittest.TestCase):
    def test_kernel_and_broker_fixture_do_not_inherit_resource_or_model_credentials(
        self,
    ):
        with patch.dict(
            os.environ,
            {
                "PATH": "/bin",
                "CHIO_JOB_DATABASE_URL": "secret-db",
                "CHIO_JOB_DATABASE_CA": "/private/ca",
                "OPENROUTER_API_KEY": "secret-model",
            },
            clear=True,
        ):
            self.assertEqual(host.host_environment(), {"PATH": "/bin"})

    def test_operator_retains_prepared_body_and_never_dispatches_on_preparation_failure(
        self,
    ):
        connection = {
            "socket_path": "/private/socket",
            "credential": "local-credential",
        }
        envelope = {"schema": "chio.broker-execute.v1", "request": {"body": [1, 2]}}
        with patch.object(
            host.ProcessClient, "prepare_invocation", return_value=envelope
        ) as prepare:
            with patch.object(host.ProcessClient, "invoke") as invoke:
                request = host.prepared_request(
                    connection, "original", "assign", {"limit": 1}
                )
                self.assertIs(request["arguments"], envelope)
                self.assertTrue(request["known_outcome_only"])
                prepare.assert_called_once_with(
                    "original", "jobs-admin-assign", "assign", {"limit": 1}
                )
                self.assertNotIn("credential", request)
                prepare.side_effect = WorkerError("conflict")
                with self.assertRaises(WorkerError):
                    host.prepared_request(
                        connection, "original", "assign", {"limit": 2}
                    )
                invoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
