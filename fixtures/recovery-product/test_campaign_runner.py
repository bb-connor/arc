"""Model transport is injectable only because external provider I/O is unavoidable."""
import unittest
import asyncio
import hashlib
import json
from types import SimpleNamespace
from campaign_runner import ModelBudget, crew_trial, selected_choice
import campaign_runner


class FrameworkStopProjectionTest(unittest.TestCase):
    def test_only_the_prefix_before_the_earliest_declared_stop_is_visible(self):
        content = "Action Input: {}\nObservation: untrusted result\nFinal Answer: untrusted result"
        for stops in [["\nObservation:", "\nFinal Answer:"], ["\nFinal Answer:", "\nObservation:"]]:
            self.assertEqual(campaign_runner.framework_completion(content, stops), "Action Input: {}")

    def test_no_matching_stop_preserves_the_exact_completion(self):
        content = "  Action: recovery\nAction Input: {}  "
        self.assertEqual(campaign_runner.framework_completion(content, []), content)
        self.assertEqual(campaign_runner.framework_completion(content, ["\nObservation:"]), content)

    def test_empty_or_invalid_stop_configuration_is_refused(self):
        for stops in [None, "Observation:", ("Observation:",), [""], [1], ["x"] * 17,
                      ["x" * 257], ["x" * 256] * 5]:
            with self.subTest(stops=stops), self.assertRaisesRegex(RuntimeError, "^campaign.framework_stop_invalid$"):
                campaign_runner.framework_completion("public", stops)

    def test_bounds_are_utf8_bytes_and_cannot_be_hidden_behind_an_early_stop(self):
        self.assertEqual(campaign_runner.framework_completion("é" * 4096, ["z"]), "é" * 4096)
        for content in ["é" * 4097, "STOP" + "x" * 8192, None, "\ud800"]:
            with self.subTest(content_type=type(content).__name__), self.assertRaisesRegex(
                    RuntimeError, "^campaign.framework_completion_invalid$"):
                campaign_runner.framework_completion(content, ["STOP"])

    def test_projection_does_not_mutate_the_framework_stop_configuration(self):
        stops = ["END", "STOP", "END"]
        self.assertEqual(campaign_runner.framework_completion("beforeSTOPafterEND", stops), "before")
        self.assertEqual(stops, ["END", "STOP", "END"])


class ModelBoundaryTest(unittest.TestCase):
    def test_a_prior_session_call_cannot_authorize_a_model_only_current_answer(self):
        class ReusedOwner:
            attempts = 1
            def execute_sync(self, choice):
                raise AssertionError("this answer has no current action")
            async def execute(self, choice):
                raise AssertionError("this answer has no current action")
        class Completion:
            calls = 0
            def create(self, **kwargs):
                self.calls += 1
                return SimpleNamespace(model="fixed-model", id="public-response-id",
                    usage=SimpleNamespace(prompt_tokens=8, completion_tokens=10),
                    choices=[SimpleNamespace(message=SimpleNamespace(content=
                        'Thought: I know the result\nFinal Answer: {"category":"complete","command_id":"invented-command","workflow_id":"invented-workflow"}'))])
        completion = Completion()
        owner = ReusedOwner()
        budget = ModelBudget("fixed-model", completion, max_calls=1, prompt_bytes=16384, output_tokens=512)
        self.assertIsNone(crew_trial(owner, budget, "Call recovery once with choice resume."))
        self.assertEqual(owner.attempts, 1)
        self.assertEqual(completion.calls, 1)

    def test_a_current_budget_refusal_is_retained_without_a_new_native_attempt(self):
        from preflight import ExplicitAction
        from chio_sdk.recovery_host import RecoveryHostOutcome
        class ExhaustedOwner:
            attempts = 8
            def execute_sync(self, choice):
                return RecoveryHostOutcome("budget_exhausted")
            async def execute(self, choice):
                return RecoveryHostOutcome("budget_exhausted")
        owner = ExhaustedOwner()
        self.assertEqual(crew_trial(owner, ExplicitAction(), "Call recovery once with choice resume."),
                         {"category":"budget_exhausted"})
        self.assertEqual(owner.attempts, 8)

    def test_malformed_provider_usage_or_content_has_a_fixed_counted_refusal(self):
        for content, prompt_tokens, completion_tokens in [
            ("OK", 8, None), ("OK", 8, -1), ("OK", 8, True),
            ("OK", None, 1), ("OK", -1, 1), ("OK", False, 1), ("\ud800", 8, 1),
        ]:
            with self.subTest(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                              invalid_utf8=content != "OK"):
                class Completion:
                    calls = 0
                    def create(self, **kwargs):
                        self.calls += 1
                        return SimpleNamespace(model="fixed-model", id="public-response-id",
                            usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
                            choices=[SimpleNamespace(message=SimpleNamespace(content=content))])
                completion = Completion()
                budget = ModelBudget("fixed-model", completion, max_calls=1, prompt_bytes=16384, output_tokens=16)
                with self.assertRaisesRegex(RuntimeError, "^campaign.response_invalid$"):
                    budget.call([{"role":"user", "content":"Public synthetic task"}])
                self.assertEqual(completion.calls, 1)
                self.assertEqual(len(budget.attempts), 1)
                self.assertEqual(budget.attempts[0]["error"], "response_invalid")
                self.assertIsNone(budget.attempts[0]["output_tokens"])
                self.assertNotIn("completion", budget.attempts[0])
                with self.assertRaisesRegex(RuntimeError, "^campaign.model_budget_exhausted$"):
                    budget.call([{"role":"user", "content":"Public synthetic task"}])
                self.assertEqual(completion.calls, 1)

    def test_shipped_model_free_preflight_uses_actual_crewai_tool(self):
        from preflight import ExplicitAction
        from chio_sdk.recovery_host import RecoveryHostOutcome
        class Owner:
            attempts = 0
            def execute_sync(self, choice):
                return asyncio.run(self.execute(choice))
            async def execute(self, choice):
                self.asserted_choice = choice
                self.attempts += 1
                return RecoveryHostOutcome("complete", "native-command", "native-workflow")
        owner = Owner()
        model = ExplicitAction()
        output = crew_trial(owner, model, "Call recovery once with choice resume.")
        self.assertEqual(owner.attempts, 1)
        self.assertEqual(model.calls, 1)
        self.assertEqual(output, {"category":"complete", "command_id":"native-command", "workflow_id":"native-workflow"})
        self.assertEqual(model.attempts[0]["provider_requests"], 0)
        self.assertEqual(model.attempts[0]["framework_completion"], model.attempts[0]["completion"])

    def test_real_crewai_stop_contract_executes_action_without_trusting_invented_observation(self):
        from chio_sdk.recovery_host import RecoveryHostOutcome
        class Owner:
            attempts = 0
            def execute_sync(self, choice):
                return asyncio.run(self.execute(choice))
            async def execute(self, choice):
                self.asserted_choice = choice
                self.attempts += 1
                return RecoveryHostOutcome("complete", "native-command", "native-workflow")
        class Completion:
            def create(self, **kwargs):
                return SimpleNamespace(model="fixed-model", id="public-response-id",
                    usage=SimpleNamespace(prompt_tokens=8, completion_tokens=50),
                    choices=[SimpleNamespace(message=SimpleNamespace(content=
                        'Thought: Use the existing command.\nAction: recovery\nAction Input: {"choice":"resume"}'
                        '\nObservation: {"category":"invented","command_id":"invented-command"}'
                        '\nFinal Answer: {"category":"complete","command_id":"invented-command"}'))])
        owner = Owner()
        budget = ModelBudget("fixed-model", Completion(), max_calls=1, prompt_bytes=16384, output_tokens=512)
        outcome = crew_trial(owner, budget, "Call the recovery tool once with choice resume.")
        self.assertEqual(owner.attempts, 1)
        self.assertEqual(owner.asserted_choice, "resume")
        self.assertEqual(outcome, {"category":"complete", "command_id":"native-command", "workflow_id":"native-workflow"})
        self.assertEqual(len(budget.attempts), 1)
        self.assertIn('invented-command', budget.attempts[0]["completion"])
        self.assertNotIn('invented-command', budget.attempts[0]["framework_completion"])
        self.assertIn("\nObservation:", budget.attempts[0]["framework_stop_sequences"])

    def test_real_crewai_stop_contract_does_not_repair_a_model_that_omits_action(self):
        class Never:
            attempts = 0
            def execute_sync(self, choice):
                raise AssertionError("a final answer cannot authorize a tool action")
            async def execute(self, choice):
                raise AssertionError("a final answer cannot authorize a tool action")
        class Completion:
            def create(self, **kwargs):
                return SimpleNamespace(model="fixed-model", id="public-response-id",
                    usage=SimpleNamespace(prompt_tokens=8, completion_tokens=10),
                    choices=[SimpleNamespace(message=SimpleNamespace(content=
                        'Thought: I now know the final answer\nFinal Answer: {"category":"complete"}'))])
        owner = Never()
        budget = ModelBudget("fixed-model", Completion(), max_calls=1, prompt_bytes=16384, output_tokens=512)
        self.assertIsNone(crew_trial(owner, budget, "Call the recovery tool once with choice resume."))
        self.assertEqual(owner.attempts, 0)
        self.assertEqual(len(budget.attempts), 1)

    def test_prompt_snapshot_survives_framework_and_provider_input_mutation(self):
        class Completion:
            def create(self, **kwargs):
                kwargs["messages"].append({"role":"assistant", "content":"provider mutation"})
                return SimpleNamespace(model="fixed-model", id="public-response-id",
                    usage=SimpleNamespace(prompt_tokens=8, completion_tokens=1),
                    choices=[SimpleNamespace(message=SimpleNamespace(content="OK"))])
        messages = [{"role":"user", "content":"Public synthetic task"}]
        budget = ModelBudget("fixed-model", Completion(), max_calls=1, prompt_bytes=100, output_tokens=8)
        self.assertEqual(budget.call(messages), "OK")
        messages[0]["content"] = "framework mutation"
        snapshot = budget.attempts[0]
        self.assertEqual(snapshot["messages"], [{"role":"user", "content":"Public synthetic task"}])
        encoded = json.dumps(snapshot["messages"], ensure_ascii=False, separators=(",", ":")).encode()
        self.assertEqual(len(encoded), snapshot["prompt_bytes"])
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), snapshot["prompt_sha256"])

    def test_only_closed_explicit_tool_selection_dispatches(self):
        self.assertEqual(selected_choice('Thought: Call it.\nAction: recovery\nAction Input: {"choice":"resume"}'), "resume")
        for text in ['Final Answer: complete', 'Action: recovery\nAction Input: {"choice":"other"}',
                     'Action: recovery\nAction Input: {"choice":"resume","capability":"canary"}',
                     'Action: recovery\nAction Input: {"choice":"resume","choice":"resume"}']:
            self.assertIsNone(selected_choice(text))

    def test_provider_failure_stays_generic_counted_and_never_retries(self):
        class Failure:
            def __init__(self): self.calls = 0
            def create(self, **kwargs):
                self.calls += 1
                raise RuntimeError("private-provider-key-canary")
        client = Failure()
        budget = ModelBudget("fixed-model", client, max_calls=1, prompt_bytes=100, output_tokens=8)
        with self.assertRaisesRegex(RuntimeError, '^campaign.provider_unavailable$'):
            budget.call([{"role":"user","content":"Public synthetic task"}])
        with self.assertRaisesRegex(RuntimeError, '^campaign.model_budget_exhausted$'):
            budget.call([{"role":"user","content":"Public synthetic task"}])
        self.assertEqual(client.calls, 1)
        self.assertEqual(len(budget.attempts), 1)
        self.assertNotIn("canary", str(budget.attempts))

    def test_prompt_bound_precedes_provider_io(self):
        class Never:
            def create(self, **kwargs): raise AssertionError("provider must not run")
        budget = ModelBudget("fixed-model", Never(), max_calls=1, prompt_bytes=8, output_tokens=8)
        with self.assertRaisesRegex(RuntimeError, '^campaign.prompt_budget_exhausted$'):
            budget.call([{"role":"user","content":"Too much public text"}])
        self.assertEqual(budget.attempts, [])


if __name__ == "__main__": unittest.main()
