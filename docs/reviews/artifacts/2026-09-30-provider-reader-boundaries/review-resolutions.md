# Independent review and resolutions

One read-only reviewer, `/root/provider_reader_final_review` (`gpt-6-astra`,
high reasoning), reviewed the batch against base
`82eec927b20ec4dae1fff2a4eb149fef4592c817` and its implementation plan.
It ran no builds or tests and changed no files. Its assessment was "With fixes".
The author re-graded and resolved the findings below in one fix pass. There was
no second review of the final commit and no claim of per-fix red/green testing.

| Finding | Decision and resolution | Production-linked check |
|---|---|---|
| Important: an error frame without choices was ignored; DONE bypassed unfinished choices | Accepted. Reject provider error/invalid frames and require each started choice to finish independently of DONE. All invocation preparation precedes evaluator callbacks. | `upstream_error_and_transport_sentinel_cannot_complete_a_choice`; `invalid_tail_identity_or_arguments_prevent_all_evaluation` |
| Important: recorder cleared process-group ownership before inspecting leader exit | Accepted. Retain group ownership and terminate descendants after successful and failed capture, including children that close their pipes. | `closed_pipe_descendants_are_stopped_on_success_and_failure`; `capture_deadline_stops_a_descendant_holding_pipes` |
| Important: Ollama stream refusal echoed arbitrary done_reason | Accepted. Public policy errors use fixed text. Adjacent Gemini/Groq prompt-feedback fields now expose only a closed known reason or generic rejection. | `stream_policy_error_does_not_expose_provider_diagnostics`; both `refusal_diagnostics_do_not_echo_arbitrary_provider_text` tests |
| Minor: shared URL/header parsing discarded native errors | Required for the approved mechanism C contract. Native URL, header-name and header-value parser failures now remain error sources; logical policy rejections retain their structured reason separately. | `malformed_headers_and_urls_retain_native_parser_causes` |

## Rulings on declined behavior

- Build, feature and hosted qualification: the author owns the local campaign;
  terminal results are in qualification.json. No hosted or live-provider result
  is inferred from hermetic tests.
- Broader real-provider event-model compatibility: this batch retains the
  existing Cohere assembled-event and Gemini whole-function-call contracts.
  Preparing the whole stream before evaluation and bounded strict input do not
  qualify a new live protocol implementation. Compatibility beyond those
  contracts remains a separate interoperability task.
- Anthropic recorder start-only reconstruction: promoted into this batch because
  the recorder could retain arguments different from its captured stream. It now
  reconstructs bounded final deltas and requires a complete message; ambiguous
  or mixed inputs fail. `capture_reconstructs_arguments_and_rejects_ambiguous_or_incomplete_message`
  exercises this owner. The recorder produces fixture data, not admitted authority.
- Untouched baseline errors: remain tracked by their own reader/semantic queues;
  this batch does not declare workspace-wide error-taxonomy completion.
- Non-Unix and adversarial filesystem/process isolation: Unix nofollow regular
  file and Linux process-group controls are qualified here. A deliberately
  escaping descendant or hostile ancestor replacement needs OS isolation.
  Windows process-tree and path-race qualification is not claimed.
- Concurrent qualification repairs: the author inspected the final source diff,
  then ran final tests against its source hashes. The one reviewer did not
  re-review later fixture, formatting, recorder-reconstruction or documentation
  repairs. Final test evidence is distinct from that review.
