# Independent review and disposition

Reviewed range: `d51afb4a5ffc1caafb63540b8651d19ac767b95e..cb91af8aa9`.
One fresh reviewer inspected source, configuration, the diff and function-body
comparisons. It did not run builds. Its verdict at that revision was not ready
to merge, with no critical runtime regression identified and three Important
ownership gaps. The implementer accepted all three.

| Finding | Reason | Final disposition |
| --- | --- | --- |
| Broker authority results in the service ancestor | Private ancestor fields remain accessible to transport descendants, permitting construction without authorization routines. | `68acb34aca`: ordinary results belong to authorization with immutable/consuming projections; audit results are entirely private there. |
| Retained credentials in the service ancestor | Transport descendants could inspect or mutate the prepared map and secret-bearing record. | `68acb34aca`: the custody owner holds private map/record fields and preparation/execution children. Other modules can discard an operation but cannot obtain its lock or credentials. Test observations return keys only. |
| Reserved plans in the event-consumer ancestor | Orchestration siblings could construct or rebind the trusted plan directly. | `68acb34aca`: reservation owns the fields, fresh construction, checked reconstruction and verified artifact binding. |

Actual compiler probes demonstrate accepted sibling access before these fixes
and rejected access afterward. Behavioral qualification after the fix passes
171 broker cases and 261 control-plane cases, including reconstruction corruption
coverage; strict Clippy passes. This was one fix pass without a second review.
There were no deferred minor findings.

The reviewer declined runtime qualification of native x86 confinement, the stopped
native-flow timing campaign, other platforms/feature combinations, the entire
workspace, hosted CI, publication and operations. Each remains open. It also set
aside redesign of public runtime-validated wire carriers such as
`TrustedExecutionContext`; that is distinct from the private proof/custody
requirements addressed here. The execution record retains the implementer's
corresponding rulings and costs.

The implementer's final packaging search found one additional old helper package
selection in the release workflow. `938b76c311` fixes it with a source-gate
regression and hostile self-test. That correction does not claim an executed
hosted release workflow.
