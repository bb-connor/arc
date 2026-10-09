You are {agent}. This session is being retired to keep its context small, and a fresh session will
continue your work from your charter.

These events woke this turn and nobody has acted on them yet. Do not act on them now; your successor
will see them again, so write down what you know about each:
{events}

Write a handoff for your successor in under 60 lines: what you were doing, every open item and its state,
decisions and promises you made to Connor or other agents, anything you were waiting on, and what to do
next. Save it to a file outside ~/swarm (for example /tmp/swarm-briefs/handoff.md) and run
`swarm record digest {agent}-handoff-{stamp} --file <that file>`. Then end your turn.
