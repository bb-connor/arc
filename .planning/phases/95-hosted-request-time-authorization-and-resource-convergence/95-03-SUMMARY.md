# Summary 95-03

Made ARC's runtime artifact boundary explicit across hosted auth, review, and
approval surfaces. Access tokens remain runtime-admission artifacts, while
approval tokens, ARC capabilities, and reviewer evidence stay outside bearer
authorization.

The hosted regression flow now proves negative paths where wrong-resource
requests are rejected and reviewer-side artifacts such as authorization codes
cannot be replayed as runtime bearer tokens.
