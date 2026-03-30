-- ARC formal verification -- root import file.

import Arc.Core.Capability
import Arc.Core.Scope
import Arc.Core.Revocation
import Arc.Spec.Properties

-- Standalone proof modules are not imported into the launch-claim root until
-- they are free of `sorry`. The shipped release gate relies on the executable
-- differential tests under `formal/diff-tests` plus runtime/conformance lanes.
-- Import individually for exploratory proof checking:
--   Arc.Proofs.Monotonicity
