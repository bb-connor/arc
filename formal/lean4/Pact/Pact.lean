-- PACT Formal Verification -- Root import file

import Pact.Core.Capability
import Pact.Core.Scope
import Pact.Core.Revocation
import Pact.Spec.Properties

-- Proof modules not imported into root to avoid pulling in sorry.
-- Import individually for proof checking:
--   Pact.Proofs.Monotonicity
