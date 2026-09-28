---------------- MODULE RevocationPropagationUnfairWitness ----------------
EXTENDS RevocationPropagationPairLiveness

UnconditionalObservation == PairRevocationObserved ~> PairCaughtUp

=============================================================================
