import Lake
open Lake DSL

package pact where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Pact where
  srcDir := "."
