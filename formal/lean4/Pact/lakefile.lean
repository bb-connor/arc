import Lake
open Lake DSL

package arc where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Arc where
  srcDir := "."
