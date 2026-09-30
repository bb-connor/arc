# Independent review and demonstrated repairs

One existing reviewer, `multiroute_final_review`, reviewed the batch and targeted
follow-ups. The implementer made the changes and ran qualification.

| Finding | Disposition |
| --- | --- |
| Docker lifetime could change between exec creation and start or before result certification. | Recheck exact pinned daemon/container identity before start and after completion; lifetime mutation regression and real adapter probes. |
| Durable broker response headers could retain noncanonical order. | Normalize and sort before signing; reject duplicate normalized names. Native provider response progressed through the repaired boundary. |
| Selected standard syscall profile was not propagated through the factory and operator ceiling. | Bind the independently selected profile to both and require exact manifest equality. The later native trace also found discovery's hardcoded minimal profile; it now uses the same selection. |
| The Python extension directory lacked enumeration permission. | Retain the single protected extension directory as well as its exact files. |
| Python archive and isolated import configuration lacked runtime content binding. | Include both in the hashed runtime-file inventory. |
| Parent and explicit child grants retained the same path twice and triggered alias rejection. | Deduplicate the same path only when the complete descriptor identity matches. Preserve distinct-path alias rejection. The native 64-resource regression passes. |

The retained-history hoist and shared journal-version repair were included in
the follow-up review; no additional concrete finding was reported for them.
Review does not close the failing long-history mini-SWE campaign or unexecuted
consumer/CI acceptance gates.
