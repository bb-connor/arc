# Diagnostic attempts

These actual pre-freeze attempts are retained for review. They do not satisfy
current-source acceptance. Linux cross lint found needless return and a musl
CMSG_LEN conversion; both are corrected without lint suppression. Earlier
hygiene failures prompted extraction of cage preparation into a Rust module.
Bindings may differ because the reviewed inputs were subsequently expanded.
Final required gates live in the parent evidence directory.

The registry-order attempt exposed two prior order-sensitive artifact tests.
The wire-registry attempt exposed missing modern aliases in the complete wire
test registry and an incompletely regenerated manifest self-hash. Both are
corrected; the complete owning-crate suite and schema gate now pass. The retained
broad diagnostic run also passed. The registry-followup P3 attempt exited zero
but was correctly invalidated when sources changed during its execution. Its
fresh final gate passed on the sealed source binding.
