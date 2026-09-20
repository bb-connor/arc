# Chio regress backport

Source: regress 0.11.1 registry archive, SHA-256
`158a764437582235e3501f683b93a0a6f8d825d04a789dbe5ed30b8799b8908a`.

Apply upstream commit `5e5141c1f6d132f2890b09f998f6a0a93c5d94ab`
without changing its API guard or regression assertions. The upstream test
is retained in a separate integration target with an explicit Regex import
because the release test file predates its surrounding upstream context. The public UTF-8 search
entry point rejects non-character-boundary start offsets before constructing the match iterator. Out-of-range and ASCII behavior follow the upstream contract.

This patch is not a certification of the entire dependency.

One whitespace-only line in the inert upstream autofix workflow is normalized
so the retained source passes the repository whitespace gate.
