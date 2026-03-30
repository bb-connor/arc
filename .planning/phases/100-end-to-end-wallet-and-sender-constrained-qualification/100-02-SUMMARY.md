# Summary 100-02

Qualified ARC's asynchronous holder path and sender-constrained negative
cases over the hosted authorization edge.

Validated:

- public challenge fetch and response submit as the supported message-oriented
  or asynchronous holder path
- optional identity-assertion continuity rejection on stale or mismatched
  input
- DPoP sender proof continuity across token exchange and MCP runtime
- mTLS thumbprint binding plus bounded attestation confirmation
- fail-closed rejection when attestation binding is attempted without DPoP or
  mTLS

Unsupported sender semantics remain bounded and explicit.
