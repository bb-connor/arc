<!--
Target: spec/PROTOCOL.md
Insertion point: replace one sentence inside "### 8.2 MCP Compatibility".
Apply only after ADR-0039 is marked Accepted. Until then 8.2 is unchanged.

Text to replace (in the "remote HTTP auth discovery" bullet):

  Hosted OAuth authorization-server product work is
  explicitly blocked until the OAuth AS ADR or equivalent decision note is
  accepted.

Replacement text follows this comment; drop this comment.
-->

  [ADR-0039](../docs/adr/ADR-0039-customer-hosted-root-exchange.md) accepts
  the customer-hosted root exchange on the local authorization server inside
  `serve-http` (section 5.6); other hosted OAuth authorization-server product
  work stays blocked until a further accepted ADR defines its scope.
