# Steps

1. Build the local `arc` binary once.
2. Start trust control with dedicated SQLite state under this bundle.
3. Start the wrapped provider MCP edge.
4. Start the buyer FastAPI service with the live provider client enabled.
5. Start `arc api protect` in front of the buyer.
6. Submit a governed quote request for a `hotfix-review`.
7. Create a governed job under budget so execution proceeds immediately.
8. Query trust control for all receipts plus provider capability-specific receipts.
