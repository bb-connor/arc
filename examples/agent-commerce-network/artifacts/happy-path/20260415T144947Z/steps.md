# Steps

1. Start trust control and the buyer/provider topology.
2. Submit `contracts/quote-request.json` through the buyer procurement API.
3. Have the provider return `contracts/quote-response.json`.
4. Create a buyer job from the accepted quote.
5. Execute the provider review and emit `contracts/fulfillment-package.json`.
6. Reconcile using `contracts/settlement-reconciliation.json`.
