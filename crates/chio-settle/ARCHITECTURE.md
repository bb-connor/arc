# chio-settle Architecture

`chio-settle` owns settlement preparation, runtime controls, retry envelopes, cross-chain delivery reconciliation, and receipt projection for the official Chio web3 contract family.

The crate exposes one public facade from `src/lib.rs` and keeps the implementation split by settlement concern: EVM preparation and finalization, Solana parity, CCIP coordination, x402 and payment compatibility, runtime operations, automation watchdogs, finality observation, and local devnet config.

The trust boundary is pre-chain and post-chain determinism. Inputs from policies, operator config, receipts, payment rails, and RPC observations must either become stable prepared artifacts or fail closed before a contract call, automation job, runtime report, or reconciliation receipt is emitted.

Current hardening: x402 public payment requirements reject blank or whitespace-bearing facilitator, resource, and accepted-token fields before those values can be advertised to callers.
