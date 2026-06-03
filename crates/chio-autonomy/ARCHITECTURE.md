# chio-autonomy Architecture

`chio-autonomy` owns bounded autonomous pricing, capital optimization, execution, rollback, drift, comparison, and qualification contracts. It ties core monetary amounts, market liability classes, and web3 settlement states into one evidence-referential automation layer.

The crate is intentionally data-contract heavy: public structs model wire artifacts and validator functions enforce schema ids, required references, authority envelopes, safety gates, rollback coverage, and fail-safe drift behavior.

The core security constraint is bounded execution. A validated artifact must not smuggle broader authority through malformed amounts, loose references, mismatched currencies, or unchecked automation modes.

Planned improvement: make currency validation exact for declared and nested monetary amounts so canonical artifacts cannot differ only by lowercase or padded currency strings.
