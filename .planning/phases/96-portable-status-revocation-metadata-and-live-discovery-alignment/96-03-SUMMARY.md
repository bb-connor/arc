# Summary 96-03

Added qualification coverage for the two edge cases phase 96 was supposed to
close: public lifecycle distribution without TTL and stale-but-still-published
passport lifecycle state.

The docs, release boundary, and qualification matrix now describe the same
portable lifecycle story the code enforces: `active` is healthy, `stale` is a
real state, and over-aged lifecycle truth is denied fail closed.
