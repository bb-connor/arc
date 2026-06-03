# chio-listing Architecture

`chio-listing` owns Chio's generic listing, discovery, search, comparison, and trust-activation contracts. It is the publishing and admission boundary for marketplace listings before governance, open-market, federation, or runtime components consume them.

The crate is split between core listing artifacts, search/report aggregation, marketplace discovery with signed pricing hints, shared validation helpers, and the trust-activation flow. Listings are signed by namespace owners, reports aggregate verified listings from publishers, and activation artifacts convert visible listings into locally reviewed trust decisions.

The security constraint is visibility without ambient admission. A listing may be discoverable, searchable, and comparable, but it cannot imply runtime trust unless the explicit activation path validates freshness, publisher role, status, signer authority, and local review requirements.

Planned improvement: require exact uppercase 3-letter currency codes on signed pricing hints so marketplace search and comparison cannot split price buckets through lowercase money identifiers.
