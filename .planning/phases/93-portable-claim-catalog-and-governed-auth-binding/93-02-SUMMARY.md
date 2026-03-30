# Summary 93-02

Aligned hosted governed authorization metadata with the same portable identity
model. The ARC OAuth authorization profile now advertises:

- `portableClaimCatalog`
- `portableIdentityBinding`
- `governedAuthBinding`

Authorization-context rows also now fail closed unless both subject and issuer
binding can be derived from receipt attribution or capability lineage, and the
row validator enforces sender-constraint consistency.
