# Plan 117-01 Summary

Phase `117-01` is complete.

ARC now has one generic signed listing substrate over the existing public actor
families:

- added one shared signed listing envelope for tool servers, credential
  issuers, credential verifiers, and liability providers
- preserved actor-specific provenance through compatibility references instead
  of flattening source artifacts into untraceable registry rows
- defined explicit lifecycle, subject, boundary, and compatibility metadata for
  future registry actors

The result is one reusable listing model without erasing the source artifact
truth that each actor family already shipped.
