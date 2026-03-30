# Plan 94-02 Summary

Verification is now profile-specific and fail closed. ARC validates SD-JWT VC
and JWT VC JSON compact responses through separate bounded contracts, rejects
mixed configuration or format requests, and keeps unsupported portable formats
out of issuer metadata.
