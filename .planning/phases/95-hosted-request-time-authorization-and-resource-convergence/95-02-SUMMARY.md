# Summary 95-02

Aligned ARC's protected-resource metadata, authorization-server metadata,
request `resource` parameter, and bearer-token audience or resource checks to
one canonical protected-resource binding.

The hosted authorization flow now fails closed on resource drift instead of
publishing one metadata story and admitting a different runtime audience rule.
