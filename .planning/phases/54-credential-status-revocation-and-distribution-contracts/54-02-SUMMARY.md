# Summary 54-02

Wired portable lifecycle publication and query semantics across local CLI and
trust-control issuance surfaces.

## Delivered

- trust-control public lifecycle resolve route at
  `/v1/public/passport/statuses/resolve/{passport_id}`
- default advertised lifecycle distribution now points at the public read-only
  resolve plane when the service is actually configured with passport statuses
- portable issuance fails closed when lifecycle support is configured but the
  target passport is not already published active with at least one resolve URL

## Notes

- local issuance can attach the same portable lifecycle reference when the
  operator passes `--passport-statuses-file`
- admin publish/list/get/revoke surfaces remain operator-authenticated
