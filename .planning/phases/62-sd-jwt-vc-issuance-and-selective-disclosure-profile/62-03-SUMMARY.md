# Summary 62-03

Added regression coverage for SD-JWT VC issuance and disclosure failure paths.

## Delivered

- added unit coverage for successful SD-JWT VC roundtrip verification
- added fail-closed unit coverage for missing holder binding and unsupported
  disclosure claim keys
- kept the projected issuance integration proof and local fail-closed
  unsupported-offer regression green

## Notes

- the supported ARC SD-JWT VC profile is now explicit in code, docs, and
  tests rather than implied by implementation only
