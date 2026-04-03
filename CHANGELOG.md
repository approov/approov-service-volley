# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.


## [3.5.4] - 2026-04-03

### Added
- ApproovServiceMutator support for centralizing Volley service-layer decisions and request mutation hooks.
- HTTP message signing support via `ApproovDefaultMessageSigning`.
- `ApproovFetchStatusException` and `ApproovRequestMutations`.
- REFERENCE.md, USAGE.md, and CHANGELOG.md documentation.
- Unit and contract tests covering the service API, HurlStack request flow, message signing, and shared signature utilities.

### Changed
- Approov request processing now routes through `ApproovServiceMutator`, including request token-header value selection.
- Added `setUseApproovStatusIfNoToken` / `getUseApproovStatusIfNoToken` compatibility behavior and documented how it interacts with mutators.
- Update version to 3.5.4.

### Fixed
- Prevented install message-signing failures from aborting requests when the device keypair is unavailable; the service now logs and continues without an install signature.
- Ensured fallback Approov fetch statuses can be forwarded instead of a JWT when configured and a request is allowed to proceed.
- Fixed Volley message signing to handle header names case-insensitively and to replace stale signature headers correctly.

### Deprecated
- `setProceedOnNetworkFail()` and `getProceedOnNetworkFail()` in favor of `setServiceMutator()`.
