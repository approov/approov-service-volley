# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.


## [3.5.4] - 2026-04-13

### Added
- ApproovServiceMutator support for centralizing Volley service-layer decisions and request mutation hooks.
- HTTP message signing support via `ApproovDefaultMessageSigning`.
- `ApproovFetchStatusException` and `ApproovRequestMutations`.
- REFERENCE.md, USAGE.md, and CHANGELOG.md documentation.
- Unit and contract tests covering the service API, HurlStack request flow, message signing, and shared signature utilities.
- Added `ApproovService.isInitialized()` to expose the service-layer initialization state.
- Thread-safe failure mode caching for the request path when the platform SDK returns a failure status (`NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`, `NO_APPROOV_SERVICE`).
- Consumer ProGuard rules (`consumer-rules.pro`) to automatically preserve native SDK interfaces and internal cryptography bounds.

### Changed
- Approov request processing now routes through `ApproovServiceMutator`, including request token-header value selection.
- Added `setUseApproovStatusIfNoToken` / `getUseApproovStatusIfNoToken` compatibility behavior and documented how it interacts with mutators.
- Shaded and relocated the BouncyCastle dependency (`io.approov.internal.bouncycastle`) to prevent version collisions for consuming applications.
- Removed the transitive `org.bouncycastle:bcprov-jdk15to18` dependency from `pom.xml`.
- Update version to 3.5.4.

### Removed
- Removed legacy `substituteHeader` and `substituteQueryParam` methods that did not accept a `url` parameter in order to bypass secure string execution for unprotected URLs.

### Fixed
- Prevented install message-signing failures from aborting requests when the device keypair is unavailable; the service now logs and continues without an install signature.
- Ensured fallback Approov fetch statuses can be forwarded instead of a JWT when configured and a request is allowed to proceed.
- Fixed Volley message signing to handle header names case-insensitively and to replace stale signature headers correctly.
- Improved service re-initialization consistency for internal state management.
- Initializing with an empty config string now keeps the service layer initialized while returning a `null` `BaseHttpStack` (falling back to standard Volley stack) without Approov processing.
- Initializing first with an empty config string and later with a valid non-empty config string now enables Approov at runtime instead of being rejected as a different-config reinitialization.
- Enforced strict failure by throwing `IllegalArgumentException` in `ApproovService.initialize` if a malformed configuration string is provided.

### Deprecated
- `setProceedOnNetworkFail()` and `getProceedOnNetworkFail()` in favor of `setServiceMutator()`. The `proceedOnNetworkFail` state has been fully decoupled from the default `ApproovServiceMutator` logic. The default mutator now unconditionally throws an `ApproovNetworkException` on `NO_NETWORK`, `POOR_NETWORK`, and `MITM_DETECTED` to provide a secure default fallback behavior, unless cleanly overridden by a custom mutator.
