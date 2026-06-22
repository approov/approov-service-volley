# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [3.5.5] - 2026-06-05

### Added
- Added `SECURITY.md` with supported version and vulnerability reporting guidance.
- Added a migration section to `USAGE.md` covering the behavioral changes since the pre-mutator releases.

### Fixed
- Message signing is now fail-open symmetrically: an unavailable or empty **account** (HS256) signature no longer fails the request — it is logged at error level and the request proceeds unsigned, matching the existing install (ES256) behaviour. Only an unsupported signing algorithm or a required-but-ungeneratable body digest fail closed.
- Genuine message-signing failures (base64/ASN.1 decode, serialization) are now surfaced as `ApproovException` rather than escaping as an unchecked exception.
- `setApproovHeader(header, prefix)` treats a `null` prefix as no prefix (empty string), preventing a literal `"null"` from being prepended to the Approov token header value.
- Empty-config reinitialization now preserves the active protected state when the service layer has already been initialized with a valid config.
- Aligned Volley empty-config unit tests with the updated initialized-but-disabled behavior used by OkHttp.
- Corrected the consumer ProGuard keep rule to reference the relocated BouncyCastle package and removed an overly broad rule that disabled enum obfuscation in consuming applications.
- Fixed structured field value decimal serialization dropping leading zeros in the fractional part (for example 1.05 previously serialized as `1.5`).
- Removed `Map` overrides requiring Android API 24 from the vendored structured field values `Parameters` class.

## [3.5.4] - 2026-04-13

### Added
- ApproovServiceMutator support for centralizing Volley service-layer decisions and request mutation hooks.
- HTTP message signing support via `ApproovDefaultMessageSigning`.
- `ApproovFetchStatusException` and `ApproovRequestMutations`.
- REFERENCE.md, USAGE.md, and CHANGELOG.md documentation.
- Unit and contract tests covering the service API, HurlStack request flow, message signing, and shared signature utilities.
- Added `ApproovService.isInitialized()` to expose the service-layer initialization state.
- Consumer ProGuard rules (`consumer-rules.pro`) to automatically preserve native SDK interfaces and internal cryptography bounds.

### Changed
- Approov request processing now routes through `ApproovServiceMutator`, including request token-header value selection.
- Added `setUseApproovStatusIfNoToken` / `getUseApproovStatusIfNoToken` compatibility behavior and documented how it interacts with mutators.
- Shaded and relocated the BouncyCastle dependency (`io.approov.internal.volley.bouncycastle`) to prevent version collisions for consuming applications.
- Removed the transitive `org.bouncycastle:bcprov-jdk15to18` dependency from `pom.xml`.
- Simplified `initialize` — removed the service-layer re-initialization guards (same-config short-circuit, `reinit` comment check). The service layer now always resets its own state and forwards non-empty config directly to the platform SDK. The SDK returns `false` if already initialized with the same config (service layer logs and continues), or throws `IllegalStateException` for a different config (service layer re-throws).
- Update version to 3.5.4.

### Removed
- Removed legacy `substituteHeader` and `substituteQueryParam` methods that did not accept a `url` parameter in order to bypass secure string execution for unprotected URLs.

### Fixed
- Enforced SDK initialization gating across all public API endpoints (`fetchCustomJWT`, `getDeviceID`, `setDataHashInToken`, `setInstallAttrsInToken`, etc.) to prevent unhandled `IllegalStateException` crashes from the platform SDK when the service layer is operating in bypass/uninitialized mode.
- Prevented install message-signing failures from aborting requests when the device keypair is unavailable; the service now logs and continues without an install signature.
- Ensured fallback Approov fetch statuses can be forwarded instead of a JWT when configured and a request is allowed to proceed.
- Fixed Volley message signing to handle header names case-insensitively and to replace stale signature headers correctly.
- Initializing with an empty config string now keeps the service layer initialized while returning a `null` `BaseHttpStack` (falling back to standard Volley stack) without Approov processing.
- Initializing first with an empty config string and later with a valid non-empty config string now enables Approov at runtime instead of being rejected as a different-config reinitialization.
- `initialize` now explicitly throws `IllegalArgumentException` when `config` is `null`, with a clear message directing callers to pass `""` for bypass mode. Passing `null` previously caused a silent coercion to `""` which masked caller errors.
- The 2-arg `initialize(context, config)` overload now correctly passes `null` (not `""`) as the comment to the native SDK, preventing unexpected re-initialization mismatches on subsequent calls.
- `IllegalStateException` from the native SDK during initialization is now re-thrown instead of being silently swallowed, so callers are aware of configuration conflicts.

### Deprecated
- `setProceedOnNetworkFail()` and `getProceedOnNetworkFail()` in favor of `setServiceMutator()`. The `proceedOnNetworkFail` state has been fully decoupled from the default `ApproovServiceMutator` logic. The default mutator now unconditionally throws an `ApproovNetworkException` on `NO_NETWORK`, `POOR_NETWORK`, and `MITM_DETECTED` to provide a secure default fallback behavior, unless cleanly overridden by a custom mutator.
