# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [3.7.0] - YYYY-MM-DD

Entries marked **Breaking** need a source change. See [Upgrading from 3.5.x](README.md#upgrading-from-35x).

### Changed
- **Breaking:** The message signing helper classes moved from `io.approov.util.http.sfv` and `io.approov.util.sig` to `io.approov.util.volley.http.sfv` and `io.approov.util.volley.sig`. Update imports of classes such as `SignatureParameters` and `ComponentProvider`.
- **Breaking:** `initialize` passes every non-empty account ID and comment to the Approov SDK and the SDK decides, so the layer no longer compares account IDs itself. It resets the configuration each time, so make your configuration calls after it. It throws `IllegalArgumentException` for a null context, also in bypass mode (`""`). See [initialize, then configure](ADVANCED.md#initialize-then-configure).
- **Breaking:** `SignatureParametersFactory` has a new protected field, `useInstallMessageSigning`, which starts `true`, and its parameters no longer set the algorithm, as the signer produces one signature per algorithm the factory selects. A subclass that sets `useAccountMessageSigning = true` directly now produces both signatures. Call `setUseAccountMessageSigning()` to produce the account signature only.
- The package follows the redirects of the requests it processes. A hop to another origin carries nothing the package added, and a hop to the same origin is protected again. See [redirects](ADVANCED.md#redirects).
- `getBaseHttpStack()` no longer returns `null` before `initialize` or in bypass mode. Requests through that stack go out without Approov protection until `initialize` is called, and the same stack then protects them.
- A WebSocket upgrade request is sent untouched, with no Approov token, secure strings or signature.
- Pins are matched against the certificate chain the platform validated. A pin matches the host without regard to case and with one trailing dot ignored.
- If the SDK cannot supply the pins, connections continue on OS trust and one error is logged. See [connection validation](ADVANCED.md#connection-validation).
- Every `https` connection requests `Connection: close`, so that each request opens a new connection and the pins apply to it. A `Connection` header set by your request replaces it.
- A failed token fetch only affects requests to your Approov API domains, the hosts in your pin set. Requests to other hosts are sent unchanged.
- A failed secure string fetch no longer fails the request under the standard mutators. The substitution is skipped and the request proceeds. The status name replaces the placeholder, such as `X-Api-Key: REJECTED`. A value that is not a secure string key (`UNKNOWN_KEY`) is left as your app wrote it. See [secure strings](ADVANCED.md#secure-strings).
- Secure strings are substituted on requests to secrets-only API domains (`approov api -add <domain> -noApproovToken`) as well as on token-protected ones.
- `NO_APPROOV_SERVICE` proceeds with the trace header, as a failure status does, where 3.5.x sent no Approov headers.
- A token fetch that is rejected throws `ApproovFetchStatusException`, where 3.5.x threw `ApproovRejectionException`.
- `ApproovRejectionException` is now a subclass of `ApproovFetchStatusException` with the status `REJECTED`, so a handler for `ApproovFetchStatusException` catches it. Its constructor and getters are unchanged.
- An exception from your own mutator reaches your app as an `ApproovException` that names the hook, with the original as its cause. Volley delivers it as an `AuthFailureError`.
- The token header is set after your `handleRequestProcessedHeaders` hook runs, so the hook cannot remove it.
- Each token is bound to its own request's binding header value, also when requests with different values are in flight at once.
- `Content-Length` is not a covered component of a signature, because the platform adds it after signing. `Content-Digest` covers the body.
- A missing install or account signature is logged as a warning once per process, and a request sent unsigned as an error once per process. Later occurrences are logged at debug level.
- The signed `@target-uri` leaves out an explicit default port (`:443` for `https`, `:80` for `http`) and any `#fragment`, and the `@authority` is the lowercase host with a non-default port. The URL is no longer read with `java.net.URI`, so a URL it rejects, such as one with `|` in the query, is signed. A host factory is matched by host name without regard to case and without a port.
- Message signatures take their `created` and `expires` times from the server adjusted time.
- `getLastARC()` makes no token fetch of its own. It returns the ARC of the most recent token, secure string or custom JWT fetch, or an empty string.
- BouncyCastle is replaced by Google Tink 1.23.0. It is bundled in the AAR and relocated, so it cannot clash with your own dependencies. The published POM adds none.
- The package depends on Approov SDK 3.7.0, where 3.5.x depended on 3.5.3.

### Deprecated
- `getMessageSignature(message)`. Use `getAccountMessageSignature`.
- `setApproovHeader` and `setApproovTraceIDHeader`. Use `setTokenHeader(header, prefix)` and `setTraceIDHeader(header)`.

### Added
- `ApproovDefaultMessageSigning.combined()` and `combined(ApproovServiceMutator decisions)` give a signer that adds both the install and the account signature and makes the decisions you pass, for example `ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED)`. See [message signing](ADVANCED.md#message-signing).
- Message signing can produce the account signature as well as the install signature: `SignatureParametersFactory.setUseInstallAndAccountMessageSigning()`.
- `ApproovService.addSubstitutionHeader`, `addSubstitutionQueryParam`, their `remove` methods and their getters register the headers and URL query parameters for secure strings. The HTTP stack substitutes them on every attempt of a request, so a `Request` needs no change. See [secure strings](ADVANCED.md#secure-strings).
- `ApproovServiceMutator.handlePinningShouldProcessRequest(Request)`, which skips Approov pinning for chosen requests. The package asks it for each request, and for each redirect it follows.
- `ApproovServiceMutator.CLOSE_FAILURE`, the default, which keeps the 3.5.x decisions, and `ALWAYS_PROCEED`, which never aborts a request on a token fetch failure. See [what happens by default](ADVANCED.md#what-happens-by-default).
- `ApproovService.getServerAdjustedCurrentTimeMS()`, the current time corrected to the Approov servers' clock. If the server time is not available the device clock is used and a warning is logged.
- `ApproovService.setLoggingLevel(ApproovLogLevel)`, `INFO` by default. `OFF` silences the layer, and debug logging for the `ApproovService` tag raises any other level to `DEBUG`. The loggable token is logged at `DEBUG` only, with the URL without its query, user info or fragment. See [diagnostics](ADVANCED.md#diagnostics).
- The names shared by all Approov packages: `isApproovServiceEnabled()`, `isApproovProtectionEnabled()`, `setInstallAttributes(String)`, `getTokenHeader()`, `getTokenPrefix()`, `getTraceIDHeader()`, `setTokenHeader(header, prefix)` and `setTraceIDHeader(header)`.

### Removed
- **Breaking:** `setProceedOnNetworkFail(boolean)`, which had no effect in 3.5.x. Use `ALWAYS_PROCEED` or `setUseApproovStatusIfNoToken(true)`.
- **Breaking:** `prefetch()`. The SDK manages prefetching itself.
- BouncyCastle, which the package no longer bundles.

### Fixed
- A request to an `http` URL on your API domains is never sent a secure string.
- A `Content-Digest` is made only over a body that Volley sends (POST, PUT and PATCH). A `DELETE` or `GET` request that returns a body from `getBody()` is no longer signed over bytes that Volley never sends.

## [3.5.6] - 2026-10-07

### Changed
- `prefetch()` is now deprecated and does nothing, retained so existing callers still compile. The Approov SDK starts its own initialization fetch, so a service layer should not fetch on its own. The package-private `PrefetchCallbackHandler` is removed.

## [3.5.5] - 2026-06-05

### Added
- Automatic release tagging on merge to `main` (`tag-release` job in `build_and_test.yml`): once the build/tests pass, the top CHANGELOG entry drives a matching git tag, which triggers the Maven publish workflow. Skipped if the tag already exists.
- Added `SECURITY.md` with supported version and vulnerability reporting guidance.
- Added a migration section to `USAGE.md` covering the behavioral changes since the pre-mutator releases.

### Changed
- Android build migrated from the unmaintained `com.github.johnrengelman.shadow` 8.1.1 plugin to the maintained fork `com.gradleup.shadow` 8.3.11 for Gradle 9 compatibility (Gradle 9 removed `FileCopyDetails.mode`, making the old plugin fail with a `MissingPropertyException`). Shaded BouncyCastle jar verified byte-identical; minimum supported Gradle remains 8.3.
- Removed the defunct `jcenter()` repository from the root build — JCenter is shut down and the `jcenter()` method is removed in Gradle 9.
- Certificate public-key pin hashing now uses the platform `MessageDigest`/`Base64`, so the service layer's own code no longer references `com.squareup.okhttp3:okhttp` (okio), which was previously pulled in solely for SHA-256/base64. Note: `okhttp` is retained as a `runtime`-scope dependency because the closed-source Approov SDK (`approov-android-sdk`) uses okhttp3 internally and does not declare it itself; dropping it entirely makes `Approov.initialize()` fail with `NoClassDefFoundError: okhttp3.EventListener` in consuming apps.
- `REFERENCE.md`: documented that `precheck` is for development-time verification, and that manual (`setDataHashInToken`) and automatic (`setBindingHeader`) token binding must not be mixed.

### Fixed
- Pinned HTTPS connections now request `Connection: close` so a dynamic pin update takes effect on the next request. The pinning `HostnameVerifier` only runs during a new TLS handshake, so without this an established keep-alive connection could be reused under a now-superseded pin set. From 3.7.0 every `https` connection requests it.
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
