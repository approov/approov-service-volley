# Reference

This document provides a reference for the public API exposed by the Approov Service for Volley.

**Java import:**
```java
import io.approov.service.volley.ApproovService;
```

**Kotlin import:**
```kotlin
import io.approov.service.volley.ApproovService
```

# Exceptions

The service methods may throw `ApproovException` or one of its subclasses:

- `ApproovFetchStatusException`: a fetch returned a non-success Approov status.
- `ApproovNetworkException`: deprecated compatibility subtype for retryable network-related failures.
- `ApproovRejectionException`: the app failed attestation; use `getARC()` and `getRejectionReasons()` for more detail.

# ApproovService

## initialize

Initializes the Approov SDK and enables the Volley integration.

This is the standard form and should be used in most cases. The `comment` parameter defaults to `null` when not supplied.

```java
void initialize(Context context, String config)
```

Use the application context.

It is possible to pass an empty `config` string to bypass Approov SDK initialization. In that case the service layer still reports itself as initialized, but any `BaseHttpStack` obtained from it will be `null`, preserving standard Volley request processing without Approov features.

This empty-config mode is intended as a bootstrap or bypass state for advanced integrations. A later call to `initialize()` with a valid non-empty config string is allowed and will then enable the native Approov SDK at runtime. Reinitializing from one non-empty config string to a different non-empty config string is rejected by the platform SDK.

If you need to supply a `comment` to the native SDK (for example to pass `options:...` startup flags or trigger a `reinit...` flow), use the extended form instead:

**Java:**
```java
void initialize(Context context, String config, String comment)
```

**Kotlin:**
```kotlin
fun initialize(context: Context, config: String, comment: String?)
```

The `comment` parameter is passed directly to the native Approov SDK. Key uses:
* Pass a string starting with `options:` during the initial setup to forward custom startup options to the native SDK.
* Pass a string starting with `reinit` to trigger native re-initialization on a subsequent same-config call.
* Pass `null` (or use the 2-arg form) when no comment is needed — this is the default.

Please refer to the [Approov SDK documentation](https://approov.io/docs/latest/approov-direct-sdk-integration/#sdk-initialization-options) for full details on supported comment values.

If initialization fails, `getBaseHttpStack()` remains `null`, so `Volley.newRequestQueue(context, ApproovService.getBaseHttpStack())` continues to operate with the standard Volley stack and without Approov request processing.

## isInitialized

Returns whether the service layer itself has been initialized.

```java
boolean isInitialized()
```

Returns `true` if `initialize` has been called successfully, including when bypass mode is active (empty config string). Returns `false` if `initialize` has never been called or if the last initialization attempt failed. Use `isApproovEnabled()` to distinguish between bypass and protected modes.

## isApproovEnabled

Returns whether Approov protection is currently enabled.

```java
boolean isApproovEnabled()
```

Returns `true` only when the service layer was initialized with a valid, non-empty configuration string and the native Approov SDK is active. Returns `false` in all other cases: not initialized, or initialized in bypass mode (empty config). All direct Approov SDK methods (such as `fetchToken`, `precheck`, `fetchSecureString`) will throw `ApproovException` if called when this returns `false`.

## setServiceMutator

Installs the active `ApproovServiceMutator`.

```java
void setServiceMutator(ApproovServiceMutator mutator)
```

Pass `null` to restore `ApproovServiceMutator.DEFAULT`.

## getServiceMutator

Gets the currently active mutator.

```java
ApproovServiceMutator getServiceMutator()
```

## setProceedOnNetworkFail

Legacy compatibility API.

```java
void setProceedOnNetworkFail(boolean proceed)
```

**Obsolete / Deprecated:** This method no longer has any effect. It is completely decoupled from the default `ApproovServiceMutator` logic. To change the default fallback behavior on network failures, you must implement a custom mutator via `setServiceMutator(...)`.

## setUseApproovStatusIfNoToken

Enables compatibility behavior that sends the Approov fetch status instead of a JWT when a request is allowed to proceed without a real token.

```java
void setUseApproovStatusIfNoToken(boolean shouldUse)
```

When enabled, the default mutator allows `NO_NETWORK`, `POOR_NETWORK`, and `MITM_DETECTED` to continue, and the request path also forwards fallback statuses such as `NO_APPROOV_SERVICE` when the request proceeds without a token.

## getUseApproovStatusIfNoToken

Returns whether the compatibility fallback-status behavior is enabled.

```java
boolean getUseApproovStatusIfNoToken()
```

## setDevKey

Sets a [development key](https://approov.io/docs/latest/approov-usage-documentation/#using-a-development-key) so a development build can pass attestation.

```java
void setDevKey(String devKey) throws ApproovException
```

## setApproovHeader

Sets the header name and optional prefix used when transmitting the Approov token.

```java
void setApproovHeader(String header, String prefix)
```

By default the header is `Approov-Token` with an empty prefix.

## setApproovTraceIDHeader

Sets the optional header used to pass the Approov TraceID value returned by the SDK.

```java
void setApproovTraceIDHeader(String header)
```

Pass `null` to disable the TraceID header.

## setBindingHeader

Sets the request header whose value should be used for [token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding).

```java
void setBindingHeader(String header)
```

## formatApproovTokenHeaderValue

Formats a raw token or status value using the configured Approov token prefix.

```java
String formatApproovTokenHeaderValue(String value)
```

## getApproovTokenHeaderValue

Builds the Approov token header value from a successful fetch result.

```java
String getApproovTokenHeaderValue(Approov.TokenFetchResult approovResults)
```

Returns `null` if there is no token.

## getApproovTokenHeaderValueOrStatus

Builds the Approov token header value from a fetch result, falling back to the fetch status string when no token is available.

```java
String getApproovTokenHeaderValueOrStatus(Approov.TokenFetchResult approovResults)
```

This is intended for mutators that deliberately proceed with a request after a token fetch failure and want to send the Approov failure status to the backend in place of the JWT.

## addExclusionURLRegex

Adds a URL regular expression that excludes matching requests from Approov processing.

```java
void addExclusionURLRegex(String urlRegex)
```

Use with care because pinning state is updated via Approov fetches.

## removeExclusionURLRegex

Removes an exclusion regex added earlier.

```java
void removeExclusionURLRegex(String urlRegex)
```

## prefetch

Starts an asynchronous prefetch to reduce the latency of a later fetch.

```java
void prefetch()
```

## precheck

Performs a precheck to determine whether the app is likely to pass attestation.

```java
void precheck() throws ApproovException
```

This may require network access.

## getDeviceID

Gets the device ID used by Approov for this app installation.

```java
String getDeviceID() throws ApproovException
```

## setDataHashInToken

Sets arbitrary data to be hashed into subsequently fetched tokens.

```java
void setDataHashInToken(String data) throws ApproovException
```

This is normally handled automatically by token binding.

## fetchToken

Directly fetches an Approov token for the supplied URL.

```java
String fetchToken(String url) throws ApproovException
```

Use this only when you cannot use the Approov `BaseHttpStack`.

## getMessageSignature

Legacy alias for account message signing.

```java
String getMessageSignature(String message) throws ApproovException
```

## getAccountMessageSignature

Gets the account message signature for the supplied message.

```java
String getAccountMessageSignature(String message) throws ApproovException
```

## getInstallMessageSignature

Gets the install message signature for the supplied message.

```java
String getInstallMessageSignature(String message) throws ApproovException
```

This uses the device install keypair and returns the base64-encoded ASN.1 DER signature produced by the SDK.

## fetchSecureString

Fetches a secure string by key, or defines a per-install value when `newDef` is provided.

```java
String fetchSecureString(String key, String newDef) throws ApproovException
```

Pass `null` for lookup only. Pass the empty string to remove a previous definition.

## fetchCustomJWT

Fetches a custom JWT using the supplied JSON payload.

```java
String fetchCustomJWT(String payload) throws ApproovException
```

## getLastARC

Returns the most recent ARC value that can be derived from the current Approov state.

```java
String getLastARC()
```

Returns an empty string if no ARC is available.

## setInstallAttrsInToken

Sets signed install attributes to be sent with the next token fetch.

```java
void setInstallAttrsInToken(String attrs) throws ApproovException
```

## getBaseHttpStack

Gets the Volley `BaseHttpStack` that enables Approov token injection and pinning.

```java
BaseHttpStack getBaseHttpStack()
```

Typical usage:

```java
RequestQueue queue = Volley.newRequestQueue(context, ApproovService.getBaseHttpStack());
```

## substituteHeader

Substitutes a header value in-place using secure strings.

```java
void substituteHeader(String url, Map<String, String> headers, String substitutionHeader, String requiredPrefix)
    throws ApproovException
```

Use this from `Request.getHeaders()`, supplying `this.getUrl()` to natively block unauthorized unprotected lookups.

## substituteQueryParam

Substitutes a form/query parameter value in-place using secure strings.

```java
void substituteQueryParam(String url, Map<String, String> params, String queryParam) throws ApproovException
```

Use this from `Request.getParams()`, supplying `this.getUrl()` to natively block unauthorized unprotected lookups.

## substituteQueryParamInURLString

Substitutes a query parameter embedded in a URL string.

```java
String substituteQueryParamInURLString(String url, String queryParameter) throws ApproovException
```

Use this when the parameter is part of the request URL rather than a params map. If the provided URL belongs to an unprotected domain, the original URL is preserved and no Approov fetch occurs natively.

# ApproovServiceMutator

`ApproovServiceMutator` centralizes policy decisions for the Volley integration.

## Default constant

```java
ApproovServiceMutator DEFAULT
```

Use this when delegating back to the standard behavior from a custom mutator.

## Request-path hooks

### handleRequestShouldProcess

Determines whether a Volley request should be processed by Approov at all.

```java
boolean handleRequestShouldProcess(Request<?> request, Map<String, String> additionalHeaders)
    throws ApproovException
```

### handleRequestFetchTokenResult

Controls how the mutator reacts to the request token fetch result.

```java
boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
    throws ApproovException
```

Return:

- `true` to continue through the Approov request pipeline
- `false` to send the request without further Approov modifications

### handleRequestTokenHeaderValue

Determines the value to place on the configured Approov token header.

```java
String handleRequestTokenHeaderValue(Approov.TokenFetchResult approovResults, String url)
    throws ApproovException
```

The default implementation only returns a real token for `SUCCESS`. Override this to return `ApproovService.getApproovTokenHeaderValueOrStatus(...)` if you want to proceed on specific failures and send the status instead.

If `setUseApproovStatusIfNoToken(true)` is enabled, the default implementation also falls back to the fetch status when the SDK returns an empty token for `SUCCESS`.

### handleRequestProcessedHeaders

Allows additional header mutation after Approov token processing.

```java
Map<String, String> handleRequestProcessedHeaders(
    Request<?> request,
    Map<String, String> headers,
    ApproovRequestMutations changes
) throws ApproovException
```

This is also the hook used by `ApproovDefaultMessageSigning`.

## Direct-fetch hooks

These hooks customize the direct `ApproovService` helper methods:

```java
void handlePrecheckResult(Approov.TokenFetchResult approovResults) throws ApproovException
void handleFetchTokenResult(Approov.TokenFetchResult approovResults) throws ApproovException
void handleFetchSecureStringResult(Approov.TokenFetchResult approovResults, String operation, String key)
    throws ApproovException
void handleFetchCustomJWTResult(Approov.TokenFetchResult approovResults) throws ApproovException
```

## Secure strings substitution hooks

These hooks customize the secure strings helper methods:

```java
boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult approovResults, String header)
    throws ApproovException

boolean handleRequestQueryParamSubstitutionResult(Approov.TokenFetchResult approovResults, String queryKey)
    throws ApproovException
```

# ApproovDefaultMessageSigning

`ApproovDefaultMessageSigning` is a mutator implementation that adds HTTP message signing headers to Approov-processed requests.

## Enable default signing

```java
ApproovDefaultMessageSigning signer =
    new ApproovDefaultMessageSigning().setDefaultFactory(
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
    );

ApproovService.setServiceMutator(signer);
```

## Methods

```java
ApproovDefaultMessageSigning setDefaultFactory(SignatureParametersFactory factory)
ApproovDefaultMessageSigning putHostFactory(String hostName, SignatureParametersFactory factory)
static SignatureParametersFactory generateDefaultSignatureParametersFactory()
static SignatureParametersFactory generateDefaultSignatureParametersFactory(SignatureParameters baseParametersOverride)
```

## SignatureParametersFactory

Use `ApproovDefaultMessageSigning.SignatureParametersFactory` to customize the signature behavior:

```java
SignatureParametersFactory setBaseParameters(SignatureParameters baseParameters)
SignatureParametersFactory setBodyDigestConfig(String bodyDigestAlgorithm, boolean required)
SignatureParametersFactory setUseInstallMessageSigning()
SignatureParametersFactory setUseAccountMessageSigning()
SignatureParametersFactory setAddCreated(boolean addCreated)
SignatureParametersFactory setExpiresLifetime(long expiresLifetime)
SignatureParametersFactory setAddApproovTokenHeader(boolean addApproovTokenHeader)
SignatureParametersFactory setAddApproovTraceIDHeader(boolean addApproovTraceIDHeader)
SignatureParametersFactory addOptionalHeaders(String... headers)
```

Useful constants:

```java
ApproovDefaultMessageSigning.DIGEST_SHA256
ApproovDefaultMessageSigning.DIGEST_SHA512
ApproovDefaultMessageSigning.ALG_ES256
ApproovDefaultMessageSigning.ALG_HS256
```

# ApproovRequestMutations

`ApproovRequestMutations` describes which request changes Approov already applied before `handleRequestProcessedHeaders(...)` is called.

## Methods

```java
String getTokenHeaderKey()
String getTraceIDHeaderKey()
List<String> getAddedHeaderKeys()
```

This is especially useful when composing a custom mutator with `ApproovDefaultMessageSigning`.
