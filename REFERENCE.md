# Reference
This page lists every public method of `ApproovService`, the entry point of the Approov Package for Volley, and the extension classes. To use them, import:

**Java:**
```java
import io.approov.service.volley.ApproovService;
```

**Kotlin:**
```kotlin
import io.approov.service.volley.ApproovService
```

The rest of this introduction explains what happens to requests sent through the HTTP stack, and which exceptions your app can see. The methods follow it.

A request sent through a `RequestQueue` built with `getBaseHttpStack` sometimes cannot be protected, for example because no token could be fetched. Whether it is still sent is decided by the installed [service mutator](ADVANCED.md#service-mutators), an `ApproovServiceMutator`. See [setServiceMutator](#setservicemutator) and [what happens by default](ADVANCED.md#what-happens-by-default).

* The default, `ApproovServiceMutator.DEFAULT`, is `CLOSE_FAILURE`. It makes the same decisions as 3.5.x. A request goes ahead on `SUCCESS`, and on `NO_APPROOV_SERVICE` with an empty token header. Otherwise it fails with one of the `ApproovException` subclasses listed below.
* With `ApproovServiceMutator.ALWAYS_PROCEED` the request always goes ahead. If it could not be protected, it carries the `Approov-Token` header with an empty token after any prefix, and the trace header whenever the SDK gives one. It carries no secure strings.
* With [setUseApproovStatusIfNoToken](#setuseapproovstatusifnotoken) turned on, such a request carries the fetch status name in the token header instead of an empty token. Under `CLOSE_FAILURE` this also lets `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` go ahead with the status instead of failing.

Some requests are never failed by a token fetch:

* A token fetch failure for a host that is not one of your Approov API domains goes out unchanged. Your API domains are the keys of the SDK pin set, not counting the `*` key. If the pin set is empty or cannot be read, no host counts. No standard mutator aborts such a request. An exception raised there by the `CLOSE_FAILURE` decisions is ignored, even in a custom mutator that inherits or calls them. Only an exception your own mutator throws from `handleRequestFetchTokenResult` aborts it, which is an opt-in.
* A request to an API you added with `-noApproovToken` (status `UNPROTECTED_URL`) gets its secure strings and its pins, but no Approov header.
* A request to a host you have not added to Approov (status `UNKNOWN_URL`) is sent unchanged.
* A WebSocket upgrade request (`Upgrade: websocket`) is sent untouched, with no token fetch and no Approov connection check.

Whatever mutator is installed, these other exceptions can reach your code from a request:

* Your app's own configuration errors. A required body digest that cannot be generated, and an unsupported signing algorithm, fail every request they apply to with an `ApproovException`. For the body digest, its cause is `ApproovDefaultMessageSigning.RequiredBodyDigestException`.
* Pinning failures on your API domains throw `javax.net.ssl.SSLPeerUnverifiedException`. Volley delivers it to your error listener as a `NoConnectionError` with that exception as its cause.
* An abort your app opted in to through a service mutator throws an `ApproovException` that names the hook, with your exception as its cause.

Volley delivers each of these to your `Response.ErrorListener`. An `ApproovException` is a Volley `AuthFailureError`, which is a `VolleyError`.

An exception the Approov SDK throws while a request is processed fails that request with an `ApproovException`, whose cause is the SDK's exception. Its message is `Wrapped <exception class>: <exception message>`. This covers the token fetch, a secure string substitution, token binding and the configuration update.

If the SDK cannot give the pins for a connection check, the connection continues on OS trust, which has already accepted it. This is logged once at error level.

Secure string problems are handled like this:

* A secure string that cannot be obtained never fails a request under either standard mutator, whatever its status. The status name replaces the placeholder. A debug line names the header or query parameter, with the status, the ARC and the rejection reasons.
* A secure string that a header cannot carry is not substituted. That is anything other than tab and printable ASCII.
* A secure string that a URL cannot carry unchanged in a query parameter is not substituted either. That is one with a space, a control or non-ASCII character, an `&` or a `#`.
* In those two cases the placeholder stays and the request goes ahead under every mutator. A warning names the header or query parameter, never the value.
* A placeholder left because the request is not `https`, or because its URL is `BAD_URL`, is logged as a warning.

Header values are checked too:

* A value your app supplies that a header cannot carry fails the request with an `ApproovException`. Examples are a token prefix, or a header your mutator sets. The exception never quotes the value.
* A token or trace ID issued by the SDK that a header cannot carry fails the request with an `ApproovException`. It reports an SDK problem and names the header, never quoting the value.

If a message signing SDK call fails, only that signature is left out.

A request to one of your Approov API domains that goes ahead after a failed token fetch carries the token header, so with message signing installed it is signed too, over the empty token or the status.

The direct methods (`precheck`, `fetchToken`, `fetchSecureString`, `fetchCustomJWT` and so on) return a value to your code. They report a failure with the exceptions described below.

Before `initialize`, and in [bypass mode](ADVANCED.md#bypass-initialization), a request made through the stack from `getBaseHttpStack` goes out without any Approov processing and without Approov pinning. It is neither failed nor held.

# Exceptions

Many methods throw an `ApproovException` when there is a problem. It is a Volley `AuthFailureError`, so it is a checked exception, and `getMessage()` gives a description. It has these subclasses:

* `ApproovFetchStatusException`, a subclass of `ApproovException`, carries the SDK fetch status in `getTokenFetchStatus()`.
* `ApproovNetworkException`, a subclass of `ApproovFetchStatusException`, means a network problem caused the failure (`NO_NETWORK`, `POOR_NETWORK` or `MITM_DETECTED`). Your app should let the user retry. This class is deprecated: catch `ApproovFetchStatusException` and check `getTokenFetchStatus()` instead. It is still thrown, so existing handlers keep working.
* `ApproovRejectionException`, a subclass of `ApproovFetchStatusException` with the status `REJECTED`, means the app failed attestation. The direct methods throw it. `getARC()` returns the [Attestation Response Code](https://approov.io/docs/latest/approov-usage-documentation/#attestation-response-code). Your user can give it to your app support, who can then find the reason for the failure without it being revealed to the user. `getRejectionReasons()` returns the [Rejection Reasons](https://approov.io/docs/latest/approov-usage-documentation/#rejection-reasons) as a comma separated list, if the feature is enabled.

Every method that calls the Approov SDK first checks [isApproovProtectionEnabled](#isapproovprotectionenabled). While it is `false`, the method throws `ApproovException` with the message `<method>: SDK not initialized`, without calling the SDK. These methods are `setDevKey`, `precheck`, `getDeviceID`, `getServerAdjustedCurrentTimeMS`, `setDataHashInToken`, `fetchToken`, `getAccountMessageSignature`, `getInstallMessageSignature`, `fetchSecureString`, `fetchCustomJWT`, `setInstallAttributes` and `setInstallAttrsInToken`. The deprecated `getMessageSignature` throws the same exception.

# ApproovService

## initialize
Initializes the Approov SDK, which turns on the Approov features.

The `config` parameter is your Approov account ID. It is in your onboarding email, and the Approov CLI gives it with `approov sdk -getConfigString` (the CLI and the SDK call it the SDK config string). It identifies your account to the SDK. It is not a secret, and it is the same for every app in your account. See [obtaining it](https://approov.io/docs/latest/approov-usage-documentation/#getting-the-initial-sdk-configuration).

The package passes every non-empty account ID to the Approov SDK, with the comment exactly as you passed it, and the SDK decides. The package does not store or compare the account ID.

* The first initialization succeeds.
* A call with the same account ID and comment again is reported by the SDK as already initialized, and `initialize` returns at once. So every part of your app that uses Approov may call it.
* A `null` context throws `IllegalArgumentException` with the message `initialize: null context`. A `null` account ID throws `IllegalArgumentException` with the message `config must not be null; pass "" for bypass mode`.
* Anything else the SDK rejects throws the SDK's own `IllegalStateException` or `IllegalArgumentException`, unchanged. That includes a different account ID or comment, and an account ID that did not reach the app intact. The package state stays as it was.

Every `initialize` that is not ignored resets the configuration to its defaults, by whichever caller made it. A repeat call with the same account ID resets it too. The reset covers:
* the HTTP stack, which `initialize` replaces
* the token header and prefix, and the trace header
* `setUseApproovStatusIfNoToken`
* the binding header
* the service mutator, and so any message signing
* substitution headers and query parameters, and exclusions
* the value of `getLastARC()`

The logging level is not reset. An empty account ID while protection is enabled is ignored, and resets nothing. So initialize first, then make your configuration calls. See [initialize, then configure](ADVANCED.md#initialize-then-configure).

Initialize before you build your queue. A queue built before any `initialize` goes out without Approov processing.

This is the standard form, and the one most apps should use. The `comment` parameter defaults to `null`.

**Java:**
```java
void initialize(Context context, String config)
```

**Kotlin:**
```kotlin
fun initialize(context: Context, config: String)
```

Pass the [application context](https://developer.android.com/reference/android/content/Context#getApplicationContext()) as the `context` parameter.

You can pass an empty string instead of the account ID to skip initializing the Approov SDK. This is bypass mode:

* `isApproovServiceEnabled()` returns `true` and `isApproovProtectionEnabled()` returns `false`.
* The SDK is not called.
* `getBaseHttpStack()` returns the stack, which sends requests without Approov token, message signing, secure strings or Approov pinning. Connections are checked by the operating system's trust alone.

Bypass mode is meant as a starting state for advanced integrations. A later `initialize` with the account ID is passed to the SDK, and turns on Approov protection if the SDK accepts it. Like any `initialize`, it resets the configuration. If the SDK rejects it, the package stays in bypass mode. An empty string after protection is on is ignored and not passed to the SDK. See [bypass initialization](ADVANCED.md#bypass-initialization).

To pass a `comment` to the native SDK, use the extended form. You might do this to pass `options:...` startup flags, or to start a `reinit...` flow.

**Java:**
```java
void initialize(Context context, String config, String comment)
```

**Kotlin:**
```kotlin
fun initialize(context: Context, config: String, comment: String?)
```

The `comment` parameter is passed directly to the native Approov SDK. Its main uses:
* A string starting with `options:`, passed during the initial setup, forwards custom startup options to the native SDK.
* A string starting with `reinit` triggers native re-initialization on a later call with the same account ID.
* `null`, or the two-argument form, means no comment. This is the default. Note that `null` and `""` are different comments to the SDK.

See the [Approov SDK documentation](https://approov.io/docs/latest/approov-direct-sdk-integration/#sdk-initialization-options) for the full list of comment values.

## isApproovServiceEnabled
Returns whether the package is enabled, that is, whether it is processing requests.

**Java:**
```java
boolean isApproovServiceEnabled()
```

Returns `true` once any `initialize` has succeeded, including in bypass mode (an empty string instead of the account ID). Returns `false` only if no `initialize` has succeeded.

A later call that is rejected, for example one with a different account ID, throws and leaves the previous state in place. So this method keeps returning `true`. Use `isApproovProtectionEnabled()` to tell bypass mode from protected mode.

`isInitialized()` is the same method under its 3.5.x name:

**Java:**
```java
boolean isInitialized()
```

## isApproovProtectionEnabled
Returns whether Approov protection is enabled.

**Java:**
```java
boolean isApproovProtectionEnabled()
```

Returns `true` once the Approov SDK has been initialized with the account ID and Approov protection is active. Returns `false` before initialization and in bypass mode (an empty string).

While this returns `false`, the methods that call the Approov SDK, such as `fetchToken`, `precheck` and `fetchSecureString`, throw `ApproovException` without calling the SDK.

After a successful `initialize`, check `isApproovServiceEnabled()` and then this method. This one is `false` only in deliberate bypass mode.

`isApproovEnabled()` is the same method under its 3.5.x name:

**Java:**
```java
boolean isApproovEnabled()
```

## getBaseHttpStack
Gets the Volley `BaseHttpStack` with Approov protection. Build your `RequestQueue` with it.

The stack:
* adds the Approov token in a header to requests
* performs any header or query parameter substitutions
* signs the requests, if you installed message signing
* pins the connections (see [connection validation](ADVANCED.md#connection-validation)). On every connection it checks the current pins for the request's host against the certificate chain that the platform accepted.
* follows the redirects of the requests it processes (see [redirects](ADVANCED.md#redirects))

**Java:**
```java
BaseHttpStack getBaseHttpStack()
```

Typical use:

```java
RequestQueue queue = Volley.newRequestQueue(context, ApproovService.getBaseHttpStack());
```

It never returns `null`, and it returns the same stack each time. Before `initialize` and in bypass mode, the stack sends requests without any Approov processing and without Approov pinning. Once `initialize` turns Approov on, the same stack protects requests, so a stack or a queue that you built earlier needs no replacement.

A pin failure fails only that request. If the SDK cannot give the pins, the connection continues on OS trust and one error is logged.

## setServiceMutator
Installs an `ApproovServiceMutator`, which receives callbacks from `ApproovService`. A service mutator lets you customize what the package does at key points in the configuration and attestation flows. See [service mutators](ADVANCED.md#service-mutators) for the hooks and examples.

**Java:**
```java
void setServiceMutator(ApproovServiceMutator mutator)
```

The standard mutator is `ApproovServiceMutator.DEFAULT`, and passing `null` puts it back. Every `initialize` puts it back too, so install your mutator after `initialize`.

Message signing is a mutator too, [ApproovDefaultMessageSigning](#approovdefaultmessagesigning). Installing another mutator removes it.

A `Request` keeps the mutator that was installed when the package first processed it. Every attempt, every redirect and the pinning hook for the request use that mutator. This holds even if you install another mutator while the request is in flight. If your app adds the same `Request` object to a queue again, the mutator it started with still applies, also after `setServiceMutator` or `initialize`. Build a new `Request` to use a new mutator. A new mutator applies to requests processed after the call.

Three standard mutators are provided:

| Mutator | Decisions |
| :--- | :--- |
| `ApproovServiceMutator.CLOSE_FAILURE` | The 3.5.x token decisions, which are also the interface defaults. A token fetch goes ahead on `SUCCESS` (token and trace headers) and on `NO_APPROOV_SERVICE` (an empty token header, or the status with `setUseApproovStatusIfNoToken`, and any trace header). `UNKNOWN_URL` and `UNPROTECTED_URL` send the request with no Approov headers (`UNPROTECTED_URL` with its secure strings). `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` throw `ApproovNetworkException`, unless `setUseApproovStatusIfNoToken` is on, when they go ahead with the status. Every other status throws `ApproovFetchStatusException`, `REJECTED` included. These failure decisions apply only to a host in the SDK pin set. A failure for any other host goes out untouched. A secure string is substituted on `SUCCESS`. `UNKNOWN_KEY` leaves the value as the app wrote it. For every other secure string status, the status name, unchanged, replaces the placeholder and the request goes ahead. |
| `ApproovServiceMutator.ALWAYS_PROCEED` | Never aborts. Every token fetch status except `UNKNOWN_URL` and `UNPROTECTED_URL` goes ahead with the Approov headers its status allows. On a failure status that is the token header with an empty token (or the status with `setUseApproovStatusIfNoToken`) and any trace header, and no secure strings. A failure for a host not in the SDK pin set goes out untouched. A secure string is substituted on `SUCCESS`, and otherwise its status name, unchanged, replaces the placeholder. A request the SDK answers with `BAD_URL` keeps its placeholders and never gets a secure string. That is every cleartext `http` request, and an `https` URL the SDK cannot parse. |
| `ApproovServiceMutator.DEFAULT` | Points to the release's default behaviour: `CLOSE_FAILURE`. If your app wants a fixed behaviour, name `CLOSE_FAILURE` or `ALWAYS_PROCEED` explicitly. |

**Java:**
```java
ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
```

A custom mutator gets the `CLOSE_FAILURE` decisions for every hook it does not override. To make one that never aborts, delegate `handleRequestFetchTokenResult` to `ALWAYS_PROCEED` (see [service mutators](ADVANCED.md#service-mutators)).

A custom mutator may choose to abort a request from any `handleRequest...` hook. To do so it throws an `ApproovException`. The request then fails with an `ApproovException` that names the hook, with yours as its cause. That is an explicit decision for you to make.

The aborts that `CLOSE_FAILURE` makes keep the 3.5.x Approov exception types, so an existing app catches the same exceptions as before.

## getServiceMutator
Gets the service mutator that is currently installed.

**Java:**
```java
ApproovServiceMutator getServiceMutator()
```

## setDevKey
[Sets a development key](https://approov.io/docs/latest/approov-usage-documentation/#using-a-development-key) that makes your app pass attestation. Use it when the app has to be re-signed for a test environment, and would otherwise fail attestation.

**Java:**
```java
void setDevKey(String devKey) throws ApproovException
```

It throws `ApproovException` if the SDK rejects the development key. Before `initialize` and in bypass mode it throws `ApproovException` with the message `setDevKey: SDK not initialized`, without calling the SDK.

## setTokenHeader
Sets the `header` that carries the Approov token, and an optional `prefix` such as "`Bearer `".

* By default the token goes on `Approov-Token` with no prefix.
* Pass `null` or an empty string as `prefix` if you don't need one. `null` never adds the literal text "null".
* The header carries a token only on a request whose token fetch succeeded. If no token could be obtained and the mutator lets the request go ahead, the header is sent with an empty token after the prefix, or with the fetch status name if [setUseApproovStatusIfNoToken](#setuseapproovstatusifnotoken) is on.
* `initialize` puts back the default header and prefix, so call this after it.
* With message signing installed, a token header that is also a covered optional header (`Authorization` in the default factory) is covered only once.
* A `null` header adds no token header to any request.

**Java:**
```java
void setTokenHeader(String header, String prefix)
```

## getTokenHeader
Gets the name of the header that carries the Approov token.

**Java:**
```java
String getTokenHeader()
```

## getTokenPrefix
Gets the prefix, such as "Bearer ", that is added before the Approov token in its header.

**Java:**
```java
String getTokenPrefix()
```

## setTraceIDHeader
Sets the name of the header that carries the optional Approov TraceID debug value. The default is `Approov-TraceID`, and `initialize` puts it back. Passing `null` turns the TraceID header off.

**Java:**
```java
void setTraceIDHeader(String header)
```

## getTraceIDHeader
Gets the name of the header used for the Approov TraceID. Returns `null` if it is turned off.

**Java:**
```java
String getTraceIDHeader()
```

## setUseApproovStatusIfNoToken
Sets whether a request that goes ahead without a token carries the token fetch status in the token header. See [what happens by default](ADVANCED.md#what-happens-by-default).

* Off by default. A request that goes ahead after a failed token fetch then carries the token header with an empty token after any prefix.
* With the flag on, the token header carries the SDK fetch status name after any prefix, unchanged, such as `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`, `NO_APPROOV_SERVICE` or `REJECTED`. It always describes the token fetch, never a secure string fetch.
* Under `CLOSE_FAILURE`, the flag also lets `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` go ahead with the status, instead of throwing `ApproovNetworkException`. Every other failure still throws.
* The token header only goes to a host in the SDK pin set, that is an API domain you added to Approov. It is never sent to a host you have not added (`UNKNOWN_URL`), or to a secrets-only API added with `-noApproovToken` (`UNPROTECTED_URL`).
* `initialize` turns the flag off again, so call this after it.

**Java:**
```java
void setUseApproovStatusIfNoToken(boolean shouldUse)
```

## getUseApproovStatusIfNoToken
Gets whether the token fetch status is sent in the token header when no token is available.

**Java:**
```java
boolean getUseApproovStatusIfNoToken()
```

## Deprecated header aliases
These older names still work, but are deprecated. Each one calls the method with the name that every Approov package now uses:

* `setApproovHeader(header, prefix)` calls `setTokenHeader`
* `setApproovTraceIDHeader(header)` calls `setTraceIDHeader`

## formatApproovTokenHeaderValue
Formats a raw token or status value with the configured token prefix. It is meant for custom mutators.

**Java:**
```java
String formatApproovTokenHeaderValue(String value)
```

## getApproovTokenHeaderValue
Builds the value of the token header from a successful fetch result, with the configured prefix. It returns `null` if the result has no token.

**Java:**
```java
String getApproovTokenHeaderValue(Approov.TokenFetchResult approovResults)
```

## getApproovTokenHeaderValueOrStatus
Builds the value of the token header from a fetch result. It falls back to the fetch status name when there is no token. A custom mutator can use it to send the status in place of a token.

**Java:**
```java
String getApproovTokenHeaderValueOrStatus(Approov.TokenFetchResult approovResults)
```

## setLoggingLevel
Sets the level of the package's own logging. The levels are: `io.approov.service.volley.ApproovLogLevel.OFF`, `ERROR`, `WARNING`, `INFO` (the default) and `DEBUG`.

Each level includes the ones before it:
* `ERROR` writes errors only.
* `WARNING` adds warnings.
* `INFO` adds information lines, such as the result of initialization.
* `DEBUG` adds the debug lines. These include the [loggable form](https://approov.io/docs/latest/approov-usage-documentation/#loggable-tokens) of each request's token, whose claims include the device ID, and the device ID from `getDeviceID`.
* `OFF` writes nothing, not even errors.

You can set the level at any time, including before `initialize`. It takes effect for requests already in flight, and `initialize` does not reset it. Passing `null` throws `IllegalArgumentException` and leaves the level unchanged. The Approov SDK's own logging is not affected.

You can also turn on debug logging for the `ApproovService` tag with `adb shell setprop log.tag.ApproovService DEBUG`. This raises any level except `OFF` to `DEBUG`, for every tag of the package. It lets support read the debug lines of an installed build, release builds included, without a rebuild. Run `adb shell setprop log.tag.ApproovService INFO`, or reboot, to end it. `OFF` is final: if your app turned the package's logging off, this does not override it.

**Java:**
```java
void setLoggingLevel(ApproovLogLevel level)
```

## setBindingHeader
Sets a binding `header` for the [token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding) feature (see also [token binding](ADVANCED.md#token-binding)). Choose a header whose value stays the same for most requests, such as an Authorization header.

If the `header` is present on a request, its SHA256 hash is given to Approov. The issued token can then carry the matching `pay` claim, and so be bound to that value. Your backend integration can then check it.

The binding header cannot also be a secure string substitution header. That would bind the Approov token to the placeholder, while sending the substituted value to your backend. So either configuration call throws `IllegalArgumentException` when it detects the conflict, with the message `Header <name> cannot be used for both token binding and secure string substitution`. Header names are compared without regard to case. `initialize` clears the binding header, so call this after it.

**Java:**
```java
void setBindingHeader(String header)
```

## addSubstitutionHeader
Adds a `header` whose value is replaced by a [secure string](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings). If the header is present on a request, its value is used as a key to look up a secure string, which then replaces the header value. This makes it easy to move existing code to secure strings. See [secure strings](ADVANCED.md#secure-strings).

* `requiredPrefix` handles values with a fixed start, such as "`Bearer `" in an authorization header. Set it to `null` if you don't need one.
* If the secure string fetch returns `UNKNOWN_KEY`, the value is not a secure string key and the header is left as the app wrote it.
* If it returns any other status than `SUCCESS` and the request goes ahead, the status name, unchanged, goes after the prefix instead (`X-Api-Key: REJECTED`).
* A secure string is only substituted into a request sent over TLS (`https`) whose token fetch returned `SUCCESS` or `UNPROTECTED_URL`. Any other request keeps the placeholder under every mutator, custom mutators included. No secure string is fetched and the substitution hooks are not consulted. A cleartext or `BAD_URL` request logs a warning naming the header; the others log it at DEBUG.
* It applies to requests processed after the call, including through queues you already have. The stack substitutes it on every attempt and on each redirect that it protects.
* `initialize` removes every substitution header, so call this after it.

Header names are matched without regard to case. Adding the same header again replaces its configuration, and keeps the casing from the latest call. A substitution header cannot also be the token binding header. Either configuration call throws `IllegalArgumentException` when it detects the conflict. A `null` header throws `IllegalArgumentException` too.

**Java:**
```java
void addSubstitutionHeader(String header, String requiredPrefix)
```

## removeSubstitutionHeader
Removes a `header` you added with `addSubstitutionHeader`. Header names are matched without regard to case.

**Java:**
```java
void removeSubstitutionHeader(String header)
```

## getSubstitutionHeaders
Gets the headers currently subject to secure string substitution, each mapped to its required prefix. It returns a copy.

Before any `initialize` it throws `IllegalStateException` with the message `ApproovService is not initialized`. In bypass mode it works.

**Java:**
```java
Map<String, String> getSubstitutionHeaders()
```

## addSubstitutionQueryParam
Adds the `key` of a query parameter whose value is replaced by a [secure string](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings). If the query parameter is present in a URL, its value is used as a key to look up a secure string, which then replaces the value. This makes it easy to move existing code to secure strings.

* The `key` is matched as literal text, not as a regular expression. A `.` in it matches only a `.`.
* Every occurrence of the key in a URL's query is substituted. Each value is looked up as its own secure string key, and checked on its own.
* An occurrence whose secure string a URL would not carry unchanged keeps its placeholder, while the others are substituted.
* An occurrence whose fetch returns `UNKNOWN_KEY` is left as the app wrote it.
* An occurrence whose fetch returns any other status than `SUCCESS` becomes that status name (`REJECTED`, `NO_NETWORK` and so on).
* A cleartext (`http`) request, or one whose token fetch returned `BAD_URL`, keeps every placeholder under every mutator.
* `initialize` removes every substitution query parameter, so call this after it.

A redirect target URL is used exactly as the server sent it. Its query values are never looked up, even under a substitution query parameter. If the server echoes a secure string into it, the secure string is not changed back to the placeholder.

The stack substitutes the query of the request URL. It does not read the form parameters in the body of a request. Use [substituteQueryParam](#substitutequeryparam) for those.

> **Note**: The package inserts secure strings into the URL exactly as the Approov cloud returns them. It does **not** URL-encode them. A secure string that a URL would not carry unchanged (one with `&`, `#`, a space, a control or non-ASCII character) is not substituted. The placeholder stays and the request goes ahead. If your secure strings contain reserved characters, store them URL-encoded when you add them with the Approov CLI.

**Java:**
```java
void addSubstitutionQueryParam(String key)
```

## removeSubstitutionQueryParam
Removes a query parameter `key` you added with `addSubstitutionQueryParam`.

**Java:**
```java
void removeSubstitutionQueryParam(String key)
```

## getSubstitutionQueryParams
Gets the query parameter keys currently subject to secure string substitution, each mapped to its compiled regular expression pattern. It returns a copy.

Before any `initialize` it throws `IllegalStateException` with the message `ApproovService is not initialized`. In bypass mode it works.

**Java:**
```java
Map<String, Pattern> getSubstitutionQueryParams()
```

## addExclusionURLRegex
Adds a [regular expression](https://regex101.com/), the `urlRegex` parameter, for URLs to exclude. A request whose URL matches it gets no Approov token, secure strings or signature. See [excluding URLs](ADVANCED.md#excluding-urls).

**Java:**
```java
void addExclusionURLRegex(String urlRegex)
```

An invalid regular expression is logged as an error and nothing is added. No exception is thrown. The exclusions you already added are kept. `initialize` removes every exclusion, so call this after it.

Use this with *EXTREME CAUTION*, because of the way dynamic pinning works. Pinning may apply to every domain you added to Approov, and pin updates arrive when an Approov fetch is made. If you exclude some URLs on a domain protected by Approov, those URLs still use the Approov pins. But they give the pins no way to update until a URL that is not excluded is used.

So you must make sure your app can always call a URL that is not excluded, through the queue. A direct call to `fetchToken` does not update the pins.

Excluding URLs can also let a connection be made before any dynamic pins have arrived from Approov. That may open the connection to a man-in-the-middle (MitM) attack.

## removeExclusionURLRegex
Removes an exclusion regular expression (`urlRegex`) you added with `addExclusionURLRegex`.

**Java:**
```java
void removeExclusionURLRegex(String urlRegex)
```

## precheck
Checks whether your app will pass attestation. This needs [secure strings](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings) to be enabled for your account, although you don't need to set up any strings. Use it to check your integration while you develop.

**Java:**
```java
void precheck() throws ApproovException
```

It throws `ApproovException` if the precheck fails. That is an `ApproovFetchStatusException`, with the status in `getTokenFetchStatus()`. For `REJECTED` it is an `ApproovRejectionException`.

It will probably need network access, so it may take some time. Don't call it from the UI thread.

Before `initialize` and in bypass mode it throws `ApproovException` with the message `precheck: SDK not initialized`, without calling the SDK.

## getDeviceID
Gets the [device ID](https://approov.io/docs/latest/approov-usage-documentation/#extracting-the-device-id) that Approov uses to identify the device the SDK is running on. Different Approov apps on the same device get different IDs. The ID may also change if the app is uninstalled and reinstalled.

**Java:**
```java
String getDeviceID() throws ApproovException
```

It throws `ApproovException` if there was a problem getting the device ID. Before `initialize` and in bypass mode it throws `ApproovException` with the message `getDeviceID: SDK not initialized`, without calling the SDK.

## getServerAdjustedCurrentTimeMS
Gets the current time in milliseconds since the epoch, corrected to the Approov servers' clock. The SDK learns the offset between the device clock and the Approov servers' clock at each attestation. Before the installation's first attestation the value is the device clock. Message signatures take their `created` and `expires` times from it, so a device whose clock is wrong still signs within the window your backend accepts. Use it for timestamps of your own that your backend compares with its clock.

**Java:**
```java
long getServerAdjustedCurrentTimeMS() throws ApproovException
```

If the server time is not available, it returns the device clock. It throws `ApproovException` if the SDK call fails. Before `initialize` and in bypass mode it throws `ApproovException` with the message `getServerAdjustedCurrentTimeMS: SDK not initialized`, without calling the SDK.

## setDataHashInToken
Sets the [token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding) hash directly, for the Approov tokens fetched after it.

If the hash differs from any value set before, the next token fetch gets a new token with the new payload data hash. The token is expected to carry the `pay` claim, a base64 encoded string of the SHA256 hash of the data. The data is hashed on the device and never sent to the Approov cloud service.

This is an alternative to `setBindingHeader`. Don't use both at the same time.

**Java:**
```java
void setDataHashInToken(String data) throws ApproovException
```

It throws `ApproovException` if there was a problem changing the data hash. Before `initialize` and in bypass mode it throws `ApproovException` with the message `setDataHashInToken: SDK not initialized`, without calling the SDK.

## fetchToken
Fetches an Approov token for the given `url`. Use it where the stack cannot add the token to a request for you. Never cache the returned token in your app. Call this method each time you need one.

**Java:**
```java
String fetchToken(String url) throws ApproovException
```

It throws `ApproovException` if there was a problem getting a token. When the fetch did not succeed, that is an `ApproovFetchStatusException`, with the status in `getTokenFetchStatus()`.

It may need network access, so it may take some time. Don't call it from the UI thread.

Before `initialize` and in bypass mode it throws `ApproovException` with the message `fetchToken: SDK not initialized`, without calling the SDK.

It does not update the pins that the stack applies. Only requests made through the stack do that.

## getMessageSignature
Deprecated: use `getAccountMessageSignature` instead. It is kept in the 3.7.x releases as an alias, and returns the same value as `getAccountMessageSignature`.

**Java:**
```java
String getMessageSignature(String message) throws ApproovException
```

Before `initialize` and in bypass mode it throws `ApproovException` with the message `getAccountMessageSignature: SDK not initialized`, without calling the SDK.

## getAccountMessageSignature
Gets the [account message signature](https://approov.io/docs/latest/approov-usage-documentation/#account-message-signing) for the given message, as a base64 encoded string.

It uses a signing key specific to your account. The SDK receives this key after a successful fetch, if the feature is enabled for your account. If attestation failed, the key it receives is random, so the signature will be wrong. Always include an Approov token in the message you sign, and send the token alongside the signature, to prevent replay attacks.

**Java:**
```java
String getAccountMessageSignature(String message) throws ApproovException
```

It throws `ApproovException` with the message `no account signature available` if no signature is available, because there has been no fetch yet or the feature is not enabled. Before `initialize` and in bypass mode it throws `ApproovException` with the message `getAccountMessageSignature: SDK not initialized`, without calling the SDK.

## getInstallMessageSignature
Gets the [install message signature](https://approov.io/docs/latest/approov-usage-documentation/#installation-message-signing) for the given message. It is returned as the base64 encoding of the signature in ASN.1 DER format.

It uses a signing key specific to this installation of the app, generated the first time the app launches. The key is an ECC key pair whose private key is managed by the device's secure element or trusted execution environment. Where it can, Approov uses attested key pairs for this signing. Always include an Approov token in the message you sign, and send the token alongside the signature, to prevent replay attacks.

**Java:**
```java
String getInstallMessageSignature(String message) throws ApproovException
```

It throws `ApproovException` with the message `no device signature available` if no signature is available, because there has been no fetch yet or the feature is not enabled. Before `initialize` and in bypass mode it throws `ApproovException` with the message `getInstallMessageSignature: SDK not initialized`, without calling the SDK.

## fetchSecureString
Fetches the [secure string](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings) with the given `key`, or defines a new one.

* With `newDef` set to `null`, it looks up the secure string. It returns `null` if no secure string is defined for `key`.
* With `newDef` not `null`, it may define a secure string for this particular app instance. It then returns the new value as the secure string.
* An empty string as `newDef` removes the entry.

Never cache the returned string in your app. Call this method each time you need it.

**Java:**
```java
String fetchSecureString(String key, String newDef) throws ApproovException
```

It throws `ApproovException` if there was a problem getting the secure string. When the fetch did not succeed, that is an `ApproovFetchStatusException`, with the status in `getTokenFetchStatus()`. For `REJECTED` it is an `ApproovRejectionException`, with the ARC and rejection reasons.

It may need network access, so it may take some time. Don't call it from the UI thread.

Before `initialize` and in bypass mode it throws `ApproovException` with the message `fetchSecureString: SDK not initialized`, without calling the SDK.

## fetchCustomJWT
Fetches a [custom JWT](https://approov.io/docs/latest/approov-usage-documentation/#custom-jwts) with the given `payload`, which is a marshaled JSON string.

**Java:**
```java
String fetchCustomJWT(String payload) throws ApproovException
```

It throws `ApproovException` if there was a problem getting the custom JWT. When the fetch did not succeed, that is an `ApproovFetchStatusException`, with the status in `getTokenFetchStatus()`. For `REJECTED` it is an `ApproovRejectionException`, with the ARC and rejection reasons.

It may need network access, so it may take some time. Don't call it from the UI thread.

Before `initialize` and in bypass mode it throws `ApproovException` with the message `fetchCustomJWT: SDK not initialized`, without calling the SDK.

## getLastARC
Gets the [Attestation Response Code](https://approov.io/docs/latest/approov-usage-documentation/#attestation-response-code) (ARC) from the most recent fetch this package made. The ARC is a code that tells Approov support why attestation gave its result.

The fetch can be a token, secure string or custom JWT fetch. It can come from the HTTP stack (including secure string substitutions) or from a direct method (`fetchToken`, `fetchSecureString`, `fetchCustomJWT`, `precheck`).

It returns an empty string if:
* no fetch has been made since the last `initialize`, which clears it
* the last fetch produced no ARC
* ARC is not enabled for your account
* the last fetch failed without a result (an SDK exception in a direct method)

It makes no SDK call and does no fetch. It returns the value the app already received, so you can read it after a rejected request and match it up with your backend. Where possible, prefer logging the ARC your backend saw.

**Java:**
```java
String getLastARC()
```

## setInstallAttributes
Sets an [install attributes token](https://approov.io/docs/latest/approov-usage-documentation/#application-installation-attributes), which is sent to the server and associated with this app installation for future Approov token fetches. The token must be signed, within its expiry time, and bound to the correct device ID. The package passes it to the SDK's `Approov.setInstallAttrsInToken`.

**Java:**
```java
void setInstallAttributes(String attrs) throws ApproovException
```

It throws `ApproovException` if the SDK refuses the attributes. Before `initialize` and in bypass mode it throws `ApproovException` with the message `setInstallAttributes: SDK not initialized`, without calling the SDK.

`setInstallAttrsInToken(attrs)` does the same under its 3.5.x name. Before `initialize` and in bypass mode its message is `setInstallAttrsInToken: SDK not initialized`.

**Java:**
```java
void setInstallAttrsInToken(String attrs) throws ApproovException
```

## substituteHeader
Substitutes a header value in a map with a [secure string](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings). Do not use it for headers in new code. Register the header with [addSubstitutionHeader](#addsubstitutionheader), and the stack substitutes it on every request. This method stays for code that already calls it.

Call it from `Request.getHeaders()`, with `getUrl()` as `url`. It does nothing if Approov protection is not enabled. It substitutes only for a URL on a protected channel, which is an API added to Approov, with or without a token, over `https`. The rules for statuses and for values that a header cannot carry are the same as for `addSubstitutionHeader`.

**Java:**
```java
void substituteHeader(String url, Map<String, String> headers, String substitutionHeader, String requiredPrefix)
        throws ApproovException
```

A value that this method places belongs to your own headers, so a redirect carries it as the platform carries any header. This differs from the substitutions that the stack makes.

## substituteQueryParam
Substitutes a form parameter value in a map with a secure string. This is the only way to substitute the form parameters in the body of a request. Call it from `Request.getParams()`, with `getUrl()` as `url`.

**Java:**
```java
void substituteQueryParam(String url, Map<String, String> params, String queryParam) throws ApproovException
```

## substituteQueryParamInURLString
Substitutes a query parameter in a URL string. Do not use it in new code. Register the query parameter with [addSubstitutionQueryParam](#addsubstitutionqueryparam), and the stack substitutes it on every request. It returns the URL unchanged if nothing is substituted.

**Java:**
```java
String substituteQueryParamInURLString(String url, String queryParameter) throws ApproovException
```

# Extension classes

The classes below complete the public API of the package. A standard integration never uses them. See [ADVANCED.md](ADVANCED.md) for when you need them.

## ApproovServiceMutator

An interface with default methods, which you install with `setServiceMutator`. Its request defaults are the `CLOSE_FAILURE` decisions, the same as in 3.5.x. See [service mutators](ADVANCED.md#service-mutators).

Every `handleRequest...` hook declares `ApproovException`, and a mutator aborts a request by throwing one. `handlePinningShouldProcessRequest` declares no checked exception, so it aborts by throwing a `RuntimeException`. The request then fails with an `ApproovException` whose message is `ApproovServiceMutator.<hook> failed: <your exception>`, with yours as its cause. A pinning failure itself is unchanged: it fails with `SSLPeerUnverifiedException`.

Anything else a hook throws is treated as a failed request too. That includes a `NullPointerException` or other programming error, and a deliberate `RuntimeException`. The request fails with an `ApproovException` whose cause is the original exception. The hook is named in the exception message and in an error-level log line.

A hook can throw an Approov exception (`ApproovException` or a subclass) that is not one of the `CLOSE_FAILURE` decisions. The request then fails with an `ApproovException` that names the hook, with the original as its cause.

The `CLOSE_FAILURE` token decisions keep their 3.5.x exception types, whether a custom mutator inherits them or calls them. The standard substitution decisions never throw.

If a direct method hook (`handleFetchTokenResult`, `handleFetchSecureStringResult`, `handleFetchCustomJWTResult` or `handlePrecheckResult`) throws a `RuntimeException`, the direct method throws it as an `ApproovException`, with the original as its cause.

| Method | Default decision |
| :--- | :--- |
| `boolean handleRequestShouldProcess(Request<?>, Map<String, String> additionalHeaders) throws ApproovException` | `false` if the URL matches an exclusion regex, else `true` |
| `boolean handleRequestFetchTokenResult(TokenFetchResult, String url) throws ApproovException` | `true` for `SUCCESS` (token and trace headers) and `NO_APPROOV_SERVICE` (an empty token header, or the status, and any trace header). `false` for `UNKNOWN_URL` and `UNPROTECTED_URL` (no Approov headers). Throws `ApproovNetworkException` for `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED`, or returns `true` for them when `setUseApproovStatusIfNoToken` is on. Throws `ApproovFetchStatusException` for every other status, with the message `Approov token fetch for <url>: <status>`. For a failure status on a host that is not in the SDK pin set, the answer is ignored and the request goes out untouched. An exception from the standard decisions is ignored there too. Only your own exception aborts it. The answer only controls the Approov headers, and so whether an installed signer signs. Secure strings follow the token fetch status: they are substituted on `SUCCESS` and `UNPROTECTED_URL` over `https`, and never otherwise. Returning `true` on `UNKNOWN_URL` or `UNPROTECTED_URL` adds nothing |
| `boolean handleRequestHeaderSubstitutionResult(TokenFetchResult, String header) throws ApproovException` | Consulted only on a `SUCCESS` or `UNPROTECTED_URL` request over `https`. `true` for `SUCCESS`. `false` for every other status. The status name then replaces the placeholder, after any required prefix, and the request goes ahead. Never throws. An override may throw an `ApproovException` to abort. An override that returns `true` for a result with no secure string is treated as `false`. One that returns `false` on `SUCCESS` leaves the placeholder |
| `boolean handleRequestQueryParamSubstitutionResult(TokenFetchResult, String queryKey) throws ApproovException` | as for headers |
| `Map<String, String> handleRequestProcessedHeaders(Request<?>, Map<String, String> headers, ApproovRequestMutations) throws ApproovException` | returns the headers unchanged. `ApproovDefaultMessageSigning` signs here. The map holds the headers that Volley adds for its cache, the headers of your `Request` and the Approov headers. The package sets the token header itself, whatever this hook returns |
| `boolean handlePinningShouldProcessRequest(Request<?>)` | `true`. The package asks it for each request it sends and for each redirect hop it follows. It does not declare an exception |
| `String handleRequestTokenHeaderValue(TokenFetchResult, String url)` | deprecated and no longer called. The package sets the token header from the fetch result. Change the header in `handleRequestProcessedHeaders` |
| `void handlePrecheckResult(TokenFetchResult) throws ApproovException` | throws for every status except `SUCCESS` and `UNKNOWN_KEY` |
| `void handleFetchTokenResult(TokenFetchResult) throws ApproovException` | throws for every status except `SUCCESS` |
| `void handleFetchSecureStringResult(TokenFetchResult, String operation, String key) throws ApproovException` | throws for every status except `SUCCESS` and `UNKNOWN_KEY` |
| `void handleFetchCustomJWTResult(TokenFetchResult) throws ApproovException` | throws for every status except `SUCCESS` |

| Constant | Meaning |
| :--- | :--- |
| `CLOSE_FAILURE` | an instance with these defaults |
| `ALWAYS_PROCEED` | Never aborts. `handleRequestFetchTokenResult` returns `false` for `UNKNOWN_URL` and `UNPROTECTED_URL`, and `true` for every other status. The substitution decisions return `true` only for `SUCCESS` |
| `DEFAULT` | Declared as `ApproovServiceMutator`. It points to the release's default behaviour: `CLOSE_FAILURE`. If your app wants a fixed behaviour, name `CLOSE_FAILURE` or `ALWAYS_PROCEED` explicitly |

The standard mutators do not sign. [ApproovDefaultMessageSigning](#approovdefaultmessagesigning) is the mutator that signs.

## ApproovRequestMutations

Passed to `handleRequestProcessedHeaders`. It describes what the stack did to the request.

| Method | Meaning |
| :--- | :--- |
| `String getTokenHeaderKey()` | name of the token header added, or `null` if none |
| `String getTokenHeaderPrefix()` | prefix placed before the token, empty if none |
| `String getTraceIDHeaderKey()` | name of the trace header added, or `null` |
| `List<String> getAddedHeaderKeys()` | names of the headers that the stack added |
| `List<String> getSubstitutionHeaderKeys()` | headers whose values were replaced by secure strings, or `null`. A header that carries a fetch status instead of its placeholder is not listed |
| `String getOriginalURL()` | the URL before query parameters were replaced by secure strings, or `null` |
| `List<String> getSubstitutionQueryParamKeys()` | query parameters replaced by secure strings, or `null`. One that carries a fetch status is not listed |

The class also has setters for each of these. The stack uses them, and so do tests that build a mutations object for a custom mutator. A mutator that receives the object only needs to read it. Calling the setters changes nothing the package does.

## SignatureParameters

`io.approov.util.volley.sig.SignatureParameters` holds the covered components and the signature parameters of one signature (RFC 9421 section 2.3). It is used in three places: `SignatureParametersFactory.setBaseParameters` takes it, `generateDefaultSignatureParametersFactory(SignatureParameters)` accepts it, and a subclass of `ApproovDefaultMessageSigning` returns it from `buildSignatureParameters`.

| Method | Meaning |
| :--- | :--- |
| `SignatureParameters()` | empty parameter set |
| `SignatureParameters(SignatureParameters base)` | copy of the components, parameters and debug flag of another set |
| `SignatureParameters addComponentIdentifier(String)` / `(StringItem)` | covers a component. That is a derived component such as `ComponentProvider.DC_METHOD` (`@method`) or `DC_TARGET_URI` (`@target-uri`), or a header name. A component already covered, with the same name and parameters, is not added again (RFC 9421 section 2) |
| `boolean containsComponentIdentifier(String)` / `(StringItem)` | whether a component is covered |
| `String getAlg()` / `SignatureParameters setAlg(String)` | signature algorithm. The default factory leaves it unset, so that one signature is produced per configured algorithm. Set it to produce a single signature |
| `Long getCreated()` / `setCreated(Long)` | the `created` parameter, in seconds since the epoch |
| `Long getExpires()` / `setExpires(Long)` | the `expires` parameter |
| `String getKeyid()` / `setKeyid(String)` | the `keyid` parameter, not used by Approov signatures |
| `String getNonce()` / `setNonce(String)` | the `nonce` parameter |
| `String getTag()` / `setTag(String)` | the `tag` parameter |
| `Object getCustomParameter(String)` / `setCustomParameter(String, Object)` | any other signature parameter |
| `SignatureParameters setParameters(Map<String, Object>)` | replaces all signature parameters |
| `boolean isDebugMode()` / `void setDebugMode(boolean)` | when `true`, the signer adds `Signature-Base-Digest`, a SHA-256 of each signature base, to help you debug a verifier |
| `StringItem toComponentIdentifier()` | the `@signature-params` identifier |
| `InnerList toComponentValue()` | the `Signature-Input` member value for this set |
| `static SignatureParameters fromDictionaryEntry(Dictionary, String sigId)` | parses a `Signature-Input` member back into a parameter set. It keeps the components exactly as received, repeats included |

## Supporting signing classes

The packages `io.approov.util.volley.sig` (`ComponentProvider`, `SignatureBaseBuilder` and `SignatureParameters`) and `io.approov.util.volley.http.sfv` (the RFC 8941 structured field values, such as `StringItem`, `Dictionary` and `InnerList`) are public because the signing extension points use them. `ComponentProvider` names the derived components of RFC 9421 section 2.2, such as `DC_METHOD` and `DC_TARGET_URI`, and `SignatureBaseBuilder` builds the signature base that `ApproovDefaultMessageSigning` signs. Your app needs them only in a subclass of the signer or in a custom factory.

## ApproovDefaultMessageSigning

The message signing service mutator. Install it with `setServiceMutator` to sign requests (RFC 9421). See [message signing](ADVANCED.md#message-signing).

**Java:**
```java
ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
```

Every request that carries the Approov token header is signed after all the other changes the package makes, so the signature covers what is sent. That includes a request to one of your Approov API domains that goes ahead after a failed token fetch. Its token header then holds an empty token or the status. A request is signed again on every attempt: on a Volley retry and on each redirect hop that the package protects.

Signing is off unless you install it. The signer makes the interface default decisions, the same as `CLOSE_FAILURE`. Installing another mutator, passing `null` to `setServiceMutator` or calling `initialize` removes it. To sign under other decisions, use `combined(decisions)`, or call the signer from your own mutator (see [sign with other decisions](ADVANCED.md#sign-with-other-decisions)).

A signature that cannot be produced is left out, and the request goes ahead with the other one, or unsigned. Only configuration errors fail the request: a required body digest that cannot be generated (an `ApproovException` whose cause is `RequiredBodyDigestException`), or an unsupported signature algorithm (`ApproovException` with the message `Message signing: unsupported algorithm identifier: <alg>`).

`Content-Length` is never a covered component, because the platform adds it after signing. A `Content-Digest` header covers the body of a POST, PUT or PATCH request. Volley sends no body for another method, so no digest is made for it.

| Member | Meaning |
| :--- | :--- |
| `ApproovDefaultMessageSigning()` | a signer with no factory, which signs nothing until you set one |
| `ApproovDefaultMessageSigning setDefaultFactory(SignatureParametersFactory)` | the factory for every host without one of its own, or `null` to sign nothing for such hosts. Returns the signer |
| `ApproovDefaultMessageSigning putHostFactory(String hostName, SignatureParametersFactory)` | the factory for one host, matched without regard to case and without the port. `null` removes it, so the default applies again. Returns the signer |
| `protected SignatureParameters buildSignatureParameters(VolleyComponentProvider, ApproovRequestMutations)` | The override point for choosing parameters per request. The default builds them with the factory for the request's host. Returning `null` leaves the request unsigned. Let a `RequiredBodyDigestException` from `super` propagate |
| `Map<String, String> handleRequestProcessedHeaders(Request<?>, Map<String, String> headers, ApproovRequestMutations) throws ApproovException` | signs the request and returns the headers with the signature headers added. A mutator that calls it from its own `handleRequestProcessedHeaders` makes its changes first. A subclass that overrides it makes its changes, then calls `super` |
| `static SignatureParametersFactory generateDefaultSignatureParametersFactory()` | The default factory. It produces the install signature only. It covers the method and target URI, the token and trace headers, and `Authorization` and `Content-Type` when present. It never covers `Content-Length`. It also covers a SHA-256 body digest when one can be computed. It adds `created` and a 15 second `expires` |
| `static ApproovDefaultMessageSigning combined()` | a signer whose default factory adds both the install and the account signature. It makes the `ApproovServiceMutator.DEFAULT` decisions. Install it with `setServiceMutator` |
| `static ApproovDefaultMessageSigning combined(ApproovServiceMutator decisions)` | as `combined()`, but it makes the decisions of `decisions`, for example `ApproovServiceMutator.CLOSE_FAILURE` or `ALWAYS_PROCEED`. Each call returns a new signer. Throws `IllegalArgumentException` if `decisions` is `null` |
| `static SignatureParametersFactory generateDefaultSignatureParametersFactory(SignatureParameters base)` | as above, over a custom base set of components |
| `DIGEST_SHA256`, `DIGEST_SHA512` | body digest algorithms |
| `ALG_ES256`, `ALG_HS256` | signature algorithms (`ecdsa-p256-sha256`, `hmac-sha256`) |
| `SIG_ID_INSTALL`, `SIG_ID_ACCOUNT` | dictionary member names `install` and `account` |
| `RequiredBodyDigestException` | An `IllegalStateException` thrown by `buildSignatureParameters` when a required body digest cannot be generated. The request then fails with an `ApproovException` that has it as its cause |

## ApproovDefaultMessageSigning.SignatureParametersFactory

Builds the signature parameters for each request. All setters return the factory, so you can chain them. A factory is shared by every request it applies to. So configure it fully before you pass it to `setDefaultFactory` or `putHostFactory`, and use a separate instance for each distinct configuration.

| Method | Meaning |
| :--- | :--- |
| `setBaseParameters(SignatureParameters)` | components that are always covered |
| `setUseInstallMessageSigning()` | produce the install signature only. A newly constructed factory, and the default factory, start in this state |
| `setUseAccountMessageSigning()` | produce the account signature only |
| `setUseInstallAndAccountMessageSigning()` | produce both, as the members `install` and `account` of the same headers |
| `List<String> getAlgs()` | the configured algorithms, in the order the signatures are emitted. Throws `IllegalStateException` if there are none, and a request signed by such a factory is sent unsigned |
| `setAddCreated(boolean)` | add the `created` parameter, the signing time from [getServerAdjustedCurrentTimeMS](#getserveradjustedcurrenttimems) |
| `setExpiresLifetime(long seconds)` | add `expires` this many seconds after `created`; `0` leaves it out |
| `setAddApproovTokenHeader(boolean)` | cover the token header |
| `setAddApproovTraceIDHeader(boolean)` | cover the trace header when present |
| `addOptionalHeaders(String...)` | cover these headers when present |
| `setBodyDigestConfig(String algorithm, boolean required)` | compute `Content-Digest` with `DIGEST_SHA256` or `DIGEST_SHA512`, or pass `null` for none. With `required` set, the request fails when the digest cannot be generated |
| `protected SignatureParameters buildSignatureParameters(VolleyComponentProvider, ApproovRequestMutations)` | Builds the parameters for one request. The signer calls it. If the returned parameter set has an explicit `alg`, that single signature is produced. Otherwise the algorithms come from the factory (`getAlgs()`). To choose parameters per request, override `buildSignatureParameters` on `ApproovDefaultMessageSigning` instead |
